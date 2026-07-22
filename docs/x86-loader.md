# x86 loader analysis

This document explains where the x86 loader logic lives in the repository and how the 32-bit loading path works end to end.

## Scope

This note focuses on the x86 path in sRDI:

- how the conversion code builds the final shellcode buffer;
- how the x86 bootstrap computes runtime addresses and calls the reflective loader;
- how `LoadDLL` performs manual PE loading in memory;
- what behavior is x86-specific versus x64.

## Where the corresponding code is

### 1. x86 bootstrap generation

The main x86 bootstrap implementation is in:

- `Python/ShellcodeRDI.py:146-222`

Equivalent implementations exist in other frontends:

- `DotNet/Program.cs:628-723`
- `PowerShell/ConvertTo-Shellcode.ps1:182-277`

These files all build the same logical memory layout:

1. bootstrap shellcode
2. embedded RDI loader shellcode
3. raw DLL bytes
4. user data

In the Python implementation that layout is returned at:

- `Python/ShellcodeRDI.py:217-222`

### 2. RDI loader entry point

The manual PE loader implementation is here:

- `ShellcodeRDI/ShellcodeRDI.c:118-604`

The function signature is:

```c
ULONG_PTR LoadDLL(
    PBYTE pbModule,
    DWORD dwFunctionHash,
    LPVOID lpUserData,
    DWORD dwUserdataLen,
    PVOID pvShellcodeBase,
    DWORD dwFlags
)
```

This is the function the x86 bootstrap eventually calls.

### 3. API self-resolution helper

The loader resolves core APIs without relying on a normal import table. That helper is here:

- `ShellcodeRDI/GetProcAddressWithHash.h:51-55`

On x86 it reads the PEB from `fs:[0x30]`:

```c
PebAddress = (PPEB) __readfsdword( 0x30 );
```

### 4. Minimal test harness

A simple local call into `LoadDLL` exists here:

- `FunctionTest/FunctionTest.cpp:87-114`

That file is useful to understand the expected arguments and flags, even though the shellcode bootstrap path is more interesting for x86 analysis.

## Big picture

sRDI does not execute the original DLL in place. Instead, it turns the DLL into position-independent shellcode by prepending:

- a small architecture-specific bootstrap;
- an embedded reflective loader (`rdiShellcode32` for x86);
- then appending the raw DLL bytes and optional user data.

At runtime the x86 bootstrap:

1. discovers its own current address using a `call` / `pop` trick;
2. computes where the embedded DLL and user data sit in memory;
3. pushes arguments for `LoadDLL` using the x86 cdecl calling convention;
4. calls the embedded reflective loader;
5. restores the stack and returns.

The reflective loader then performs manual PE loading:

1. resolve core APIs;
2. validate the in-memory PE image;
3. allocate destination memory;
4. copy headers and sections;
5. apply relocations;
6. repair imports and delay imports;
7. set final page protections;
8. run TLS callbacks;
9. call `DllMain`;
10. optionally resolve and call an exported function.

## Stage 1: how the x86 bootstrap is built

The x86 bootstrap is generated in `Python/ShellcodeRDI.py:149-212`.

### Runtime layout

The final x86 shellcode block returned by `ConvertToShellcode` is:

```text
[ x86 bootstrap ][ rdiShellcode32 ][ raw DLL bytes ][ user data ]
```

Relevant code:

- bootstrap size definition: `Python/ShellcodeRDI.py:149-150`
- offset to DLL: `Python/ShellcodeRDI.py:155-156`
- final concatenation: `Python/ShellcodeRDI.py:217-222`

### Why the bootstrap starts with `call` / `pop`

The x86 shellcode is position-independent. It does not know in advance where it has been copied in memory. Because x86 has no RIP-relative addressing like x64, the bootstrap obtains a runtime code pointer like this:

- `Python/ShellcodeRDI.py:152-159`

Semantics:

```text
call next   ; push address of next instruction
pop eax     ; EAX = runtime address inside current shellcode block
```

Once `EAX` holds a reliable pointer into the current shellcode buffer, the bootstrap can compute the addresses of:

- the embedded DLL (`eax + dllOffset`)
- the user data (`edx + dllOffset + len(dllBytes)`)
- the shellcode base argument (`eax` before it is adjusted)

### x86 bootstrap instruction-by-instruction

Below is the x86 bootstrap in source order.

#### Prologue and position discovery

- `Python/ShellcodeRDI.py:152-159`
  - `call next`
  - `pop eax`

Purpose: obtain a runtime pointer to the current shellcode block.

- `Python/ShellcodeRDI.py:161-165`
  - `push ebp`
  - `mov ebp, esp`

Purpose: set up a simple frame so the bootstrap can use `leave` before returning.

- `Python/ShellcodeRDI.py:167-168`
  - `mov edx, eax`

Purpose: preserve the original runtime pointer in `EDX` while `EAX` is later adjusted to the DLL start.

#### Building `LoadDLL` arguments

The target function is:

```c
LoadDLL(pbModule, dwFunctionHash, lpUserData, dwUserdataLen, pvShellcodeBase, dwFlags)
```

Since x86 cdecl pushes arguments right-to-left, the bootstrap pushes them in reverse order.

1. `dwFlags`
   - `Python/ShellcodeRDI.py:170-172`
   - `push <Flags>`

2. `pvShellcodeBase`
   - `Python/ShellcodeRDI.py:174-175`
   - `push eax`
   - At this moment `EAX` still points into the current shellcode block and is used as the shellcode-base argument.

3. `lpUserData`
   - `Python/ShellcodeRDI.py:177-187`
   - `EDX` is advanced by `dllOffset + len(dllBytes)` and then pushed.

4. `dwUserdataLen`
   - `Python/ShellcodeRDI.py:182-184`
   - `push <Length of User Data>`

5. `dwFunctionHash`
   - `Python/ShellcodeRDI.py:189-191`
   - `push <hash of function>`

6. `pbModule`
   - `Python/ShellcodeRDI.py:193-198`
   - `EAX` is advanced by `dllOffset` and then pushed.
   - This makes `pbModule` point at the raw DLL bytes embedded after the RDI shellcode.

In stack order, just before the call, the bootstrap has prepared:

```text
push dwFlags
push pvShellcodeBase
push dwUserdataLen
push lpUserData
push dwFunctionHash
push pbModule
```

Because cdecl reads arguments from right to left, this matches the `LoadDLL(...)` signature exactly.

#### Calling the embedded reflective loader

- `Python/ShellcodeRDI.py:200-203`
  - relative `call`

This call does not jump to an imported function. It jumps forward into the embedded `rdiShellcode32` blob that lives immediately after the bootstrap.

The displacement is computed as:

- `bootstrapSize - len(bootstrap) - 4`

That expression skips over the remaining bootstrap bytes so execution lands at the start of the embedded x86 reflective loader.

#### Stack cleanup and return

- `Python/ShellcodeRDI.py:205-206`
  - `add esp, 0x14`

This removes the five pushed arguments that the caller is responsible for cleaning in cdecl.

- `Python/ShellcodeRDI.py:208-211`
  - `leave`
  - `ret`

This restores the stack frame and returns to the original caller.

## Stage 2: what `LoadDLL` does

The real loader logic is in `ShellcodeRDI/ShellcodeRDI.c:118-604`.

The source already organizes the implementation into numbered steps, which makes the control flow easy to follow.

## Step 1: self-resolve required functions

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:213-255`
- `ShellcodeRDI/GetProcAddressWithHash.h:51-55`

The loader cannot rely on a normal import table because it is itself running as shellcode. So it first resolves a minimal API set manually.

Process:

1. `GetProcAddressWithHash(...)` resolves `LdrLoadDll` and `LdrGetProcAddress`.
2. `LdrLoadDll` loads `kernel32.dll`.
3. `LdrGetProcAddress` resolves:
   - `VirtualAlloc`
   - `VirtualProtect`
   - `FlushInstructionCache`
   - `GetNativeSystemInfo`
   - `Sleep`
   - `LoadLibraryA`
   - optionally `RtlAddFunctionTable` on x64

For x86 analysis, the important point is that the shellcode bootstraps itself into a usable loader environment before it starts touching the embedded PE image.

## Step 2: validate the embedded PE and allocate memory

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:257-329`

The loader interprets `pbModule` as a PE file already present in memory. It then:

1. locates the NT headers;
2. checks the PE signature;
3. checks that the image machine type matches the current build target;
4. verifies section alignment;
5. computes the final aligned image size;
6. tries to allocate memory at the preferred `ImageBase`;
7. falls back to an arbitrary address if the preferred base is unavailable.

The architecture gate is here:

- `ShellcodeRDI/ShellcodeRDI.c:46-50`
- `ShellcodeRDI/ShellcodeRDI.c:268-269`

For x86 builds:

```c
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
```

So an x86 shellcode path will reject a non-x86 DLL.

## Step 3: copy headers and sections

Relevant code:

- headers: `ShellcodeRDI/ShellcodeRDI.c:314-329`
- sections: `ShellcodeRDI/ShellcodeRDI.c:331-341`

The loader copies the PE headers and then copies each section's raw bytes into the new image base.

If `SRDI_CLEARHEADER` is enabled, the DOS header/stub is mostly wiped while preserving `e_lfanew` so the NT headers remain discoverable.

## Step 4: apply relocations

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:343-372`

This is one of the most important parts of the x86 loading path.

The loader computes:

```c
baseOffset = baseAddress - ntHeaders->OptionalHeader.ImageBase;
```

If the image did not land at its preferred base and the relocation directory exists, it walks the base relocation blocks and patches each relocation entry.

### Why this matters on x86

For x86 DLLs, absolute addresses in code or data commonly use `IMAGE_REL_BASED_HIGHLOW` relocations. That case is handled here:

- `ShellcodeRDI/ShellcodeRDI.c:359-362`

```c
else if (relocList->type == IMAGE_REL_BASED_HIGHLOW)
    *(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += (DWORD)baseOffset;
```

Meaning:

- find the 32-bit absolute address recorded at the relocation site;
- add the difference between the new base and the preferred base;
- after that adjustment, the pointer is valid at the new in-memory location.

This is the core x86 relocation behavior in this project.

The loader also contains branches for `DIR64`, `HIGH`, and `LOW`, but `HIGHLOW` is the main x86 case.

## Step 5: repair the import address table

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:374-430`

The loader walks the import descriptor array and patches the IAT manually.

For each imported DLL:

1. `LoadLibraryA` loads the dependency.
2. `FirstThunk` and `OriginalFirstThunk` are located.
3. Each import is resolved by ordinal or by name.
4. The resolved function address is written into `FirstThunk`.

This reproduces what the Windows loader would normally do during a standard DLL load.

### Import obfuscation flag

If `SRDI_OBFUSCATEIMPORTS` is set, the code can:

- randomize import descriptor processing order;
- sleep between import groups using the high 16 bits of the flags field.

That logic lives at:

- `ShellcodeRDI/ShellcodeRDI.c:389-404`
- `ShellcodeRDI/ShellcodeRDI.c:426-428`

## Step 6: repair delayed imports

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:432-459`

This is conceptually the same as normal import repair, but it targets the delay-import directory instead of the regular import directory.

## Step 7: finalize section protections

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:463-510`

After patching and copying, the image is still in writable memory. The loader now applies final page protections based on section characteristics.

It derives whether a section is:

- executable
- readable
- writable

Then it translates those bits into a corresponding `PAGE_*` protection and calls `VirtualProtect` for each section.

Finally it flushes the instruction cache:

- `ShellcodeRDI/ShellcodeRDI.c:508-509`

That avoids stale instructions being executed from recently written code pages.

## Step 8: execute TLS callbacks

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:511-525`

If the image has a TLS directory, the loader walks `AddressOfCallBacks` and invokes each callback with `DLL_PROCESS_ATTACH`.

That is important because many DLLs rely on TLS setup code before normal execution.

## Step 9: x64-only exception registration

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:527-539`

This block is compiled only under `_WIN64`.

That means the x86 path does **not** perform runtime function table registration. This is one of the clearest differences between x86 and x64 behavior in the project.

## Step 10: call `DllMain`

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:541-546`

The loader calculates the entry point from `AddressOfEntryPoint` and calls:

```c
dllMain((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, (LPVOID)1);
```

At this point the image has been copied, relocated, had its imports repaired, and had final protections applied.

## Step 11: optionally call an exported function

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:548-595`

If `dwFunctionHash` is non-zero, the loader:

1. walks the export directory;
2. hashes each export name;
3. compares it with `dwFunctionHash`;
4. resolves the target function address;
5. calls the function.

Argument selection depends on flags:

- if `SRDI_PASS_SHELLCODE_BASE` is set, it passes `pvShellcodeBase`;
- otherwise it passes `lpUserData` and `dwUserdataLen`.

Relevant lines:

- `ShellcodeRDI/ShellcodeRDI.c:585-589`

## Cleanup behavior

Relevant code:

- `ShellcodeRDI/ShellcodeRDI.c:597-603`

If `SRDI_CLEARMEMORY` is set, the original `pbModule` buffer can be freed after loading.

The loader returns `baseAddress`, which is effectively the loaded module base.

## x86-specific implementation notes

### 1. Position discovery uses `call` / `pop`

On x64, the bootstrap logic uses x64 calling-convention registers and stack alignment. On x86, the shellcode instead relies on the classic `call` / `pop` technique because it needs a position-independent way to find its current address.

Relevant x86 source:

- `Python/ShellcodeRDI.py:152-159`

### 2. Calling convention is cdecl

The x86 bootstrap cleans up the stack itself with:

- `Python/ShellcodeRDI.py:205-206`

That indicates caller cleanup and matches the cdecl-style `LoadDLL` invocation used by this shellcode bootstrap.

### 3. Main relocation type is `IMAGE_REL_BASED_HIGHLOW`

The x86 path mainly depends on `HIGHLOW` relocations:

- `ShellcodeRDI/ShellcodeRDI.c:361-362`

This is the practical heart of x86 relocation support in the loader.

### 4. PEB access differs on x86

`GetProcAddressWithHash.h` uses:

- x86: `__readfsdword(0x30)`
- x64: `__readgsqword(0x60)`

Relevant lines:

- `ShellcodeRDI/GetProcAddressWithHash.h:51-55`

### 5. No x64-style exception metadata registration

The x86 path does not execute the `_WIN64` exception-registration block found at:

- `ShellcodeRDI/ShellcodeRDI.c:531-538`

## End-to-end x86 execution chain

A compact view of the x86 path is:

```text
ConvertToShellcode()
  -> build [bootstrap][rdiShellcode32][dll][userdata]
  -> execute bootstrap
  -> call/pop obtains runtime shellcode address
  -> compute pbModule and lpUserData
  -> push LoadDLL args using x86 cdecl order
  -> call embedded rdiShellcode32
  -> LoadDLL resolves core APIs
  -> validate PE headers
  -> allocate destination image memory
  -> copy headers and sections
  -> apply x86 relocations (mainly HIGHLOW)
  -> repair imports and delay imports
  -> set section protections
  -> flush instruction cache
  -> run TLS callbacks
  -> call DllMain
  -> optionally call export by hash
  -> return loaded base address
```

## Quick code map for reviewers

If you only want the shortest path through the code, read these locations in order:

1. `Python/ShellcodeRDI.py:146-222`
2. `ShellcodeRDI/GetProcAddressWithHash.h:51-55`
3. `ShellcodeRDI/ShellcodeRDI.c:118-255`
4. `ShellcodeRDI/ShellcodeRDI.c:261-372`
5. `ShellcodeRDI/ShellcodeRDI.c:378-459`
6. `ShellcodeRDI/ShellcodeRDI.c:463-546`
7. `ShellcodeRDI/ShellcodeRDI.c:552-603`

## Notes for maintainers

- The Python, C#, and PowerShell frontends all implement the same bootstrap idea. If one frontend is changed, the others should be reviewed for consistency.
- The x86 bootstrap is intentionally tiny and architecture-specific. It only prepares arguments and transfers control to the embedded reflective loader; the actual PE loading logic lives in `ShellcodeRDI/ShellcodeRDI.c`.
- The x86 path is easiest to reason about by separating it into two layers:
  - a small bootstrap that computes pointers and sets up a call;
  - a full in-memory PE loader that performs relocation/import/TLS/protection work.
