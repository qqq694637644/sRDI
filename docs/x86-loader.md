# x86 加载器分析

本文说明仓库中 x86 加载逻辑对应的代码位置，以及 32 位加载路径是如何从头到尾运作的。

## 分析范围

本文重点关注 sRDI 的 x86 路径：

- 转换代码如何构造最终的 shellcode 缓冲区；
- x86 bootstrap 如何在运行时计算地址并调用反射式 loader；
- `LoadDLL` 如何在内存中手工完成 PE 加载；
- 哪些行为是 x86 特有的，哪些是和 x64 的差异点。

## 对应代码在哪里

### 1. x86 bootstrap 的生成位置

x86 bootstrap 的主要实现位于：

- `Python/ShellcodeRDI.py:146-222`

其他前端里也有等价实现：

- `DotNet/Program.cs:628-723`
- `PowerShell/ConvertTo-Shellcode.ps1:182-277`

这些文件都会构造出相同的逻辑内存布局：

1. bootstrap shellcode
2. 内嵌的 RDI loader shellcode
3. 原始 DLL 字节
4. 用户数据

在 Python 实现中，这个布局最终返回的位置是：

- `Python/ShellcodeRDI.py:217-222`

### 2. RDI loader 的入口位置

手工 PE loader 的实现位于：

- `ShellcodeRDI/ShellcodeRDI.c:118-604`

函数签名是：

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

x86 bootstrap 最终调用的就是这个函数。

### 3. API 自解析辅助函数

loader 不依赖常规导入表来获取核心 API，对应的辅助函数在这里：

- `ShellcodeRDI/GetProcAddressWithHash.h:51-55`

在 x86 下，它通过 `fs:[0x30]` 读取 PEB：

```c
PebAddress = (PPEB) __readfsdword( 0x30 );
```

### 4. 最小测试调用入口

一个简单的本地 `LoadDLL` 调用示例在：

- `FunctionTest/FunctionTest.cpp:87-114`

虽然 x86 分析里更关键的是 shellcode bootstrap 路径，但这个文件有助于理解参数和 flags 的预期形式。

## 整体思路

sRDI 不是“直接原地执行 DLL”。它的做法是先把 DLL 转成位置无关的 shellcode，具体方式是前面拼接：

- 一段很小的、和架构相关的 bootstrap；
- 一个内嵌的反射式 loader（x86 对应 `rdiShellcode32`）；
- 然后再附上原始 DLL 字节和可选的用户数据。

在运行时，x86 bootstrap 会：

1. 用 `call` / `pop` 技巧获取自己当前的地址；
2. 计算内嵌 DLL 和用户数据在内存中的位置；
3. 按 x86 cdecl 调用约定，为 `LoadDLL` 压入参数；
4. 调用内嵌的反射式 loader；
5. 恢复栈并返回。

反射式 loader 随后会手工完成 PE 加载：

1. 解析核心 API；
2. 校验内存中的 PE 映像；
3. 分配目标映像内存；
4. 拷贝头部和节；
5. 执行重定位；
6. 修复导入表和延迟导入；
7. 设置最终页面权限；
8. 执行 TLS 回调；
9. 调用 `DllMain`；
10. 如有需要，再解析并调用一个导出函数。

## 第一阶段：x86 bootstrap 是如何构造的

x86 bootstrap 由 `Python/ShellcodeRDI.py:149-212` 生成。

### 运行时内存布局

`ConvertToShellcode` 返回的最终 x86 shellcode 块结构如下：

```text
[ x86 bootstrap ][ rdiShellcode32 ][ raw DLL bytes ][ user data ]
```

相关代码：

- bootstrap 大小定义：`Python/ShellcodeRDI.py:149-150`
- DLL 偏移计算：`Python/ShellcodeRDI.py:155-156`
- 最终拼接返回：`Python/ShellcodeRDI.py:217-222`

### 为什么 bootstrap 以 `call` / `pop` 开头

x86 shellcode 是位置无关的。它事先不知道自己会被拷贝到哪块内存里执行。由于 x86 不像 x64 那样有 RIP-relative addressing，因此 bootstrap 会这样获取一个可靠的运行时代码指针：

- `Python/ShellcodeRDI.py:152-159`

语义如下：

```text
call next   ; 把下一条指令地址压栈
pop eax     ; EAX = 当前 shellcode 块中的运行时地址
```

一旦 `EAX` 保存了当前 shellcode 缓冲区中的可靠地址，bootstrap 就能据此计算出：

- 内嵌 DLL 的位置（`eax + dllOffset`）
- 用户数据的位置（`edx + dllOffset + len(dllBytes)`）
- shellcode 基址参数（`eax` 在被继续调整前的值）

### x86 bootstrap 逐条指令分析

下面按源码顺序拆解 x86 bootstrap。

#### 前序和位置发现

- `Python/ShellcodeRDI.py:152-159`
  - `call next`
  - `pop eax`

作用：获取当前 shellcode 块中的运行时指针。

- `Python/ShellcodeRDI.py:161-165`
  - `push ebp`
  - `mov ebp, esp`

作用：建立一个简单栈帧，便于 bootstrap 在返回前使用 `leave`。

- `Python/ShellcodeRDI.py:167-168`
  - `mov edx, eax`

作用：先把原始运行时指针保存在 `EDX` 中，因为后续 `EAX` 会被改造成 DLL 起始地址。

#### 构造 `LoadDLL` 的参数

目标函数是：

```c
LoadDLL(pbModule, dwFunctionHash, lpUserData, dwUserdataLen, pvShellcodeBase, dwFlags)
```

由于 x86 cdecl 是从右到左压参，所以 bootstrap 会按逆序压入这些参数。

1. `dwFlags`
   - `Python/ShellcodeRDI.py:170-172`
   - `push <Flags>`

2. `pvShellcodeBase`
   - `Python/ShellcodeRDI.py:174-175`
   - `push eax`
   - 此时 `EAX` 仍然指向当前 shellcode 块中的某个位置，因此被当作 shellcode 基址参数使用。

3. `lpUserData`
   - `Python/ShellcodeRDI.py:177-187`
   - 先把 `EDX` 加上 `dllOffset + len(dllBytes)`，再压栈。

4. `dwUserdataLen`
   - `Python/ShellcodeRDI.py:182-184`
   - `push <Length of User Data>`

5. `dwFunctionHash`
   - `Python/ShellcodeRDI.py:189-191`
   - `push <hash of function>`

6. `pbModule`
   - `Python/ShellcodeRDI.py:193-198`
   - 把 `EAX` 加上 `dllOffset` 后再压栈。
   - 这样 `pbModule` 就指向了内嵌在 RDI shellcode 之后的原始 DLL 字节。

因此，在真正调用前，栈上的准备顺序是：

```text
push dwFlags
push pvShellcodeBase
push dwUserdataLen
push lpUserData
push dwFunctionHash
push pbModule
```

而由于 cdecl 会从右到左读取参数，这和 `LoadDLL(...)` 的函数签名正好完全匹配。

#### 调用内嵌反射式 loader

- `Python/ShellcodeRDI.py:200-203`
  - 相对 `call`

这里调用的不是导入函数，而是向前跳到紧跟在 bootstrap 后面的内嵌 `rdiShellcode32` blob。

它的位移这样计算：

- `bootstrapSize - len(bootstrap) - 4`

这个表达式的作用是跨过 bootstrap 剩余字节，让执行流准确落到内嵌 x86 反射式 loader 的起始位置。

#### 清理栈并返回

- `Python/ShellcodeRDI.py:205-206`
  - `add esp, 0x14`

这一步清理的是由调用方负责回收的那部分参数栈空间，符合 cdecl 约定。

- `Python/ShellcodeRDI.py:208-211`
  - `leave`
  - `ret`

作用是恢复原来的栈帧并返回给最初调用者。

## 第二阶段：`LoadDLL` 实际做了什么

真正的 loader 逻辑位于 `ShellcodeRDI/ShellcodeRDI.c:118-604`。

源码本身已经按编号把实现拆成多个步骤，因此执行流程很好跟踪。

## 第一步：自解析所需函数

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:213-255`
- `ShellcodeRDI/GetProcAddressWithHash.h:51-55`

loader 自己运行时不能依赖普通导入表，因此第一步是手工解析出一组最小可用 API。

过程如下：

1. `GetProcAddressWithHash(...)` 解析出 `LdrLoadDll` 和 `LdrGetProcAddress`。
2. `LdrLoadDll` 加载 `kernel32.dll`。
3. `LdrGetProcAddress` 再解析出：
   - `VirtualAlloc`
   - `VirtualProtect`
   - `FlushInstructionCache`
   - `GetNativeSystemInfo`
   - `Sleep`
   - `LoadLibraryA`
   - x64 下还会额外解析 `RtlAddFunctionTable`

对 x86 分析来说，关键点在于：shellcode 会先把自己引导到一个“足够可用的 loader 环境”，然后才开始处理内嵌 PE 映像。

## 第二步：校验内嵌 PE 并分配内存

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:257-329`

loader 把 `pbModule` 当成一个已经在内存中的 PE 文件，然后执行：

1. 定位 NT headers；
2. 校验 PE 签名；
3. 检查映像机器类型是否和当前构建目标一致；
4. 校验节对齐；
5. 计算最终按页对齐后的映像大小；
6. 优先尝试在首选 `ImageBase` 上分配内存；
7. 如果首选基址不可用，则退回到任意可用地址。

架构检查的位置在：

- `ShellcodeRDI/ShellcodeRDI.c:46-50`
- `ShellcodeRDI/ShellcodeRDI.c:268-269`

对于 x86 构建：

```c
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
```

因此 x86 shellcode 路径会拒绝加载非 x86 DLL。

## 第三步：拷贝头部和各节

相关代码：

- 头部：`ShellcodeRDI/ShellcodeRDI.c:314-329`
- 节：`ShellcodeRDI/ShellcodeRDI.c:331-341`

loader 会先拷贝 PE header，再把每个节的原始字节复制到新的映像基址中。

如果启用了 `SRDI_CLEARHEADER`，它还会把 DOS header / stub 大部分清掉，只保留 `e_lfanew` 等必要信息，以保证后续仍能找到 NT headers。

## 第四步：执行重定位

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:343-372`

这是整个 x86 加载路径里最重要的部分之一。

loader 先计算：

```c
baseOffset = baseAddress - ntHeaders->OptionalHeader.ImageBase;
```

如果映像没有被加载到首选基址，且重定位目录存在，它就会遍历 base relocation blocks，对每一个重定位项做修补。

### 为什么这对 x86 特别关键

对 x86 DLL 来说，代码或数据里的绝对地址通常会依赖 `IMAGE_REL_BASED_HIGHLOW` 重定位。对应代码在：

- `ShellcodeRDI/ShellcodeRDI.c:359-362`

```c
else if (relocList->type == IMAGE_REL_BASED_HIGHLOW)
    *(PULONG_PTR)((PBYTE)baseAddress + relocation->VirtualAddress + relocList->offset) += (DWORD)baseOffset;
```

它的含义是：

- 找到重定位位置上记录的那个 32 位绝对地址；
- 给它加上“新基址 - 首选基址”的差值；
- 修正后，这个指针在新的内存映像里就仍然有效。

这就是该项目里 x86 重定位行为的核心。

loader 同时还处理了 `DIR64`、`HIGH` 和 `LOW` 分支，但在 x86 路径中，最关键的就是 `HIGHLOW`。

## 第五步：修复导入地址表（IAT）

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:374-430`

loader 会遍历导入描述符数组，并手工修补 IAT。

对于每一个被导入的 DLL：

1. 用 `LoadLibraryA` 加载依赖模块；
2. 找到 `FirstThunk` 和 `OriginalFirstThunk`；
3. 对每个导入项按序号或按名称解析；
4. 把最终解析到的函数地址写回 `FirstThunk`。

这一步本质上是在手工复现 Windows loader 正常加载 DLL 时会做的导入修补工作。

### 导入混淆相关 flag

如果启用了 `SRDI_OBFUSCATEIMPORTS`，代码还可以：

- 打乱导入描述符的处理顺序；
- 用 flags 高 16 位指定的秒数，在处理导入组之间暂停。

对应逻辑在：

- `ShellcodeRDI/ShellcodeRDI.c:389-404`
- `ShellcodeRDI/ShellcodeRDI.c:426-428`

## 第六步：修复延迟导入

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:432-459`

这部分和普通导入修复思路相同，只不过处理目标从常规导入目录换成了 delay-import 目录。

## 第七步：设置最终节权限

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:463-510`

在完成拷贝和修补后，映像最初仍然处于可写内存状态。接下来 loader 会根据每个节的 `Characteristics` 设置最终页面权限。

它会先判断每个节是否：

- 可执行
- 可读
- 可写

然后把这些属性转换成对应的 `PAGE_*` 权限，并对每个节调用 `VirtualProtect`。

最后还会刷新指令缓存：

- `ShellcodeRDI/ShellcodeRDI.c:508-509`

这样可以避免刚刚写入的代码页在执行时仍然使用旧缓存。

## 第八步：执行 TLS 回调

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:511-525`

如果映像带有 TLS 目录，loader 会遍历 `AddressOfCallBacks`，并以 `DLL_PROCESS_ATTACH` 的方式依次调用每个 TLS 回调。

这一步很重要，因为不少 DLL 在真正运行前依赖 TLS 初始化逻辑。

## 第九步：仅 x64 才有的异常注册

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:527-539`

这段代码只在 `_WIN64` 下编译。

也就是说，x86 路径**不会**执行运行时函数表注册。这是该项目里 x86 和 x64 最清晰的差异之一。

## 第十步：调用 `DllMain`

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:541-546`

loader 会根据 `AddressOfEntryPoint` 计算入口点，然后调用：

```c
dllMain((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, (LPVOID)1);
```

到这一步为止，映像已经完成了拷贝、重定位、导入修复和页面权限设置。

## 第十一步：按需调用导出函数

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:548-595`

如果 `dwFunctionHash` 不为 0，loader 会：

1. 遍历导出目录；
2. 对每个导出名计算哈希；
3. 与 `dwFunctionHash` 比较；
4. 定位目标函数地址；
5. 调用该函数。

传入参数取决于 flags：

- 如果设置了 `SRDI_PASS_SHELLCODE_BASE`，则传入 `pvShellcodeBase`；
- 否则传入 `lpUserData` 和 `dwUserdataLen`。

对应位置：

- `ShellcodeRDI/ShellcodeRDI.c:585-589`

## 清理行为

相关代码：

- `ShellcodeRDI/ShellcodeRDI.c:597-603`

如果启用了 `SRDI_CLEARMEMORY`，原始 `pbModule` 缓冲区会在加载完成后被释放。

函数最终返回 `baseAddress`，也就是实际加载后的模块基址。

## x86 特有的实现要点

### 1. 位置发现依赖 `call` / `pop`

x64 的 bootstrap 会更多依赖 x64 调用约定寄存器和栈对齐，而 x86 shellcode 则采用经典的 `call` / `pop` 技巧，因为它需要一种位置无关的方式来找到自己当前的运行地址。

对应 x86 源码：

- `Python/ShellcodeRDI.py:152-159`

### 2. 调用约定是 cdecl

x86 bootstrap 会通过下面这段代码自己清理参数栈：

- `Python/ShellcodeRDI.py:205-206`

这说明调用方负责清栈，和这里使用的 cdecl 风格 `LoadDLL` 调用方式一致。

### 3. 主要重定位类型是 `IMAGE_REL_BASED_HIGHLOW`

x86 路径最依赖的是 `HIGHLOW` 重定位：

- `ShellcodeRDI/ShellcodeRDI.c:361-362`

这可以看作该 loader 支持 x86 重定位的实际核心。

### 4. x86 下 PEB 的访问方式不同

`GetProcAddressWithHash.h` 里使用的是：

- x86：`__readfsdword(0x30)`
- x64：`__readgsqword(0x60)`

对应行号：

- `ShellcodeRDI/GetProcAddressWithHash.h:51-55`

### 5. 没有 x64 风格的异常元数据注册

x86 路径不会执行 `_WIN64` 下那段异常注册逻辑，位置在：

- `ShellcodeRDI/ShellcodeRDI.c:531-538`

## x86 端到端执行链

可以把整个 x86 路径浓缩为：

```text
ConvertToShellcode()
  -> 构造 [bootstrap][rdiShellcode32][dll][userdata]
  -> 执行 bootstrap
  -> 通过 call/pop 获取当前 shellcode 地址
  -> 计算 pbModule 和 lpUserData
  -> 按 x86 cdecl 顺序压入 LoadDLL 参数
  -> 调用内嵌 rdiShellcode32
  -> LoadDLL 解析核心 API
  -> 校验 PE headers
  -> 分配目标映像内存
  -> 拷贝头部和各节
  -> 执行 x86 重定位（主要是 HIGHLOW）
  -> 修复导入和延迟导入
  -> 设置节权限
  -> 刷新指令缓存
  -> 执行 TLS 回调
  -> 调用 DllMain
  -> 按需按哈希调用导出函数
  -> 返回已加载模块基址
```

## 给审阅者的快速代码地图

如果你只想走最短路径读代码，建议按下面顺序看：

1. `Python/ShellcodeRDI.py:146-222`
2. `ShellcodeRDI/GetProcAddressWithHash.h:51-55`
3. `ShellcodeRDI/ShellcodeRDI.c:118-255`
4. `ShellcodeRDI/ShellcodeRDI.c:261-372`
5. `ShellcodeRDI/ShellcodeRDI.c:378-459`
6. `ShellcodeRDI/ShellcodeRDI.c:463-546`
7. `ShellcodeRDI/ShellcodeRDI.c:552-603`

## 给维护者的备注

- Python、C# 和 PowerShell 前端实现的是同一套 bootstrap 思路。如果改了其中一个前端，最好顺手检查另外两个前端是否也需要保持一致。
- x86 bootstrap 故意做得很小，而且强依赖架构。它只负责准备参数并把控制流转移给内嵌反射式 loader；真正的 PE 加载逻辑都在 `ShellcodeRDI/ShellcodeRDI.c` 里。
- 理解 x86 路径时，最容易的方法是把它拆成两层：
  - 一层是负责算指针和搭建调用的微型 bootstrap；
  - 另一层是负责重定位 / 导入 / TLS / 页面权限处理的完整内存 PE loader。
