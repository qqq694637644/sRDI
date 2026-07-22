# sRDI - Shellcode 反射式 DLL 注入
sRDI 可以把 DLL 文件转换为位置无关的 shellcode。它尝试实现一个功能完整的 PE loader，支持正确的节权限、TLS 回调和基本完整性检查。你可以把它理解为：把一个 shellcode 形式的 PE loader 和一个打包后的 DLL 绑在一起执行。

整个功能由两个部分组成：
- 一个 C 项目，用来把 PE loader 实现（RDI）编译成 shellcode
- 一套转换代码，用 bootstrap 把 DLL、RDI 和用户数据拼接到一起

这个项目包含以下组成部分：
- **ShellcodeRDI:** 将 DLL loader 编译为 shellcode
- **NativeLoader:** 必要时先把 DLL 转为 shellcode，再注入到内存中
- **DotNetLoader:** NativeLoader 的 C# 实现
- **Python\\ConvertToShellcode.py:** 直接把 DLL 转换为 shellcode
- **Python\\EncodeBlobs.py:** 对编译后的 sRDI blob 做编码，便于静态嵌入
- **PowerShell\\ConvertTo-Shellcode.ps1:** 直接把 DLL 转换为 shellcode
- **FunctionTest:** 导入 sRDI C 函数进行调试测试
- **TestDLL:** 示例 DLL，包含两个导出函数，分别用于加载时调用和加载后调用

## 补充文档
- [`docs/x86-loader.md`](docs/x86-loader.md)：详细说明 x86 bootstrap 和反射式加载路径。

**目标 DLL 不需要专门以 RDI 方式编译，不过这项技术本身是可以跨实现兼容使用的。**

## 使用场景 / 示例
在使用之前，建议先熟悉 [Reflective DLL Injection](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html) 及其用途。

#### 使用 Python 将 DLL 转为 shellcode
```python
from ShellcodeRDI import *

dll = open("TestDLL_x86.dll", 'rb').read()
shellcode = ConvertToShellcode(dll)
```

#### 使用 C# loader 将 DLL 加载到内存
```
DotNetLoader.exe TestDLL_x64.dll
```

#### 使用 Python 脚本转换 DLL，再用 Native EXE 加载
```
python ConvertToShellcode.py TestDLL_x64.dll
NativeLoader.exe TestDLL_x64.bin
```

#### 使用 PowerShell 转换 DLL，并配合 Invoke-Shellcode 加载
```powershell
Import-Module .\Invoke-Shellcode.ps1
Import-Module .\ConvertTo-Shellcode.ps1
Invoke-Shellcode -Shellcode (ConvertTo-Shellcode -File TestDLL_x64.dll)
```

## Flags
PE loader 代码通过 `flags` 参数控制不同的加载行为：

- `SRDI_CLEARHEADER` [0x1]：加载时会把目标 DLL 的 DOS Header 和 DOS Stub 用空字节清掉（`e_lfanew` 除外）。如果你后续把模块基址当成伪 `HMODULE` 传给原生 Windows API，这可能会导致兼容性问题。
- `SRDI_CLEARMEMORY` [0x2]：在调用完已加载模块中的函数（`DllMain` 和任意导出函数）后，会清除该 DLL 的原始内存数据。如果你还希望继续在这个模块中执行代码（例如线程或 `GetProcAddressR`），这个选项会比较危险。
- `SRDI_OBFUSCATEIMPORTS` [0x4]：在开始修补 IAT 前，会先随机化模块导入项的处理顺序。此外，flag 的高 16 位可以用来保存每次处理下一个导入前需要暂停的秒数。例如 `flags | (3 << 16)` 表示每处理一个导入后暂停 3 秒。
- `SRDI_PASS_SHELLCODE_BASE` [0x8]：导出函数将不再接收用户提供的数据，而是改为接收当前正在执行的 shellcode 块基址。这对更复杂模块中的自清理逻辑会很有用。

## 构建
本项目使用 Visual Studio 2019 (v142) 和 Windows SDK 10 构建。Python 脚本使用 Python 3 编写。

Python 和 PowerShell 脚本位于：
- `Python\ConvertToShellcode.py`
- `PowerShell\ConvertTo-Shellcode.ps1`

构建完成后，其他二进制文件位于：
- `bin\NativeLoader.exe`
- `bin\DotNetLoader.exe`
- `bin\TestDLL_<arch>.dll`
- `bin\ShellcodeRDI_<arch>.bin`

如果你想更新任意工具中静态嵌入的 blob：
```
> python .\lib\Python\EncodeBlobs.py -h
usage: EncodeBlobs.py [-h] solution_dir

sRDI Blob Encoder

positional arguments:
  solution_dir  Solution Directory

optional arguments:
  -h, --help    show this help message and exit

> python lib\Python\EncodeBlobs.py C:\code\srdi

[+] Updated C:\code\srdi\Native/Loader.cpp
[+] Updated C:\code\srdi\DotNet/Program.cs
[+] Updated C:\code\srdi\Python/ShellcodeRDI.py
[+] Updated C:\code\srdi\PowerShell/ConvertTo-Shellcode.ps1

```

## 可选替代方案
如果你觉得我的代码写得很难看，或者只是想找一个别的内存 PE loader 项目，可以看看下面这些：

- https://github.com/fancycode/MemoryModule - 也许是最干净的 PE loader 之一，很适合当参考。
- https://github.com/TheWover/donut - 想把 .NET 程序集转起来？或者 JScript？
- https://github.com/hasherezade/pe_to_shellcode - 可以生成多态的 PE + shellcode 混合体。
- https://github.com/DarthTon/Blackbone - 一个体量很大的库，包含很多内存操作 / hook 原语。

## 致谢
本项目的基础来自 Dan Staples 的 ["Improved Reflective DLL Injection"](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html)，而它本身又是基于 Stephen Fewer 的原始项目演化而来。

把 C 代码编译成 shellcode 的项目框架则取自 Mathew Graeber 的研究 ["PIC_BindShell"](http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html)。