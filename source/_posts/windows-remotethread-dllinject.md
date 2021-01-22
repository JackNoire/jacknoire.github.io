---
title: 使用CreateRemoteThread向目标进程注入DLL
date: 2021-01-22 16:55:06
tags: [Windows,远程线程,DLL注入]
categories: Windows
toc: true
typora-root-url: windows-remotethread-dllinject
---

在之前的文章中提到，如果要使用CreateRemoteThread在目标进程中创建远程线程：

> 在正常使用时，远程线程的代码是在目标进程中本来就有的。

是否有一种手段，使得在目标进程中创建的远程线程，执行任意自己想要执行的代码呢？一种方法是通过DLL注入来实现。

<!--more-->

假如当前用户正在运行一个记事本notepad进程，那么，其他进程就可以通过CreateRemoteThread在notepad进程中创建一个线程。不过通常情况下，线程中执行的代码是notepad进程中本来就有的。现在想让notepad进程执行下述代码：

```c
    char str[100];
    sprintf(str, "pid: %d", GetCurrentProcessId());
    while(1)
        MessageBoxA(NULL, str, "DLL Inject", MB_ICONSTOP | MB_OK);
```

notepad本身不可能有这种无限弹窗的代码，所以没法直接通过CreateRemoteThread创建线程执行它们。通过DLL注入的方式，可以让notepad进程最终能执行上面这个无限弹窗的代码。

## 编写具有DllMain的DLL

动态链接库dll文件中，通常包含一些其他代码可能会使用到的函数和数据。其他程序可以通过LoadLibraryA函数加载dll文件，然后就能使用dll中的函数了。

一些dll中会有一个DllMain函数，它被称为dll的入口点。当dll被装载时，DllMain中的代码就会被执行。Microsoft的文档：[DllMain entry point](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain)

当自己编写dll的代码时，也可以自定义DllMain函数的内容。比如，将DllMain函数的内容写成无限弹窗的代码：

```c
#include <windef.h>
#include <winuser.h>
#include <processthreadsapi.h>
#include <stdio.h>

BOOL WINAPI DllMain() {
    char str[100];
    sprintf(str, "pid: %d", GetCurrentProcessId());
    while(1)
        MessageBoxA(NULL, str, "DLL Inject", MB_ICONSTOP | MB_OK);
}
```

将上述代码保存在文件`0.c`中。接下来，将其编译成`0.dll`。我使用的mingw-gcc将其编译成dll的命令为：

```
gcc -c 0.c -o 0.o
gcc -shared 0.o -o 0.dll
```

可以写个代码测试一下，看看加载这个dll文件是否会执行DllMain函数中的语句：

```c
#include <libloaderapi.h>

int main() {
    HMODULE h0 = LoadLibraryA("0.dll");
    return 0;
}
```

编译运行，程序立刻弹窗，说明加载dll文件的行为确实是可以导致DllMain函数被执行的。

## 编写程序实现DLL注入

现在，已经有了一个`0.dll`文件。当程序尝试加载这个dll文件时，会执行DllMain函数中的内容，发生无限弹窗。于是，现在的目标就变成了，让目标进程notepad加载这个`0.dll`文件。

### 将字符串"D:\\0.dll"传入notepad内存空间中

为了方便起见，使用绝对路径加载dll文件。所以，先把`0.dll`复制到D盘根目录下，这样一来它的绝对路径就变成了"D:\\0.dll"。

字符串"D:\\0.dll"是LoadLibraryA函数的参数，要想办法让这个字符串出现在notepad的内存空间当中。可以通过以下步骤达成这一点：

1. 使用OpenProcess获得目标进程notepad的句柄
2. 使用VirtualAllocEx在目标进程中申请一块内存，并得到这块内存的起始地址
3. 使用WriteProcessMemory将字符串"D:\\0.dll"写入这块内存当中

```c
    //获取目标进程句柄
    int pid = atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(NULL == hProcess) {
        printf("OpenProcess Error: %d\n", GetLastError());
        return -1;
    }
    //在目标进程中申请一块内存空间，写入字符串"D:\0.dll"
    void *dllNamePtr = VirtualAllocEx(hProcess, NULL, 10, MEM_COMMIT, PAGE_READWRITE);
    if(NULL == dllNamePtr) {
        printf("VirtualAllocEx Error: %d\n", GetLastError());
        return -1;
    }
    BOOL result = WriteProcessMemory(hProcess, dllNamePtr, "D:\\0.dll", 9, NULL);
    if(!result) {
        printf("WriteProcessMemory Error: %d\n", GetLastError());
        return -1;
    }
    printf("\"D:\\0.dll\" String Address: 0x%p\n", dllNamePtr);
```

某次执行这段代码，申请到的内存地址为0x000001CE24A90000，使用x64dbg查看notepad中的这块内存：

![0x000001CE24A90000处的内存空间](memory-string-address.png)

说明成功写入了字符串"D:\\0.dll"。

### 获取LoadLibraryA的内存地址

首先，通过GetModuleHandleA获取kernel32.dll模块的句柄，然后再使用GetProcAddress获取LoadLibraryA的地址：

```c
    //找到LoadLibraryA的地址
    void *funcAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    printf("LoadLibraryA Address: 0x%p\n", funcAddr);
```

有人可能会担心，通过上述方法，找到的是自身进程中LoadLibraryA的内存地址，并不是目标进程notepad中LoadLibraryA的地址。不过通常情况下，LoadLibraryA在不同进程中的地址是相同的。[Dll injection - Wikipedia](https://en.wikipedia.org/wiki/DLL_injection)中提到：

> kernel32.dll is mapped to the same address in almost all processes. Therefore LoadLibrary (which is a function of kernel32.dll) is mapped to the same address as well.

所以，这种方法得到的LoadLibraryA的地址可以认为就是目标进程notepad中LoadLibraryA的地址。比如在某次执行上面的代码，得到的LoadLibraryA的地址为0x00007FFFC185EBB0，x64dbg找到进程notepad在这里的语句：

![notepad进程在0x00007FFFC185EBB0处的语句](LoadLibraryA.png)

说明这个地方确实就是LoadLibraryA的入口点。

### 创建远程线程调用LoadLibraryA("D:\\0.dll")

CreateRemoteThread中，线程函数只允许有一个参数，而LoadLibraryA恰好就是只需要一个参数。而且，经过之前的操作，已经知道了在notepad进程中LoadLibraryA的地址，以及字符串"D:\\0.dll"的地址，于是就可以通过CreateRemoteThread创建线程调用LoadLibraryA了。

```c
    //创建远程线程调用LoadLibraryA("D:\0.dll")，加载0.dll
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, funcAddr, dllNamePtr, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode); //获取LoadLibraryA的返回值
    if(!exitCode) {
        printf("LoadLibraryA Failed!\n");
        return -1;
    }
    printf("Inject Complete.\n");
    return 0;
```

一旦notepad加载0.dll，就会执行其中的DllMain函数，而DllMain的内容又是无限弹窗程序。这样一来，notepad就会开始无限弹窗了。

### 完整代码及运行结果

```c
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Usage: injectdll [pid]\n");
        return -1;
    }
    //获取目标进程句柄
    int pid = atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(NULL == hProcess) {
        printf("OpenProcess Error: %d\n", GetLastError());
        return -1;
    }
    //在目标进程中申请一块内存空间，写入字符串"D:\0.dll"
    void *dllNamePtr = VirtualAllocEx(hProcess, NULL, 10, MEM_COMMIT, PAGE_READWRITE);
    if(NULL == dllNamePtr) {
        printf("VirtualAllocEx Error: %d\n", GetLastError());
        return -1;
    }
    BOOL result = WriteProcessMemory(hProcess, dllNamePtr, "D:\\0.dll", 9, NULL);
    if(!result) {
        printf("WriteProcessMemory Error: %d\n", GetLastError());
        return -1;
    }
    printf("\"D:\\0.dll\" String Address: 0x%p\n", dllNamePtr);
    //找到LoadLibraryA的地址
    void *funcAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    printf("LoadLibraryA Address: 0x%p\n", funcAddr);
    //创建远程线程调用LoadLibraryA("D:\0.dll")，加载0.dll
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, funcAddr, dllNamePtr, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode); //获取LoadLibraryA的返回值
    if(!exitCode) {
        printf("LoadLibraryA Failed!\n");
        return -1;
    }
    printf("Inject Complete.\n");
    return 0;
}
```

首先，打开记事本，然后在任务管理器的“详细信息”这一栏找到notepad.exe的pid，比如pid为5908。

假设上述代码被编译成了injectdll.exe，接下来，执行`injectdll 5908`，便能看到记事本的弹窗了：

![记事本的弹窗](/messagebox.png)