---
title: 在Windows中使用CreateProcess创建子进程
date: 2021-01-17 16:34:58
tags: [Windows,进程]
categories: Windows
toc: true
---

本文记录了在Windows中使用CreateProcessA创建子进程的方法。

<!--more-->

## CreateProcessA函数原型

```c
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,    //应用程序名
  LPSTR                 lpCommandLine,        //命令行
  LPSECURITY_ATTRIBUTES lpProcessAttributes,  //如果为NULL，则子进程不会继承新进程的句柄
  LPSECURITY_ATTRIBUTES lpThreadAttributes,   //如果为NULL，则子进程不会继承新线程的句柄
  BOOL                  bInheritHandles,      //父进程的可继承句柄是否继承给新的进程
  DWORD                 dwCreationFlags,      //控制子进程的创建过程和优先级的标志
  LPVOID                lpEnvironment,        //如果为NULL，则新的进程会使用父进程的环境
  LPCSTR                lpCurrentDirectory,   //如果为NULL，则新的进程与父进程会有相同目录
  LPSTARTUPINFOA        lpStartupInfo,        //用于设置新进程的主窗口特性
  LPPROCESS_INFORMATION lpProcessInformation  //PROCESS_INFORMATION指针，用于获取新进程的信息
);
```

本文只关心`lpApplicationName`, `lpCommandLine`, `lpStartupInfo`, `lpProcessInformation` 这四个参数。

## 简单示例

接下来，写一个简单的示例来说明这个函数的基本用法。

### 编写程序作为子进程

编写child.c，代码为：

```c
#include <stdio.h>

int main(int argc, char **argv) {
    for(int i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }
    return 0;
}
```

功能很简单，就是打印argv字符串数组的内容。编译后在命令行中运行`child 123456789 abcdefg !@#$%`：

```
> child 123456789 abcdefg !@#$%
argv[0]: child
argv[1]: 123456789
argv[2]: abcdefg
argv[3]: !@#$%
```

### 编写程序调用CreateProcessA创建子进程

编写程序parent，代码如下：

```c
#include <processthreadsapi.h>
#include <stdio.h>

int main() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    CreateProcessA( "child.exe",        //lpApplicationName
                    "abcdefg !@#$%^&",  //lpCommandLine
                    NULL,
                    NULL,
                    FALSE,
                    0,
                    NULL,
                    NULL,
                    &si,    //lpStartupInfo
                    &pi);   //lpProcessInformation
    return 0;
}
```

parent会调用CreateProcessA，创建子进程child，而child则会打印argv数组：

```
> parent
argv[0]: abcdefg
argv[1]: !@#$%^&
```

child中argv的内容和lpCommandLine字符串的内容是一致的。

lpApplicationName可以为NULL，此时应用程序的名字为lpCommandLine中第一个被空格隔开的字符串：

[CreateProcessA function (processthreadsapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)

## 对简单示例的进一步完善

### 对创建进程操作是否成功的判断

CreateProcessA会返回BOOL类型的变量，表示本次创建进程的操作是否成功。因此，可以加上对函数返回值的判断：

```c
    BOOL result = CreateProcessA( "child.exe",        //lpApplicationName
                    "abcdefg !@#$%^&",  //lpCommandLine
                    NULL,
                    NULL,
                    FALSE,
                    0,
                    NULL,
                    NULL,
                    &si,    //lpStartupInfo
                    &pi);   //lpProcessInformation
    if(!result) {
        printf("Create Process Failed!\n");
        return -1;
    }
```

### 创建进程失败时获取错误码

如果CreateProcessA返回FALSE，则可以通过GetLastError获取错误码，GetLastError定义在头文件errhandlingapi.h中。

```c
    if(!result) {
        printf("Create Process Failed! Error Code:%d\n", GetLastError());
        return -1;
    }
```

在调用CreateProcessA之前，会通过`STARTUPINFO si = {0};`将STARTUPINFO结构体si的内容清零。现在将清零操作去掉，重新编译运行parent，看是否还能成功创建子进程：

```
> parent
Create Process Failed! Error Code:998
```

创建子进程失败了，错误码为998，查阅[System Error Codes (500-999)](https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--500-999-)：

> **ERROR_NOACCESS**
>
> - 998 (0x3E6)
> - Invalid access to memory location.

发生了对内存地址的无效访问。这说明STARTUPINFO结构体使用之前清零是有必要的。

### 通过PROCESS_INFORMATION结构体获取子进程信息

CreateProcessA的最后一个参数为`LPPROCESS_INFORMATION lpProcessInformation`，是一个PROCESS_INFOMATION结构体指针。PROCESS_INFOMATION的定义为：

```c
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;
  HANDLE hThread;
  DWORD  dwProcessId;
  DWORD  dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
```

CreateProcessA会创建一个进程和它的主线程，hProcess就是这个进程的句柄，hThread就是进程的主线程的句柄。dwProcessId和dwThreadId分别为进程和它的主线程的标识符ID。

简单示例中传入的参数为&pi，因此就可以通过pi得到创建的进程以及其主线程的句柄和标识符了。添加如下代码，打印子进程的进程标识符：

```c
printf("Child Process ID: %d\n", pi.dwProcessId);
```

运行parent：

```
> parent
Child Process ID: 13816
argv[0]: abcdefg
argv[1]: !@#$%^&
```

### 父进程等待子进程执行结束

在Linux中，父进程可以通过wait系统调用等待子进程执行完毕。Windows中也有类似的功能，即[WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)。

WaitForSingleObject的函数原型为：

```c
DWORD WaitForSingleObject(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);
```

需要传入两个参数，hHandle为对象的句柄，dwMilliseconds为等待的毫秒数。如果对象结束，或对象没有结束但经过了dwMilliseconds毫秒，则等待完毕，进程继续执行后面的语句。

父进程可以通过PROCESS_INFORMATION结构体获取子进程的进程句柄，然后再将子进程的句柄传入WaitForSingleObject中，即可等待子进程执行完毕。

在打印子进程ID前，添加语句：

```c
WaitForSingleObject(pi.hProcess, 10000);
```

再运行parent，得到的结果为：

```
> parent
argv[0]: abcdefg
argv[1]: !@#$%^&
Child Process ID: 3944
```

说明父进程会等待子进程child执行完毕后再打印子进程的ID。

### 关闭PROCESS_INFORMATION中的句柄

一个更好的习惯是在PROCESS_INFORMATION中的句柄使用完毕后，用CloseHandle将其关闭。

> If the function succeeds, be sure to call the [CloseHandle](https://docs.microsoft.com/en-us/windows/desktop/api/handleapi/nf-handleapi-closehandle) function to close the **hProcess** and **hThread** handles when you are finished with them. Otherwise, when the child process exits, the system cannot clean up the process structures for the child process because the parent process still has open handles to the child process. However, the system will close these handles when the parent process terminates, so the structures related to the child process object would be cleaned up at this point.

在parent.c的末尾添加CloseHandle代码：

```c
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
```

最终，得到的完整的parent.c代码为：

```c
#include <processthreadsapi.h>
#include <stdio.h>
#include <errhandlingapi.h>
#include <synchapi.h>
#include <handleapi.h>

int main() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    BOOL result = CreateProcessA( "child.exe",        //lpApplicationName
                    "abcdefg !@#$%^&",  //lpCommandLine
                    NULL,
                    NULL,
                    FALSE,
                    0,
                    NULL,
                    NULL,
                    &si,    //lpStartupInfo
                    &pi);   //lpProcessInformation
    if(!result) {
        printf("Create Process Failed! Error Code:%d\n", GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    printf("Child Process ID: %d\n", pi.dwProcessId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

