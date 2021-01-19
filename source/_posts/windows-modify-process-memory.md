---
title: Windows读写其他进程内存的方法
date: 2021-01-19 17:49:39
tags: [Windows,进程,内存]
categories: Windows
toc: true
---

本文记录了如何使用Windows提供的ReadProcessMemory和WriteProcessMemory对其他进程的内存空间进行读写操作。

<!--more-->

## ReadProcessMemory和WriteProcessMemory的函数原型

```c
BOOL ReadProcessMemory(
  HANDLE  hProcess,
  LPCVOID lpBaseAddress,
  LPVOID  lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesRead
);
```

```c
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

Microsoft的文档中有对每个参数的详细解释：

[ReadProcessMemory function (memoryapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)

[WriteProcessMemory function (memoryapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

使用这两个函数，需要传入目标进程的句柄、想要读写内存的基地址、读写内存的大小等信息。在通过CreateProcess创建子进程时，可以通过PROCESS_INFORMATION结构体得到子进程的句柄。因此，先来看读写子进程内存的方法。

## 读写子进程内存

### 编写子进程

子进程的功能为打印全局变量`i`的值，并使变量`i`不断自增。

```c
#include <stdio.h>
#include <synchapi.h>

int i;
int main() {
    while(1) {
        printf("%d. ", i++);
        Sleep(100);
    }
}
```

运行结果为：

```console
> child
0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 24. 25. 26. 27. 28. 29. 30. 31. 32. 33. 34. 35. 36. 37. 38. 39. 40. 41. 42. 43. 44. 45. 46. 47. 48. 49. 
```

### 编写父进程读取子进程内存

父进程首先要通过CreateProcess创建子进程，然后通过PROCESS_INFORMATION结构体获取子进程的句柄。之后，再将句柄传入ReadProcessMemory，即可读取子进程的内存。

如果要让父进程修改子进程的全局变量`i`，则需要知道`i`的内存地址，这可以通过反汇编工具（如IDA Pro）获取。我使用的编译器会将全局变量`i`的内存地址设置为0x407970，不同编译器编译得到的child中`i`的内存地址可能不同。

```c
#include <processthreadsapi.h>
#include <stdio.h>
#include <errhandlingapi.h>
#include <synchapi.h>
#include <handleapi.h>
#include <memoryapi.h>

int main() {
    //创建子进程
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    BOOL result = CreateProcessA( "child.exe",        //lpApplicationName
                    NULL,  //lpCommandLine
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
    //读写子进程全局变量i，地址为0x407970
    int childi;
    while(1) {
        ReadProcessMemory(pi.hProcess, (void *)0x407970, &childi, sizeof(int), NULL);
        printf("\nparent read child i: %d\n", childi);
        Sleep(600);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

运行parent：

```
> parent

parent read child i: 0
0. 1. 2. 3. 4. 5.
parent read child i: 6
6. 7. 8. 9. 10. 11.
parent read child i: 12
12. 13. 14. 15. 16. 17.
parent read child i: 18
18. 19. 20. 21. 22. 23.
parent read child i: 24
24. 25. 26. 27. 28. 29.
parent read child i: 30
```

可以看出parent成功读取了child中变量`i`的内容。

### 添加修改子进程内存的代码

使用WriteProcessMemory可以修改子进程中`i`的值。在parent中添加代码：

```c
    //读写子进程全局变量i，地址为0x407970
    int childi;
    while(1) {
        ReadProcessMemory(pi.hProcess, (void *)0x407970, &childi, sizeof(int), NULL);
        if(childi > 20) {
            childi = 0;
            WriteProcessMemory(pi.hProcess, (void *)0x407970, &childi, sizeof(int), NULL);
        }
        Sleep(600);
    }
```

当读取到的`i`大于20时，就将`i`清零，并写入子进程的内存当中。运行parent：

```
> parent
0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 0. 1. 2. 
3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 0. 1. 2. 3. 4. 5. 
6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 0. 1. 2. 3. 4. 5. 6. 7. 8. 
9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 0. 1. 2. 3. 4. 5. 6. 
```

`i`大于20后不久就会被清零。之所以没有立即清零是因为parent中有一个`Sleep(600);`。

## 读取其他进程的内存

读写其他进程内存需要首先获取其句柄，这可以通过函数OpenProcess得到。

### OpenProcess函数原型

```c
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```

因此，知道了目标进程的进程标识符ProcessId，就可以获得其句柄了。

[OpenProcess function (processthreadsapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

### 编写目标进程代码

目标进程会先调用GetCurrentProcessId获取自身的进程标识符并打印出来，然后就开始不断打印全局变量`i`的值并将`i`加一。

```c
#include <stdio.h>
#include <synchapi.h>
#include <processthreadsapi.h>

int i;
int main() {
    printf("My Process ID: %d\n", GetCurrentProcessId());
    while(1) {
        printf("%d. ", i++);
        Sleep(100);
    }
}
```

### 编写修改器代码

修改器会先根据目标进程的ProcessId获取句柄，然后再调用ReadProcessMemory和WriteProcessMemory读写目标进程的全局变量`i`，当`i`大于20时清零。

```c
#include <stdlib.h>
#include <stdio.h>
#include <processthreadsapi.h>
#include <synchapi.h>
#include <memoryapi.h>
#include <errhandlingapi.h>

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Usage: modifier [pid]\n");
        return -1;
    }
    //OpenProcess获得目标进程的句柄
    int targetPid = atoi(argv[1]);
    HANDLE hTarget = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, targetPid);
    if(NULL == hTarget) {
        printf("Open Process Failed! Error Code: %d\n", GetLastError());
        return -1;
    }
    //读写目标进程全局变量i，地址为0x407970
    int targetI;
    BOOL result;
    while(1) {
        result = ReadProcessMemory(hTarget, (void *)0x407970, &targetI, sizeof(int), NULL);
        if(!result) {
            printf("Read Process Memory Failed! Error Code: %d\n", GetLastError());
            return -1;
        } else if(targetI > 20) {
            targetI = 0;
            result = WriteProcessMemory(hTarget, (void *)0x407970, &targetI, sizeof(int), NULL);
            if(!result) {
                printf("Write Process Memory Failed! Error Code: %d\n", GetLastError());
                return -1;
            }
        }
        Sleep(600);
    }
    return 0;
}
```

### 运行结果

首先运行目标程序program，得到其进程标识符为4372，然后再运行修改器程序并传入参数4372，即`modifier 4372`，一段时间后终止修改器。最终，program的打印结果如下：

```
> program
My Process ID: 4372
0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 24. 25. 
26. 27. 28. 29. 30. 31. 32. 33. 34. 35. 36. 37. 38. 39. 40. 41. 42. 43. 44. 45. 46. 47. 48. 
49. 50. 51. 52. 53. 54. 0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 
20. 21. 22. 0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 0. 
1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 0. 1. 2. 3. 4. 5. 
6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 24. 25. 26. 27. 28. 29. 
30. 31. 32. 33. 34. 35. 36. 37. 38. 39. 40. 41. 42. 43. 44. 45. 46. 47. 48. 49. 50. 51. 52. 
53. 54. 55. 56. 57.
```

全局变量`i`一开始会不断自增，当修改器开始运行后，`i`的值便被清零，然后当`i`的值超过20后也会被清零。修改器停止运行后，`i`的值又会不断自增而不会被清零。