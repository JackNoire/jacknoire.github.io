---
title: 在Windows中创建线程和远程线程
date: 2021-01-20 19:19:03
tags: [Windows,线程,远程线程]
categories: Windows
toc: true
---

本文记录了如何使用CreateThread和CreateRemoteThread创建线程和远程线程。

<!--more-->

## 创建线程

### CreateThread函数

在Windows中创建线程可以使用CreateThread函数，其原型为：

```c
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  __drv_aliasesMem LPVOID lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);
```

最重要的两个参数为lpStartAddress和lpParameter，分别表示线程的起始地址和线程函数的参数。在C语言中，可以用函数名表示函数的起始地址。如果线程创建成功，则会返回新线程的句柄。

参数的详细解释可以参考Microsoft的文档：

[CreateThread function (processthreadsapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)

下面编写一个简单示例来说明CreateThread函数的用法。

### 线程函数的编写

由于线程可以共享进程的全局变量，因此可以编写线程对全局变量进行读写操作。

首先设置一个全局变量`i`：

```c
int i;
```

然后编写两个线程函数。第一个函数会让`i`不断加上一个数，内容为：

```c
/*  thread_func1
 *  传入参数：
 *      param[0]: 循环次数
 *      param[1]: 自增数
 *  功能：
 *      每次循环让全局变量i加上param[1]
 *      循环param[0]次
 */
void thread_func1(int *param) {
    printf("Thread 1 Start\n");
    for(int j = 0; j < param[0]; j++) {
        i += param[1];
        printf("%d. ", i);
        Sleep(100);
    }
    printf("\nThread 1 End\n");
}
```

第二个函数会检查`i`是否大于某个值，如果是则会将`i`清零：

```c
/*  thread_func2
 *  传入参数：
 *      param[0]: 循环次数
 *      param[1]: 上限
 *  功能：
 *      每次循环检查全局变量i是否大于param[1]
 *      如果大于param[1]则将i清零
 *      循环param[0]次
 */
void thread_func2(int *param) {
    printf("\nThread 2 Start\n");
    for(int j = 0; j < param[0]; j++) {
        if(i > param[1]) {
            i = 0;
        }
        Sleep(100);
    }
    printf("\nThread 2 End\n");
}
```

CreateThread中函数的参数只允许传入一个，所以如果需要传入多个参数，可以通过传入数组来实现。

### main函数的编写

接下来编写main函数。

首先要准备两个函数参数的数组：

```c
    int func1_param[2] = {70, 3};
    int func2_param[2] = {30, 20};
```

第一个函数的两个参数为70和3，说明要循环70次，每次循环`i`要加上3；第二个函数的两个参数为30和20，说明要循环30次，如果`i`大于20则将`i`清零。

然后调用CreateThread先后创建两个线程：

```c
    HANDLE threadHandles[2];
    //创建第一个线程，执行thread_func1
    threadHandles[0] = CreateThread(NULL,   //lpThreadAttributes
                                    0,      //dwStackSize
                                    thread_func1,   //lpStartAddress
                                    func1_param,    //lpParameter
                                    0,      //dwCreationFlags
                                    NULL);  //lpThreadId
    if(NULL == threadHandles[0]) {  //检查线程是否创建成功
        printf("Create Thread 1 Failed! Error Code: %d\n", GetLastError());
        return -1;
    }
    //2秒后创建第二个线程，执行thread_func2
    Sleep(2000);
    threadHandles[1] = CreateThread(NULL,   //lpThreadAttributes
                                    0,      //dwStackSize
                                    thread_func2,   //lpStartAddress
                                    func2_param,    //lpParameter
                                    0,      //dwCreationFlags
                                    NULL);  //lpThreadId
    if(NULL == threadHandles[1]) {  //检查线程是否创建成功
        printf("Create Thread 2 Failed! Error Code: %d\n", GetLastError());
        return -1;
    }
```

如果要等待两个线程同时结束后再继续接下来的操作，则可以使用WaitForMultipleObjects：

```c
    WaitForMultipleObjects(2, threadHandles, TRUE, 100000);
```

最后关闭句柄：

```c
    CloseHandle(threadHandles[0]);
    CloseHandle(threadHandles[1]);
    return 0;
```

### 完整代码及运行结果

```c
#include <stdio.h>
#include <processthreadsapi.h>
#include <synchapi.h>
#include <errhandlingapi.h>
#include <handleapi.h>

int i;
/*  thread_func1
 *  传入参数：
 *      param[0]: 循环次数
 *      param[1]: 自增数
 *  功能：
 *      每次循环让全局变量i加上param[1]
 *      循环param[0]次
 */
void thread_func1(int *param) {
    printf("Thread 1 Start\n");
    for(int j = 0; j < param[0]; j++) {
        i += param[1];
        printf("%d. ", i);
        Sleep(100);
    }
    printf("\nThread 1 End\n");
}
/*  thread_func2
 *  传入参数：
 *      param[0]: 循环次数
 *      param[1]: 上限
 *  功能：
 *      每次循环检查全局变量i是否大于param[1]
 *      如果大于param[1]则将i清零
 *      循环param[0]次
 */
void thread_func2(int *param) {
    printf("\nThread 2 Start\n");
    for(int j = 0; j < param[0]; j++) {
        if(i > param[1]) {
            i = 0;
        }
        Sleep(100);
    }
    printf("\nThread 2 End\n");
}
int main() {
    int func1_param[2] = {70, 3};
    int func2_param[2] = {30, 20};
    HANDLE threadHandles[2];
    //创建第一个线程，执行thread_func1
    threadHandles[0] = CreateThread(NULL,   //lpThreadAttributes
                                    0,      //dwStackSize
                                    thread_func1,   //lpStartAddress
                                    func1_param,    //lpParameter
                                    0,      //dwCreationFlags
                                    NULL);  //lpThreadId
    if(NULL == threadHandles[0]) {  //检查线程是否创建成功
        printf("Create Thread 1 Failed! Error Code: %d\n", GetLastError());
        return -1;
    }
    //2秒后创建第二个线程，执行thread_func2
    Sleep(2000);
    threadHandles[1] = CreateThread(NULL,   //lpThreadAttributes
                                    0,      //dwStackSize
                                    thread_func2,   //lpStartAddress
                                    func2_param,    //lpParameter
                                    0,      //dwCreationFlags
                                    NULL);  //lpThreadId
    if(NULL == threadHandles[1]) {  //检查线程是否创建成功
        printf("Create Thread 2 Failed! Error Code: %d\n", GetLastError());
        return -1;
    }
    WaitForMultipleObjects(2, threadHandles, TRUE, 100000);
    CloseHandle(threadHandles[0]);
    CloseHandle(threadHandles[1]);
    return 0;
}
```

```
> threadtest
Thread 1 Start
3. 6. 9. 12. 15. 18. 21. 24. 27. 30. 33. 36. 39. 42. 45. 48. 51. 54. 57.
Thread 2 Start
3. 6. 9. 12. 15. 18. 21. 3. 6. 9. 12. 15. 18. 21. 3. 6. 9. 12. 15. 18. 21. 3. 6. 9. 12. 15. 18. 21. 3. 6.
Thread 2 End
9. 12. 15. 18. 21. 24. 27. 30. 33. 36. 39. 42. 45. 48. 51. 54. 57. 60. 63. 66. 69.
Thread 1 End
```

线程1开始后，`i`会不断增加，然后，当线程2开始后，`i`超过20便会被清零。线程2结束后，`i`又会不断增加，而不会被清零。

## 创建远程线程

在Windows中，进程除了可以给自己创建线程，还可以给其他进程创建线程，这就是远程线程。创建远程线程需要用到CreateRemoteThread函数。

### CreateRemoteThread函数

```c
HANDLE CreateRemoteThread(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
```

和CreateThread相比，只多了一个hProcess参数，表示目标进程的句柄。此外，这里的lpStartAddress指的是目标进程中函数的内存地址，所以在正常使用时，远程线程的代码是在目标进程中本来就有的。

参数的详细解释可以查看Microsoft的文档：

[CreateRemoteThread function (processthreadsapi.h)](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

接下来，编写一个简单示例来说明这个函数的用法。

### 编写目标程序

目标进程的代码中首先还是设置一个全局变量`i`，然后是main函数：

```c
int main() {
    printf("Process ID: %d\n", GetCurrentProcessId());
    while(1) {
        printf("%d. ", i++);
        Sleep(100);
    }
    return 0;
}
```

main函数首先会打印自身的Process ID，然后就会不断地让全局变量`i`加一，并打印出来。

接下来，再编写一个函数thread_func：

```c
int thread_func() {
    while(1) {
        if(i > 20) {
            i = 0;
        }
        Sleep(600);
    }
}
```

由于main函数中并没有调用这个函数，因此正常运行目标程序，全局变量`i`并不会清零。

```
> program
Process ID: 14032
0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 24. 25. 26. 27. 28. 29. 30. 31. 32. 33. 34. 
```

### 编写程序为目标进程开启远程线程

首先通过反汇编工具（如IDA Pro）获取目标程序中thread_func的起始地址。我的机器上thread_func起始地址为0x401550。

然后就可以编写创建远程线程的代码：

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if(argc < 0) {
        return -1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
    if(NULL == hProcess) {
        printf("Open Process Failed! (%d)\n", GetLastError());
        return -1;
    }
    //program中thread_func起始地址为0x401550
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 0x401550, NULL, 0, NULL);
    if(NULL == hThread) {
        printf("Create Thread Failed! (%d)\n", GetLastError());
        return -1;
    }
    CloseHandle(hProcess);
    CloseHandle(hThread);
    return 0;
}
```

首先通过OpenProcess获取目标进程的句柄。然后，再将目标进程句柄、thread_func起始内存地址等参数传入CreateRemoteThread当中。这样就可以在目标进程中开启远程线程执行thread_func中的代码了。

### 运行结果

首先运行目标程序program，得知其进程ID为16500，然后再运行`remotethread 16500`，remotethread程序就可以根据16500获取目标进程的句柄，进而为目标程序开启远程线程。新的线程就会运行thread_func函数中的代码，从而实现对全局变量`i`清零的操作。之后，remotethread进程退出了，但由于thread_func线程是属于program进程的，因此仍然会继续运行，`i`会继续被清零。

```
> program
Process ID: 16500
0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 23. 24. 25. 
26. 27. 28. 29. 30. 31. 32. 33. 34. 35. 36. 37. 38. 39. 40. 41. 42. 43. 44. 45. 46. 47. 48. 49. 
50. 51. 52. 53. 54. 55. 56. 57. 58. 0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 
17. 18. 19. 20. 21. 22. 23. 0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 
19. 20. 21. 22. 23. 0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 
21. 22. 23. 0. 1. 2. 3. 4. 5. 6. 7. 8. 9. 10. 11. 12. 13. 14. 15. 16. 17. 18. 19. 20. 21. 22. 
```

