---
title: 函数参数及返回值为结构体时的汇编代码
date: 2021-08-13 19:33:04
tags: [逆向分析,结构体,函数]
categories: Reverse
toc: true
typora-root-url: structure-function-parameter-return-value
---

本文记录了函数参数以及返回值是结构体时，汇编代码是什么样的。本文使用的编译器为Visual Studio中的cl.exe，版本为`用于 x86 的 Microsoft (R) C/C++ 优化编译器 19.28.29910 版`。

<!--more-->

## 定义结构体

定义这样一个结构体：

```c
struct tagTest {
    int a;
    long long b;
    char c[4];
};
```
编译后，各成员的偏移为：

```x86asm
tagTest         struc ; (sizeof=0x18, mappedto_56)
	a               dd ?
	field_4         dd ?
	b               dq ?
	c               db 4 dup(?)             ; string(C)
	field_14        dd ?
tagTest         ends
```

其中field_4和field_14是填充，结构体大小为24字节。

## 函数参数为结构体

编写函数并调用：

```c
long long paramTest(int p1, struct tagTest p2, int p3) {
    return p1 + p2.a + p2.b + p3;
}

int main() {
    struct tagTest param = {0xAAAAAAAA, 0xBBBBBBBBCCCCCCCC, "aaaa"};
    paramTest(1, param, 3);

    return 0;
}
```
调用paramTest前将参数压入堆栈的汇编代码为：

```x86asm
push    3
sub     esp, 24
mov     edx, esp
mov     eax, [ebp+param.a]
mov     [edx], eax
mov     ecx, [ebp+param.field_4]
mov     [edx+4], ecx
mov     eax, dword ptr [ebp+param.b]
mov     [edx+8], eax
mov     ecx, dword ptr [ebp+param.b+4]
mov     [edx+12], ecx
mov     eax, dword ptr [ebp+param.c]
mov     [edx+16], eax
mov     ecx, [ebp+param.field_14]
mov     [edx+20], ecx
push    1
call    paramTest
```

首先压入第三个参数3，然后将24字节的结构体全部复制到栈中，最后压入第一个参数1，所以在调用paramTest前栈的结构为：

![结构体作为函数参数时栈的结构](/结构体作为函数参数时栈的结构.svg)

**总结：**当函数参数为结构体时，在将参数压栈的过程中，结构体中的所有内容都会复制到栈中。

## 函数返回值为结构体

编写函数并调用：

```c
struct tagTest retTest(int a, long long b) {
    struct tagTest retVal = {a, b, "cccc"};
    return retVal;
}

int main() {
    struct tagTest result = retTest(0x11111111, 0x2222222233333333);

    return 0;
}
```

调用retTest函数前将参数压栈的代码：

```x86asm
push    22222222h
push    33333333h       ; b
push    11111111h       ; a
lea     edx, [ebp+retVal]
push    edx             ; retstr
call    retTest
```

除了函数原有的两个参数外，还压了位于栈中的结构体变量retVal的地址，命名为pRetVal。

进入retTest函数，这个函数有一个`struct tagTest`类型的局部变量，命名为tmp。函数开头的这段汇编代码将tmp赋值为`{a, b, "cccc"}`：

```x86asm
mov     eax, [ebp+a]
mov     [ebp+tmp.a], eax
mov     ecx, [ebp+b_low]
mov     edx, [ebp+b_high]
mov     dword ptr [ebp+tmp.b], ecx
mov     dword ptr [ebp+tmp.b+4], edx
mov     eax, dword_419000 ; "cccc"
mov     dword ptr [ebp+tmp.c], eax
```

接下来这段汇编代码则将tmp的内容复制到pRetVal指向的结构体retVal：

```x86asm
mov     ecx, [ebp+pRetVal]
mov     edx, [ebp+tmp.a]
mov     [ecx], edx
mov     eax, [ebp+tmp.field_4]
mov     [ecx+4], eax
mov     edx, dword ptr [ebp+tmp.b]
mov     [ecx+8], edx
mov     eax, dword ptr [ebp+tmp.b+4]
mov     [ecx+0Ch], eax
mov     edx, dword ptr [ebp+tmp.c]
mov     [ecx+10h], edx
mov     eax, [ebp+tmp.field_14]
mov     [ecx+14h], eax
```

函数的返回值为pRetVal：

```x86asm
mov     eax, [ebp+pRetVal]
```

**总结：**当函数返回值为结构体，函数的调用方main函数会在栈中预留一段空间retVal用于存放返回值。当main函数调用retTest函数时，除了本身的两个参数外，还会压入retVal的地址&retVal。retTest函数会根据传入的retVal的地址，将返回值复制到retVal当中，并返回&retVal。

使用IDA的Set type...功能也能看出这一点，如果在Set type...窗口输入：

```c
tagTest retTest(int a, long long b)
```

IDA会将其自动转换为：

```c
tagTest *retTest(tagTest *__return_ptr __struct_ptr retstr, int a, __int64 b);
```

其中retstr就是指向retVal的指针。

下面这两个C语言函数编译后的汇编代码应该是一样的：

```c
struct tagTest retTest(int a, long long b) {
    struct tagTest retVal = {a, b, "cccc"};
    return retVal;
}

struct tagTest *retTest2(struct tagTest *pRetVal, int a, long long b) {
    struct tagTest tmp = {a, b, "cccc"};
    *pRetVal = tmp;
    return pRetVal;
}

int main() {
    struct tagTest result1 = retTest(0x11111111, 0x2222222233333333);
    
    struct tagTest retVal;
    struct tagTest *pRetVal = retTest2(&retVal, 0x11111111, 0x2222222233333333);
    struct tagTest result2 = *pRetVal;
    return 0;
}
```

