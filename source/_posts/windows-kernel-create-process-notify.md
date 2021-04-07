---
title: 利用Windows事件通知机制监控进程创建
date: 2021-04-05 17:05:38
tags: [Windows,内核编程,通知与回调]
categories: Windows
toc: true
typora-root-url: windows-kernel-create-process-notify
---

利用Windows内核提供的事件通知机制，可以对系统内某一类事件的操作进行监控。比如，可以通过PsSetCreateProcessNotifyRoutineEx函数注册一个创建进程的通知，从而实现对进程创建的监控。

本文主要参考《Windows内核编程》第21章。

<!--more-->

## PsSetCreateProcessNotifyRoutineEx的用法

PsSetCreateProcessNotifyRoutineEx的函数原型为：

```c
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  BOOLEAN                           Remove
);
```

其中NotifyRoutine为一个函数指针，这个函数的原型被规定为：

```c
PCREATE_PROCESS_NOTIFY_ROUTINE_EX PcreateProcessNotifyRoutineEx;

void PcreateProcessNotifyRoutineEx(
  PEPROCESS Process,
  HANDLE ProcessId,
  PPS_CREATE_NOTIFY_INFO CreateInfo
)
{...}
```

这个函数被称为通知例程，只要发生了“进程创建或销毁”这一事件，这个PcreateProcessNotifyRoutineEx就会被调用一次，这样就实现了对进程创建的监控。

另一个参数为Remove，Remove为FALSE时，表示要进行注册一个通知；Remove为TRUE，表示要移除这个通知。因此，一般会在DriverEntry，即驱动的入口函数中调用PsSetCreateProcessNotifyRoutineEx时将Remove设置为FALSE；在DriverUnload，即驱动的卸载函数中再调用一次PsSetCreateProcessNotifyRoutineEx，此时需要将Remove设置为FALSE。

## 通知例程函数的参数说明

通知例程函数有三个形参，通过这三个形参，就可以知道要创建（或销毁）的进程的一些基本信息。

ProcessId为要创建的进程对应的进程ID。

根据CreateInfo可以判断当前进行的是进程的创建还是销毁操作。如果要进行进程销毁操作，则CreateInfo的值会是NULL。因此，通过判断CreateInfo是否为NULL，可以得知要进行的操作是进程创建还是进程销毁。

进行进程创建操作时，CreateInfo的结构体定义为：

```c
typedef struct _PS_CREATE_NOTIFY_INFO {
  SIZE_T              Size;
  union {
    ULONG Flags;
    struct {
      ULONG FileOpenNameAvailable : 1;
      ULONG IsSubsystemProcess : 1;
      ULONG Reserved : 30;
    };
  };
  HANDLE              ParentProcessId;
  CLIENT_ID           CreatingThreadId;
  struct _FILE_OBJECT *FileObject;
  PCUNICODE_STRING    ImageFileName;
  PCUNICODE_STRING    CommandLine;
  NTSTATUS            CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
```

从中可以得到进程的名字、参数、父进程ID等信息。

## 进程监控驱动程序编写

### 函数和全局变量声明

在程序的最开始先声明几个需要用到的函数和全局变量：

```c
#include <ntddk.h>

/*函数原型声明*/
VOID DriverUnload(__in struct _DRIVER_OBJECT* DriverObject); //驱动卸载函数
VOID ProcessNotify(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo); //通知例程

BOOLEAN g_bSuccRegister = FALSE; //用于记录是否成功注册通知例程
```

### DriverEntry

```c
NTSTATUS DriverEntry(__in struct _DRIVER_OBJECT* DriverObject, __in PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	do {
		DriverObject->DriverUnload = DriverUnload;
		if (STATUS_SUCCESS != PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE)) {
			break;
		}
		g_bSuccRegister = TRUE;
		nStatus = STATUS_SUCCESS;
	} while (FALSE);
	return nStatus;
}
```

DriverEntry的主要功能是调用PsSetCreateProcessNotifyRoutineEx，将ProcessNotify函数注册为进程创建的通知例程。

### DriverUnload

```c
VOID DriverUnload(__in struct _DRIVER_OBJECT* DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	if (g_bSuccRegister) {
		PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
	}
	return;
}
```

在卸载驱动模块时，需要再调用一次PsSetCreateProcessNotifyRoutineEx，将之前注册的事件通知移除。

### ProcessNotify

这一函数为进程创建或销毁的通知例程，每当发生进程创建或进程销毁时，这一函数都会被调用，内容为：

```c
VOID ProcessNotify(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	if (NULL == CreateInfo) { //进程结束
		DbgPrint("[Destroy] [PID = 0x%x] [CurrentPID = 0x%x]\n", ProcessId, PsGetCurrentProcessId());
		return;
	}
	//进程创建
	DbgPrint("[Create] [PID = 0x%x, Name=%wZ] [CurrentPID = 0x%x] [PPID = 0x%x]\n", ProcessId, 
		CreateInfo->ImageFileName, PsGetCurrentProcessId(), CreateInfo->ParentProcessId);
	return;
}
```

函数会打印和进程有关的一些信息。

### 完整代码

```c
#include <ntddk.h>

/*函数原型声明*/
VOID DriverUnload(__in struct _DRIVER_OBJECT* DriverObject); //驱动卸载函数
VOID ProcessNotify(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo); //通知例程

BOOLEAN g_bSuccRegister = FALSE; //用于记录是否成功注册通知例程

NTSTATUS DriverEntry(__in struct _DRIVER_OBJECT* DriverObject, __in PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	do {
		DriverObject->DriverUnload = DriverUnload;
		if (STATUS_SUCCESS != PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE)) {
			break;
		}
		g_bSuccRegister = TRUE;
		nStatus = STATUS_SUCCESS;
	} while (FALSE);
	return nStatus;
}

VOID DriverUnload(__in struct _DRIVER_OBJECT* DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	if (g_bSuccRegister) {
		PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
	}
	return;
}

VOID ProcessNotify(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	if (NULL == CreateInfo) { //进程结束
		DbgPrint("[Destroy] [PID = 0x%x] [CurrentPID = 0x%x]\n", ProcessId, PsGetCurrentProcessId());
		return;
	}
	//进程创建
	DbgPrint("[Create] [PID = 0x%x, Name=%wZ] [CurrentPID = 0x%x] [PPID = 0x%x]\n", ProcessId, 
		CreateInfo->ImageFileName, PsGetCurrentProcessId(), CreateInfo->ParentProcessId);
	return;
}
```

### 编译时需要加上/INTEGRITYCHECK

使用Visual Studio对驱动进行编译时，需要加上/INTEGRITYCHECK选项，否则PsSetCreateProcessNotifyRoutineEx会返回STATUS_ACCESS_DENIED错误码。

![image-20210405184948334](/image-20210405184948334.png)

## 运行结果

在虚拟机中禁用驱动程序强制签名，然后运行驱动，打开DbgView查看打印的结果：

![image-20210405185411989](/image-20210405185411989.png)

上图为部分打印结果，驱动成功监测到notepad进程的创建和销毁。

## 通知例程的上下文

在创建和销毁进程时，通知例程都会被调用，那么通知例程是在哪个进程中被调用的呢？根据《Windows内核编程》的说法：

> 对于进程创建通知来说，通知例程运行在创建该进程的线程上下文中，如果线程A调用应用层CreateProcess函数创建子进程B，那么通知例程就运行在A线程的上下文中。对于进程结束通知来说，通知例程运行在该进程中最后一个退出的线程的上下文中（一般是主线程）。

根据上面的运行结果也可以看出，当进程创建时，调用PsGetCurrentProcessId得到的进程ID（CurrentPID）是和父进程的ID相同的；而当进程结束时，PsGetCurrentProcessId得到的进程ID是和要销毁的进程ID相同的。不过也有进程创建时，CurrentPID和PPID不相等的情况。

![image-20210405230102151](/image-20210405230102151.png)

## 进程是32位还是64位

在内核驱动中，要想知道进程是32位还是64位，可以使用ZwQueryInformationProcess函数，但这个函数需要传入进程的句柄，所以在这之前要先想办法获取进程的句柄。现在已经有了指向进程对象的指针，类型为PEPROCESS，变量名为Process，因此可以使用ObOpenObjectByPointer得到这个进程对象的一个句柄：

```c
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hProcess); //获取进程句柄
		if (STATUS_SUCCESS != status) {
			DbgPrint("ObOpenObjectByPointer Failed:0x%x", status);
			break;
		}
```

接下来使用ZwQueryInformationProcess，但发现头文件中并没有这个函数，因此要使用MmGetSystemRoutineAddress找到这个函数。首先在文件开头定义全局变量存储ZwQueryInformationProcess的地址：

```c
typedef NTSTATUS(*ZWQUERYINFORMATIONPROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

ZWQUERYINFORMATIONPROCESS g_pZwQueryInformationProcess = NULL; //ZwQueryInformationProcess函数地址
```

在DriverEntry中添加代码，对g_pZwQueryInformationProcess变量赋值：

```c
		UNICODE_STRING uFuncName = { 0 };
		DriverObject->DriverUnload = DriverUnload;
		RtlInitUnicodeString(&uFuncName, L"ZwQueryInformationProcess");
		g_pZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&uFuncName);
		if (NULL == g_pZwQueryInformationProcess) {
			break;
		}
```

最后在通知例程中添加代码，使用ZwQueryInformationProcess判断其是32位进程还是64位进程：

```c
		status = g_pZwQueryInformationProcess(hProcess, ProcessWow64Information, &isWOW64, sizeof(isWOW64), NULL);
		if (STATUS_SUCCESS != status) {
			DbgPrint("ZwQueryInformationProcess Failed:0x%x", status);
			break;
		}
		if (isWOW64) { //32位进程
			DbgPrint("[Detail 0x%x] 32bit", ProcessId);
		}
		else { //64位进程
			DbgPrint("[Detail 0x%x] 64bit", ProcessId);
		}
```

添加了上面这些代码后，源代码为：

```c
#include <ntifs.h>
#include <ntddk.h>

/*函数原型声明*/
VOID DriverUnload(__in struct _DRIVER_OBJECT* DriverObject); //驱动卸载函数
VOID ProcessNotify(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo); //通知例程
typedef NTSTATUS(*ZWQUERYINFORMATIONPROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

/*全局变量定义*/
ZWQUERYINFORMATIONPROCESS g_pZwQueryInformationProcess = NULL; //ZwQueryInformationProcess函数地址
BOOLEAN g_bSuccRegister = FALSE; //用于记录是否成功注册通知例程

NTSTATUS DriverEntry(__in struct _DRIVER_OBJECT* DriverObject, __in PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	do {
		UNICODE_STRING uFuncName = { 0 };
		DriverObject->DriverUnload = DriverUnload;
		RtlInitUnicodeString(&uFuncName, L"ZwQueryInformationProcess");
		g_pZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&uFuncName);
		if (NULL == g_pZwQueryInformationProcess) {
			break;
		}
		if (STATUS_SUCCESS != PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE)) {
			break;
		}
		g_bSuccRegister = TRUE;
		nStatus = STATUS_SUCCESS;
	} while (FALSE);
	return nStatus;
}

VOID DriverUnload(__in struct _DRIVER_OBJECT* DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	if (g_bSuccRegister) {
		PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
	}
	return;
}

VOID ProcessNotify(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	if (NULL == CreateInfo) { //进程结束
		DbgPrint("[Destroy] [PID = 0x%x] [CurrentPID = 0x%x]\n", ProcessId, PsGetCurrentProcessId());
		return;
	}
	//进程创建
	DbgPrint("[Create] [PID = 0x%x, Name=%wZ] [CurrentPID = 0x%x] [PPID = 0x%x]\n", ProcessId, 
		CreateInfo->ImageFileName, PsGetCurrentProcessId(), CreateInfo->ParentProcessId);
	
	HANDLE hProcess = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG_PTR isWOW64 = 0;
	do {
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hProcess); //获取进程句柄
		if (STATUS_SUCCESS != status) {
			DbgPrint("ObOpenObjectByPointer Failed:0x%x", status);
			break;
		}
		status = g_pZwQueryInformationProcess(hProcess, ProcessWow64Information, &isWOW64, sizeof(isWOW64), NULL);
		if (STATUS_SUCCESS != status) {
			DbgPrint("ZwQueryInformationProcess Failed:0x%x", status);
			break;
		}
		if (isWOW64) { //32位进程
			DbgPrint("[Detail 0x%x] 32bit", ProcessId);
		}
		else { //64位进程
			DbgPrint("[Detail 0x%x] 64bit", ProcessId);
		}
	} while (FALSE);

	if (NULL != hProcess) {
		ZwClose(hProcess);
		hProcess = NULL;
	}
	return;
}
```

运行结果如下：

![image-20210407163040051](/image-20210407163040051.png)

说明驱动程序可以分辨出32位和64位进程。