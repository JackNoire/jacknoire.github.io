---
title: 在VMware Workstation中安装X86版Android 2.2，并运行2010年的安卓游戏
date: 2024-02-16 14:28:20
tags: [Android, VMWare]
categories: Android
toc: true
typora-root-url: android-x86-2-2-battleground
---



![](image-20240215203731179.png)

在Reddit上看到一篇帖子，希望能找到一个老版本的安卓模拟器，在上面运行一款2010年左右，由广州奥兹软件公司制作的手机游戏Battleground，中文名称为《战争之王》，该游戏无法在Android 4.0+的系统上运行。

<!--more-->

https://www.reddit.com/r/BlueStacks/comments/rgfl7z/question_old_version_of_android/

搜索后找到这款游戏的APK文件：https://www.androidout.com/item/android-apps/27008/battleground/

我在VMware® Workstation 15 Pro上安装Android 2.2虚拟机，在里面成功安装并运行了这款游戏，不过没法播放游戏声音，但是不影响正常游玩。

## 安装Android 2.2虚拟机

### 下载Android-x86 2.2的ISO文件

Android-x86 2.2的ISO文件由Android-x86项目提供：https://www.android-x86.org/

下载地址：

https://sourceforge.net/projects/android-x86/files/Release%202.2/

下载文件：[android-x86-2.2-generic.iso](https://sourceforge.net/projects/android-x86/files/Release 2.2/android-x86-2.2-generic.iso/download)

### 在VMware中创建虚拟机

新建虚拟机，选择典型，安装程序光盘映像文件选择android-x86-2.2-generic.iso

![image-20240216125741741](/image-20240216125741741.png)

取消勾选“创建后开启此虚拟机”

![image-20240216125832373](/image-20240216125832373.png)

### 编辑.vmx文件的ethernet选项

打开虚拟机文件夹下的.vmx文件，将这里的ethernet0.virtualDev的e1000修改为vlance。如果文件中包含中文，这一步需要注意编码问题，通常该文件的编码是GB 2312。

![image-20240216130153267](/image-20240216130153267.png)

![image-20240216130238804](/image-20240216130238804.png)

###  启动虚拟机，安装Android系统

启动虚拟机后进入这个页面，可以不安装系统直接Live CD进入系统，也可以将Android-x86至硬盘。

![image-20240216130655468](/image-20240216130655468.png)

选择Installation安装，再按一次回车，进到这里：

![image-20240216130848687](/image-20240216130848687.png)

方向键左右可以选择，回车可以确认。依次选择：New 👉 Primary 👉 Size (in MB): 10733.99（直接回车） 👉 Bootable 👉 Write 👉 输入yes然后回车 👉 Quit

![image-20240216131219471](/image-20240216131219471.png)

进到这个页面，选中sda1后直接回车：

![image-20240216131251724](/image-20240216131251724.png)

方向键下，选中ext3，然后回车：

![image-20240216131326812](/image-20240216131326812.png)

后面直接全部回车即可。另外：在这里有一个Create a fake SD card功能，我试过发现，Android 2.2的镜像用了这个功能后，会导致无法开机，不过在Android 2.3镜像里这个功能似乎是正常的。因为目前是用的Android 2.2，所以直接Run Android-x86：

![image-20240216131423996](/image-20240216131423996.png)

Android 2.3的镜像可在这里下载：https://code.google.com/archive/p/android-x86/downloads

### 检查网络连接是否正常

在虚拟机中，Alt+F1可进入命令行界面，Alt+F7可返回图形界面。

Alt+F1之后，输入`ip a`命令，如果网络正常，可以看到eth0，以及下面的IP地址，我这里的IP地址是192.168.163.154。

![image-20240216141256697](/image-20240216141256697.png)

网络正常时可以ping通baidu.com：

![image-20240216141358714](/image-20240216141358714.png)

如果网络有问题，并且只能看到lo，看不到eth0，则需要检查之前的.vmx文件中ethernet0.virtualDev是否已经修改为了vlance。如果看到了eth0，但是没有IP地址，网络也连不上，则可以参考这里的解决方法：

[Solve Android x86 No Network Problems in VMware Workstation | virten.net](https://www.virten.net/2014/02/solve-android-x86-no-network-problems-in-vmware-workstation/)

也就是运行下面两条命令：

```
setprop net.dns1 8.8.8.8
dhcpcd eth0
```

如果网络正常，那么记住eth0的这个IP地址。然后，Alt+F7返回图形界面。

## adb连接Android虚拟机并安装apk文件

在Windows宿主机中，使用adb通过IP地址连接到Android虚拟机，命令为`adb connect [IP地址]`，例如我这里的IP地址是192.168.163.154，那么连接命令为`adb connect 192.168.163.154`：

```
> adb connect 192.168.163.154
connected to 192.168.163.154:5555

> adb devices
List of devices attached
192.168.163.154:5555    device
```

之后，再cd到apk所在路径，用`adb install`安装APP：

```
> adb install battleground.apk
Performing Push Install
battleground.apk: 1 file pushed, 0 skipped. 10.7 MB/s (11615871 bytes in 1.031s)
        pkg: /data/local/tmp/battleground.apk
Success
```

现在就能在虚拟机中运行该游戏了：

![image-20240216142434510](/image-20240216142434510.png)

![image-20240216142513923](/image-20240216142513923.png)

![image-20240216142650484](/image-20240216142650484.png)
