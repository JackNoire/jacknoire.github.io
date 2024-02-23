---
title: 口袋侦探2安卓内购破解流程
date: 2024-02-22 22:48:39
tags: [Android, reverse]
categories: Android
toc: true
typora-root-url: crack-koudaizhentan-2
---

![Untitled](/Untitled.png)

在上一篇文章中，我介绍了口袋侦探1的破解流程。本文会介绍口袋侦探2的破解流程。

本文使用的是从3DM下载的口袋汉化组汉化版本。

本文的项目地址为：https://github.com/JackNoire/InfinitePrivateEye_CHS

<!--more-->

## 分析Java层

和口袋侦探1类似，还是先进入商店，选择支付，然后进logcat看报错信息：

![Untitled](/Untitled-1.png)

搜索字符串，找到：

![Untitled](/Untitled-2.png)

使用Frida对该函数挂钩，注意使用旧版的Python和frida：

```
Python==3.8
frida==15.1.11
frida-tools==10.4.1
```

test.js：

```jsx
setTimeout(function () {
    Java.perform(function () {
        let IabHelper = Java.use("com.nflystudio.InfinitePrivateEye2.util.IabHelper");
        IabHelper["logError"].implementation = function (msg) {
            console.log(`IabHelper.logError is called: msg=${msg}`);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            this["logError"](msg);
        };
    });
}, 0);
```

执行：

```
frida -U -l test.js -f com.nflystudio.InfinitePrivateEye2
然后执行%resume
```

在APP里进入商店，执行支付操作，得到：

```
IabHelper.logError is called: msg=Illegal state for operation (launchPurchaseFlow): IAB helper is not set up.
java.lang.Exception
        at com.nflystudio.InfinitePrivateEye2.util.IabHelper.logError(Native Method)
        at com.nflystudio.InfinitePrivateEye2.util.IabHelper.logError(Native Method)
        at com.nflystudio.InfinitePrivateEye2.util.IabHelper.logError(Native Method)
        at com.nflystudio.InfinitePrivateEye2.util.IabHelper.checkSetupDone(IabHelper.java:755)    
        at com.nflystudio.InfinitePrivateEye2.util.IabHelper.launchPurchaseFlow(IabHelper.java:357)
        at com.nflystudio.InfinitePrivateEye2.util.IabHelper.launchPurchaseFlow(IabHelper.java:324)
        at com.nflystudio.InfinitePrivateEye2.InfinitePrivateEye2.purchaseItem(InfinitePrivateEye2.java:182)
        at com.nflystudio.InfinitePrivateEye2.SqliteManager.purchaseItem(SqliteManager.java:254)
        at org.cocos2dx.lib.Cocos2dxRenderer.nativeRender(Native Method)
        at org.cocos2dx.lib.Cocos2dxRenderer.onDrawFrame(Cocos2dxRenderer.java:94)
        at android.opengl.GLSurfaceView$GLThread.guardedRun(GLSurfaceView.java:1534)
        at android.opengl.GLSurfaceView$GLThread.run(GLSurfaceView.java:1251)
```

于是可以找到这个函数：`com.nflystudio.InfinitePrivateEye2.SqliteManager.purchaseItem`

也就是说，游戏逻辑写在native里，当点击支付后，会调用Java的这个purchaseItem函数。

接下来，搜索native函数，会发现和口袋侦探1相同，也有一个名为receiveResult的native函数：

![Untitled](/Untitled-3.png)

如果支付成功，Java层就会调用这个receiveResult函数，再回到native层。

## 分析native层

口袋侦探2只有一个so文件，libgame.so，用IDA Pro分析该文件，会发现和口袋侦探1差不多。

首先找SqliteManager.purchaseItem，可以找到SqliteManagerJni::purchaseItemJni：

![Untitled](/Untitled-4.png)

找它的xrefs，最终可以找到ShopLayer::_runBuyItem调用MJScene::runPurchaseItem，而在runPurchaseItem里面，也是一样的先给数组赋值，再调用purchaseItem函数：

![Untitled](/Untitled-5.png)

![Untitled](/Untitled-6.png)

再看receiveResult，在native层名字叫Java_com_nflystudio_InfinitePrivateEye2_InfinitePrivateEye2_receiveResult，这个和口袋侦探1也一样：

![Untitled](/Untitled-7.png)

而在completePurchaseItem里面，也是通过某种方式去调用ShopLayer::_completeBuyItem

![Untitled](/Untitled-8.png)

结构基本上和口袋侦探1一样，所以破解思路也和口袋侦探1一样，修改ShopLayer::_runBuyItem的开头，让它直接调用ShopLayer::_completeBuyItem

## Keypatch修改native函数内容

在汇编窗口里定位到ShopLayer::_runBuyItem，从.text:0015FB76开始修改，给参数赋值、调用ShopLayer::_completeBuyItem，然后跳到函数末尾。

![Untitled](/Untitled-9.png)

修改后：

![Untitled](/Untitled-10.png)

Edit→Patch program→Apply patches to input file，将修改写到文件里。

## apktool重打包并签名

在重打包前，记得将lib/armeabi路径下IDA Pro生成的idb文件移出来，以免这个文件被打包进apk。

重打包、签名的操作和口袋侦探1相同，注意**使用Java jdk1.8.0_202版本或这个附近的版本**的keytool和jarsigner。

```
apktool b .
cd dist
keytool -genkey -v -keystore my-release-key.keystore -alias cert -keyalg RSA -keysize 2048 -sigalg SHA1withRSA -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore koudaizhentan2.apk cert
```

安装APK，运行：

![Untitled](/Untitled-11.png)

![Untitled](/Untitled-12.png)

![Untitled](/Untitled-13.png)