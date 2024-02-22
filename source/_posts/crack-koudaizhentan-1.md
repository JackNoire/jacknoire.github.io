---
title: 口袋侦探1安卓内购破解流程
date: 2024-02-22 22:44:19
tags: [Android, reverse]
categories: Android
toc: true
typora-root-url: crack-koudaizhentan-1
---


![Untitled](/Untitled.png)

口袋侦探是由韩国NFLY STUDIO于2013年左右推出的手机游戏，分为1、2两部，由口袋汉化组汉化。NFLY STUDIO传闻已解散，该游戏也很久未更新，安卓版只能在很老的Android 4环境下运行。

<!--more-->

目前，网上能下载到的口袋侦探安卓汉化版主要包括以下版本：

| 版本 | 来源 | 特点 | 下载 |
| --- | --- | --- | --- |
| 口袋侦探1汉化版 | 口袋汉化组汉化 | 存在BGM缺失的bug | https://shouyou.3dmgame.com/android/588.html |
| 口袋侦探1无限金币版 | 口袋汉化组汉化+爱吾破解 | 初始金币修改为25252525 | https://www.bilibili.com/video/BV1yL411U7P1/ |
| 口袋侦探2汉化版 | 口袋汉化组汉化 | 正常 | https://shouyou.3dmgame.com/android/1358.html |
| 口袋侦探2无限金币版 | 口袋汉化组汉化+爱吾破解 | 初始金币修改为25252525 | https://m.25game.com/android/View/4206/ |

口袋侦探1汉化版存在的BGM缺失问题，试验后发现，只需用apktool作一个简单的重打包即可解决。本文会在3DM上面下载的口袋侦探1汉化版APK上进行实验。

游戏中有一个“侦探商店”功能，在商店中购买金币，游戏会卡死。

本文会介绍除修改初始金币外的另一种破解思路，即对“侦探商店”这一功能进行破解。

本文的项目地址为：https://github.com/JackNoire/InfinitePrivateEye_CHS

## 下载安卓4模拟器

目前很多安卓模拟器都仅支持安卓5及以上的安卓版本，例如新版雷电模拟器仅支持安卓5.0、7.1、9.0这几个版本。可以在这个地址下载安卓4.3版本的雷电模拟器：

[http://res.ldmnq.com/download/1.9.1/ldinst_1.9.1.exe](http://res.ldmnq.com/download/1.9.1/ldinst_1.9.1.exe)

也可使用其他的安卓4模拟器。

## 对侦探商店功能进行分析

### 分析Java层

启动安卓模拟器，然后使用logcat（可以用Android Studio里面的logcat），用APK的包名（com.creativefactory）进行过滤。

接下来，在模拟器中启动APP，进入侦探商店，尝试购买金币。发现报错："Could not bind to service."

![Untitled](/Untitled-1.png)

使用JADX对该APK进行静态分析：

[skylot/jadx: Dex to Java decompiler](https://github.com/skylot/jadx)

搜索该字符串，可以找到：

![Untitled](/Untitled-2.png)

使用Frida对bindToMarketBillingService挂钩。由于运行环境是Android 4，新版Frida无法在上面运行，因此需要使用老版的Frida，而老版的Frida又需要老版的Python。

使用的Python和Frida的版本为：

```
Python==3.8
frida==15.1.11
frida-tools==10.4.1
```

首先创建一个Python 3.8的环境，如果使用anaconda则：

```
conda create -n py38 python=3.8
conda activate py38
```

然后用pip安装特定版本的frida和frida-tools：

```
pip install frida==15.1.11
pip install frida-tools==10.4.1
```

pip install frida时可能会卡住，在这里找到一个解决方法：

[https://github.com/frida/frida/issues/2012](https://github.com/frida/frida/issues/2012)

也就是进入这个网站：[https://pypi.org/project/frida/15.1.11/#files](https://pypi.org/project/frida/15.1.11/#files)

下载frida-15.1.11-py3.8-win-amd64.egg，然后将该文件丢到`C:\Users\用户名`这个路径下，例如我的电脑上是`C:\Users\lenovo`。之后再重新执行pip install命令。

安装完frida后，再挂钩bindToMarketBillingService，编写JS脚本test.js：

```jsx
setTimeout(function () {
    Java.perform(function () {
        let BillingService = Java.use("com.creativefactory.BillingService");
        BillingService["bindToMarketBillingService"].implementation = function () {
            console.log(`BillingService.bindToMarketBillingService is called`);
            let result = this["bindToMarketBillingService"]();
            console.log(`BillingService.bindToMarketBillingService result=${result}`);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            return result;
        };
    });
}, 0);
```

启动安卓模拟器，安装口袋侦探1的APK文件。getprop检查模拟器架构为x86：

```
> adb shell getprop ro.product.cpu.abi
x86
```

adb push放入x86的15.1.11版本frida-server，adb shell chmod修改运行权限，然后运行：

```
> adb shell
# /data/local/tmp/frida-server-15.1.11-android-x86
```

在电脑上执行命令挂钩：

```
frida -U -l test.js -f com.creativefactory
再输入%resume
```

输出如下：

```
BillingService.bindToMarketBillingService is called
BillingService.bindToMarketBillingService result=false
java.lang.Exception
        at com.creativefactory.BillingService.bindToMarketBillingService(Native Method)
        at com.creativefactory.BillingService.bindToMarketBillingService(Native Method)
        at com.creativefactory.BillingService.bindToMarketBillingService(Native Method)
        at com.creativefactory.BillingService.access$0(BillingService.java:417)
        at com.creativefactory.BillingService$BillingRequest.runRequest(BillingService.java:100)
        at com.creativefactory.BillingService.requestPurchase(BillingService.java:457)
        at com.creativefactory.ExecuteBilling$1.run(ExecuteBilling.java:74)
        at android.os.Handler.handleCallback(Handler.java:730)
        at android.os.Handler.dispatchMessage(Handler.java:92)
        at android.os.Looper.loop(Looper.java:137)
        at android.app.ActivityThread.main(ActivityThread.java:5103)
        at java.lang.reflect.Method.invokeNative(Native Method)
        at java.lang.reflect.Method.invoke(Method.java:525)
        at com.android.internal.os.ZygoteInit$MethodAndArgsCaller.run(ZygoteInit.java:737)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:553)
        at dalvik.system.NativeStart.main(Native Method)
```

由stacktrace可以找到purchaseItem：

![Untitled](/Untitled-3.png)

于是，再对purchaseItem挂钩：

```jsx
setTimeout(function () {
    Java.perform(function () {
        let ExecuteBilling = Java.use("com.creativefactory.ExecuteBilling");
        ExecuteBilling["purchaseItem"].implementation = function (pID) {
            console.log(`ExecuteBilling.purchaseItem is called: pID=${pID}`);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            this["purchaseItem"](pID);
        };
    });
}, 0);
```

输出如下：

```
ExecuteBilling.purchaseItem is called: pID=com.creativefactory.timeprivate.10000p
java.lang.Exception
        at com.creativefactory.ExecuteBilling.purchaseItem(Native Method)
        at com.creativefactory.ExecuteBilling.purchaseItem(Native Method)
        at com.creativefactory.ExecuteBilling.purchaseItem(Native Method)
        at com.creativefactory.SqliteManager.purchaseItem(SqliteManager.java:234) 
        at org.cocos2dx.lib.Cocos2dxRenderer.nativeRender(Native Method)
        at org.cocos2dx.lib.Cocos2dxRenderer.onDrawFrame(Cocos2dxRenderer.java:59)
        at android.opengl.GLSurfaceView$GLThread.guardedRun(GLSurfaceView.java:1534)
        at android.opengl.GLSurfaceView$GLThread.run(GLSurfaceView.java:1251)
```

也就是说，是从native层代码调用的Java层的SqliteManager.purchaseItem，然后SqliteManager.purchaseItem再去调用ExecuteBilling.purchaseItem

可以猜测，游戏主要逻辑写在native层，点击付费后会调用Java层函数，在Java层处理完付费后，会回到native层，继续执行付费成功/失败的游戏逻辑。于是，在JADX中搜索native函数，找到native函数`com.creativefactory.TimePrivate.receiveResult`，在`com.creativefactory.PurchaseObserver.onRequestPurchaseResponse`这里被调用：

![Untitled](/Untitled-4.png)

### 分析native层

apktool对apk文件解包：

```
apktool d koudaizhentan.apk
```

在lib/armeabi中看到这四个文件：

```
libcocos2d.so
libcocosdenshion.so
libgame.so
libgame_logic.so
```

由于是x86模拟器，没法直接用frida挂钩arm的函数，所以只能静态分析。使用IDA Pro分析，在libgame_logic.so里面发现对Java层purchaseItem的调用：

![Untitled](/Untitled-5.png)

用快捷键x往上查找该函数的xrefs，可以找到MJScene::runPurchaseItem：

![Untitled](/Untitled-6.png)

这个函数里对一个数组作了赋值操作，然后调用了purchaseItem。

而在ShopLayer::_runBuyItem里调用了MJScene::runPurchaseItem，这里GameInfo::shared函数返回的地址+60的地方，就有下标为64和66的地方分别被赋值了_completeBuyItem和_failedBuyItem这两个函数。

![Untitled](/Untitled-7.png)

ShopLayer::_buySelectedItem出现了ShopLayer::_runBuyItem：

![Untitled](/Untitled-8.png)

联想到游戏中侦探商店购买物品会弹一个窗，让玩家选确认，再由这个函数名，猜测这里可能是弹一个窗，点击窗口中的“确定”就会执行ShopLayer::_runBuyItem这个函数。

![Untitled](/Untitled-9.png)

接下来，再分析如果交易成功，会执行哪段代码。在libgame_logic.so中搜索native函数receiveResult，找到Java_com_creativefactory_TimePrivate_receiveResult

![Untitled](/Untitled-10.png)

如果交易成功，会执行MJScene::completePurchaseItem

![Untitled](/Untitled-11.png)

IDA Pro在反编译时，可能弄错参数的个数。查找网上cocos2d的代码示例，找到：

```cpp
this->runAction(CCSequence::actions(CCDelayTime::actionWithDuration(3),
CCCallFunc::actionWithTarget(this, callfunc_selector(GameOverLayer::gameOverDone)),
NULL));
```

actionWithTarget应该至少有两个参数。如果参数个数不对，可以右键actionWithTarget→Set item type…，然后修改函数参数为两个以上：

![Untitled](/Untitled-12.png)

而在MJScene::failedPurchaseItem中，则是：

![Untitled](/Untitled-13.png)

之前已经知道，某个下标为64的地方被赋值了下标为64和66的地方分别被赋值了ShopLayer::_completeBuyItem和ShopLayer::_failedBuyItem这两个函数。这里也出现了64和66这两个下标，也就是说，这里MJScene::completePurchaseItem很可能最终会以某种方式去调用ShopLayer::_completeBuyItem。

在ShopLayer::_completeBuyItem中会发现似乎是会去调用ShopLayer::_showCompletePopup：

![Untitled](/Untitled-14.png)

粗略查看一下_showCompletePopup，里面内容非常复杂，猜测会更新金币数量。

于是，考虑对native层的内容进行修改，在点击确认交易的弹窗后，调用ShopLayer::_runBuyItem时，去调用ShopLayer::_showCompletePopup。

## Keypatch修改native函数内容

使用IDA Pro的Keypatch插件修改ShopLayer::_runBuyItem的内容，让它调用ShopLayer::_showCompletePopup。

在ShopLayer::_runBuyItem中，从std::string::compare开始修改，直接修改为一个对ShopLayer::_showCompletePopup的调用。

![Untitled](/Untitled-15.png)

ShopLayer::_completeBuyItem需要传两个参数进去，一个ShopLayer *this，一个浮点数。

![Untitled](/Untitled-16.png)

浮点数可以就传一个0。而对于这个ShopLayer *this，恰好ShopLayer::_runBuyItem的第一个参数也是ShopLayer *this。所以可以直接将ShopLayer::_runBuyItem的第一个参数传给ShopLayer::_completeBuyItem。

从`SUB SP, SP, #0x2C`后面一条，即.text:000A9B96开始修改。

![Untitled](/Untitled-17.png)

这个地方R0的值还没被修改，所以还等于ShopLayer::_runBuyItem的第一个参数。只需要将第二个参数设置为0.0，然后调用ShopLayer::_completeBuyItem即可。

Keypatch的使用方法：Ctrl+Alt+K，或Edit→Keypatch→Patcher，再输入指令即可。

修改后：

![Untitled](/Untitled-18.png)

![Untitled](/Untitled-19.png)

然后，Edit→Patch program→Apply patches to input file，将修改写到文件里。

## apktool重打包并签名

在重打包前，记得将lib/armeabi路径下IDA Pro生成的idb文件移出来，以免这个文件被打包进apk。

在解包的文件夹路径下，执行：

```
apktool b .
```

然后使用Java JDK里的keytool和jarsigner进行签名，这两个工具通常在`%JAVA_HOME%\bin`里面。

**建议使用jdk1.8.0_202版本或这个附近的版本**。如果使用新版Java（例如Java 17）中的工具签名，在Android 4中可能报错：INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION

```
cd dist
keytool -genkey -v -keystore my-release-key.keystore -alias cert -keyalg RSA -keysize 2048 -sigalg SHA1withRSA -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore koudaizhentan.apk cert
```

我使用的apktool版本为2.7.0，如果使用老版的apktool，可能还需要用zipalign对齐。

最后，在雷电模拟器上卸载并重新安装新的口袋侦探APK文件。进入侦探商店并购买金币：

![Untitled](/Untitled-20.png)

![Untitled](/Untitled-21.png)

![Untitled](/Untitled-22.png)