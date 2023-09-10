---
title: 在Android中使用AIDL实现进程间通信
date: 2023-09-08 17:46:22
tags: [Android, AIDL]
categories: Android
toc: true
typora-root-url: android-aidl-ipc
---

在Android中，可以使用AIDL（The Android Interface Definition Language，安卓接口定义语言）实现进程间通信。本文记录了使用AIDL实现进程间通信的方法。

Android官方给的AIDL文档地址：

https://developer.android.com/guide/components/aidl

<!--more-->

## 开发工具

Android Studio Giraffe | 2022.3.1 Patch 1

## 创建项目

使用Android Studio创建两个APP项目，分别命名为AIDLServer和AIDLClient，模板均选择Empty Views Activity：

![image-20230908182729223](/image-20230908182729223.png)

![image-20230908182812532](/image-20230908182812532.png)

![image-20230908182909027](/image-20230908182909027.png)

## 编程目标

通过AIDL实现进程间通信，让AIDLClient获取到AIDLServer的进程ID。

首先编写AIDLServer的代码，在AIDLServer界面上打印AIDLServer的进程ID。

在activity_main.xml中为中间的`Hello World!`字符串添加ID，然后在MainActivity.java的onCreate中让其打印AIDLServer的进程ID：

![image-20230909103003560](/image-20230909103003560.png)

![image-20230909103439272](/image-20230909103439272.png)

编译运行APP，AIDLServer在本次运行的进程ID为2820：

![Screenshot_20230909-103638](/Screenshot_20230909-103944.png)

## 编写AIDL接口

由官方文档可知，使用AIDL创建服务包含以下几个步骤：

1. 创建aidl文件
2. 实现接口
3. 将接口暴露给client

### 创建aidl文件

文档中说，需要将aidl文件保存在`src/`文件夹下，build项目时，SDK工具会在`gen/`路径下自动生成一个java文件，文件名与aidl文件相同。

在Android Studio左侧Project栏中，右键`src/`路径，选择新建aidl文件，命名为IRemoteService.aidl。如果提示`Requires setting the buildFeatures.aidl to true in the build file`，可以编辑`app/`路径下的build.gradle.kts文件，在`android{...}`中添加`buildFeatures.aidl = true`，并Sync Project with Gradle Files：

![image-20230909120240281](/image-20230909120240281.png)

![image-20230909122553753](/image-20230909122553753.png)

会发现IRemoteService.aidl的路径为`src/main/aidl/包名/`：

![image-20230909122954174](/image-20230909122954174.png)

AIDL文件的内容基本可以照抄文档：

```java
// IRemoteService.aidl
package com.example.aidlserver;

// Declare any non-default types here with import statements

/** Example service interface */
interface IRemoteService {
    /** Request the process ID of this service. */
    int getPid();

    /** Demonstrates some basic types that you can use as parameters
     * and return values in AIDL.
     */
    void basicTypes(int anInt, long aLong, boolean aBoolean, float aFloat,
            double aDouble, String aString);
}
```

build项目后，可在`build/generated/aidl_source_output_dir/debug/out/包名/`路径下找到IRemoteService.java文件，文件内容非常复杂。

### 实现接口并将接口暴露给client

文档中给出的示例，使用匿名类扩展IRemoteService.java中的IRemoteService.Stub类，并实现了getPid方法：

```java
private final IRemoteService.Stub binder = new IRemoteService.Stub() {
    public int getPid(){
        return Process.myPid();
    }
    public void basicTypes(int anInt, long aLong, boolean aBoolean,
        float aFloat, double aDouble, String aString) {
        // Does nothing.
    }
};
```

关于Java匿名类可参考：https://www.runoob.com/java/java-anonymous-class.html

暴露接口的方法是：扩展Service类，并实现其中的onBind方法，让onBind返回IRemoteService.Stub类的实例binder。

在APP的项目中，`src/main/java/包名/`下，新建一个RemoteService类`RemoteService.java`，其内容可直接照抄文档：

```java
package com.example.aidlserver;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;

public class RemoteService extends Service {
    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public IBinder onBind(Intent intent) {
        // Return the interface.
        return binder;
    }

    private final IRemoteService.Stub binder = new IRemoteService.Stub() {
        public int getPid(){
            return Process.myPid();
        }
        public void basicTypes(int anInt, long aLong, boolean aBoolean,
                               float aFloat, double aDouble, String aString) {
            // Does nothing.
        }
    };
}
```

### 在manifest中声明service

代码编写完成后，还需要编辑AndroidManifest.xml，在`<application>`的tag中添加`<service>`，声明RemoteService这个服务。

```xml
    <application
        ...>
        <activity
            android:name=".MainActivity"
            android:exported="true">
            ...
        </activity>

        <service android:name=".RemoteService" android:exported="true"/>
    </application>
```

注意service的tag里面需要添加`android:exported="true"`属性。

之后即可编译并运行APP。

## 客户端调用IPC方法

官方文档中说，如果client和service运行在不同的APP中，那么client的`src/`文件夹中需要有AIDL文件的拷贝。可以直接将AIDLService的`src/main/aidl`文件夹复制到AIDLClient项目的`src/main`路径下。复制完成后，AIDLClient的文件结构如下图所示：

![image-20230909141754952](/image-20230909141754952.png)

另外，如果使用的是版本较新的Android Studio，则和前面的AIDLServer相同，也要编辑`app/`路径下的build.gradle.kts文件，在`android{...}`中添加`buildFeatures.aidl = true`。

此时build AIDLClient项目，即可在`build/generated/aidl_source_output_dir/debug/out/com.example.aidlserver/`下看到IRemoteService.java。

在AIDLClient的`src/main/java/MainActivity.java`中，实现ServiceConnection类，这里可以仿照文档中的示例，在MainActivity中用匿名类的方法实现，并在ServiceConnection的`onServiceConnected`方法中，调用`IRemoteService.Stub.asInterface(service)`，将service转换成`IRemoteService`类型。

```java
import com.example.aidlserver.IRemoteService;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ...
    }

    /** The primary interface we are calling on the service. */
    IRemoteService mService = null;
    /**
     * Class for interacting with the main interface of the service.
     */
    private ServiceConnection mConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className,
                                       IBinder service) {
            mService = IRemoteService.Stub.asInterface(service);
        }

        public void onServiceDisconnected(ComponentName className) {
            mService = null;
        }
    };
}
```

接下来，在onCreate中调用bindService，传入实现的ServiceConnection，文档中给的示例是：

```java
Intent intent = new Intent(Binding.this, RemoteService.class);
intent.setAction(IRemoteService.class.getName());
bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
```

但是在实际编写AIDLClient的代码时，遇到一个问题：RemoteService这个类是在AIDLServer中编写的，AIDLClient里面没有这个类，所以没法使用`RemoteService.class`这个参数。

在网上找到了这个问题的解决方法：https://stackoverflow.com/a/55697742

在onCreate中编写这些代码：

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    Intent intent = new Intent();
    intent.setAction(IRemoteService.class.getName());
    intent.setClassName("com.example.aidlserver",
                        "com.example.aidlserver.RemoteService");
    bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
}
```

最后在onServiceConnected中，即可调用`mService.getPid`获取AIDLServer的进程ID。MainActivity.java的完整代码如下：

```java
package com.example.aidlclient;

import androidx.appcompat.app.AppCompatActivity;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;
import android.os.RemoteException;
import android.widget.TextView;

import com.example.aidlserver.IRemoteService;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Intent intent = new Intent();
        intent.setAction(IRemoteService.class.getName());
        intent.setClassName("com.example.aidlserver",
                "com.example.aidlserver.RemoteService");
        bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
    }

    /** The primary interface we are calling on the service. */
    IRemoteService mService = null;
    /**
     * Class for interacting with the main interface of the service.
     */
    private ServiceConnection mConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className,
                                       IBinder service) {
            // This is called when the connection with the service is
            // established, giving us the service object we can use to
            // interact with the service.  We are communicating with our
            // service through an IDL interface, so get a client-side
            // representation of that from the raw service object.
            mService = IRemoteService.Stub.asInterface(service);
            if (mService != null) {
                try {
                    String text = "Service PID: " + String.valueOf(mService.getPid()) +
                            "\nClient PID: " + Process.myPid();
                    TextView hello_world = (TextView) findViewById(R.id.hello_world);
                    hello_world.setText(text);
                } catch (RemoteException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        public void onServiceDisconnected(ComponentName className) {
            // This is called when the connection with the service is
            // unexpectedly disconnected&mdash;that is, its process crashed.
            mService = null;
        }
    };
}
```

## 运行结果

在Android设备上安装AIDLServer和AIDLClient，先后运行AIDLServer和AIDLClient，可以发现AIDLClient成功获取到AIDLServer的进程ID：

![Screenshot_20230909-151051](/Screenshot_20230909-151051.png)

![Screenshot_20230909-151106](/Screenshot_20230909-151106.png)