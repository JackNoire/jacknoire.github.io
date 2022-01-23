---
title: 设置iframe中body的contentEditable属性
date: 2022-01-23 12:16:43
tags: [HTML,iframe]
categories: Web
typora-root-url: html-iframe-body-contenteditable
---

在HTML中，实现富文本/所见即所得编辑器的一种方法是将iframe中body的contentEditable属性设置为true。QQ邮箱的写信功能就使用了这一原理：

![QQ邮箱写信功能](QQ邮箱写信功能.png)

<!--more-->

获取iframe中body的方法可以在这里找到：

[html - How to get the body's content of an iframe in Javascript? - Stack Overflow](https://stackoverflow.com/questions/926916)

编写JS代码，将contentEditable设置为true：

```javascript
var iframe = document.getElementById("ifrm");
var iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
iframeDocument.body.contentEditable = "true";
```

这段JS代码需要在iframe加载之后执行，可以将其放在window.onload当中:

```html
<!DOCTYPE html>
<html>
    <head>
        <script>
            window.onload = function() {
                var iframe = document.getElementById("ifrm");
                var iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
                iframeDocument.body.contentEditable = "true";
            }
        </script>
    </head>
    <body>
        <iframe id="ifrm" width=1000 height=500></iframe>
    </body>
</html>
```

document.onload和window.onload的区别是：document.onload会在DOM加载后、图片等外部资源加载前触发，window.onload在整个页面（包括CSS文件、脚本文件、图片等）加载后才会触发。

现在打开页面，就会出现一个框，可以向框中粘贴一些有样式的文本。

接下来，再给页面添加一个按钮，用户点击按钮向网页提交输入的文本。可以构造一个表单：

```html
<form action=https://httpbin.org/post method=post>
    <iframe id="ifrm" width=1000 height=500></iframe>
    <input type=hidden name="iframe" id="ifrmcontent">
    <input type=submit>
</form>
```

用户提交表单时，执行一段JS代码，将iframe的内容复制给下面的input hidden。实现这一功能的JS代码为：

```javascript
function copyIfrm2Hidden() {
    var iframe = document.getElementById("ifrm");
    var iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
    document.getElementById("ifrmcontent").value = iframeDocument.body.innerHTML;
}
```

设置form的onsubmit属性，在提交表单时执行copyIfrm2Hidden函数：

```html
<form action=https://httpbin.org/post method=post onsubmit="copyIfrm2Hidden()">
    <iframe id="ifrm" width=1000 height=500></iframe>
    <input type=hidden name="iframe" id="ifrmcontent">
    <input type=submit>
</form>
```

完整代码为：

```html
<!DOCTYPE html>
<html>
    <head>
        <script>
            function copyIfrm2Hidden() {
                var iframe = document.getElementById("ifrm");
                var iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
                document.getElementById("ifrmcontent").value = iframeDocument.body.innerHTML;
            }

            window.onload = function() {
                var iframe = document.getElementById("ifrm");
                var iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
                iframeDocument.body.contentEditable = "true";
            }
        </script>
    </head>
    <body>
        <form action=https://httpbin.org/post method=post onsubmit="copyIfrm2Hidden()">
            <iframe id="ifrm" width=1000 height=500></iframe>
            <input type=hidden name="iframe" id="ifrmcontent">
            <input type=submit>
        </form>
    </body>
</html>
```

也可以使用其他方式提交请求，比如很多邮箱都使用XMLHttpRequest的方式发送邮件。