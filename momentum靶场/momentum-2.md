# 前言

靶机采用`virtual box`虚拟机，桥接网卡

攻击采用`VMware`虚拟机，桥接网卡

靶机：`momentum-2   192.168.1.40`

攻击：`kali   192.168.1.16`

# 主机发现

使用`arp-scan -l`扫描

![](D:\stu\vulnhub\momentum靶场\pic-2\1.jpg)



# 信息收集

## 使用namp扫描

这里的命令对目标进行`vulner`中的漏洞数据库进行对比，有的话，会给出漏洞编号及链接，和危害等级

```shell
nmap -sV 192.168.1.40 -O --script=vulners --script-args mincvss=5.0
```

不过这里只进行简单的扫描即可

![](D:\stu\vulnhub\momentum靶场\pic-2\2.jpg)

## 网站探测

### 访问网站

![](D:\stu\vulnhub\momentum靶场\pic-2\3.jpg)

和`momentum-1`差不多，都是图片，不过这里页面源代码中并没有调用`js`函数等，不过图片放在`/img`目录，至少确定是目录型网站。

## 尝试指纹识别

![](D:\stu\vulnhub\momentum靶场\pic-2\4.jpg)





## 网站目录扫描

使用`dirsearch、gobuster、ffuf、dirb、dirbuster`都可以

![](D:\stu\vulnhub\momentum靶场\pic-2\5.jpg)

看到几个目录，尝试访问查看，首先访问`js`，可以看到是一个文件上传的`js`函数，并且调用`ajax.php`文件，采用`post`

![](D:\stu\vulnhub\momentum靶场\pic-2\6.jpg)

访问`ajax.php`文件，全是后端php语言

![](D:\stu\vulnhub\momentum靶场\pic-2\7.jpg)

访问`css`，是网站的样式，无其他内容

访问`dashboard.html`页面，有文件上传页面，并且查看页面源代码后，发现与之前`js`中的获取`file`的id对应上了，并且点击提交，调用了`js`的函数。并且上传后的文件也给出提示，在`owls`

![](D:\stu\vulnhub\momentum靶场\pic-2\8.jpg)



OK，到这里网站的信息基本上了解了，下面就是进行总结一下，首先在80端口网站中，有`js`目录，其中有一个函数，该函数与`dashboard.html`联合在一起，并且涉及到`ajax.php`文件以及`POST`提交方式。

文件上传--->JS函数---->ajax.php



# 漏洞寻找

上传`php`中的反弹`shell`脚本文件进行测试，直接上传发现不行

![](D:\stu\vulnhub\momentum靶场\pic-2\9.jpg)



这里建议了解一下`XMLHttpRequest`，参考链接`https://blog.csdn.net/abraham_ly/article/details/113526496`

```js
function uploadFile() {
    var files = document.getElementById("file").files;
    if(files.length > 0 ){
       var formData = new FormData();
       formData.append("file", files[0]);
       var xhttp = new XMLHttpRequest();
       // Set POST method and ajax file path
       xhttp.open("POST", "ajax.php", true);
       // call on request changes state
       xhttp.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
 
            var response = this.responseText;
            if(response == 1){
               alert("Upload successfully.");
            }else{
               alert("File not uploaded.");
            }
          }
       };
       // Send request with data
       xhttp.send(formData);
    }else{
       alert("Please select a file");
    }
 }
```

根据上面上传后的提示，以及代码来看，主要是在`response==1`这个条件出错

测试上传图片，还是出错
![](D:\stu\vulnhub\momentum靶场\pic-2\10.jpg)





使用`burp`抓包分析，对请求修改也没有效果，返回都是`0`，无法进入上传成功，怀疑可能是网站目录没有扫全，再检测一遍，这次多加后缀名测试，结果还真出来一些东西，不能太依赖`dirsearch`的默认扫描，毕竟有的后缀名还是挺重要的。

使用`gobustrt`扫描，`-x`表示扩展名，`-d`表示对备份进行检测，也就是自己加上常见的扩展备份名，`-b`过滤包含状态码`400-404`的结果

![](D:\stu\vulnhub\momentum靶场\pic-2\11.jpg)

这里对于`dirsearch`不太清楚了，加上备份文件的格式，也无法扫描出来

![](D:\stu\vulnhub\momentum靶场\pic-2\12.jpg)

或者使用`ffuf`也是能够扫描出来的



# 漏洞利用

这里知道有备份，下载备份文件审计代码

![](D:\stu\vulnhub\momentum靶场\pic-2\13.jpg)

直接测试，先直接上传`txt`文件看看，是否有该逻辑性.上传成功，说明正确

![](D:\stu\vulnhub\momentum靶场\pic-2\14.jpg)

上传`php`反弹sehll的脚本。使用`burp`抓包进行修改，然后注意，在代码审计时，有一个注释说，在`cookie`的末尾添加一个大写字母，所以，这就需要构造好准备的数据，然后进行爆破



![](D:\stu\vulnhub\momentum靶场\pic-2\15.jpg)

把该数据包发送到`intruder`模块，先在末尾加入一个`A`，用于知道爆破位置

![](D:\stu\vulnhub\momentum靶场\pic-2\16.jpg)



构造`payload`然后攻击测试

![](D:\stu\vulnhub\momentum靶场\pic-2\17.jpg)

![](D:\stu\vulnhub\momentum靶场\pic-2\18.jpg)

得出`Cookie`的最后一位为`R`

# 反弹shell

此时在`kali`中开启监听，这里我在`php`脚本设置的是1234端口

![](D:\stu\vulnhub\momentum靶场\pic-2\19.jpg)



在浏览器访问

![](D:\stu\vulnhub\momentum靶场\pic-2\20.jpg)

点击脚本文件后，`kali`获取反弹`shell`

![](D:\stu\vulnhub\momentum靶场\pic-2\21.jpg)





登录成功，查看`/home`目录，获取到一个密码，不知道是否可用

![](D:\stu\vulnhub\momentum靶场\pic-2\22.jpg)



# ssh登录

测试该内容`myvulnerableapp[Asterisk]`是否是`ssh`的密码，测试发现并不是，寻找其他可用

找了一圈，没有可用，就网上查了一下，说`[Asterisk]`是`*`，我真服了，这在英语词典中确实有`*`的含义

所以上面文本应该是`myvulnerableapp*`，再次登录测试，登录成功

![](D:\stu\vulnhub\momentum靶场\pic-2\23.jpg)

因为之前不知道密码的时候，我把其他方法都看了一下，这里直接`find`寻找具有SUID的文件

![](D:\stu\vulnhub\momentum靶场\pic-2\24.jpg)



# 提权

然后使用`sudo -l`列出

![](D:\stu\vulnhub\momentum靶场\pic-2\25.jpg)



首先查看该`py`文件，发现无写权限，查看导入的包有哪些

![](D:\stu\vulnhub\momentum靶场\pic-2\26.jpg)



导入三个包，查看这三个包的权限

![](D:\stu\vulnhub\momentum靶场\pic-2\27.jpg)



看了都无写权限，我就再看看代码。

首先用户输入`seed`，然后生成`cookie`，然后就是执行写入内容到`log.txt`，传参是输入的`seed`，然后子进程打开这个`cmd`。运行`py`脚本，然后输入可执行命令

![](D:\stu\vulnhub\momentum靶场\pic-2\28.jpg)



这里通过`nc`执行`/bin/bash`然后给`kali`，但是这里不行，没有提权成功

查看发现，其他人也有执行的权限，所以不能直接变为`root`

![](D:\stu\vulnhub\momentum靶场\pic-2\29.jpg)

但是吧，突然想到，我是用`sudo`获取该文件的，怎么就没有使用`sudo`执行呢。

啧啧啧啧啧啧啧啧啧啧啧

重新使用`sudo`执行

![](D:\stu\vulnhub\momentum靶场\pic-2\30.jpg)



提权成功

![](D:\stu\vulnhub\momentum靶场\pic-2\31.jpg)





# 清除痕迹



![](D:\stu\vulnhub\momentum靶场\pic-2\32.jpg)





# 总结

1. 代码审计，知道满足哪些条件才能执行
2. 对于网站目录，可以多测几遍，不要错过关键信息
3. 多了解点英语单词吧
4. `python`代码要有一定基础
5. `nc`命令的一些参数了解































