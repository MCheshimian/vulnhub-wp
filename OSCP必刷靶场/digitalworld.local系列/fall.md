# 前言

靶机：`digitalworld.local-fall`，IP地址为`192.168.10.10`

攻击：`kali`，IP地址为`192.168.10.6`

`kali`采用`VMware`虚拟机，靶机选择使用`VMware`打开文件，都选择桥接网络

这里官方给的有两种方式，一是直接使用`virtualbox`加载，另一种是通过`VMware`直接加载，也给出了`iso`镜像文件。	

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过网盘下载`https://pan.quark.cn/s/86cf8a398835`

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](pic-fall\1.jpg)

# 信息收集

## 使用nmap扫描端口

扫描`tcp`端口，并保存于`nmap-tcp`

```shell
nmap -sT 192.168.10.10 --min-rate=1000 -p- -oA nmap-tcp
```

![](pic-fall\2.jpg)

扫描常见的20个`udp`端口，不过这里的端口大部分都是不确定的情况

```shell
nmap -sU 192.168.10.10 --top-ports 20 -T4 -oA nmap-udp
```

![](pic-fall\3.jpg)

把前面扫描出的`tcp、udp`端口，进行处理，只取端口号

```shell
grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','
#这里就是包括可能开放的端口都不要，因为是靶机，可能过滤的话，也会无法进一步扫描
ports=22,80,8080,68,69,138,161,631,1434,1900
```

![](pic-fall\4.jpg)

对特定的端口号进行深入探测

```shell
nmap -sV -O -sC -sT 192.168.10.10 -p $ports -oA detail
```

![](pic-fall\5.jpg)

![6](pic-fall\6.jpg)

![7](pic-fall\7.jpg)

使用脚本检测有无漏洞，只有80端口的目录枚举以及443端口的目录枚举有用

```shell
nmap --script=vuln 192.168.10.10 -p $ports -oA vuln
```

![](pic-fall\8.jpg)

![9](pic-fall\9.jpg)

## SMB探测

使用`nmap`脚本进行测试，出现的版本以及分享有用

```shell
nmap --script=smb* 192.168.10.10
```

![](pic-fall\10.jpg)

使用`enum4linux`枚举，分享是与`nmap`枚举出的一样，不过这里枚举出一个用户`qiu`

```shell
enum4linux 192.168.10.10 -a
```

![](pic-fall\11.jpg)

## 网站信息探测

### 80端口网站测试

访问默认的界面，明显的看到网站的`cms`以及一个文章的创建者`qiu`![12](pic-fall\12.jpg)

点击查看一些文章，发现另一个人名`patrick`

![](pic-fall\13.jpg)

继续查看，发现一个`backdoor`的文章，可能存在后门

![](pic-fall\14.jpg)

查看另一个文章，说的是`webroot`可能存在脚本，也就是网站根目录，那么尝试进行扫描

![](pic-fall\15.jpg)

使用`gobuster`工具尝试进行目录爆破

```shell
gobuster dir -u http://192.168.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.bak,.txt,.sh,.html,.cgi -b 403-404
```

![](pic-fall\16.jpg)

访问`admin`发现是一个登录界面

![](pic-fall\17.jpg)

访问`phpinfo.php`，发现并没有解析，查看页面源代码后，可以看到代码

![](pic-fall\18.jpg)

访问`robots.txt`，发现提示有`user-agent`这个很有可能会有不同

![](pic-fall\19.jpg)

访问`test.php`，发现有弹窗，给出的提示是`get`参数问题。但是这个界面与`error.html`相似。不过还是猜测这是有参数的

![](pic-fall\21.jpg)

使用`ffuf`测试参数，假设这里是有路径遍历的，所以测试

```shell
ffuf -u http://192.168.10.10/test.php?FUZZ=../../../../../../etc/passwd -w /usr/share/wordlists/dirb/big.txt -fs 80
```

![](pic-fall\22.jpg)

发现有一个传参`file`，在浏览器访问，发现确实可以，并且能够路径遍历

![](pic-fall\23.jpg)

暂时记住，这里有一个文件包含的接口

访问`missing.html`，发现一个用户名`patrick@goodtech.inc`

![](pic-fall\24.jpg)

目前80端口就发现了一个文件包含，并且不能解析`php`，搜索`CMS`漏洞，但是不知道版本，无法具体使用



443端口的网站与80端口网站是一样的

### 9090端口网站探测

之前`nmap`扫描的9090端口服务是`zeus-admin`，百度搜索发现，这是一个后台管理系统，尝试访问查看

![](pic-fall\25.jpg)

但是这个界面，与网上搜索的`zeus-admin`不一样，对这个进行目录爆破

```shell
dirb https://192.168.10.10:9090
```

![](pic-fall\26.jpg)

发现了`ping`，访问测试后，发现一个`server`字段，为`cockpit`

![](pic-fall\27.jpg)

并且在浏览器的网络功能中，进行分析的时候，也是有多个`cockpit`字段，猜测这是一个服务，直接搜索，发现确实如此，并且界面与当前界面极其相似

![](pic-fall\28.jpg)

不过这里测试了一下，默认的账户密码不能登录，啧，利用之前的文件包含漏洞

# 文件包含漏洞利用

尝试把网站默认配置文件都通过文件包含漏洞去查看，不过并未有很多配置文件可以看到

结合信息，当前有一个用户名`qiu`，是文件包含`/etc/passwd`文件看到的。

22端口到现在没有运用，可能，对，文件包含看能否看到`ssh`私钥文件，也就是`qiu`用户的

```shell
/home/qiu/.ssh/id_rsa
```

这是默认的配置文件路径以及名称，确实有

![](pic-fall\29.jpg)

访问`authorized_keys`和`id_rsa.pub`，也是可以的，说明有公私钥的形式

复制这里的私钥，放在`kali`中的一个文件中即可，这里命名为`per`，然后修改文件权限，再使用`ssh`连接测试

```shell
ssh qiu@192.168.10.10 -i per
```

![](pic-fall\30.jpg)



# 提权

查看当前用户的目录下的`.bash_history`文件，也就是历史命令记录，发现一串字符，并且配合`sudo`的，这可能是密码`remarkablyawesomE`

![](pic-fall\31.jpg)

使用`find`寻找具有SUID权限的文件，如果有`sudo`，搭配这个可能是密码的字符，就可能成功

![](pic-fall\32.jpg)

确实有`sudo`，那么直接测试`sudo -s`，输入密码后，提权至`root`

![](pic-fall\33.jpg)

查看文件

![](pic-fall\34.jpg)

这里把`qiu`密码改了之后，再登录网站`192.168.10.10:9090`，登陆后并未有任何东西，说明这个确实不是攻击点

```shell
[root@FALL log]# passwd qiu
Changing password for user qiu.
New password: 
BAD PASSWORD: The password is shorter than 8 characters
Retype new password: 
passwd: all authentication tokens updated successfully.
```

![](pic-fall\35.jpg)



# 总结

该靶机有以下几点：

1. `smb`枚举出用户`qiu`
2. 访问80端口网站，发现文章编辑者`qiu`，并且通过目录爆破，找到一个后门文件，具有文件包含漏洞
3. 3306端口虽然开放，但是不能直接连接
4. 通过文件包含漏洞，首先测试系统有哪些用户，然后通过访问`linux`中的一些文件，最终确定用户`qiu`下的`ssh`文件，发现私钥
5. 对于提权，这个靶机比之前的都简单，直接查看`history`命令历史记录，即可发现疑似密码的内容