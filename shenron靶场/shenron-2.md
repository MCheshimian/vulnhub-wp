# 前言

靶机：`shenron-2`

攻击：`kali`

都采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`

![](D:\stu\vulnhub\shenron靶场\pic-2\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\shenron靶场\pic-2\2.jpg)

## 网站探测

访问80端口

![](D:\stu\vulnhub\shenron靶场\pic-2\3.jpg)

访问8080端口，可能是`wordpress`模板

![](D:\stu\vulnhub\shenron靶场\pic-2\4.jpg)

使用`whatweb`进行指纹识别

![](D:\stu\vulnhub\shenron靶场\pic-2\5.jpg)

使用`gobuster、dirsearch、ffuf、dirb、dirbuster`等工具进行目录扫描

扫描80端口

```shell
gobuster dir -u http://192.168.1.56 -w /usr/share/wordlists/dirb/big.txt -x php,zip,md,txt,html,jpg -b 404
```

![](D:\stu\vulnhub\shenron靶场\pic-2\6.jpg)

访问`README.txt`，可能是作者名称等，收集起来

![](D:\stu\vulnhub\shenron靶场\pic-2\7.jpg)

扫描8080端口

```shell
gobuster dir -u http://192.168.1.56:8080 -w /usr/share/wordlists/dirb/big.txt -x php,zip,md,txt,html,jpg -b 404
```

![](D:\stu\vulnhub\shenron靶场\pic-2\9.jpg)



因为确认8080端口的是`wordpress`，所以采用专门的扫描工具进行测试

![](D:\stu\vulnhub\shenron靶场\pic-2\8.jpg)

![](D:\stu\vulnhub\shenron靶场\pic-2\10.jpg)

# 漏洞寻找

发现`admin`用户，尝试枚举密码

```shell
wpscan --url http://192.168.1.56:8080 -e u -P /usr/share/wordlists/fasttrack.txt 
```

![](D:\stu\vulnhub\shenron靶场\pic-2\11.jpg)

访问8080端口，点击登录，发现出现问题，域名解析问题

![](D:\stu\vulnhub\shenron靶场\pic-2\12.jpg)

修改`/etc/hosts`解析文件

![](D:\stu\vulnhub\shenron靶场\pic-2\13.jpg)

这时候再访问8080端口网站，发现显示正常了

![](D:\stu\vulnhub\shenron靶场\pic-2\14.jpg)

以`admin`和密码`admin`登录，寻找一圈发现插件中并无可用，使用`wp-scan`再次扫描，这次加上一些参数，并使用`wp-scan`官方的`api`，如果有漏洞，会列出

```shell
wpscan --url http://192.168.1.56:8080 -e ap --detection-mode aggressive --plugins-detection aggressive --api-token 【api】
```

检测出一堆，但是也只是可能有漏洞，这里经过对比后，发现有一个可以

![](D:\stu\vulnhub\shenron靶场\pic-2\15.jpg)

# 漏洞利用

查看用法

![](D:\stu\vulnhub\shenron靶场\pic-2\16.jpg)

构造链接进行测试

```shell
http://shenron:8080/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

发现两个用户`jenny`和`shenron`

![](D:\stu\vulnhub\shenron靶场\pic-2\17.jpg)

但是这里也只能进行文件包含，还是绝对路径

知道用户名，只能尝试弱密码爆破，因为实在无可用漏洞

![](D:\stu\vulnhub\shenron靶场\pic-2\18.jpg)

# 提权

## 提权至shenron

尝试进行ssh连接，可以，使用`find`寻找具有SUID权限的文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\shenron靶场\pic-2\19.jpg)

发现`sudo`，但是不允许当前用户使用，不过之前未见有过`execute`，下载 到本地查看一下

```shell
scp jenny@192.168.1.56:/usr/bin/Execute ./
```

![](D:\stu\vulnhub\shenron靶场\pic-2\20.jpg)

使用`strings`等工具进行查看

![](D:\stu\vulnhub\shenron靶场\pic-2\21.jpg)

发现执行该文件时，会把`bash`复制到`/nmt`目录下，并且给予777权限，更改用户为`shenron`，也给予SUID权限。

代表执行`Execute`后，在`/mnt`目录下有一个SUID权限的用户为`shenron`的bash

![](D:\stu\vulnhub\shenron靶场\pic-2\22.jpg)

使用`find`寻找关键字`pass`

```shell
find / -name "*pass*" 2>/dev/null
```

![](D:\stu\vulnhub\shenron靶场\pic-2\23.jpg)

查看这个文件，为什么这里不使用`sudo -l`，因为，这里的主用户还是`jenny`，所以不被允许

![](D:\stu\vulnhub\shenron靶场\pic-2\24.jpg)

这里我是猜测，毕竟很像`base`类型的编码，也可以使用网站识别`www.dcode.fr`

![](D:\stu\vulnhub\shenron靶场\pic-2\25.jpg)

## 提权至root

这一串，结合文件名，可能就是`shenron`的密码`ShEnRoNShEnRoNShEnRoNShEnRoNShEnRoN@ShEnRoN#ShEnRoNPaSsWoRd`

尝试登录，发现可以

![](D:\stu\vulnhub\shenron靶场\pic-2\26.jpg)

查看`bash`的所有者，发现是`root`，所以可以直接`sudo bash`

![](D:\stu\vulnhub\shenron靶场\pic-2\27.jpg)





# 清除痕迹

清理日志及历史记录等

可以使用

```shell
sed -i "/192.168.1.16/d" auth.log
```

为省事，后面都是直接置空

![](D:\stu\vulnhub\shenron靶场\pic-2\28.jpg)



# 总结

1. `wordpress`网站模板的漏洞使用，这里借助工具`wpscan`，不过需要`api-token`
2. 根据收集的信息进行弱密码爆破
3. 对于具有SUID权限的文件，最好是都看一下，尤其是可能没见到过的
4. 使用关键字搜索，如`pass、zip、bak`等















