# 前言

靶机：`whowantstobeking-1`，ip地址`192.168.1.67`

攻击：`kali` ，ip地址`192.168.1.16`

# 主机发现

使用`arp-sacn -l`或者`netdiscover -r 192.168.1.1/24`扫描

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\2.jpg)

## 网站信息探测

访问80端口默认界面，发现一个文件

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\3.jpg)

把该文件下载到`kali`中，发现该文件是一个可执行文件

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\4.jpg)

暂时放置，使用工具进行目录爆破

使用`gobuster、dirsearch、dirb、dirbuster、ffuf`等

但是这里目录爆破并没有任何内容出现

# 使用strings

再回到这里的文件，使用`strings`查看这个可执行文件中的一些内容

```shell
strings skeylogger
```

查看一会，发现都是正常的字符串，不过发现一个可能是编码的字符`ZHJhY2FyeXMK`

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\5.jpg)

以及发现一个目录，可能靶机内存在该用户`sunita`

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\6.jpg)

解码`ZHJhY2FyeXMK`，这里可以自己识别什么编码或者使用工具把编码类型都走一遍

这里是`base64`编码，解码发现一串字符`dracarys`

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\7.jpg)

# 登录daenerys用户

猜测可能是网站目录，但是访问后并不行，使用上面获取的用户尝试进行`ssh`登录，发现也不行，那么继续收集信息

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\8.jpg)

尝试进行用户名字典爆破，啧，我的字典跑了一下，没有出结果，也没有其他信息可用

看了一下网上的WP，啧，怎么说呢，就是都是根据靶机开机后的一个用户名进行登录的

这真就是告诉你是靶机了，这让人感觉过程都错了

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\9.jpg)

以其身份进行远程`ssh`登录（搞的我都想直接在靶机登录了）

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\10.jpg)

# 靶机内信息收集

查看家目录下的`secret`文件，以及使用`find`寻找具有SUID权限文件，发现`sudo`

通过网站`gtfobins.github.io`可以查询是否有可用的SUID文件，发现没有

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\11.jpg)

再使用`find`寻找`capabilites`文件，并无可用

```shell
find / -type f -executable 2>/dev/null | xargs getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\12.jpg)

查看网络状态，系统内核，以及定时任务，并未发现可疑点

```shell
ip addr
ss -antlp
cat /etc/crontab
uname -a 
```

使用具有SUID权限文件`sudo`进一步收集，发现三个文件

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\13.jpg)

查看用户家目录下的隐藏文件`.bash_history`，发现一些操作，那么跟着其操作去看一看

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\14.jpg)

跟着步骤，发现确实已被删除，但是发现一个压缩文件，解压后就是删除的文件，但是其内容执行一个文件的位置，访问后，只有一段话

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\15.jpg)

查看`sudo -l`的三个文件，发现其目录下，都是没有写权限的，即使没有这个文件，但是也无法尝试写一个文件进行操作

开始思考给出的这段话，应该是有什么用处的`I'm khal .....`似乎是没有完整的话

查看靶机作者的提示，`google`是好帮手

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\16.jpg)

# 提取

尝试在`google`搜索这段话，发现大部分都指向一个人名

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\17.jpg)

那么在靶机内没有查到该用户`cat /etc/passwd`

猜测可能是密码，并且在`home`目录下只有当前用户，那么就假设是`root`的密码，尝试进行登录`khaldrogo`

提取成功，并且还给出了一个编码后的数据，解码后发现是链接，广告，这广告！！！

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\18.jpg)

访问链接，发现是一段BGM，当然这里面有没有进行隐写，就不深入了

![](D:\stu\vulnhub\whowantstobeking靶场\pic-1\19.jpg)



# 痕迹清除

这里其实痕迹很少了，把解压后的文件删除，以及身份认证产生的日志文件清理就已经差不多了

```shell
rm -rf /home/daenerys/.local/share/djkdsnkjdsn
sed -i "/192.168.1.16/d" /var/log/auth.log
echo > /var/log/faillog
echo > /var/log/lastlog
echo > /var/log/btmp
echo > /var/log/wtmp

history -r
history -c
```



# 总结

该靶机主要是专项训练吧，靶机空间占比很大，但是就考察一点，`strigs`的使用，只有使用了，就可以看到可执行文件中的一个编码处理的字符，然后进行操作。

这里的用户名都是靶机启动后，在虚拟机看到的，对于信息收集，没有什么考察之处

对于提取，这里更是提示用户多用`google`搜索信息，意图可能是想让别人能够进行`google`暗黑搜索吧

















