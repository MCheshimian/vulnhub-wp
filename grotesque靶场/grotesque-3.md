# 前言

靶机：`grotesque-3    192.168.1.44`

攻击 ：`kali   192.168.1.16`

都是虚拟机环境，桥接模式

# 主机发现

使用`arp-scan -l`或者`netdiscover -r 192.168.1.1/24`搜索

![](D:\stu\vulnhub\grotesque靶场\pic-3\1.jpg)



# 信息收集

## 使用nmap扫描

防止有遗漏，再扫描全端口

![](D:\stu\vulnhub\grotesque靶场\pic-3\2.jpg)



## 网站信息收集

访问80界面，有个超链接，查看页面源代码

![](D:\stu\vulnhub\grotesque靶场\pic-3\3.jpg)

是定位的另一个图片

![](D:\stu\vulnhub\grotesque靶场\pic-3\4.jpg)



访问后，是这样的一张图片

![](D:\stu\vulnhub\grotesque靶场\pic-3\5.jpg)



先下载，然后使用目录扫描工具，测试看网站目录，直接扫描并无内容

现在大多数的网站目录其实都经过编码，有的是`base64`编码，有的是`md5`加密，反转就是让目录不是那么容易被扫描

寻找一番，这里可能是提示，`md5`加密

![](D:\stu\vulnhub\grotesque靶场\pic-3\6.jpg)

假设网站目录都`md5`加密，那么就需要把目录字典，进行`md5`加密

```shell
for i in $(cat /usr/share/wordlists/dirb/big.txt);do echo $i | md5sum >>dirmd5.txt
```

不过试了两个字典后，还是没有，开始怀疑判断错误，看网上的wp，确实如此，还是字典问题。啧

这里需要注意，看了一下生成的字典，会在每一行加入`  -`，两个空格，所以先把这个替换掉

```shell
awk '{sub(/  -$/,"");print}' dirmd5.txt >1.txt &&mv 1.txt dirmd5.txt 
```



![](D:\stu\vulnhub\grotesque靶场\pic-3\7.jpg)



# 漏洞寻找

找到`f66b22bf020334b04c7d0d3eb5010391.php`，浏览器访问并无返回，这里只能猜测了，一般都是有参数进行接收的，如果设置的话，前面知道一个图片的路径，测试能否通过这样查看

```shell
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://192.168.1.44/f66b22bf020334b04c7d0d3eb5010391.php?FUZZ=atlasg.jpg -c -fs 0
```



过滤掉返回没有字节的，剩下的可能就是参数

![](D:\stu\vulnhub\grotesque靶场\pic-3\8.jpg)

说明文件包含是有的，那么测试路径遍历是否可行

![](D:\stu\vulnhub\grotesque靶场\pic-3\9.jpg)



可以，再测试是否可获得`/etc/shadow`，显示空白，还是没有权限

尝试获取其中一个用户的`ssh`私钥和公钥，发现不行，可能没权限或没文件

```http
http://192.168.1.44/f66b22bf020334b04c7d0d3eb5010391.php?purpose=file:///etc/passwd
```

如果`file://`不能使用，当然这里还可以使用`base64`编码取出

```http
http://192.168.1.44/f66b22bf020334b04c7d0d3eb5010391.php?purpose=php://filter/read=convert.base64-encode/resource=/etc/passwd
```

当然这种是以`base64`编码的形式，所以要再解码

# 密码爆破

现在获取的信息有限，好像到这里没有什么可以利用了，这个估计可能都是`md5`，所以可以尝试进行密码爆破，就使用这个生成的`md5`字典

```
hydra -l freddie -P dirmd5.txt -vV -f ssh://192.168.1.44
```

![](D:\stu\vulnhub\grotesque靶场\pic-3\10.jpg)

爆破成功，用户`freddie`，密码`61a4e3e60c063d1e472dd780f64e6cad`

# 使用ssh登录

![](D:\stu\vulnhub\grotesque靶场\pic-3\11.jpg)

去`.ssh`看下，发现确实是没有权限读取

![](D:\stu\vulnhub\grotesque靶场\pic-3\12.jpg)

# 提权

尝试使用`find`寻找具有SUID的文件，没有可直接利用的

![](D:\stu\vulnhub\grotesque靶场\pic-3\13.jpg)



使用`find`尝试寻找关键字`user、pass、back`等，无任何特殊文件

日志文件也无权访问。查看网络配置及连接

只有一个网络地址，没有容器

![](D:\stu\vulnhub\grotesque靶场\pic-3\14.jpg)



发现两个本地开放的端口

![](D:\stu\vulnhub\grotesque靶场\pic-3\15.jpg)

## smb利用

这两个端口`445`和`139`大致都是共享服务`SMB`

既然在本地有，那么测试本地是否可连接，可连接，并且有一个明显的共享`grotesque`



```shell
smbclient -L //地址
```

这里因为不知道密码，所以是直接回车的，没想到不需要密码

![](D:\stu\vulnhub\grotesque靶场\pic-3\16.jpg)

连接指定的共享进行查看

![](D:\stu\vulnhub\grotesque靶场\pic-3\17.jpg)



## 监控pspy

发现里面没有东西，啧，继续信息收集吧，尝试查看`/etc/crontab`，没发现什么，使用`top`等命令也没有，尝试下载一个`pspy64`来进行更详细的监控

项目地址：`https://github.com/DominicBreuker/pspy`

然后传输到靶机上，这里是采用`scp`，上传是文件在地址前，下载是地址在文件前

![](D:\stu\vulnhub\grotesque靶场\pic-3\18.jpg)

在靶机上运行该文件，首先使用`chmod`加执行权限，然后直接运行即可进行监听

![](D:\stu\vulnhub\grotesque靶场\pic-3\19.jpg)

发现有使用`sh`执行`smbshare`中的所有文件，进一步观察，发现一分钟执行一次

![](D:\stu\vulnhub\grotesque靶场\pic-3\19-1.jpg)

查看这个目录，大概率就是SMB的共享路径

![](D:\stu\vulnhub\grotesque靶场\pic-3\20.jpg)

搞一个反弹`shell`，写入文档，然后上传进文件夹中，直接在这个文件夹中编辑没有权限

![](D:\stu\vulnhub\grotesque靶场\pic-3\21.jpg)





# 清除痕迹

![](D:\stu\vulnhub\grotesque靶场\pic-3\22.jpg)

![](D:\stu\vulnhub\grotesque靶场\pic-3\23.jpg)

![24](D:\stu\vulnhub\grotesque靶场\pic-3\24.jpg)

![25](D:\stu\vulnhub\grotesque靶场\pic-3\25.jpg)



# 总结

1. 网站信息提供的`md5`加密，这个贯穿到`ssh`爆破
2. 对于`awk、sed、gobuster、ffuf`越熟练越好
3. 对于`smb`服务的一些了解，以及一些命令
4. 对于`pspy64`在不需要`root`也能监控很多的情况有一点了解
5. 反弹`shell`为什么能够提权到`root`，要搞清楚

























