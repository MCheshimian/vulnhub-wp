# 前言

靶机：`hacksudo-ProximaCentauri`

攻击：`kali`

都采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或者`netdiscover -r 192.168.1.1/24`

![](./pic-PC/1.jpg)

# 信息收集

## 使用nmap扫描端口

![](./pic-PC/2.jpg)

## 网站探测

访问网站，点击测试，发现几个值得关注点，其一是一个`get`参数为`file`，在后面进行测试时，有检测路径遍历，所以无用处

![](./pic-PC/3.jpg)

其次底部两个链接，查看页面源代码

![](./pic-PC/4.jpg)

脚本语言`php`，目录型网站，并是一个登录界面，然后就是给出CMS

进行目录扫描

使用`gobuster、ffuf、dirsearch、dirb、dirbuster`等工具

```shell
gobuster dir -u http://192.168.1.53 -w /usr/share/wordlists/dirb/big.txt -x php,bak,txt,js,html,md -b 403-404
```

![](./pic-PC/5.jpg)

![](./pic-PC/6.jpg)

使用`whatweb`测试网站指纹

![](./pic-PC/7.jpg)

访问一圈目录，有用的只有两个，登录界面，以及`planet`和`planet.html`两个

# 漏洞寻找

不知道是做什么的，记录一下

![](./pic-PC/8.jpg)

访问`planet/travel`

![](./pic-PC/9.jpg)

查看页面源代码

![](./pic-PC/10.jpg)

翻译这段话，毕竟注释的，可能是提示

![](./pic-PC/11.jpg)

访问链接，并无直接信息，在加上搜索RA和DEC

![](./pic-PC/12.jpg)

结合翻译来说，RA表示打开，DEC表示关闭，那么在扫描的时候，22端口显示过滤，这里因为多个数值，可能需要敲门测试。

![](./pic-PC/13.jpg)

但是到这里也没有啥，只是开启ssh服务，使用`searchsploit`寻找有无`pluck`版本的漏洞

![](./pic-PC/14.jpg)

虽然是上传和代码执行，但是需要登录后，之前访问`login.php`时，并无密码测试，并且直接使用万能密码等也无法成功。

# 漏洞利用

## 字典爆破

到这里真没思路了，网上查看wp，发现使用`ssh`尝试登录后，会有一个链接，该链接是字典，啧啧啧。

![](./pic-PC/15.jpg)

不过这里访问链接，已经不存在了，可能时间长了，不过发现了其他的字典，也有可能位置移动，所以这里使用这个`dict`字典

![](./pic-PC/16.jpg)

使用`burp`抓取登录时的数据包，然后使用这个字典进行爆破测试，筛选后发现一个可以

![](./pic-PC/17.jpg)

使用密码登录成功

![](./pic-PC/18.jpg)

发现有上传功能，尝试上传测试，发现可以上传，但是进行了一个后缀名的追加

![](./pic-PC/19.jpg)

## 反弹shell

之前的漏洞搜索时，有可用漏洞，那么就直接使用

```shell
python3 49909.py 【IP地址】 【端口】 【密码】 【CMS路径】
```

![](./pic-PC/20.jpg)

访问上传的文件

![](./pic-PC/21.jpg)

尝试进行反弹shell

![](./pic-PC/22.jpg)

使用`find`寻找具有SUID权限的文件，并未发现可用

![](./pic-PC/23.jpg)

# 靶机内信息收集

寻找备份，发现在`/var/backups`目录下有`mysql.bak`可查看

用户名`alfauser`，密码`passw0rd`，数据库`proximacentauri`

![](./pic-PC/24.jpg)

查看网络连接状态

![](./pic-PC/25.jpg)

数据库可能开启，使用上面获取的进行测试，连接之前对终端再加一层`shell`，以防数据库不显示数据

查看当前用户是否可用`python`

![](./pic-PC/26.jpg)

使用`python`获取`shell`

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

![](./pic-PC/27.jpg)

再次获取一个用户名和密码

![](./pic-PC/28.jpg)

查看当前系统的几个用户

![](./pic-PC/29.jpg)

# 提权

## 提权至alfauser

测试使用获取的用户名密码进行ssh登录，用户名`proxima`，密码`alfacentauri123`

![](./pic-PC/30.jpg)

查看当前目录，再获取一个flag

![](./pic-PC/31.jpg)

查看当前目录下的所有文件，发现`bash_history`有记录，查看

![](./pic-PC/33.jpg)

跟着这个记录查看，说是`bash`过老，给出路径让更新

![](./pic-PC/34.jpg)

## 提权至root

使用`find`再寻找一些信息，发现`capacilities`

```shell
find / -type f -executable 2>/dev/null | xargs getcap -r 2>/dev/null
```

![](./pic-PC/35.jpg)

查看网站后获取用法

![](./pic-PC/36.jpg)

```shell
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

使用命令，提权成功

![](./pic-PC/37.jpg)



# 清除痕迹

使用`sed`可以筛选自己的IP进行删除日志，这里仅使用一次，为了省事，后面直接置为空

```shell
sed -i "/192.168.1.16/d" auth.log
```

![](./pic-PC/38.jpg)

# 总结

1. 这里有提示，还是可以，不然的话，对于信息可以进行`knock`是真的想不到
2. 在`ssh`登录时，给出一个字典，这我也没想到，只能说脑洞大
3. 对于`cms pluck`的漏洞有印象，版本不同，漏洞不同
4. 进入靶机后，要一步步去收集，这里就是发现无可用SUID权限后，寻找备份文件，然后一步步收集，网络信息等。
5. 提权方式挺多，都去试试，比如`suid`，`capabilities`，等

