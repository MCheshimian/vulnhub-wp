# 前言

靶机：`hacksudo   192.168.1.45 `

攻击：`kali    192.168.1.16`

都是虚拟机环境，桥接模式

# 主机发现

使用`netdiscover`或者`arp-scan -l`扫描

```shell
netdiscover -r 192.168.1.1/24
```



![](D:\stu\vulnhub\hacksudo靶场\pic-1\1.jpg)

# 信息收集

## 使用nmap扫描

![](D:\stu\vulnhub\hacksudo靶场\pic-1\2.jpg)



因为看到2222是`ssh`服务，所以又扫了全端口，发现还是一样的结果

`tomcat  8080端口`和`apache   80端口` 是`http`服务

`2222  openssh`是`ssh`服务

## 网站收集

### 测试80端口

登录和注册在同一界面

![](D:\stu\vulnhub\hacksudo靶场\pic-1\3.jpg)

#### 查看页面源代码

这里看到有`php`代码泄露，这里是进行开启`session`的，并且`session`中存在`username`，就会定位到`fandom.php`

![](D:\stu\vulnhub\hacksudo靶场\pic-1\4.jpg)

![](D:\stu\vulnhub\hacksudo靶场\pic-1\5.jpg)

继续查看，这里有一个判断，`get`请求中有参数`file`的话，就会包含这个，否则包含`index.php`

![](D:\stu\vulnhub\hacksudo靶场\pic-1\6.jpg)

这里知道是目录型网站，使用`gobuster、ffuf、dirsearch、dirb、dirbuster`扫描

```shell
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://192.168.1.45 -x .txt,.php,.html,.xml,.zip,.tar -d -b 403-404
```

![](D:\stu\vulnhub\hacksudo靶场\pic-1\7.jpg)

可以看到有很多的页面，访问进行测试

访问`add.php`，出现错误，这个地址，啧，可能是内部地址，暴露了

![](D:\stu\vulnhub\hacksudo靶场\pic-1\8.jpg)

访问`config.php`，确认是连接数据库，并且是`mysql`数据库

![](D:\stu\vulnhub\hacksudo靶场\pic-1\10.jpg)

访问`admin.php`，虽然可以操控，并且界面可以导向`got.php、hg.php、hp.php`，但是出错

![](D:\stu\vulnhub\hacksudo靶场\pic-1\9.jpg)

大概都是这样

![](D:\stu\vulnhub\hacksudo靶场\pic-1\11.jpg)

并且在`admin.php`控制着即可`php`文件

`admin.php`--->`fandom.php`---->`got.php、hp.php、hg.php`

`admin.php`--->`inventory.php、add_product.php、remove_product.php`

`admin.php`--->`destory.php`



与上面的`add.php`一样，`delete.php`对应着`remove_product.php`

不过这里是`localhost`

![](D:\stu\vulnhub\hacksudo靶场\pic-1\12.jpg)

再通过点击，收集一些报错信息

![](D:\stu\vulnhub\hacksudo靶场\pic-1\13.jpg)

访问`info.txt`，发现有邮箱和密码

![](D:\stu\vulnhub\hacksudo靶场\pic-1\16.jpg)

访问`scripts`获取三个`js`代码，其中的函数是进行一些验证的

![](D:\stu\vulnhub\hacksudo靶场\pic-1\16-2.jpg)

使用`dirsearch`扫描，获取到一个`users.sql`，下载查看，有信息泄露

![](D:\stu\vulnhub\hacksudo靶场\pic-1\16-1.jpg)

> ###### 流程总结
>
> 登录中含有`username`跳转到`admin.php`下的`fandom.php`界面
>
> `get`中含有`file`时，把其值赋值给变量`$file`，然后`include`包含该变量
>
> 并且通过一些报错信息，找到一些信息
>
> 访问`info.txt`获取邮箱和密码
>
> 下载`users.sql`文件获取信息

### 测试8080端口

访问8080端口，发现是`tomcat`的默认管理界面

![](D:\stu\vulnhub\hacksudo靶场\pic-1\14.jpg)

使用`gobuster、dirsearch、dirb、ffuf`等工具扫描

![](D:\stu\vulnhub\hacksudo靶场\pic-1\15.jpg)



# 漏洞寻找

根据前面的信息收集，可以知道

- 80端口网站，已有用户名密码，可以进行登录测试，并且还可能具有文件包含漏洞等

- 8080端口网站，管理界面可能存在默认登录密码`tomcat`

## 已知信息登录80网站

使用`info.txt`中的邮箱和密码进行登录，提示密码错误，不过这里确定邮箱正确

![](D:\stu\vulnhub\hacksudo靶场\pic-1\17.jpg)

但是经过`users.sql`中的`md5`解密后，密码与`info.txt`中的一致，使用万能密码也无法登录，这里可能进行了密码修改等情况

使用注册，也无法注册，说是`record`错误

测试文件包含，也没有成返回

## 测试8080端口



使用用户名和密码都是`tomcat`登录成功，可以在这里上传一个`war`反弹，来进行反弹`shell`

![](D:\stu\vulnhub\hacksudo靶场\pic-1\18.jpg)

这里选择刚刚生成的`1.war`，然后点击`deploy`即可

![](D:\stu\vulnhub\hacksudo靶场\pic-1\19.jpg)

可以看到这里部署成功

![](D:\stu\vulnhub\hacksudo靶场\pic-1\20.jpg)





在`kali`中开启监听，然后点击部署的`1`即可

![21](D:\stu\vulnhub\hacksudo靶场\pic-1\21.jpg)

# 提权

## 寻找信息

搜索一番，在`/var/www/html`中，找到`flag1.txt`和`level1.sh`

![](D:\stu\vulnhub\hacksudo靶场\pic-1\23.jpg)

然后后面使用`find`搜索具有SUID的文件，发现有`sudo`、`at`等，但是当前不知道`tomcat`的密码，所以这里搜索关键字，看有无信息`pass*、user*、back*`等，发现`www`目录有一个文件，查看

![](D:\stu\vulnhub\hacksudo靶场\pic-1\24.jpg)

只是提示，没有任何泄露

然后在`/var/backups`中，发现一个可读的`hacksudo`文件夹，进入查看，属于`www-data`的

![](D:\stu\vulnhub\hacksudo靶场\pic-1\25.jpg)



## 提权至vishal

把这里的东西全部下载到`kali`中，进行查看。这里原本想用`python`的，不过出了问题，然后`sh`断开了，下面就不用`pyhton`了，直接使用`nc`下载

![](D:\stu\vulnhub\hacksudo靶场\pic-1\22.jpg)

查看内容信息`ilovestegno`

![](D:\stu\vulnhub\hacksudo靶场\pic-1\26.jpg)

使用`steghide`发现图片中无隐藏信息，查看图片，发现有字符`Nikon`出现

![](D:\stu\vulnhub\hacksudo靶场\pic-1\27.jpg)

解压后的压缩包，发现是一个空的

查看靶机上的`/home`目录，发现两个用户，测试上面的信息，能否登录这两个用户的`ssh`，测试还是不行

![](D:\stu\vulnhub\hacksudo靶场\pic-1\28.jpg)

那么可能还是图片，尝试使用`stegcracker`对图片进行密码破解

![](D:\stu\vulnhub\hacksudo靶场\pic-1\29.jpg)

查看破解出的文件，啧，应该是加密了，测试一下

![](D:\stu\vulnhub\hacksudo靶场\pic-1\30.jpg)

放在网站分析什么加密

![](D:\stu\vulnhub\hacksudo靶场\pic-1\31.jpg)



在一个个的测试后发现是`rot-13`加密

![](D:\stu\vulnhub\hacksudo靶场\pic-1\32.jpg)

现在是知道用户`vishal`的密码，可能是`hash`可以本地破解，或者在线网站破解，首先还是使用这个网站分析

![](D:\stu\vulnhub\hacksudo靶场\pic-1\33.jpg)

然后破解成功

![](D:\stu\vulnhub\hacksudo靶场\pic-1\34.jpg)

使用账户`vishal`和密码`hacker`登录成功，并访问到`flag`

![](D:\stu\vulnhub\hacksudo靶场\pic-1\35.jpg)



## 提取至hacksudo

在`hacksudo.c`代码中，发现有提权的，可以利用这个`setuid`，因为这里表示可以通过这个来执行只有`hacksudo`才能执行的文件

![](D:\stu\vulnhub\hacksudo靶场\pic-1\36.jpg)

把`hacksudo.c`下载，然后编译后上传，但是这样不行，因为靶机无环境，或者说环境不一样。

![](D:\stu\vulnhub\hacksudo靶场\pic-1\37.jpg)



查看网络连接等，在查看任务计划发现有定时任务

![](D:\stu\vulnhub\hacksudo靶场\pic-1\38.jpg)

查看该文件，发现是可执行文件，把其下载到`kali`中，测试，发现一个执行

![](D:\stu\vulnhub\hacksudo靶场\pic-1\39.jpg)

也就是有定时任务，然后执行这个`manage.sh`文件，所以只需要编写这个文件即可，前面查看是有写权限的

![](D:\stu\vulnhub\hacksudo靶场\pic-1\40.jpg)

查看目录下文件

![](D:\stu\vulnhub\hacksudo靶场\pic-1\41.jpg)



发现这个加密，尝试解密`bb81133d9e5c204f15a466d357f3b519`，cmd5解出了，但是要钱啊

![](D:\stu\vulnhub\hacksudo靶场\pic-1\42.jpg)



## 提取root

看网上的`wp`，竟然使用`sudo -l`可以不用输入密码了，直接进行

![](D:\stu\vulnhub\hacksudo靶场\pic-1\43.jpg)



发现可以使用`scp`，那么查询`sudo`时的用法，网址`https://gtfobins.github.io/gtfobins/scp/#sudo`

```shell
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
sudo scp -S $TF x y:
```

![](D:\stu\vulnhub\hacksudo靶场\pic-1\44.jpg)

直接复制命令执行即可

![](D:\stu\vulnhub\hacksudo靶场\pic-1\45.jpg)



查看`/root`目录

![](D:\stu\vulnhub\hacksudo靶场\pic-1\46.jpg)





# 清除痕迹



## 清除日志

![](D:\stu\vulnhub\hacksudo靶场\pic-1\47.jpg)

以`vishal`登录，把之前修改的内容去掉

![](D:\stu\vulnhub\hacksudo靶场\pic-1\48.jpg)



# 总结

1. 信息收集一定要别急，越多的信息，表示越多的可能
2. `tomcat`的默认登录密码
3. 反弹`shell`的使用
4. 搜索关键字的一些文件，可能会有信息
5. 多查看网络、进程、定时任务等
6. 一些常见的`sudo`提取



这里不知道80端口什么原因，我想着应该有可利用点的





















