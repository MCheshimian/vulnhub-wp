# 前言

靶机：`shenron-1`

攻击：`kali`

都采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`扫描

![](D:\stu\vulnhub\shenron靶场\pic-1\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\shenron靶场\pic-1\2.jpg)

## 网站信息探测

查看页面，发现是`apache2`的默认界面，查看页面源代码，可能是目录型网站

![](D:\stu\vulnhub\shenron靶场\pic-1\3.jpg)

使用`gobuster、dirsearch、ffuf、dirb、dirbuster`等工具就进行目录扫描

```shell
gobuster dir -u http://192.168.1.55 -w /usr/share/wordlists/dirb/big.txt -x php,zip,md,txt,html,jpg -b 404
```

![](D:\stu\vulnhub\shenron靶场\pic-1\4.jpg)

发现目录`joomla`，可能是`cms`，访问`joomla`目录，发现确实如此

![](D:\stu\vulnhub\shenron靶场\pic-1\5.jpg)

可以使用针对`joomla`的扫描工具`joomscan`

```shell
joomscan -u http://192.168.1.55/joomla
```

发现版本以及管理员登录界面

![](D:\stu\vulnhub\shenron靶场\pic-1\6.jpg)

访问`test`目录，发现一个`password`，访问后，提示这里有信息，查看页面源代码，发现一个用户名密码

![](D:\stu\vulnhub\shenron靶场\pic-1\7.jpg)

# 漏洞寻找

用户名`admin`，密码`3iqtzi4RhkWANcu@$pa$$`

尝试使用这个身份登录`joomla/administrator`的管理员界面，发现确实可以

![](D:\stu\vulnhub\shenron靶场\pic-1\8.jpg)

可以通过这个页面，收集靶机中的信息，发现`php`等信息

![](D:\stu\vulnhub\shenron靶场\pic-1\9.jpg)

![10](D:\stu\vulnhub\shenron靶场\pic-1\10.jpg)

# 漏洞利用

测试功能点，在扩展中，有主题模块，可以写入修改文件，那么就写一个`php`的反弹`shell`，可以把`kali`中的`/usr/share/webshells/php/php-reverse-shell.php`中的内容粘贴

![](D:\stu\vulnhub\shenron靶场\pic-1\11.jpg)

![](D:\stu\vulnhub\shenron靶场\pic-1\12.jpg)

然后在`kali`中开启监听，再使用浏览器访问，默认的`beez3`模板的地址是`joomla/templates/bezz3`，其后跟上脚本`shell.php`即可

![](D:\stu\vulnhub\shenron靶场\pic-1\13.jpg)

使用`dpkg -l | grep python`查看有无安装`python`，使用`python`获取交互式界面

![](D:\stu\vulnhub\shenron靶场\pic-1\14.jpg)

# 靶机内信息收集

使用`find`寻找具有SUID权限的文件，发现`sudo`，测试，发现还是需要密码的

![](D:\stu\vulnhub\shenron靶场\pic-1\15.jpg)

使用`find`寻找`capabilities`，暂无可用

![](D:\stu\vulnhub\shenron靶场\pic-1\16.jpg)

查看内核版本及网络状态

![](D:\stu\vulnhub\shenron靶场\pic-1\17.jpg)

查看`joomla`模板中的配置文件`configuration.php`，发现连接数据库的用户名`jenny`和密码`Mypa$$wordi$notharD@123`

![](D:\stu\vulnhub\shenron靶场\pic-1\18.jpg)

查看家目录的用户，发现两个用户，`jenny`和`shenron`

![](D:\stu\vulnhub\shenron靶场\pic-1\19.jpg)

# 提权

## 提权至jenny

使用获取的密码测试，是否一码多用，发现可以

![](D:\stu\vulnhub\shenron靶场\pic-1\20.jpg)

之前使用`find`寻找过具有SUID权限文件，发现`sudo`，这里有密码，直接测试，发现有`shenron`用户的一个文件

![](D:\stu\vulnhub\shenron靶场\pic-1\21.jpg)

直接复制`/home`目录下的`shenron`文件到这里，测试发现不行

![](D:\stu\vulnhub\shenron靶场\pic-1\22.jpg)

## 提权至shenron

那就反过来，生成一个公私钥，然后复制到`shenron`的目录下，为什么呢，因为这里先使用`ssh`登录测试，发现这里直接使用证书认证，说明存在`.ssh`文件，可能就是在`shenron`目录下

![](D:\stu\vulnhub\shenron靶场\pic-1\23.jpg)

首先使用`ssh-keygen -t rsa`生成公私钥

![](D:\stu\vulnhub\shenron靶场\pic-1\24.jpg)

然后在`kali`开启简易的`http`服务，这里是测试过靶机可以通过命令下载文件的，尽量在`/tmp`目录下进行操作

```shell
sudo -u shenron /usr/bin/cp id_rsa.pub /home/shenron/.ssh/authorized_keys
```

![](D:\stu\vulnhub\shenron靶场\pic-1\25.jpg)

在`kali`中指定私钥文件进行连接

![](D:\stu\vulnhub\shenron靶场\pic-1\26.jpg)

## 提权至root

使用`find`再寻找关键字`pass*`等

![](D:\stu\vulnhub\shenron靶场\pic-1\27.jpg)

查看后发现密码为`YoUkNowMyPaSsWoRdIsToStRoNgDeAr`，测试`sudo -l`，发现`apt`命令

![](D:\stu\vulnhub\shenron靶场\pic-1\28.jpg)

使用命令提权，这里可以查看网站`gtfobins.github.io`

![](D:\stu\vulnhub\shenron靶场\pic-1\29.jpg)

使用命令，提权成功

![](D:\stu\vulnhub\shenron靶场\pic-1\30.jpg)



# 清理痕迹

各种日志的清除

![](D:\stu\vulnhub\shenron靶场\pic-1\31.jpg)

删除之前的公钥，以及历史记录

![](D:\stu\vulnhub\shenron靶场\pic-1\32.jpg)

这里还有个网站中的反弹`shell`文件要删除，这里就不附图片了

# 总结

1. 主要考察CMS`joomla`的渗透方法，最常见的就是模板的注入
2. 考察`ssh`公私钥连接的过程，以及相关文件
3. 考察对于`joomla`的一个配置文件`configuration.php`
4. 考察在靶机内的信息收集，可能有存储密码













