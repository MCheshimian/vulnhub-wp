# 前言

靶机：`hacksudo-2`

攻击：`kali`

都是采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或者`netdiscover -r 192.168.1.1/24`或者`nmap`和`masscan`等可以扫描网段的扫描工具，不过建议使用前两个即可，因为靶机与攻击机都是在局域网内的

![](D:\stu\vulnhub\hacksudo靶场\pic-2\1.jpg)



# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\hacksudo靶场\pic-2\2.jpg)

对全端口再进行扫描一下

![](D:\stu\vulnhub\hacksudo靶场\pic-2\2-1.jpg)

## rpc、nfs收集

发现有`rpc`，使用`nmap`脚本进一步收集

```shell
nmap --script=rpcinfo 192.168.1.51
```

![](D:\stu\vulnhub\hacksudo靶场\pic-2\3.jpg)

再次对`nfs`进行收集

```shell
nmap --script=nfs-* 192.168.1.51
```

![](D:\stu\vulnhub\hacksudo靶场\pic-2\4.jpg)

甚至从这里已经看到`flag1.txt`了，不过这里只做信息收集

## 网站收集

对80端口网站进行收集，访问默认界面，看到一个用户名`vishal`

![](D:\stu\vulnhub\hacksudo靶场\pic-2\5.jpg)

查看页面源代码，发现一段话，下面翻译，然后可以发现是目录型网站

![](D:\stu\vulnhub\hacksudo靶场\pic-2\6.jpg)

翻译上面的话

![](D:\stu\vulnhub\hacksudo靶场\pic-2\7.jpg)

对网站进行目录扫描

使用`gobuster、dirsearch、dirb、dirbuster、ffuf`等工具进行扫描

![](D:\stu\vulnhub\hacksudo靶场\pic-2\8.jpg)



访问`README.md`查看

![](D:\stu\vulnhub\hacksudo靶场\pic-2\9.jpg)

访问`readme.md`查看

![](D:\stu\vulnhub\hacksudo靶场\pic-2\10.jpg)

访问`audio`目录，一堆可能音频文件，可能存在音频隐写

![](D:\stu\vulnhub\hacksudo靶场\pic-2\11.jpg)

访问呢`file.php`并查看页面源代码，这个只是有一个超链接

![](D:\stu\vulnhub\hacksudo靶场\pic-2\12.jpg)

访问`game.html`，查看页面源代码，发现是从`google`请求

![](D:\stu\vulnhub\hacksudo靶场\pic-2\13.jpg)

访问`info.php`，发现是`phpinfo`

![](D:\stu\vulnhub\hacksudo靶场\pic-2\14.jpg)

访问`test.html`，发现大部分代码由`js`组成，不过收集到一些字符信息

![](D:\stu\vulnhub\hacksudo靶场\pic-2\15.jpg)

访问`test123.html`，发现内容，查看源代码详细查看

![](D:\stu\vulnhub\hacksudo靶场\pic-2\16.jpg)

访问`tiles`，发现图片

![](D:\stu\vulnhub\hacksudo靶场\pic-2\17.jpg)

访问`web`目录，看到信息

![](D:\stu\vulnhub\hacksudo靶场\pic-2\18.jpg)



# 漏洞寻找

## 反弹shell

根据之前的`nfs`寻找，尝试进行挂载

```shell
mkdir /tmp/nf
mount -t nfs 192.168.1.51:/mnt/nfs/ /tmp/nf	//挂载目标共享目录到kali本地
```

但是查看后，提示说当前系统是`root`

![](D:\stu\vulnhub\hacksudo靶场\pic-2\19.jpg)

测试之前的几个`php`文件，测试有无参数接收，然后可以导致路径遍历的，这里先测试`file.php`

```
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://192.168.1.51/file.php?FUZZ=../../../../../../etc/passwd -fs 238
//这里的-fs 238 是对返回数据大小进行过滤，238是指原界面的大小
```

![](D:\stu\vulnhub\hacksudo靶场\pic-2\20.jpg)

在浏览器测试

![](D:\stu\vulnhub\hacksudo靶场\pic-2\21.jpg)

但是经过测试，这里只能文件包含，且是本地文件包含，限制太多，很多东西看不了，或者使用一个好的字典去遍历，不过这里确定一个用户的存在`hacksudo`

不过突然想到，可以挂载的话，在其中上传一个`php`脚本，然后再通过这个文件包含，能否进行反弹呢

编辑`/usr/share/webshells/php/php-reverse-shell.php`脚本，修改地址为`kali`的地址

![](D:\stu\vulnhub\hacksudo靶场\pic-2\22.jpg)

把该文件复制到之前挂载的地址`/tmp/nf`中，因为具有同步性，所有靶机上也会有这个脚本。

使用`kali`开启监听，然后浏览器访问，确实可以

![](D:\stu\vulnhub\hacksudo靶场\pic-2\23.jpg)

然后使用`python`获得一个交互式界面

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

# 提权

因为开启`nfs`服务，所有查看其主要的文件，查看

![](D:\stu\vulnhub\hacksudo靶场\pic-2\24.jpg)

这里这个目录是有读写权限

`no_root_squash`: 客户端以 root 用户访问时，不映射为匿名用户。

也就是说，因为这里是挂载的，然后当在`kali`中对挂载的目录进行操作时，是可以进行一系列操作的。

避免两个机器的冲突，把`kali`中的`bash`脚本复制到挂载点，并改名称，然后在靶机上运行这个脚本

![](D:\stu\vulnhub\hacksudo靶场\pic-2\25.jpg)

不过版本问题，无法运行，查看版本

![](D:\stu\vulnhub\hacksudo靶场\pic-2\26.jpg)

这里需要安装对应版本的`bash`才行，但是这里`kali`中安装了高版本的`bash`，在进行编译安装时，总是不成功，可能需要一个新的虚拟机，我这里就不做演示了



或者编写`c`文件进行提取，不过也需要对应的库等，应为新的`gcc`编译与旧版本可能不兼容

```c
#include<stdlib.h>
#include<unistd.h>

int main()
{
setuid(0);
system("id");
system("/bin/bash");
}
```

说白了，这里的几个方法，都需要历史版本。。。。。



不过使用`find`寻找时，找到一个具有SUID权限的文件，可能存在漏洞

![](D:\stu\vulnhub\hacksudo靶场\pic-2\27.jpg)



百度搜索，发现`cve-2021-4034`存在，并且系统对应的版本在影响范围

从项目地址下载`poc`，地址`https://github.com/arthepsy/CVE-2021-4034`

![](D:\stu\vulnhub\hacksudo靶场\pic-2\28.jpg)

把编译好的`exp`复制到之前的挂载目录

执行后还是哈哈哈哈哈。不行，因为编译环境的问题

![](D:\stu\vulnhub\hacksudo靶场\pic-2\29.jpg)



所以这里不再继续，太麻烦了，知道方法即可

# 总结

1. 对于网站的`php`文件，可能会有参数接收的，所以要进行`fuzz`测试
2. 对于`rpcbind`和`nfs`一般都是一起出现，可以使用`rpcinfo`以及一些命令来检测是否开启共享，`showmount`
3. 对于`nfs`是配置文件`/etc/exports`中的配置简单了解，这里就是利用可写以及`root`执行
4. 提权时候文件的版本问题



















