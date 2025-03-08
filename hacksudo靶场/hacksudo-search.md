# 前言

靶机：`hacksudo-search`

攻击：`kali`

都采用虚拟化，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或者`netdiscover -r 192.168.1.1/24`

![](D:\stu\vulnhub\hacksudo靶场\pic-search\1.jpg)



# 信息收集

## 使用nmap进行扫描

![](D:\stu\vulnhub\hacksudo靶场\pic-search\2.jpg)

## 网站探测

访问网站后发现，有一个搜索界面

![](D:\stu\vulnhub\hacksudo靶场\pic-search\3.jpg)

查看页面源代码，确定为目录型网站，并且脚本语言可能是`php`

![](D:\stu\vulnhub\hacksudo靶场\pic-search\4.jpg)

进行目录扫描，使用`dirsearch、gobuster、ffuf、dirb、dirbuster`等工具

这里是`gobuster`进行扫描

```shell
gobuster dir -u http://192.168.1.49 -w /usr/share/wordlists/dirb/big.txt -x php,bak,txt,js,html -b 403-404
```



![](D:\stu\vulnhub\hacksudo靶场\pic-search\5.jpg)

使用`dirsearch`的默认字典扫描

```shell
dirsearch -u http://192.168.1.49 -x 403,404
```



![](D:\stu\vulnhub\hacksudo靶场\pic-search\6.jpg)

### 访问扫描目录

访问`robots.txt`，看到给出的信息，找到我，我是数字一搜索引擎，说这只是个玩笑，说白了，没啥

![](D:\stu\vulnhub\hacksudo靶场\pic-search\7.jpg)

访问`.env`，发现有信息，给出`APP_key`，可能经过`base64`编码。并且下面给出数据库的类型以及端口，还有用户名和密码。以及一个日志的别名(可能是)

![](D:\stu\vulnhub\hacksudo靶场\pic-search\8.jpg)

访问`README.md`，大概就是`crawler.php`是爬虫，`index.php`提供搜索，`search.php`提供搜索的返回

![](D:\stu\vulnhub\hacksudo靶场\pic-search\9.jpg)

访问`account`，发现一堆`php`

![](D:\stu\vulnhub\hacksudo靶场\pic-search\10.jpg)

经过点击后观察源代码，发现只有一个信息，就是提供了一个地址，而这个地址，可能就是其整个网站的源码地址。

![](D:\stu\vulnhub\hacksudo靶场\pic-search\11.jpg)

访问这个地址，发现可以说与扫描出的一模一样，先下载，这个很重要

![](D:\stu\vulnhub\hacksudo靶场\pic-search\12.jpg)

# 漏洞寻找

在`index.php`中尝试搜索，看有什么

![](D:\stu\vulnhub\hacksudo靶场\pic-search\13.jpg)

发现点击`search`按钮，就会跳转

![](D:\stu\vulnhub\hacksudo靶场\pic-search\14.jpg)

查看页面源代码，发现点击这个按钮，是一个超链接

![](D:\stu\vulnhub\hacksudo靶场\pic-search\15.jpg)

访问`search1.php`发现也是与之一样，不过多出几个菜单

![](D:\stu\vulnhub\hacksudo靶场\pic-search\16.jpg)

查看页面源代码，这里可以发现涉及到其他的`php`文件，并且也有参数，是否这里可以访问其他的东西呢

![](D:\stu\vulnhub\hacksudo靶场\pic-search\17.jpg)



使用`ffuf`定点测试，发现不行，那么可能是参数不止一个，毕竟这里给出的就已经有三个参数，可能还有隐藏参数。尝试测试参数，因为之前测试，发现默认界面的大小都是`2918`，这里测试的时候，直接过滤，为什么呢，因为参数接收不同，可能所做的处理不同，会导致显示不同，如果都是一样的话，那么找到这个参数，大概率也是一样的作用，换句话说，就是不管怎么样，都是加载同一个画面，如果真的有`home.php`这个文件的话，怎么会一直显示这个界面呢，如果没有`home.php`文件，也应该做其他处理，而不是直接200状态码在这个界面，所以，测试是否有无漏洞，可以通过这种方式

```shell
ffuf -c -w /usr/share/wordlists/dirb/common.txt -u http://192.168.1.49/search1.php?FUZZ=home.php -fs 2918
```



![](D:\stu\vulnhub\hacksudo靶场\pic-search\18.jpg)

# 漏洞利用

找到`me`隐藏参数，测试，这里记住上面的默认显示字节是2203，所以还是要过滤这个，与这个默认不一样，代表可能有。发现确实有

![](D:\stu\vulnhub\hacksudo靶场\pic-search\19.jpg)

这里测试的字典，是路径遍历，但是毕竟权限不够，所能读取的文件很少，那么是否可以访问外面的链接呢。这个参数是否还可以有其他操作，尝试测试

![](D:\stu\vulnhub\hacksudo靶场\pic-search\20.jpg)

# 反弹shell

存在访问外部链接，那么就可以直接在`kali`设置一个脚本，然后让其访问

打开`/usr/share/webshells/php/php-reverse-shell.php`脚本进行编辑，设置为`kali`的地址即可。

![](D:\stu\vulnhub\hacksudo靶场\pic-search\21.jpg)

然后在`kali`使用`python`打开一个简易的`http`服务

![](D:\stu\vulnhub\hacksudo靶场\pic-search\22.jpg)

在`kali`上`nc`进行监听1234端口，当利用漏洞加载这个远程的链接时，就会出现反弹

![](D:\stu\vulnhub\hacksudo靶场\pic-search\23.jpg)

# 内网信息收集

在这里搜索挺久，使用之前获取到的数据库的用户名和密码无法登录，然后查看网络连接状态，也只有`3306`端口开启，搜索具有SUID权限的文件，也没有可以利用的，寻找关键字的一些文件，也没有找到。

最终返回`/var/www/html`寻找，然后在`account`目录下的`dbconnect.php`找到一个连接数据库的用户名和密码，尝试再进行连接数据库，发现成功

![](D:\stu\vulnhub\hacksudo靶场\pic-search\24.jpg)

查看数据库中的内容，发现两个数据库，但是其中无表

![](D:\stu\vulnhub\hacksudo靶场\pic-search\25.jpg)

查看`iformation_schema`中的表，一眼看到小写字符的，就看他试试，因为一般在这个数据库中的表，都是大写字符的，而且这个数据库中的表，其实是一个单独的数据库

![](D:\stu\vulnhub\hacksudo靶场\pic-search\26.jpg)

好吧，又是无权访问

![](D:\stu\vulnhub\hacksudo靶场\pic-search\27.jpg)

那么到现在为止，我是已经找不到利用的点了，只能尝试爆破

查看有几个用户

![](D:\stu\vulnhub\hacksudo靶场\pic-search\28.jpg)

把前面获取到的信息归档，这里的信息并非对应关系，只是整理

| 用户名     | 密码              |
| ---------- | ----------------- |
| `hacksudo` | `p@ssw0rd`        |
| `john`     | `MyD4dSuperH3r0!` |
| `monali`   |                   |
| `search`   |                   |

# 提权

使用`hydra`进行爆破

![](D:\stu\vulnhub\hacksudo靶场\pic-search\29.jpg)

哎呀，终于找到了突破口

寻找具有SUID权限的文件

![](D:\stu\vulnhub\hacksudo靶场\pic-search\30.jpg)

切换目录，并测试文件，可能是`install`或者调用`install`

![](D:\stu\vulnhub\hacksudo靶场\pic-search\31.jpg)

访问`gtfobins.github.io`查看

![](D:\stu\vulnhub\hacksudo靶场\pic-search\32.jpg)

但是测试发现，这里不管添加什么参数，都会报错，提示查看`install`的帮助，怀疑这里是调用`install`，并且还没有把用户的传参给`install`这个命令

查看`install`的位置

![](D:\stu\vulnhub\hacksudo靶场\pic-search\33.jpg)

那么尝试使用临时变量，来执行我设置的`install`，尝试在当前目录下进行，发现还是不行

![](D:\stu\vulnhub\hacksudo靶场\pic-search\34.jpg)

切换到`/tmp`目录吧

![](D:\stu\vulnhub\hacksudo靶场\pic-search\35.jpg)

# 清除痕迹

虽然使用`sed -i "/192.168.1.16/d" auth.log`能够清除`kaili`的记录，但是记录了以哪个用户登录，虽然这不重要，不过我为了好看，排版，我全部置为空

![](D:\stu\vulnhub\hacksudo靶场\pic-search\36.jpg)

# 总结

1. 在寻找web攻击点时，收集信息很重要，不然可能连`search1.php`这个文件都发现不了，所以不能只依靠一个工具，或者说，不能只依靠一个字典，如果你的字典很强，那当我没说
2. 对于存在传参的地方，都要去进行测试，不管是针对参数的测试，还是针对参数值的测试，都不要忽略
3. 对于可能存在文件读取漏洞的地方，不止是本地，可能还有远程
4. 这里还是信息收集的比较好，不然密码爆破都可能无法成功，所以，反弹`shell`成功后，还要在系统中使劲收集信息，备份文件，网络连接状态、内核等等
5. 寻找到`suid`的文件后，要观察测试这个文件怎么触发的，这里其实给了一个`c`文件，就是用于分析的，一眼就是通过`c`编译的可执行文件，这里的提示比较明确，因为在有传参的情况下，还是提示查看帮助，那就是其本身不是`install`，可能调用的
6. 对于临时环境变量，使用`export`会使得在当前终端具有优先权，就会先调用设置的，然后再调用系统中的













