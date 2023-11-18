---
layout: single
title: WifiChallengeLab v2
excerpt: "En este post vamos a estar resolviendo algunas challenges del WifiChallengeLab de v2 donde estaremos aprendiendo a usar nuevas herramientas y a explotar APs con WPA3, WEP, WPA2 algo de recoleccion de informacion de MGT y otras mas"
date: 2023-11-18
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/wifi-challenge2-wifi/icon.PNG
  teaser_home_page: true
categories:
  - Hacking Wifi
tags:  
  - Hacking Wifi
  - WPA3
  - WPA2
  - MGT
  - OSWP
---

## Antes de empezar

Para descargar la maquina virtual y podemos acceder al laboratorio puedes hacerlo desde aquí <https://drive.proton.me/urls/Q4WPB23W7R#Qk4nxMH8Q4oQ>

<https://wifichallengelab.com/>

Las credenciales para acceder al laboratorio son `user:user`

Para poner el teclado en español usamos `setxkbmap es`  

## Introducction

# What is the contents of the file /root/flag.txt on the VM?

En este reto simplemente nos piden mostrar el contenido de la flag `flag.txt` una vez nos vamos ala ruta  `/root` vemos la flag ahora simplemente la mostramos

![](https://i.imgur.com/HUZbHgV.png)

## Recon

# What is the channel that the wifi-global Access Point is currently using?

Como primer desafío nos piden decir cual es canal donde esta operativo el **AP** **wifi-global** o donde esta corriendo, para esto podemos usar  `airodump-ng ` pero primero vamos a poner la antena en modo monitor **no es necesario que tu tengas una antena físicamente el laboratorio ya cuenta con ella** 

Para hacer esto ejecutamos lo siguiente

![](https://i.imgur.com/eMcO4wm.png)

Una vez hecho podemos proceder lo que haremos primeramente es ejecutar `airodump-ng` con las opciones de `--band abg` que sirve para que nos muestre **APs** que usan **2.4 GHz** o **5GHz** una vez dicho esto vamos a ejecutar `airodump-ng start wlan0mon --band abg` y con eso veremos en que canal opera el **AP**

![](https://i.imgur.com/fUdydXV.png)

# What is the MAC of the wifi-IT client?

Ahora nos piden conocer la dirección **MAC** que esta usando el cliente conectado al **AP** **wifi-IT client** para eso como ya conocemos los canales donde estan operando los **APs** que vimos podemos filtrar directamente por el canal para que nos muestre información de ese **AP** y ver directamente la **MAC** para eso simplemente ejecutamos el anterior comando + `-c 11` que es donde esta operando el **AP** 

![](https://i.imgur.com/ZkgCEY4.png)

# What is the probe of 78:C1:A7:BF:72:46?

Ahora nos piden saber el **probe** de esa dirección **MAC** cuando usamos  `airodump-ng` podemos ver siempre en la parte de abajo hay un apartado que se llama `Probes` lo unico que tenemos que hacer es ver el nombre del **probe** que opera en esa direccion **mac**  `airodump-ng wlan0mon --band abg` 

![](https://i.imgur.com/I8DysqE.png)

# What is the ESSID of the hidden AP (mac F0:9F:C2:6A:88:26)?

Ahora nos piden saber el **ESSID** del **AP** que esta escondido con la **MAC** **F0:9F:C2:6A:88:26** hay que saber que no siempre vamos a poder ver los nombres de todos los **APs** cuando nos hablan de **ESSID** es por que el nombre de la red no es publico y cuando nos hablan de **BSSID** es la dirección **MAC** del punto de acceso

Si recordamos previamente cuando ejecutamos `airodump-ng wlan0mon --band abg` vimos un **AP** oculto con esa dirección **MAC** que opera en el canal **11** a si que vamos a establecer **wlan0mon** que opere en el canal **11** con `iwconfig wlan0mon channel 11` 

Ahora vamos a usar **mdk4** **"Murder Death Kill 4"** para emitir **Probes** usando el **rockyou.txt** la herramienta va ir enviando **Probes** con un posible nombre del **ESSID** que los nombres están en el **rockyou.txt** y cuando el **AP** responda significa que ese es su nombre correcto

Para que esto sea mas rápido lo que podemos hacer es agregar la palabra **wifi-** antes del nombre que es como sugiere el creador para hacer esto podemos hacerlo así `sed 's/^/wifi-/' ~/rockyou-top100000.txt > ~/wifi-rockyou.txt` 

Ahora si ejecutamos lo siguiente `mdk4 wlan0mon p -t F0:9F:C2:6A:88:26 -f ~/wifi-rockyou.txt`

Y encontramos el nombre 

![](https://i.imgur.com/p9g8dIr.png)

## OPN

# What is the flag in the hidden AP router behind default credentials?

Para empezar es necesario comprender que significa una red **OPN** esto quiero decir que es una red **abierta** o sin **seguridad** no utiliza ningún método de autenticación o cifrado nos dicen que que el **hidden AP** como ya conocemos el nombre ya que previamente usamos `mdk4` para conocerlo como no emplea seguridad podemos crear un **.conf** especificando el nombre y que tiene contraseña y usar `wpa_supplicant` para asociarnos a ese **AP** le tenemos que indicar el driver que `wpa_supplicant` va a utilizar y la interfaz de red que va a usar para esto simplemente ejecutamos lo siguiente

![](https://i.imgur.com/JnwPew9.png)

Ahora ejecutamos el **wpa_supplicant**, Y en otra terminal como **root** nos vamos asignar una dirección **IP** por **DHCP** 

![](https://i.imgur.com/hUDVDKq.png)

Y ahora abrimos el navegador y nos dirigimos al **Panel de autenticaccion** donde si probamos las credenciales por defecto **admin/admin** son correctas y una vez hecho eso podremos ver la flag

![](https://i.imgur.com/IpeVlky.png)

Por ultimo para evitar conflictos ejecutamos lo siguiente `dhclient wlan2 -r`

# What is the flag on the AP router of the wifi-guest network?

Pues bueno ahora nos piden saber la flag en el **AP** de **wifi-guest** de los antiguos ataques que hemos hecho sabemos que este **AP** opera en el canal **6** a si que estaremos con **airodump-ng** capturando trafico de esa red en especifico mientras nos conectamos a ese **AP**

`airodump-ng wlan0mon --band abg --essid wifi-guest -c 6 -w captura`

Ahora vamos a crear de nuevo un **.conf** 

Y ejecutamos el `wpa_supplicant` de la misma forma que antes

![](https://i.imgur.com/3EJiMZb.png)

Ahora nos asignamos **IP** en otra terminal

`dhclient -v wlan2`

Ahora si vamos a nuestro navegador y vamos ala **IP** del **router** eh intentamos acceder con credenciales por defecto no vamos a poder 

![](https://i.imgur.com/EVrHIc6.png)

La única forma de acceder es haciendo un **Bypass** al panel de login si vemos en **airodump-ng** hay un cliente asociado al **AP** podemos usar su direccion **MAC** 

Para hacer esto vamos a matar los procesos que ya estaban corriendo 

![](https://i.imgur.com/Mys23NU.png)

Ahora nos volvemos asignar **IP** con **dhclient** 

Y nos carga 

![](https://i.imgur.com/dql1j5s.png)

Bueno para obtener las credenciales es importante saber que estamos en una web a lo que se tramita una petición ya sea por **POST** o **GET** como estamos capturando trafico podemos abrir la captura donde estamos exportando el trafico con **wireshark** y ver si hay algunas credenciales en el trafico de red

Y hay vemos las credenciales

![](https://i.imgur.com/x7Si8bG.png)

## WEP

Ahora nos piden obtener la contraseña del **AP** **wifi-old** es importante saber que **WEP** es un protocola de seguridad muy viejo que es fácilmente vulnerable si vemos las redes disponibles vemos las siguientes hay encontramos el **AP**

![](https://i.imgur.com/5pBZGU6.png)

Hay un cliente asociado al **AP**

![](https://i.imgur.com/IDER8eO.png)

Ahora como el **AP** usa **WEP** podemos usar **besside-ng** para que haga un ataque de fuerza bruta y nos encuentre la contraseña `besside-ng -c 1 -b F0:9F:C2:AA:19:29 wlan2`

![](https://i.imgur.com/I8uZJc9.png)

## PSK

Ahora entramos el **PSK** que esta orientado en **WPA2** **PSK** **"Wi-Fi Protected Access 2 con Pre-Shared Key"** es un protocolo de seguridad que operan las redes inalámbricas y cifran la comunicación entre dispositivos, **PSK** **Pre-Shared Key** es una clave de seguridad que comparte entre los dispositivos que se conectan hoy en día ya existe **WPA3** que ya no utiliza **PSK** cuando un dispositivo se conecta a un **AP** emite un **Probe Request** y el router emite el **Probe response** 

# What is the wifi-mobile AP password?

Para los ataques **WPA2 PSK** necesitamos obtener el **Handshake** o el apretón de manos se realiza cuando el dispositivo o el cliente se conecta al **AP** ya que hay viaja la contraseña encriptada

Si vemos con `airodump-ng` el **AP** usa **PSK** y opera en el canal **6** 

Primeramente nos vamos a poner a capturar trafico en el canal 6 y lo vamos a exportar para poder capturar el **handshake** `airodump-ng wlan0mon -c 6 -w captura`

Vamos a hacer ejecutar lo siguiente `iwconfig wlan0mon channel 6` 

Ahora vamos a emitir **15** paquetes de **Deautenticación** para que los clientes asociados se desconecten y cuando se vuelvan a conectar podremos capturar el **Handshake** `aireplay-ng -0 10 -a F0:9F:C2:71:22:12 wlan0mon`

Una vez se emiten y el cliente se reasocia obtenemos el **handshake** 

![](https://i.imgur.com/oHe4NrJ.png)

Ahora podemos usar `aircrack-ng` y el **rockyou** para poder encontrar la contraseña `aircrack-ng captura-01.cap -w ~/rockyou-top100000.txt` 

![](https://i.imgur.com/QY3ZXxR.png)

# What is the IP of the web server in the wifi-mobile network?

Si tenemos la contraseña del **AP** podemos desencriptar el trafico usando **airdecap-ng** <https://mikerega7.github.io/hacking-writeup-wifi/#espionaje> para esto simplemente le indicamos la captura el nombre del **AP** y la contraseña del **AP** 

![](https://i.imgur.com/ox1OFrd.png)

Ahora lo que vamos a hacer abrir el **wireshark** para ver la dirección **IP** `wireshark captura-01-dec.cap`

Hay podemos ver una **cookie** y una **IP** vamos a guardar la **cookie** 

![](https://i.imgur.com/U6feLYz.png)

# what is the flag after login in wifi-mobile?

Y bueno ahora después de todo esto que hicimos nos piden obtener la flag después de conectarnos al **AP** como nos están diciendo que nos conectemos vamos a usar `wpa_supplicant` empleando el **.conf** 

![](https://i.imgur.com/0S9vE5J.png)

Ahora de la misma forma vamos a usar el **wpa_supplicant** `wpa_supplicant -Dnl80211 -iwlan3 -c zi.conf` y una vez hecho nos vamos asignar **IP** con `dhclient wlan3 -v`

![](https://i.imgur.com/HMNacOA.png)

Ahora vamos a usar la **cookie** que tenemos y listo

# Is there client isolation in the wifi-mobile network?

Para este reto simplemente hay que usar **arp_scan** para ver si hay mas clientes en la interfaz de uso y **curl** para poder ver la flag 

# What is the wifi-office password?

Ahora pasamos al ultimo reto de la parte de **PSK** donde nos piden obtener la contraseña del **AP** **wifi-office** de igual manera tenemos que obtener un **handshake** pero asta ahora esa red esta oculta y no es visible una forma de obtener el **handshake** es creando un **Fake AP** para capturar el **handshake** de clientes que se asocian a ese **AP** podemos usar **hostapd-mana** para crear el **AP** pasándole un **.conf** donde el nombre del **AP** sea el mismo de **wifi-office** esta herramienta nos permite configurar **APs** esta herramienta permite hacer ataques **MITM** es un tipo de ataque en el cual un atacante intercepta y potencialmente altera la comunicación entre dos partes sin que ellas lo sepan https://en.wikipedia.org/wiki/Man-in-the-middle_attack

Ahora vamos a crear el **.conf** y vamos a exportar todo en `.hccapx` en el **.conf** necesitamos pasarle lo siguiente **interface, driver, hw_mode, channel, ssid, wpa, wpa_key_mgmt, el pairwise, y la contraseña** 

![](https://i.imgur.com/XEzgsrj.png)

Podemos hacer un **CTRL+C** ya que ya vimos lo siguiente AP-STA-POSSIBLE-PSK-MISMATCH.

![](https://i.imgur.com/8kJfxJQ.png)

Ahora usaremos **hashcat** para obtener la contraseña

A dia de hoy **2500** ya no funciona a si que tenemos que convertirlo a **22000** vamos a seguir instrucciones del creador del laboratorio

![](https://i.imgur.com/zSt9Zgf.png)

# SAE WPA3

# What is the wifi-management password?

Ahora entramos con **WPA3** que es la tercera generación del estándar de seguridad para redes Wi-Fi (Wireless Protected Access). Es una tecnología diseñada para mejorar la protección de las redes inalámbricas, proporcionando métodos más seguros de autenticación y cifrado de datos, lo que hace que sea más difícil para los atacantes comprometer la seguridad de una red Wi-Fi. Utiliza el protocolo Dragonfly (también conocido como SAE) para proteger las contraseñas contra ataques de fuerza bruta 

En este apartado nos piden obtener la contraseña del **AP** **wifi-management** que usa **WPA3** podemos usar esta herramienta https://github.com/blunderbuss-wctf/wacker lo único que necesitamos es el nombre del **AP** y el **bssid** que lo podemos obtener fácilmente al usar **airodump-ng** 

![](https://i.imgur.com/XS5OjVl.png)

# What is the wifi-IT password?

Ahora lo que tenemos que hacer es obtener la contraseña del **AP** **wifi-IT** en el apartado nos dicen **Downgrade WPA3 to WPA2** a si que lo que quiere decir es que vamos a hacer un **RogueAP** que ofrezca **WPA2** para obtener el handshake ya que es mas débil que **WPA3** una vez conectado el cliente podemos aprovecharno de 802.11w es una extensión del estándar de Wi-Fi que proporciona protección contra ataques de deautenticación. Cuando está habilitado, ayuda a proteger contra la desautenticación no solicitada, que es un tipo de ataque en el que un atacante intenta desconectar a los clientes de una red Wi-Fi de manera no autorizada en caso de que esta este desactivada

Lo primero que vamos a hacer es crear el **.conf** 

```bash
interface=wlan1
driver=nl80211
hw_mode=g
channel=11
ssid=wifi-IT
mana_wpaout=hostapd-management.hccapx
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=12345678
```

Ahora solo ejecutamos el **hostapd-mana**

![](https://i.imgur.com/CKe0Qdh.png)

Si nos podemos con **airodump-ng** nos daremos cuenta que hay un cliente asociado a si que haremos un ataque de deautenticacion para desasociar al cliente y que se conecte a nuestro **AP**

![](https://i.imgur.com/Yzro1Sm.png)

Una vez hecho eso obtenemos el handshake y podemos usar **hashcat** 

![](https://i.imgur.com/HrFYfyT.png)

## Recon MGT

# What is the domain of the users of the wifi-regional network?

Las redes MGT son usadas en empresas ya que cada usuario tiene su propia autenticación puede ser su nombre o contraseña los ataques contra las redes MGT incluyen obtener información de reconocimiento del Punto de Acceso (AP) y clientes, información de identidad, detalles de certificados y métodos EAP admitidos por la red https://github.com/koutto/pi-pwnbox-rogueap/wiki/13.-WPA-WPA2-Enterprise-(MGT)-Rogue-AP-Evil-Twin

En esta sección nos piden obtener el dominio de los usuarios que pertenecen a **wifi-regional** 

Lo primero que vamos hacer es estar con **airodump-ng** recolectando trafico del **AP** en cuestión que opera en el canal 44 

Una vez conectados los clientes podemos usar **wireshark** para analizar la captura

![](https://i.imgur.com/auoQT3W.png)

# What is the email address of the server certificate?

Ahora nos piden obtener el correo al que pertenece el certificado el Punto de Acceso (AP) envía el certificado al cliente en texto claro, por lo que cualquiera puede verlo vamos a utlizar una herramienta del propio creador <https://gist.github.com/r4ulcl/f3470f097d1cd21dbc5a238883e79fb2>

![](https://i.imgur.com/3wsBFMA.png)

# What is the EAP method supported by the wifi-global AP?

La autenticación EAP (Extensible Authentication Protocol) es un marco de protocolo utilizado en redes de computadoras para respaldar diversos métodos de autenticación, EAP facilita el intercambio seguro de información de autenticación entre el cliente y el servidor de autenticación. Los detalles específicos del intercambio pueden depender del método de autenticación particular utilizado nos comparten esta herramienta para este reto <https://github.com/blackarrowsec/EAP_buster>

![](https://i.imgur.com/La86Ato.png)

## Final

>Pues bueno asta aquí el Post falto la parte de **MGT** pero quiero hacer un post dedicado solo a eso ya que es muy interesante y un poco mas complicado muchas gracias por leer y gracias al creador r4ulcl <https://twitter.com/_r4ulcl_> por crear los laboratorios para mi es el mejor en este campo del Hacking wifi nos vemos en el siguiente posts cualquier cosa puedes contactarme por Discord miguelrega7
