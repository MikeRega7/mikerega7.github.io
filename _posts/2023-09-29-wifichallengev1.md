---
layout: single
title: WifiChallengeLab v1
excerpt: "En este post vamos a estar resolviendo el retos del WifiChallengeLab v1 se encuentran 2 versiones disponibles pero vamos a comenzar con la primera versión ya que el propio creador nos recomienda la versión 1 para prepararnos para el OSWP ademas estaremos poniendo aprueba conocimientos con los que ya contamos"
date: 2023-09-29
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/wifi-challenge-lab/iconn.png
  teaser_home_page: true
categories:
  - Hacking Wifi
tags:  
  - Hacking Wifi 
  - WEP 
  - WPA2
  - OSWP
---

## Introduccion 

![](/assets/images/wifi-challenge-lab/web1.png)

Lo primero que hay que hacer es registrarnos en la pagina <https://wifichallengelab.com/> y seleccionar si estas usando **vmware** o **virtual box** e importar la maquina virtual y listo

Para logearte en la maquina virtual nos comparten las contraseñas que es **user/toor**

## Recon 

Como primer apartado tenemos el de **Recon** que es la primer fase del laboratorio así que vamos a comenzar

![](/assets/images/wifi-challenge-lab/web2.png)

Nos están pidiendo obtener la dirección **MAC** del cliente asociado al **AP** `wifi-global`

Vamos a comenzar haciendo un `airmon-ng check kill` e iniciando la tarjeta de red en modo monitor

![](/assets/images/wifi-challenge-lab/web3.png)

Ahora vamos a comenzar poniéndonos en escucha para ver los `APs` con `airodump-ng wlan0mon --band abg` para indicar que las bandas que tiene que inspeccionar son de 2.4GHz y 5GHz

Y hay podemos ver la **MAC** del AP 

![](/assets/images/wifi-challenge-lab/web4.png)

Ahora podemos estar monitorisando ese **AP** para obtener la **MAC** del algún cliente `airodump-ng wlan0mon --bssid F0:9F:C2:71:22:77 --channel 44 --band abg`

![](/assets/images/wifi-challenge-lab/web5.png)

Y vemos que es correcto

![](/assets/images/wifi-challenge-lab/web6.png)

# 02. Detect APs information

Ahora vamos a por este 

![](/assets/images/wifi-challenge-lab/web7.png)

Simplemente nos enfocaremos ahora en el **AP** `wifi-corp` solo nos piden el canal en el que opera eso es fácil simplemente hacemos un `airodump-ng wlan0mon --band abg`

Y listo opera en el canal **44**

![](/assets/images/wifi-challenge-lab/web8.png)

Y queda completado

![](/assets/images/wifi-challenge-lab/web9.png)

# 03. Get probes from users

Ahora nos piden obtener el **probe** del cliente con la **MAC** **78:C1:A7:BF:72:66** empezamos con un `airodump-ng wlan0mon --band abg`

![](/assets/images/wifi-challenge-lab/web10.png)

Hay vemos que el cliente esta asociado a `wifi-office`

![](/assets/images/wifi-challenge-lab/web11.png)

Y con eso ya quedaría 

![](/assets/images/wifi-challenge-lab/web12.png)

# 04. Find hidden network ESSID

En este ultimo apartado de **recon** nos piden saber el nombre del **AP** con la **MAC** **F0:9F:C2:71:22:11** cuando se configura un **AP** no siempre se deja el **ESSID** ala vista si con `airodump-ng` monitorizamos trafico indicando el **bssid** vamos a ver que no podremos ver el nombre del **AP** `airodump-ng wlan0mon --band abg --bssid F0:9F:C2:71:22:11`

![](/assets/images/wifi-challenge-lab/web13.png)

Vemos que su longitud es de 9 caracteres y opera en el canal 1 podemos usar `mdk4` para hacer fuerza bruta usando el `rockyou` y obtener el nombre del **AP**

Primeramente vamos a parar el modo monitor `airmon-ng stop wlan0mon`

Ahora iniciamos la tarjeta de red en ese canal que es el **1** `airmon-ng start wlan0 1`

Ahora iniciamos haciendo fuerza bruta `mdk4 wlan0mon p -t F0:9F:C2:71:22:11 -f ~/rockyou.txt`

Y listo obtenemos el nombre

![](/assets/images/wifi-challenge-lab/web14.png)

Y con esto completamos el primer apartado

![](/assets/images/wifi-challenge-lab/web15.png)

## 2. Open

En este apartado nos piden que accedamos ala red `wifi-guest` pero si leemos solo nos dicen que pongamos el mecanismo que usamos para conectarnos que se le llama `bypassed security`

![](/assets/images/wifi-challenge-lab/n1.png)

Para conectarnos a una red wifi podemos usar `wpa_supplicant` que es una utilidad que gestiona la autenticación y la configuración de claves para conexiones Wi-Fi protegidas con WPA, lo primero que debemos de hacer es configurar un archivo de configuración

![](/assets/images/wifi-challenge-lab/n2.png)

Ahora vamos a usar `wpa_supplicant` pasandole como parámetros el nombre del driver , la interfaz de red donde se conectara y el **.conf** que es el archivo de configuración que utilizara

Para saber el nombre del `driver` simplemente ejecutamos un `iwconfig` ahora podemos seguir

```bash
❯ wpa_supplicant
Successfully initialized wpa_supplicant
wpa_supplicant v2.10
Copyright (c) 2003-2022, Jouni Malinen <j@w1.fi> and contributors

This software may be distributed under the terms of the BSD license.
See README for more details.

This product includes software developed by the OpenSSL Project
for use in the OpenSSL Toolkit (http://www.openssl.org/)

usage:
  wpa_supplicant [-BddhKLqqstuvW] [-P<pid file>] [-g<global ctrl>] \
        [-G<group>] \
        -i<ifname> -c<config file> [-C<ctrl>] [-D<driver>] [-p<driver_param>] \
        [-b<br_ifname>] [-e<entropy file>] [-f<debug file>] \
        [-o<override driver>] [-O<override ctrl>] \
        [-N -i<ifname> -c<conf> [-C<ctrl>] [-D<driver>] \
        [-m<P2P Device config file>] \
        [-p<driver_param>] [-b<br_ifname>] [-I<config file>] ...]

drivers:
  nl80211 = Linux nl80211/cfg80211
  wext = Linux wireless extensions (generic)
  wired = Wired Ethernet driver
  macsec_linux = MACsec Ethernet driver for Linux
  none = no driver (RADIUS server/WPS ER)
options:
  -b = optional bridge interface name
  -B = run daemon in the background
  -c = Configuration file
  -C = ctrl_interface parameter (only used if -c is not)
  -d = increase debugging verbosity (-dd even more)
  -D = driver name (can be multiple drivers: nl80211,wext)
  -e = entropy file
  -f = log output to debug file instead of stdout
  -g = global ctrl_interface
  -G = global ctrl_interface group
  -h = show this help text
  -i = interface name
  -I = additional configuration file
  -K = include keys (passwords, etc.) in debug output
  -L = show license (BSD)
  -m = Configuration file for the P2P Device interface
  -N = start describing new interface
  -o = override driver parameter for new interfaces
  -O = override ctrl_interface parameter for new interfaces
  -p = driver parameters
  -P = PID file
  -q = decrease debugging verbosity (-qq even less)
  -s = log output to syslog instead of stdout
  -t = include timestamp in debug messages
  -T = record to Linux tracing in addition to logging
       (records all messages regardless of debug verbosity)
  -u = enable DBus control interface
  -v = show version
  -W = wait for a control interface monitor before starting
example:
  wpa_supplicant -Dnl80211 -iwlan0 -c/etc/wpa_supplicant.conf
```

Ahora ejecutamos para que funcione

```bash
❯ wpa_supplicant -Dnl80211 -iwlan2 -c wifi.conf
```

![](/assets/images/wifi-challenge-lab/n3.png)

Vemos que esta rechazando la conexión ya que hay una **whitelist** de direcciones **MAC** para permitir la conexión al parecer aquí usan la dirección **MAC** para otorgarte acceso a Internet

Para conectarnos debemos de tener una dirección **MAC** valida para eso vamos a usar `airodump-ng` para ver las direcciones **MAC** de algunos clientes y utilizarla para cambiarnos nuestra **MAC** a algunas de ellas

Vemos que despues de un tiempo hay 3 clientes asociados al **AP** con esto ya podemos cambiarnos la **MAC** por que ya la conocemos

![](/assets/images/wifi-challenge-lab/clientes.png)

Vamos a utilizar `macchanger` y vamos a ejecutar los siguientes comandos, `ip link` se utliza para volver a encender la interfaz de red después de apagarla

```bash
systemctl stop network-manager
ip link set wlan2 down
macchanger -m <CLIENT MAC> wlan2
ip link set wlan2 up
```

Una vez ejecutados ya podemos volver a correr el `wpa_supplicant`

Ahora si estamos conectados

![](/assets/images/wifi-challenge-lab/clientes2.png)

Vamos a usar `dhclient` para que nos asigne una dirección **IP** por **DHCP** `dhclient wlan2 -v`

![](/assets/images/wifi-challenge-lab/zi.png)

A este mecanismo de `bypass` se le llama **Mac filtering** ahora si todo estaría completo 

![](/assets/images/wifi-challenge-lab/5.png)

Vemos que después de hacer el reto nos habré otro

# 06. Login to the server with users password 

Para esto tenemos que obtener la contraseña de algún usuario vamos a usar `wireshark` para capturar trafico por si algún cliente inicia session capturar sus contraseñas y filtraremos por trafico **http** ya que para completar el reto nos piden una flag

Vamos a capturar trafico de la red un tiempo para y exportaremos la información a un fichero `airodump-ng -w Captura --bssid <mac target> -c 1 wlan0mon`

Si abrimos la captura con `wireshark` hay podemos ver que hay credenciales

![](/assets/images/wifi-challenge-lab/clienteper.png)

Ahora simplemente nos conectamos al `router` y obtenemos la `flag`

![](/assets/images/wifi-challenge-lab/flag.png)

Y listo ahora si estaría completo ya que la flag es correcta

![](/assets/images/wifi-challenge-lab/completo.png)

## 3. WEP

Bueno pues ahora estamos en el apartado del protocolo **WEP** que es diferente a las de **WPA2** ahora nos piden obtener el la contraseña y nos dan una pista que dice **Pass in hex** que significa que la contraseña esta en hexadecimal quiero pensar a si que vamos a comenzar

![](/assets/images/wifi-challenge-lab/wep1.png)

Lo primero que vamos a hacer es analizar el entorno `airodump-ng wlan0mon`

Hay vemos la red aunque no tenemos el nombre por que es una red oculta

![](/assets/images/wifi-challenge-lab/wep2.png)

Como conocemos la dirección **MAC** de la red oculta vamos a usar `Besside-ng` para poder realizar el ataque y obtener la contraseña, ademas hace un ataque de deautenticacion para expulsar a los clientes 

La red oculta se encuentra en el canal **1** y tenemos su dirección **MAC**

```bash
❯ besside-ng -c 1 -b F0:9F:C2:71:22:11 wlan1 -v
```

![](/assets/images/wifi-challenge-lab/wep3.png)

Ahora como la red esta escondida necesitamos un **probe** a si que vamos a usar `mdk4` para eso en otra ventana y ya vemos el nombre del **AP**

![](/assets/images/wifi-challenge-lab/wep4.png)

Ahora que tenemos el nombre y la password de igual manera nos genera un **.log** donde podemos ver la **key** 

![](/assets/images/wifi-challenge-lab/wep5.png)

![](/assets/images/wifi-challenge-lab/final2.png)

# 4. PSK

> La mayoría de retos en este apartado me dieron problemas entonces no resolví todos pero tienes la resolución directamente en la web del creador a si que no hay problema

# 08. Get wifi-mobile password 

Ahora estamos en el siguiente apartado que nos piden obtener la contraseña del **AP** **wifi-mobile** bueno lo primero que vamos a hacer es obtener información sobre el **AP** y obtener su dirección **MAC** `airodump-ng wlan0mon --band abg` y ya vemos hay un cliente asociado 

![](/assets/images/wifi-challenge-lab/psk1.png)

Vamos a ponernos en el canal **1** que hay es donde esta el **AP** para capturar el **handshake**

```bash
❯ airodump-ng -c 1 --essid wifi-mobile wlan0mon -w captura
```

Ahora usaremos `aireplay-ng` en otra consola para expulsar a todos los clientes y cuando se vuelvan a conectar poder capturar el **handshake** ya que emiten el **probe request** como lo hemos visto en los posts anteriores

```bash
❯ aireplay-ng -0 0 -a F0:9F:C2:71:22:22 wlan0mon
```

![](/assets/images/wifi-challenge-lab/psk2.png)

Ahora hacemos un `ctrl+c` y esperamos a un cliente se reasocie para obtener el **handshake**

![](/assets/images/wifi-challenge-lab/psk3.png)

Ahora si podemos usar `aircrack-ng` para obtener la contraseña 

![](/assets/images/wifi-challenge-lab/keyfound.png)

Ahora si completamos el reto y se nos desbloquean otros

![](/assets/images/wifi-challenge-lab/listo.png)

# 09 Get users traffic passively

Ahora nos piden obtener trafico de los usuarios de manera pasiva y obtener la **subnet** para eso vamos a usar `airdecap-ng` si recordamos hay trafico que va encriptado y no podemos ver esos paquetes pero como tenemos la captura y la contraseña de la red wifi que nos dicen podemos usar la herramienta para desencriptar esos paquetes

```bash
❯ airdecap-ng -e wifi-mobile -p starwars Captura-01.cap
```

Y bueno como vimos en los anteriores post una vez hecho eso ya habres la captura con `wireshark` o `tshark` filtras y podras ver la **IP** y el rango **192.168.2.0/24**

![](/assets/images/wifi-challenge-lab/yaa.png)

# 10 Verify Client Isolation

Ahora nos piden una flag

![](/assets/images/wifi-challenge-lab/10.png)

Tuve demasiados problemas con esta parte del laboratorio pero aun asi puedes ver la resolución en la pagina web oficial

# 11 Login with stolen cookies

En esta parte simplemente nos piden usar una cookie que uso un usuario para conectarse a una web con wifi-mobile esa la optienes en la captura usando wireshark yo no lo hice por que la maquina virtual me comienza a dar problemas y no me muestra la cookie eh hecho el ataque varias veces pero nada pero aun asi puedes ver la solucion en su apartado a si que vamos a ir  directamente al reto 13 

# Get wifi-admin AP password 

Solamente nos piden obtener la contraseña del **AP**

![](/assets/images/wifi-challenge-lab/vale.png)

Vamos a comenzar inspeccionando el entorno

```bash
❯ airodump-ng wlan0mon --wps --band abg
```

Y hay vemos `wifi-admin` que usa **WPS** como en el post anterior de la maquina de **hackthebox** a si que usaremos **reaver** para hacer fuerza bruta como lo explique en el post anterior simplemente si te funciona el lab pues puedes completar el reto en mi caso no se por que no funciona pero bueno no es algo nuevo para mi entonces no lo hare xd

![](/assets/images/wifi-challenge-lab/vale.png)

## Importante

> Tube demasiados problemas con la maquina virtual reiniciaba varias veces el laboratorio y no pasaba nada pero si quieren ver las siguientes resoluciones se encuntran en la web oficial de wifichallengelab v1 por el mismo creador nos vemos en el siguiente post haciendo los retos pero del laboratorio de version 2
