---
layout: single
title: Evil Twin Attack with Evil Trust
excerpt: "En este post vamos a estar realizando el ataque Evil Twin Attack para obtener las credenciales de alguna red social como facebook a travez de este ataque vamos a estar empleando la herramienta de s4vitar mas conocida como evil trust"
date: 2023-11-05
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/hacking-eviltwin-wifi/evil.png
  teaser_home_page: true
categories:
  - Hacking Wifi
tags:  
  - Hacking Wifi
  - Evil Twin Attack
  - WPA2
  - OSWP
---

- En este post vamos a estar probando la herramienta **Evil Trust** de **s4vitar** <https://github.com/s4vitar/evilTrust> que despliega un **Rogue AP** con una plantilla de +2FA. 

> Rogue AP es un Access Point malicioso

![](https://i.imgur.com/Z7urRFn.png)

>En este caso necesitamos una antena wifi que acepte modo monitor en el anterior post deje la que yo uso y recomiendo

## Instalacion y Explicacion

- La herramienta esta hecha en **bash** para instalarla simplemente hacemos lo siguiente

```bash
❯ git clone https://github.com/s4vitar/evilTrust
Cloning into 'evilTrust'...
remote: Enumerating objects: 353, done.
remote: Counting objects: 100% (41/41), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 353 (delta 36), reused 33 (delta 33), pack-reused 312
Receiving objects: 100% (353/353), 2.85 MiB | 4.55 MiB/s, done.
Resolving deltas: 100% (136/136), done.
❯ cd evilTrust
```
> Para hacer el ataque Manualmente lo que se hace es que el AP malicioso opera en el mismo canal donde esta operando el AP objetivo para que los clientes se asocien y mediante una plantilla obtener los que queremos aunque debes usar reglas iptables ademas debes crear una nueva interfaz para que tenga salida a internet debes crear un tunel entre tu interfaz y la que tiene acceso a internet, con este ataque podemos hacer mas cosas como robar la contraseña real del AP podemos hacerle creer al cliente que hay una actualizacion del modem y necesita ingresar la contraseña para que se pueda hacer la actualizacion 

De primeras nos dice que tenemos que estar como el usuario **root** para poder ejecutar la herramienta

```bash
❯ ./evilTrust.sh

[!] Es necesario ser root para ejecutar la herramienta
```

Si lo ejecutamos vemos el siguiente **output**

```bash
❯ ./evilTrust.sh

╱╱╱╱╱╱╱╭┳━━━━╮╱╱╱╱╱╱╭╮
╱╱╱╱╱╱╱┃┃╭╮╭╮┃╱╱╱╱╱╭╯╰╮
╭━━┳╮╭┳┫┣╯┃┃┣┻┳╮╭┳━┻╮╭╯
┃┃━┫╰╯┣┫┃╱┃┃┃╭┫┃┃┃━━┫┃   (Hecho por s4vitar)
┃┃━╋╮╭┫┃╰╮┃┃┃┃┃╰╯┣━━┃╰╮
╰━━╯╰╯╰┻━╯╰╯╰╯╰━━┻━━┻━╯

Uso:
	[-m] Modo de ejecución (terminal|gui) [-m terminal | -m gui]
	[-h] Mostrar este panel de ayuda
```

Vemos que la herramienta ya existe con interfaz grafica pero usaremos la opcion de terminal

# Explicacion 

Para realizar este ataque la herramienta usa **Hostapd** 

![](https://i.imgur.com/xH40uAw.png)

Al igual que tambien usa **Dnsmasq** 

![](https://i.imgur.com/svcQBOz.png)

Todo lo monta en un servidor **php** y un **.conf** que se necesita para poder crear ese archivo con toda la informacion del **Access Point** 

Voy a conectar mi antena

```bash
❯ iwconfig
lo        no wireless extensions.

eth0      no wireless extensions.

wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:off
```

Ahora la pondre en modo monitor

```bash
❯ airmon-ng start wlan0

Found 2 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
   1011 NetworkManager
  33306 wpa_supplicant

PHY	Interface	Driver		Chipset

phy0	wlan0		rt2800usb	Ralink Technology, Corp. RT5572
		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)
```

Podemos matar los procesos nosotros mismos pero la herramienta te lo automatiza a si que no lo haremos ahora ejecutaremos la herramienta

## Ejecutando el ataque

Vamos a indicar que ejecutaremos el modo terminal

```bash
❯ ./evilTrust.sh -m terminal
```

- Tienes que instalar las herramientas que sean necesarias para que funcione como **php, hostapd,php** y alguna otra que te diga

- En este caso le dire que quiero usar esa interfaz que es la de mi antena

![](https://i.imgur.com/qx9IhiY.png)

Ahora le indicaremos el nombre del **AP** y le diremos al canal que queremos utlizar para que lo monte

![](https://i.imgur.com/3RkciOW.png)

Una vez eso la herramienta comienza a configurar el **hostapd** y **dnsmasq** y ahora nos pide decirle que plantilla queremos usar

![](https://i.imgur.com/SozhB1F.png)

Y listo le indique que queria la de **facebook** 

Si vamos a nuestro movil vamos a ver el **AP**

![](/assets/images/hacking-eviltwin-wifi/1.png)

Una vez nos conectamos vemos esto

![](https://i.imgur.com/soFFZ3i.png)

Una vez la victima da click lo lleva a un login que es el de **facebook** donde dara sus contraseñas

![](/assets/images/hacking-eviltwin-wifi/2.png)

Una vez ingresa las credenciales y le da en **Log In** a nosotros ya nos llegan las credenciales

![](https://i.imgur.com/JK4aLOm.png)

Para matar todo simplemente hacemos un **ctrl+c**

Y automaticamente el modo monitor lo apaga como si hicieramos un `airmong-ng stop wlan0mon`

## Conclusiones

Como tal la herramienta es muy buena nos ayuda a automatizar todo el proceso de crear el **Rogue AP** es importante usarla bajo tu propia responsabilidad puedes modificar el codigo y hacer tu propia plantilla que tambien puedes hacer el ataque manualmente solo que en mi propia experiencia no es muy estable el **AP** 
