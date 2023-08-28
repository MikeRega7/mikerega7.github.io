---
layout: single
title: Wifi Hacking 101 - TryHackMe
excerpt: "En este post vamos a estar haciendo el room Wifi Hacking 101 de la plataforma de TryHackMe donde estaremos aprendiendo conceptos básicos sobre el hacking wifi y al final nos montaremos un punto de acceso para aplicar lo aprendiendo contra un red wifi de tipo WP2 que la haremos desde nuestro celular con el objetivo de obtener la contraseña de esa red wifi"
date: 2023-08-28
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-wifi01/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
tags:  
  - Hacking Wifi
---

## Introduccion a WPA

- Pues bueno vamos a comenzar con la preparación para la certificación del [OSWP](https://help.offsec.com/hc/en-us/articles/360046904731-OSWP-Exam-Guide) vamos a partir desde los mas básico para poder obtener con éxito la certificación para eso vamos a comenzar haciendo este **room** de **TryHackMe** [wifihackfing101](https://tryhackme.com/room/wifihacking101) para ir entendiendo los conceptos básicos

![](/assets/images/try-writeup-wifi01/web1.png)

- **SSID:** Bueno el **SSID** nos dicen que es el nombre de la red a la cual nosotros nos estamos conectando tu puedes cambiar el nombre de la red de tu casa o empresa a eso se le llama **SSID**

- **ESSID:** Bueno esto es un **SSID** pero pero se aplica para múltiples puntos de acceso es para una red mas grande como la oficina de la empresa pero nos dice que para **aircrack** se refiere ala red que estamos atacando la herramienta **aircrack** la vamos a utilizar demasiado

- **BSSID:** el **BSSID** es la dirección **MAC** del Access Point del (hardware)

- **WPA2-PSK:** Esta es una red wifi que cuando te conectas la contraseña es la misma para todos la mayoría de compañías usa **WPA2** 

- **WPA2-EAP:** Esta es una red wifi para autenticarse te pide un usuario y una contraseña que se envían a un servidor **RADIUS** esto es muy común en la universidades

- **RADIUS:** Es un servidor para autenticar clientes que funciona para mas cosas no solo para wifi 

- **PSK:** Una autenticación de tipo PSK (Pre-Shared-Key), significa que se está haciendo uso de una clave pre-compartida como su nombre indica, una contraseña única que de estar a disposición de cualquiera puede ser usada para llevar a cabo una asociación contra el AP (Acess Point), esto es importante saberlo ya que hay ataques **WPA** con autenticacion **PSK**

## El núcleo de la autenticacion WPA(2) 4 way handshake

- Y bueno nos dice que la mayoría de redes domesticas y muchas otras utilizan **WPA** (2) personal, ademas nos dicen que si tenemos que iniciar sesión con una **contraseña** y no es **WEP** entonces es **WPA (2)** personal, el **WPA2-EAP** usa servidores **RADIUS** como ya sabíamos anteriormente y lo usa para autenticarse si te pide una nombre de usuario y una contraseña lo mas probable es que sea eso. 

- Ademas nos dicen que antes se usaba **WEP (Wired Equivalent Privacy)** pero se demostró que era muy inseguro y se puede romper capturando suficientes paquetes para adivinar la clave a través de métodos estáticos.

- **The 4 way handshake:** permite que el cliente y el (AP) **Access Point** demuestran que conocen la clave sin decírselo entre si, ademas nos dicen que **WPA** **WPA2** utilizan el mismo método de autenticación por lo que los ataques a ambos son los mismos.

- Las claves para **WPA** se derivan tanto del **ESSID** como de la contraseña de la red, el **ESSID** como un **salt** lo que dificulta los ataques de diccionario y nos dicen que eso significa que para una contraseña determinada la clave seguirá variando para cada punto de acceso, esto significa que a menos que calcule previamente el diccionario solo para ese punto de acceso/MAC address tendrás que probar las contraseñas asta que encuentres las correctas.

## Modo monitor

- Bueno para todo esto del **Hacking Wifi** vamos a necesitar una antena que acepte modo monitor para poder capturar los paquetes que viajan también en mi caso yo adquirí esta de aquí <https://www.amazon.com/gp/product/B01LY35HGO/ref=ppx_yo_dt_b_asin_title_o00_s00?ie=UTF8&psc=1>

![](/assets/images/try-writeup-wifi01/web2.png)

## Respuestas The basics - An Intro to WPA 

Bueno ahora después de aprender las cosas básicas vamos a contestar las preguntas

![](/assets/images/try-writeup-wifi01/web3.png)

## You're being watched - Capturing packets to attack

Y bueno nos dicen que utilizando la **Suite** de **aircrack** podemos empezar atacar redes wifi y aparte nos están diciendo las herramientas que contiene la **suite**

![](/assets/images/try-writeup-wifi01/web4.png)

Esto es lo que vamos a hacer para eso necesitamos la antena vamos a crear un **hotspot** desde nuestro celular y vamos a usar una contraseña del **rockyou**

![](/assets/images/try-writeup-wifi01/zi.png)

Bueno vamos a contestar las preguntas

```bash
❯ airmon-ng --help

usage: airmon-ng <start|stop|check> <interface> [channel or frequency]
```

Una vez conectada la (antena) para esto no se necesita pero solo es para mostrar como se hace 

Cuando conectemos nuestra antena tenemos que iniciar el modo monitor pero antes de eso tenemos que matar las tareas que interfieran con esto para eso hacemos lo siguiente (casi siempre se hace un **kill** a los **PID** que se encargan de darnos conexión a internet pero en este caso no lo haremos eso ya sera en un post mas adelante haciendo varios ataques, ademas es normal que pierdas conectividad a internet ya que estarás en modo monitor)

```bash
❯ airmon-ng check kill

Killing these processes:

    PID Name
    684 wpa_supplicant
```

Si hacemos un `iwconfig` nos tiene que aparecer el nombre para poder iniciar con `airmon-ng`

```bash
❯ iwconfig
lo        no wireless extensions.

ens33     no wireless extensions.

docker0   no wireless extensions.

br-9deedf958a2c  no wireless extensions.

tun0      no wireless extensions.

wlx9cefd5f91ec0  IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:off
```

Ahora iniciamos pasandole el nombre de la interfaz puede que el tuyo sea diferente

```bash
❯ airmon-ng start wlx9cefd5f91ec0


PHY	Interface	Driver		Chipset

phy1	wlx9cefd5f91ec0	rt2800usb	Ralink Technology, Corp. RT5572
Interface wlx9cefd5f91ec0mon is too long for linux so it will be renamed to the old style (wlan#) name.

		(mac80211 monitor mode vif enabled on [phy1]wlan0mon
		(mac80211 station mode vif disabled for [phy1]wlx9cefd5f91ec0)

```

Ahora si ya nos aparece `wlan0mon` y vemos que ya esta en modo monitor

```bash
❯ iwconfig
lo        no wireless extensions.

ens33     no wireless extensions.

docker0   no wireless extensions.

br-9deedf958a2c  no wireless extensions.

tun0      no wireless extensions.

wlan0mon  IEEE 802.11  Mode:Monitor  Tx-Power=20 dBm   
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```

Con esto podemos contestar las preguntas, en una de las preguntas nos dicen sobre el **BSSID**,  que es la dirección **MAC** y sobre el canal para eso solo ejecutamos el siguiente comando

```bash
❯ airodump-ng --help

  Airodump-ng 1.6  - (C) 2006-2020 Thomas d'Otreppe
  https://www.aircrack-ng.org

  usage: airodump-ng <options> <interface>[,<interface>,...]

  Options:
      --ivs                 : Save only captured IVs
      --gpsd                : Use GPSd
      --write      <prefix> : Dump file prefix
      -w                    : same as --write 
      --beacons             : Record all beacons in dump file
      --update       <secs> : Display update delay in seconds
      --showack             : Prints ack/cts/rts statistics
      -h                    : Hides known stations for --showack
      -f            <msecs> : Time in ms between hopping channels
      --berlin       <secs> : Time before removing the AP/client
                              from the screen when no more packets
                              are received (Default: 120 seconds)
      -r             <file> : Read packets from that file
      -T                    : While reading packets from a file,
                              simulate the arrival rate of them
                              as if they were "live".
      -x            <msecs> : Active Scanning Simulation
      --manufacturer        : Display manufacturer from IEEE OUI list
      --uptime              : Display AP Uptime from Beacon Timestamp
      --wps                 : Display WPS information (if any)
      --output-format
                  <formats> : Output format. Possible values:
                              pcap, ivs, csv, gps, kismet, netxml, logcsv
      --ignore-negative-one : Removes the message that says
                              fixed channel <interface>: -1
      --write-interval
                  <seconds> : Output file(s) write interval in seconds
      --background <enable> : Override background detection.
      -n              <int> : Minimum AP packets recv'd before
                              for displaying it

  Filter options:
      --encrypt   <suite>   : Filter APs by cipher suite
      --netmask <netmask>   : Filter APs by mask
      --bssid     <bssid>   : Filter APs by BSSID
      --essid     <essid>   : Filter APs by ESSID
      --essid-regex <regex> : Filter APs by ESSID using a regular
                              expression
      -a                    : Filter unassociated clients

  By default, airodump-ng hops on 2.4GHz channels.
  You can make it capture on other/specific channel(s) by using:
      --ht20                : Set channel to HT20 (802.11n)
      --ht40-               : Set channel to HT40- (802.11n)
      --ht40+               : Set channel to HT40+ (802.11n)
      --channel <channels>  : Capture on specific channels
      --band <abg>          : Band on which airodump-ng should hop
      -C    <frequencies>   : Uses these frequencies in MHz to hop
      --cswitch  <method>   : Set channel switching method
                    0       : FIFO (default)
                    1       : Round Robin
                    2       : Hop on last
      -s                    : same as --cswitch

      --help                : Displays this usage screen
```

![](/assets/images/try-writeup-wifi01/web5.png)

## Aircrack-ng - Let's Get Cracking

Ahora pasamos al ultimo **Task** como nos dicen nos adjuntan una captura a si que vamos a descargarlo

```bash
❯ mv /home/miguel7/Descargas/Captures.tar.gz .
❯ tar -xvf Captures.tar.gz
NinjaJc01-01.cap
NinjaJc01-01.csv
NinjaJc01-01.kismet.csv
NinjaJc01-01.kismet.netxml
NinjaJc01-01.log.csv
```

Los que nos interesan son **.cap** y **.csv** que contiene información sobre el **Access Point** 

Y bueno nos dan información **BSSID: 02:1A:11:FF:D9:BD** y el **ESSID** es  **ESSID: 'James Honor 8'**  

Para contestar las preguntas podemos obtener las respuestas de aqui

```bash
❯ aircrack-ng --help

  Aircrack-ng 1.6  - (C) 2006-2020 Thomas d'Otreppe
  https://www.aircrack-ng.org

  usage: aircrack-ng [options] <input file(s)>

  Common options:

      -a <amode> : force attack mode (1/WEP, 2/WPA-PSK)
      -e <essid> : target selection: network identifier
      -b <bssid> : target selection: access point's MAC
      -p <nbcpu> : # of CPU to use  (default: all CPUs)
      -q         : enable quiet mode (no status output)
      -C <macs>  : merge the given APs to a virtual one
      -l <file>  : write key to file. Overwrites file.

  Static WEP cracking options:

      -c         : search alpha-numeric characters only
      -t         : search binary coded decimal chr only
      -h         : search the numeric key for Fritz!BOX
      -d <mask>  : use masking of the key (A1:XX:CF:YY)
      -m <maddr> : MAC address to filter usable packets
      -n <nbits> : WEP key length :  64/128/152/256/512
      -i <index> : WEP key index (1 to 4), default: any
      -f <fudge> : bruteforce fudge factor,  default: 2
      -k <korek> : disable one attack method  (1 to 17)
      -x or -x0  : disable bruteforce for last keybytes
      -x1        : last keybyte bruteforcing  (default)
      -x2        : enable last  2 keybytes bruteforcing
      -X         : disable  bruteforce   multithreading
      -y         : experimental  single bruteforce mode
      -K         : use only old KoreK attacks (pre-PTW)
      -s         : show the key in ASCII while cracking
      -M <num>   : specify maximum number of IVs to use
      -D         : WEP decloak, skips broken keystreams
      -P <num>   : PTW debug:  1: disable Klein, 2: PTW
      -1         : run only 1 try to crack key with PTW
      -V         : run in visual inspection mode

  WEP and WPA-PSK cracking options:

      -w <words> : path to wordlist(s) filename(s)
      -N <file>  : path to new session filename
      -R <file>  : path to existing session filename

  WPA-PSK options:

      -E <file>  : create EWSA Project file v3
      -I <str>   : PMKID string (hashcat -m 16800)
      -j <file>  : create Hashcat v3.6+ file (HCCAPX)
      -J <file>  : create Hashcat file (HCCAP)
      -S         : WPA cracking speed test
      -Z <sec>   : WPA cracking speed test length of
                   execution.
      -r <DB>    : path to airolib-ng database
                   (Cannot be used with -w)

  SIMD selection:

      --simd-list       : Show a list of the available
                          SIMD architectures, for this
                          machine.
      --simd=<option>   : Use specific SIMD architecture.

      <option> may be one of the following, depending on
      your platform:

                   generic
                   avx512
                   avx2
                   avx
                   sse2
                   altivec
                   power8
                   asimd
                   neon

  Other options:

      -u         : Displays # of CPUs & SIMD support
      --help     : Displays this usage screen

```

En una de las ultimas preguntas nos piden crackear usando el **rockyou.txt** a si que vamos a hacerlo, primeramente hay vemos el **BSSID** es el mismo el cual nos están diciendo

```bash
❯ cat NinjaJc01-01.csv
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: NinjaJc01-01.csv
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP
       │ , ID-length, ESSID, Key
   3   │ 02:1A:11:FF:D9:BD, 2019-12-26 18:36:48, 2019-12-26 18:37:04, 11,  65, WPA2, CCMP, PSK, -43,      154,      254,   0.  0
       │ .  0.  0,  13, James Honor 8, 
   4   │ 
   5   │ Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
   6   │ 6C:88:14:02:A8:58, 2019-12-26 18:36:50, 2019-12-26 18:37:03, -34,      176, 02:1A:11:FF:D9:BD,
   7   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Ahora vamos a crackear 

```bash
❯ aircrack-ng -b 02:1A:11:FF:D9:BD -w /usr/share/wordlists/rockyou.txt NinjaJc01-01.cap
```

Y hay tenemos la contraseña 

```
                               Aircrack-ng 1.6 

      [00:00:44] 123974/14344392 keys tested (2786.39 k/s) 

      Time left: 1 hour, 25 minutes, 3 seconds                   0.86%

                        KEY FOUND! [ greeneggsandham ]


      Master Key     : 71 5F 17 D1 D7 9E 70 4D 6E 2E 9C AD 46 F5 45 F5 
                       AF 5E 43 48 16 F9 5B AA 14 8F 39 AA FC 5E EB 3B 

      Transient Key  : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : 9A 6A 56 EE E4 4E 42 A3 14 71 26 9F E0 E2 93 04 

```

Ahora terminamos la sala

![](/assets/images/try-writeup-wifi01/web6.png)

## Aplicamos lo aprendiendo

Lo primero que vamos a hacer es crearnos un punto de acceso vamos a crear una red desde nuestro celular yo voy a utilizar los siguientes datos 

```bash
❯ catn info.txt
SSID: SOY_WIFI
PSK: manchester 
```

La contraseña pertenece al **rockyou.txt**

```bash
❯ head /usr/share/wordlists/rockyou.txt -n 1000 | shuf -n 10 -
password2
hardcore
miamor
manchester
spider
pretty
tintin
anamaria
dreams
101010
```

Ahora creamos la red wifi en nuestro celular

![](/assets/images/try-writeup-wifi01/web7.png)

Ahora como ya habilitamos la red y el modo monitor pues podemos seguir lo primero que vamos a hacer es usar `airodump-ng wlan0mon` y nos va a mostrar todas las redes que encuentra

```bash
❯ airodump-ng wlan0mon
```

Hay encontramos la nuestra están ordenadas por potencia solo mostrare la red que configure por privacidad ya que las demás redes no son de mi propiedad y no tengo permiso de atacarlas ahora 

```bash
CH 14 ][ Elapsed: 1 min ][ 2023-08-28 10:14 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 CC:05:77:64:3D:8C   -1        0        1    0  10   -1   WPA              <length:  0>                                        
 0A:F4:0E:DA:A2:9C  -38       19        0    0   1  180   WPA2 CCMP   PSK  SOY_WIFI       
```

Y bueno lo que nos interesa es el `BSSID` que es `0A:F4:0E:DA:A2:9C` y el canal

Ahora vamos a usar `airodump-ng` para monitorear esa red y esperar a que capture el `4 way handshake` que sucede cuando un dispositivo se conecta ala `red` wifi que creamos

```bash
❯ airodump-ng --bssid 0A:F4:0E:DA:A2:9C --channel 1 -w xd wlan0mon
```

Ahora solo se esta monitoreando esa red 

![](/assets/images/try-writeup-wifi01/zi2.png)

Ahora me voy a conectar con otro dispositivo movil a esa red y nos tendrá que aparecer la información del dispositivo que se acaba de conectar y tenemos el `handshake`

![](/assets/images/try-writeup-wifi01/zi4.png)

Ahora solo hacemos un `ctrl+c` y hay tenemos los archivos

```bash
❯ ls
 info.txt   xd-01.cap   xd-01.csv   xd-01.kismet.csv   xd-01.kismet.netxml   xd-01.log.csv
```

Ahora vamos a hacer el **crackeo** pasandole la captura 

```bash
❯ aircrack-ng -w /usr/share/wordlists/rockyou.txt xd-01.cap
```

Y hay tenemos la contraseña de la red wifi 

![](/assets/images/try-writeup-wifi01/zi3.png)

Ahora quitamos el modo monitor 

```bash
❯ airmon-ng stop wlan0mon
```

Para tener conectividad a wifi otra vez solo has los siguiente, el ping a `google.com` solo es para comprobar que recuperamos la conexion a internet

```bash
❯ systemctl restart NetworkManager
❯ systemctl restart wpa_supplicant
❯ ping -c 1 google.com
PING google.com (172.217.4.174) 56(84) bytes of data.
64 bytes from qro04s04-in-f14.1e100.net (172.217.4.174): icmp_seq=1 ttl=128 time=12.2 ms

--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 12.247/12.247/12.247/0.000 ms
```

>Y bueno como tal eso fue todo solo fue de introduccion para comenzar con todo esto del Hacking wifi y prepararnos para el **OSWP** de **Offensive Security** hay que empezar con lo básico para poder comprender todo ya que hay muchos mas ataques como el Ataque de Deautenticacion dirigido, Beacon Flood Mode Attack, Ataques a redes sin clientes, para redes WEP hay muchos como el Chop Chop Attack, como dije hay demasiados a si que en los siguientes posts vamos a estar montandonos nuestros propios puntos de acceso para poder practicar todos estos ataques. 
