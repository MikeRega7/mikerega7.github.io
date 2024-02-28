---
layout: single
title: Escape - Vulnlab
excerpt: "En este post vamos a estar resolviendo la máquina Escape de la plataforma de Vulnlab donde vamos a estar usando xfreerdp para conectarnos al servicio rdp y comenzar a enumerar la máquina la cual vamos a tener que escapar de un Windows Kiosk en el cual solo está configurado para ejecutar el navegador de microsoft además vamos a estar realizando un bypass de UAC de la máquina."
date: 2024-02-27
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/Escape-vulnlab/icon.png
  teaser_home_page: true
categories:
  - hackthebox
tags:  
  - rdp
  - Windows Kiosk
  - UAC
---

## PortScan

- Comenzamos escaneando los puertos abiertos por el protocolo **TCP** donde solo encontramos un puerto abierto **3389** por el protocolo **TCP** <https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp> .

```bash
➜  nmap sudo nmap -sCV -p3389 10.10.90.255 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-27 10:47 CST
Nmap scan report for 10.10.90.255
Host is up (0.18s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-27T16:48:15+00:00; 0s from scanner time.
| rdp-ntlm-info:
|   Target_Name: ESCAPE
|   NetBIOS_Domain_Name: ESCAPE
|   NetBIOS_Computer_Name: ESCAPE
|   DNS_Domain_Name: Escape
|   DNS_Computer_Name: Escape
|   Product_Version: 10.0.19041
|_  System_Time: 2024-02-27T16:48:11+00:00
| ssl-cert: Subject: commonName=Escape
| Not valid before: 2024-02-02T11:08:33
|_Not valid after:  2024-08-03T11:08:33
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## xfreerdp

- Vamos a conectarnos.

```bash
➜  nmap xfreerdp /v:10.10.90.255 /tls-seclevel:0 -sec-nla
```

- Nos dice lo siguiente que nos conectemos con el usuario **KiosUser0** .

<p align="center">
<img src="https://i.imgur.com/UieJqtq.png">
</p>

<p align="center">
<img src="https://i.imgur.com/kH5q7gE.png">
</p>

- Una vez conectados vemos lo siguiente:

<p align="center">
<img src="https://i.imgur.com/GhZZKNL.png">
</p>

- Como tal la máquina se llama **Escape** a sí que tenemos que escapar del modo **Kios mode** si presionamos la tecla **Windows** funciona.

<p align="center">
<img src="https://i.imgur.com/3Qz8UuZ.png">
</p>

- Si intentamos arrancar una consola, simplemente no nos deja.

<p align="center">
<img src="https://i.imgur.com/xi7PNAh.png">
</p>

- Si preguntamos a **ChatGPT** sobre **Windows Kiosk** nos dice que puede ser configurado para abrir un navegador o aplicación en específico.

<p align="center">
<img src="https://i.imgur.com/7o1mxOE.png">
</p>

- Podemos ejecutar el navegador de **Windows** <https://blog.nviso.eu/2022/05/24/breaking-out-of-windows-kiosks-using-only-microsoft-edge/>.

<p align="center">
<img src="https://i.imgur.com/TGrxsKS.png">
</p>

- Vemos que **ChatGPT** también nos dice que podemos acceder a archivos.

<p align="center">
<img src="https://i.imgur.com/OUpii2B.png">
</p>

- Si escribimos `file:///C:\` vemos el **C** **Drive**.

<p align="center">
<img src="https://i.imgur.com/QDPE7We.png">
</p>

- Examinando dentro de **admin** hay un archivo **profiles.xml** con una contraseña:

<p align="center">
<img src="https://i.imgur.com/BSiTKkP.png">
</p>

- En la ruta **C:\Windows\System32** encontramos un ejecutable interesante vamos a descargarlo.

![](/assets/images/Escape-vulnlab/01.png)
  
- No podemos ejecutarlo porque como nos dijo **ChatGPT** el **Windows Kiosk** se configura para que el usuario solo pueda ejecutar algo en específico como vimos que podemos ejecutar **msedge** vamos a cambiarle el nombre al archivo y lo ejecutamos.

![](/assets/images/Escape-vulnlab/02.png)

- Funciona.

![](/assets/images/Escape-vulnlab/03.png)

- Vamos a usar **Powershell** para poder ejecutar comandos.

![](/assets/images/Escape-vulnlab/04.png)

- Si recordamos tenemos un password, pero está encriptada podemos usar lo siguiente <https://www.nirsoft.net/utils/bullets_password_view.html> .

- Una vez descargado lo pasamos a la máquina víctima.

![](/assets/images/Escape-vulnlab/05.png)

- En caso de que no se pueda hacemos lo siguiente.

![](/assets/images/Escape-vulnlab/06.png)

- Ahora vamos a copear él **.exe** a la carpeta de **_admin** .

- Ahora vamos a ejecutar el **Remote Desktop** para poder ver la contraseña.

![](/assets/images/Escape-vulnlab/07.png)

- Ahora vamos a **Manages Profiles** y despues en **Import Profiles**.

- Pero antes vamos a copear el **profiles.xml** que necesitamos.

```powershell
PS C:\_admin> copy .\profiles.xml C:\Users\kioskUser0\Downloads\    
```

- Y ahora importamos el **profiles.xml**.

![](/assets/images/Escape-vulnlab/08.png)

## Password

- Ahora, si ejecutamos el `BulletsPassView.exe` desde la consola, tenemos la contraseña:

![](/assets/images/Escape-vulnlab/09.png)

- Vemos que el usuario **admin** es un usuario del sistema.

![](/assets/images/Escape-vulnlab/10.png)

- Para convertirnos en ese usuario vamos a usar **Runas.exe** <https://www.jctsoluciones.com.co/uso-del-comando-runas-en-windows/>.

```powershell
PS C:\_admin> runas /user:admin cmd                                                                                          Enter the password for admin:  
```

## Shell as admin

- Ahora estamos como ese usuario:

![](/assets/images/Escape-vulnlab/11.png)

- Pero no somos el **administrator** .

![](/assets/images/Escape-vulnlab/12.png)

## Root.txt

- Tenemos que hacer un bypass de UAC.

- Vamos a ejecutar una **cmd.exe** con privilegios elevados usando **runas**.

![](/assets/images/Escape-vulnlab/13.png)

- Y ya podemos ver la flag porque tenemos privilegios máximos.

![](/assets/images/Escape-vulnlab/14.png)
