---
layout: single
title: Investigating Windows - TryHackMe
excerpt: "Este CTF es un poco diferente es de la plataforma de Tryhackme y es de dificultad facil es una maquina windows este CTF es mas de Analisis Forense ya que tenemos que encontrar rastros para saber que es lo que pudo hacer el hacker para comprometer la maquina ademas nos dicen que tenemos que conectarnos por RDP y nos dan credenciales tenemos que basicamente investigar el sistema windows para poder contestar las preguntas"
date: 2023-03-15
classes: wide
header:
  teaser: /assets/images/try-writeup-inwin/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
  - infosec
tags:  
  - Windows Analysis
---
<p align="center">
<img src="/assets/images/try-writeup-inwin/icon.png">
</p>

Bueno primeramente nos dicen que nos conectemos por `RDP` y nos dan credenciales
`Administrator:letmein123!`

```bash
❯ rdesktop -u Administrator -p letmein123! 10.10.16.33
```

<span style="color:yellow">Whats the version and year of the windows machine?</span>

`Windows server 2016`

![](/assets/images/try-writeup-inwin/1.png)

<span style="color:yellow">Which user logged in last?</span>

`administrator` por que nosotros fuimos los ultimos el logearnos en caso de que nuestra respuesta fuera incorrecta podriamos ver la ultima vez que se conectaron otros usuarios

![](/assets/images/try-writeup-inwin/2.png)

<span style="color:yellow">When did John log onto the system last?</span>

`03/02/2019 5:48:32 PM`

![](/assets/images/try-writeup-inwin/3.png)

<span style="color:yellow">What IP does the system connect to when it first starts?</span>

En esta pregunta tenemos que responder la IP que nos mostro cuando nos conectamos ala maquina que fue la 
`10.43.2.3`

<span style="color:yellow">What two accounts had administrative privileges (other than the Administrator user)?</span>

`Jenny, Guest`

![](/assets/images/try-writeup-inwin/4.png)

![](/assets/images/try-writeup-inwin/5.png)

<span style="color:yellow">Whats the name of the scheduled task that is malicous.</span>

`Clean file system`

![](/assets/images/try-writeup-inwin/6.png)

<span style="color:yellow">What file was the task trying to run daily?</span>

`nc.ps1`

![](/assets/images/try-writeup-inwin/7.png)

<span style="color:yellow">What port did this file listen locally for?</span>

`1348`

![](/assets/images/try-writeup-inwin/8.png)


<span style="color:yellow">When did Jenny last logon?</span>

`Never`

![](/assets/images/try-writeup-inwin/9.png)

<span style="color:yellow">At what date did the compromise take place?</span>

`03/02/2019`

![](/assets/images/try-writeup-inwin/10.png)

<span style="color:yellow">At what time did Windows first assign special privileges to a new logon?</span>

`03/02/2019 4:04:49 PM` 

![](/assets/images/try-writeup-inwin/11.png)

<span style="color:yellow">What tool was used to get Windows passwords?</span>

`mimikatz`

![](/assets/images/try-writeup-inwin/12.png)

<span style="color:yellow">What was the attackers external control and command servers IP?</span>

`76.32.97.132`

![](/assets/images/try-writeup-inwin/13.png)

<span style="color:yellow">What was the extension name of the shell uploaded via the servers website?</span>

`.jsp`

![](/assets/images/try-writeup-inwin/14.png)

<span style="color:yellow"> What was the last port the attacker opened?</span>

`1337`

![](/assets/images/try-writeup-inwin/15.png)

<span style="color:yellow">Check for DNS poisoning, what site was targeted?</span>

Si recordamos habimos visto en el `/etc/hosts` que la ip era `76.32.97.132` si revisamos que era lo que habia despues que era el dominio donde apuntaba es `google.com`

![](/assets/images/try-writeup-inwin/13.png)






















