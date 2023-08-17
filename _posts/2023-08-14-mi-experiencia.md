---
layout: single
title: Mi experiencia con el eJPTv2 - eLearn Security
excerpt: "En este post voy a contar como fue mi experiencia con esta certificacion (eJPTv2 de eLearn Security) al igual que estare contando como fue que me prepare y que es lo necesario que necesitas saber para poder sacar la certificacion facilmente y rapido"
date: 2023-08-14
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/eJPTv2-mi-experiencia/ejptv2.png
  teaser_home_page: true
categories:
  - Certificaciones
tags:  
  - eJPTv2
---

<p align="center">
<img src="/assets/images/eJPTv2-mi-experiencia/banner.png">
</p>

## Preparacion 

- Pues bueno como tal primeramente hay que prepararnos para esta certificacion la cual en mi experiencia fue sencilla y rapida aun asi es posible que por los nervios o alguna otra cosa falles asi que bueno estos son recursos, plataformas y creadores de contenido con los cuales te puedes preparar

* La primer plataforma mas conocida y recomendada es [Hackthebox](https://app.hackthebox.com/login) en esta plataforma encontraras maquinas **Linux** y **Windows** para que puedas practicar aunque en caso de que quieras practicar con maquinas retiradas tendras que pagar el **VIP** o **VIP+** y elegir el plan que quieras con estas maquinas te puedes preparar para esta certificacion ademas iras de sobra con todo lo que aprenderas.

* Esta web es un buscador de maquinas de [Hackthebox, VulnHub y otras plataformas](https://infosecmachines.io/) diseñado por un seguidor de [s4vitar](https://www.youtube.com/channel/UCNHWpNqiM8yOQcHXtsluD7Q) con este buscador podras filtrar directamente por el sistema operativo de una maquina o filtrar por maquinas te caigan en el **eJPTv2** o alguna otra certificacion.

* Antes de presentar el examen ya contaba con mas de **100** maquinas resueltas de **Hackthebox** entre otras maquinas de otras plataformas en mi experiencia te recomiendo practicar con mas maquinas **Windows** que **Linux** aunque en la certificacion no se toca nada de **Active Directory**.

* Recomiendo tambien mucho la plataforma de [TryHackMe](https://tryhackme.com/) ya que podras resolver maquinas las cuales te haran preguntas conforme vallas avanzando y este tipo de **CTFs** son muy similares a los de la certificacion.

* Recomiendo hacer el curso de **Introduccion al Hacking** de [Hack4u.io](https://hack4u.io/) con lo que aprenderas iras mas que preparado para esta certificacion iras preparado asta para otras mas dificiles.

## Conocimientos Necesarios

* Pues bueno como tal la certificacion no requiere muchos conocimientos necesarios pero como tal este tipo de conocimientos que te mencionare a continuacion son necesarios ya que el examen no tendras conexion a internet para descargar scripts de **GitHub** algo que debes de saber para esta certificacion mas que nada es el **Pivoting** que tendras que hacerlo con **Metasploit** [Pivoting Metasploit](https://www.zonasystem.com/2020/01/pivoting-con-metasploit-route-portfwd-y-portproxy.html).

* Algo importante tambien es saber enumerar un **WordPress** hay maquinas de **Hackthebox** y **TryHackMe** donde tocan mucho este gestor de contenido ademas de tener una herramienta muy conocida que te automatiza todo que es `wpscan` ademas puedes usar este post para guiarte en como hacerlo es de [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress)

* Otra cosa necesario es saber como hacer ataques de **Fuerza Bruta** con `hydra`, `john` para **crackear** **Hashes** ya que en esta certificacion los ataques de **Fuerza bruta** a **SSH** o **SMB** son muy comunes para un panel de **Wordpress** puedes usar `wpscan` o `hydra` aprende a enumerar muy bien todo tipo de cosas como una maquina linux o un gestor de contenido para que se haga muy facil eso te lo dara la practica.

## Mi experiencia con el examen 

* El examen consta de 4 secciones: **Host & Network Auditing**, **Assessment Methodologies**, **Host & Network Pentesting** y **Web Application Pentesting** debes de sacar mas de `%70` en cada session para poder aprobar en caso de sacar menos de `%70` en alguna vas a reprobar automaticamente son un total de **35** preguntas las cuales la mayoria tienen que ver con lo que vas encontrando en el **examen** es por eso que es muy importante el enumerar ademas vas a encontrar algunas preguntas que tiene que ver con **flags** con que son dinamicas o te preguntaran cual es la contraseña de **x** usuario para tal servicio.

* En mi caso de podria decir que el examen es facil y lo sacas en poco tiempo ya que la mayoria de cosas estaran muy ala vista.

## Herramientas que necesitaras

* **Metasploit** para hacer el **Pivoting** a algun tipo de **Ataque** 
* **Hydra** para hacer Fuerza Bruta 
* **Nmap** para ver puertos y servicios que corren en los **Hosts** son como **6** entre ellos `windows` y `linux`
* **Crackmapexec** para comprobar que las credenciales sean correctas
* **Wpscan** para enumerar el **Wordpress** rapidamente y encontrar credenciales y vulnerabilidades en los plugins
* **xfreerdp** para conectarte de manera remota con interfaz grafica a una maquina **Windows** contando con credenciales validas **esta herramienta es importante**
* **smbmap o smblcient** para enumerar recursos compartidos a nivel de red 
* **fping** para descubrir los **hosts** activos en tu **red** es importante contar con conocimientos de **subnetting**
* **msfvenom** para crear el ejecutable y ganar accceso con meterpreter

## Cosas importantes y consejos

* Es importante que aprendas a tomar nota de todo lo que hagas practica mucho y si te sientes perdido recuerda que tienes **48 horas** no es nada dificil solo cree en ti, si te pierdes por las preguntas solo comienza con una **host** y explotalo despues ve que preguntas estan relacionadas con la maquina que acabas de comprometer esto para ir mas rapido ve de uno en uno y asi ubicas mas rapido las preguntas que se asemejan con la maquina. 

* Siempre se curioso vel el codigo fuente para ver si hay **subdominios** prueba todo no es un **CTF** es por eso que es muy facil. 

* Y pues no se que mas decir como tal practica mucho y haslo :). 

* Quiero agradecer a toda la comunidad **Hack4u** de **s4vitar** ademas ala comunidad de [raptorattack](https://www.youtube.com/@aprendiendohacking), al igual que al team al que pertenesco **Cyb3rGh0st** y finalmente a [GatoGamer](https://gatogamer1155.github.io/) sin ellos nada de esto seria posible ya que son buenas personas que apoyan y te ayudan con muchas cosas donde tienes dudas gracias a todos :) vamos a por la siguiente certificacion.
