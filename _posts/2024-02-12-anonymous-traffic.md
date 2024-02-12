---
layout: single
title: Anonymous Traffic with Tor
excerpt: "In this post we will be configuring proxychains and tor to browse securely and anonymously so that everything goes through the tor network."
date: 2024-02-12
classes: wide
toc: true
toc_label: "Contenido"
toc_icon: "fire"
header:
  teaser: /assets/images/anonymous-traffic/icon.png
  teaser_home_page: true
categories:
  - tor browser
  - proxychains
tags:  
  - Traffic Anonymous
  - proxychains
---

## Installing requirements

- The first thing we are going to do is to update all the repositories.

<p align="center">
<img src="https://i.imgur.com/JOnIXkB.png"></img>
</p>

- Now we just update.

```bash
➜  ~ apt upgrade -y
```

- Now let's install `tor` and `proxychains`.

```bash
➜  ~ apt install tor proxychains -y
```

>Proxychains is a tool used for routing network connections through proxy servers. It is often employed by users who want to enhance their privacy and anonymity while browsing the internet or accessing online services. By chaining multiple proxy servers together, Proxychains can effectively hide the origin of network traffic, making it more difficult for third parties to track or monitor the user's activities.

>Tor Browser is a web browser specifically designed to enhance privacy and anonymity on the internet. It is built upon the Tor network, which is a decentralized network of volunteer-operated servers (called relays) that help users to conceal their location and internet usage from anyone conducting network surveillance or traffic analysis.

## Setting up proxychains

- The first thing we are going to do is edit the following file.

```bash
➜  ~ nano /etc/proxychains.conf
```

- Your file must look like this.

```bash
➜  ~ cat /etc/proxychains.conf
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#	

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
#strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#            	socks5	192.168.67.78	1080	lamer	secret
#		http	192.168.89.3	8080	justu	hidden
#	 	socks4	192.168.1.49	1080
#	        http	192.168.39.93	8080	
#		
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
socks5	127.0.0.1 9050
```

## Using tor browser

The first thing we are going to do is to start the tor service.

```bash
➜  ~ service tor start
```

Now we check that everything is OK.

```bash
➜  ~ service tor status
● tor.service - Anonymizing overlay network for TCP (multi-instance-master)
     Loaded: loaded (/usr/lib/systemd/system/tor.service; disabled; preset: disabled)
     Active: active (exited) since Mon 2024-02-12 10:58:42 CST; 39s ago
    Process: 7690 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 7690 (code=exited, status=0/SUCCESS)
        CPU: 3ms

Feb 12 10:58:42 miguelos systemd[1]: Starting tor.service - Anonymizing overlay network for TCP (multi-instance-master)...
Feb 12 10:58:42 miguelos systemd[1]: Finished tor.service - Anonymizing overlay network for TCP (multi-instance-master).
```

## Being anonymous

- Now we just run some browser with proxychains.

```bash
➜  ~ proxychains firefox
```

<p align="center">
<img src="https://i.imgur.com/z7HmjtH.png"></img>
</p>

- If we check that everything is working correctly, we see that we are going through tor.

<p align="center">
<img src="https://i.imgur.com/6h0oZUK.png"></img>
</p>

- With this we can check that it is not filtering our information.

<p align="center">
<img src="https://i.imgur.com/QcUO6Qa.png"></img>
</p>

- We will always go through the tunnel.

```bash
➜  ~ proxychains ping -c 1 google.com
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
PING google.com (142.251.34.46) 56(84) bytes of data.
64 bytes from qro01s28-in-f14.1e100.net (142.251.34.46): icmp_seq=1 ttl=128 time=23.6 ms

--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 23.598/23.598/23.598/0.000 ms
```

>You can use any tool you want but you must go through the tunnel but if you want to use nmap you have to comment out this line.

<p align="center">
<img src="https://i.imgur.com/2dNQdHk.png"></img>
</p>

- We can scan the site they tell us <https://www.101labs.net/comptia-security/lab-2-nmap/>

```bash
➜  ~ proxychains nmap scanme.nmap.org -p80
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-12 11:18 CST
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  127.0.0.1:9050 <--denied
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  45.33.32.156:80  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  45.33.32.156:80  ...  OK
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.58s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.65 seconds
➜  ~
```

If you want to stop the tor service you can do this.

```bash
➜  ~ service tor stop
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ====
Authentication is required to stop 'tor.service'.
Authenticating as: miguel,,, (miguel)
Password:
==== AUTHENTICATION COMPLETE ====
➜  ~ service tor status
○ tor.service - Anonymizing overlay network for TCP (multi-instance-master)
     Loaded: loaded (/usr/lib/systemd/system/tor.service; disabled; preset: disabled)
     Active: inactive (dead)

Feb 12 10:58:42 miguelos systemd[1]: Starting tor.service - Anonymizing overlay network for TCP (multi-instance-master)...
Feb 12 10:58:42 miguelos systemd[1]: Finished tor.service - Anonymizing overlay network for TCP (multi-instance-master).
Feb 12 11:24:01 miguelos systemd[1]: tor.service: Deactivated successfully.
Feb 12 11:24:01 miguelos systemd[1]: Stopped tor.service - Anonymizing overlay network for TCP (multi-instance-master).
```

## Extra Information

- If you want to learn how tor works here are these videos

<iframe width="560" height="315" src="https://www.youtube.com/embed/7OrMheKzuL4?si=ME6NrLIiTfmByULl" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

<iframe width="560" height="315" src="https://www.youtube.com/embed/Uadl2-gDKtA?si=kuZZokPpDxGx1u7n" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

- Thank you for reading :) 
