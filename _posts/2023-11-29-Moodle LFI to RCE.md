---
title: 'Moodle Exploitation: From LFI to RCE'
date: 2023-11-29 19:50:00 
categories: [pentest]
tags: [moodle,lfi,rce]    
---

## Introduction

In today's blog, we embark on a journey from identifying an LFI (Local File Inclusion) vulnerability to ultimately gaining root access. The emphasis will be on a hands-on approach, understanding each step and appreciating the intricacies of manual exploitation over relying solely on automated tools.

Let's call our target redacted.com.

## Scanning for Subdomains

Start by scanning for subdomains using `ffuf`. The command `ffuf -u "http://FUZZ.redacted.com" -w raft-large-directories.txt` reveals promising results. Our first subdomain, test.redacted.com, catches our attention.

![Subdomain Scan](../../assets/img/posts/1/1.png)

## Directory Bruteforce

Exploring test.redacted.com with `dirsearch` uncovers a phpmyadmin directory.

![Directory Bruteforce](../../assets/img/posts/1/2.png)

hinting at more possibilities. Subsequently, a subdomain bruteforce reveals another subdomain, moodle.

![Subdomain scan](../../assets/img/posts/1/3.png)

## Exploiting LFI in Moodle

Using nuclei we identify an LFI vulnerability in the Jmol filter on the Moodle website.

![nuclei](../../assets/img/posts/1/4.png)
 
Directly exploiting this vulnerability, we access sensitive information like `/etc/passwd`.

![LFI Exploitation](../../assets/img/posts/1/5.png)

## Leveraging PHPMyAdmin

With knowledge that the website uses phpmyadmin, we exploit the LFI vulnerability to extract credentials from `/etc/phpmyadmin/config-db.php`. 

![PHPMyAdmin Exploitation](../../assets/img/posts/1/6.png)

Logging in with phpmyadmin shows nothing but logging in with the root user reveals the available databases.

## Escalating Privileges in Moodle

By extracting information from the default configuration file in moodle which is located under `/var/www/html/moodle/config.php` 

![moodle config](../../assets/img/posts/1/7.png)

we know that the target database is moodle312 

![phpmyadmin](../../assets/img/posts/1/8.png)
 
 we proceed to escalate privileges. Switching to the **admin** user, we capture the old hash, update the password, and log in as the administrator.

![Privilege Escalation](../../assets/img/posts/1/9.png)

## Manual Moodle Exploitation

Despite Metasploit failing, we manually exploit Moodle using CVE-2019-11631. 

![Metasploit](../../assets/img/posts/1/10.png)

I came across a theme named "squared." Our goal is to inject our webshell into this theme. After downloading the theme, we'll unzip it and edit the file named theme_squared.php located in /lang/en/theme_squared.php

![Manual Exploitation](../../assets/img/posts/1/11.png)

Zip the folder again then upload it.

![Upload](../../assets/img/posts/1/12.png)

## Achieving Remote Code Execution (RCE)

Finding a theme called squared for Moodle 3.1.1, (visit redacted.com/lib/upgrade.txt to get the exact moodle version) we customize the theme file to include our webshell. After successfully uploading the theme, we access our webshell, achieving RCE.

![RCE](../../assets/img/posts/1/13.png)

## Upgrading to Reverse Shell

To enhance our access, we upgrade to a reverse shell using ngrok and revshells, gaining a more powerful foothold.

![Reverse Shell](../../assets/img/posts/1/14.png)

## Escalating to Root

Upon running linpeas on the target, we found that it is vulnerable to CVE-2021-4034. Executing the exploit, we successfully escalate privileges to root.

![Root Privileges](../../assets/img/posts/1/15.png)

## Conclusion

In conclusion, I hope you liked my post. Keep learning, stay curious, and never give up!