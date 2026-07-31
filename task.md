# Quality Assurance Engineer
## Technical Assessment

## Overview

You will build a security log analysis tool and demonstrate your approach to quality engineering.

---

## The Task

Design and implement a command-line tool that processes log files and identifies potential security incidents.

### Requirements

1. **Input:** Accept one or more log files as input
2. **Parsing:** Handle the provided log formats
3. **Detection:** Identify suspicious activities based on configurable rules
4. **Output:** Present findings in a clear, actionable format

### Log Files

Your tool must process both files and correlate findings where relevant.

**File 1: `webserver.log`**
```
192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.11 - - [03/Jul/2025:10:00:02 +0000] "GET /about.html HTTP/1.1" 200 982
10.0.0.50 - - [03/Jul/2025:10:00:03 +0000] "POST /login HTTP/1.1" 401 54
10.0.0.50 - - [03/Jul/2025:10:00:04 +0000] "POST /login HTTP/1.1" 401 54
10.0.0.50 - - [03/Jul/2025:10:00:05 +0000] "POST /login HTTP/1.1" 401 54
10.0.0.50 - - [03/Jul/2025:10:00:06 +0000] "POST /login HTTP/1.1" 401 54
10.0.0.50 - - [03/Jul/2025:10:00:07 +0000] "POST /login HTTP/1.1" 200 3842
192.168.1.12 - - [03/Jul/2025:10:00:08 +0000] "GET /products HTTP/1.1" 200 5765
203.0.113.5 - - [03/Jul/2025:10:00:09 +0000] "GET /admin HTTP/1.1" 403 128
203.0.113.5 - - [03/Jul/2025:10:00:10 +0000] "GET /admin/ HTTP/1.1" 403 128
203.0.113.5 - - [03/Jul/2025:10:00:11 +0000] "GET /admin/config HTTP/1.1" 403 128
203.0.113.5 - - [03/Jul/2025:10:00:12 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 400 0
192.168.1.13 - - [03/Jul/2025:10:00:13 +0000] "GET /search?q=laptop HTTP/1.1" 200 8762
10.0.0.88 - - [03/Jul/2025:10:00:14 +0000] "GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1" 200 54
192.168.1.14 - - [03/Jul/2025:10:00:15 +0000] "GET /search?q=O'Brien HTTP/1.1" 200 2341
10.0.0.88 - - [03/Jul/2025:10:00:16 +0000] "GET /search?q=1; DROP TABLE users-- HTTP/1.1" 200 54
192.168.1.15 - - [03/Jul/2025:10:00:17 +0000] "POST /contact HTTP/1.1" 200 89
172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET / HTTP/1.1" 200 4521
172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /admin HTTP/1.1" 403 128
172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /phpmyadmin HTTP/1.1" 404 0
172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /wp-admin HTTP/1.1" 404 0
172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /administrator HTTP/1.1" 404 0
172.16.0.20 - - [03/Jul/2025:10:00:19 +0000] "GET /.env HTTP/1.1" 404 0
172.16.0.20 - - [03/Jul/2025:10:00:19 +0000] "GET /config.php HTTP/1.1" 404 0
192.168.1.16 - - [03/Jul/2025:10:00:20 +0000] "GET /api/users/me HTTP/1.1" 200 128
[MALFORMED ENTRY - system restart
192.168.1.17 - - [03/Jul/2025:10:00:22 +0000] "GET /dashboard HTTP/1.1" 200 9821
10.0.0.99 - - [03/Jul/2025:10:00:23 +0000] "POST /api/users HTTP/1.1" 200 54
10.0.0.99 - - [03/Jul/2025:10:00:23 +0000] "POST /api/users HTTP/1.1" 200 54
10.0.0.99 - - [03/Jul/2025:10:00:23 +0000] "POST /api/users HTTP/1.1" 200 54
10.0.0.99 - - [03/Jul/2025:10:00:24 +0000] "POST /api/users HTTP/1.1" 200 54
10.0.0.99 - - [03/Jul/2025:10:00:24 +0000] "POST /api/users HTTP/1.1" 429 32
192.168.1.18 - - [03/Jul/2025:10:00:25 +0000] "GET /logout HTTP/1.1" 302 0
```

**File 2: `auth.log`**
```
Jul  3 10:00:03 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2
Jul  3 10:00:04 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52342 ssh2
Jul  3 10:00:05 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52343 ssh2
Jul  3 10:00:06 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52344 ssh2
Jul  3 10:00:07 server sshd[1234]: Accepted password for admin from 10.0.0.50 port 52345 ssh2
Jul  3 10:00:09 server sshd[1235]: Failed password for invalid user test from 203.0.113.5 port 44123 ssh2
Jul  3 10:00:10 server sshd[1235]: Failed password for invalid user root from 203.0.113.5 port 44124 ssh2
Jul  3 10:00:11 server sshd[1235]: Failed password for invalid user ubuntu from 203.0.113.5 port 44125 ssh2
Jul  3 10:00:15 server sudo: johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/bin/cat /etc/shadow
Jul  3 10:00:18 server sshd[1240]: Accepted publickey for deploy from 192.168.1.100 port 39281 ssh2
Jul  3 10:00:20 server sudo: deploy : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/systemctl restart nginx
Jul  3 10:00:25 server sshd[1245]: Connection closed by 10.0.0.50 port 52345 [preauth]
```

---

## AI Usage

You are expected to use AI assistance as part of your workflow.

**Required:** Include your AI conversation history with your submission (shared link or text transcript).

We will review how you collaborated with AI as part of our evaluation.

---

## Production Context

Consider that this tool may be deployed in an evolving environment processing high volumes of log data continuously.

---

## Submission

Provide a link to a public GitHub repository containing:

1. Your solution with a README explaining how to run the tool
2. Your AI conversation history (text transcript or shared link)

---

Good luck!
