# web log attack analysis
A python based security analyse tool that can find various injection payloads from web server and application logs 

The blog : https://blog.csdn.net/qq_29277155/article/details/107236416

# Description

The tool can be used to find various web injection payloads from any webserver logs when fed into its input，welcome to add or improve more accurate payloads.

# Attack payloads 
01) SQL Injection
02) Cross-Site-Scripting
03) sensitive file download 
04) LDAP Injection 
05) Directory Traversal
06) Command Injection
07) XPATH Injection
08) CRLF Injection
09) Abnormal HTTP request
10) local File Inclusion
11) web vulnerable scanner
12) zero day vulnerable
13) webshell invasion detection 

# Installation and run 
1) sudo yum install python3.
2) python wlaa.py or ./wlaw on linux  or wlaw.exe on windows.
3) type the path where your web access log file locates.
4) do web-log-attack-analysis and wait for the result.

# Result and find out more
1) see top 100 of the most frequently attack IP address. 
2)Search the Payloads to locate,here are some tips for find the location.
3)Windows: Ctrl+ F,type:SQL injection to locate more details, where it's attacked. 
4)Linux: more report-202101221717-07895239.txt| grep SQL injection.  

```bash
The most frequently attack IP address and attack Count are: 
[('10.10.4.88', 2919), ('10.20.4.88', 8), ('10.10.4.80', 2), ('10.20.4.89', 1), ('10.10.4.87', 1)]
**** Summary of Inspection ****
The Report name:  report-202105281155.txt 
The file directory: E:\code\web-log-attack-analysis
Number of SQL injection Payloads Found:  358
```