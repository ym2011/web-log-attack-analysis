# web log attack analysis
A python based security analyse tool that can find various injection payloads from web server and application logs

# Description
The tool can be used to find various web injection payloads from any webserver logs when fed into its input. This is a redistribution for the source coe : https://github.com/Sumeet-R/L7-Inspector

here are some improvement as  follows:
1) add more attack payloads and adjust it into the code instead of unzipping payloads.zip.
2) check if the file, which you input, is exits and if not exit,give you some tips. 
3) rename report with a new rule,make it more reasonable and the program. 
4) adjust the structure of the code, make it more comfortable
5) generate the Windows and Linux execution file,not only Python file.


Welcome to add or improve more accurate payloads,current attack payloads are supported as follows:
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
1) sudo yum install python3
2) python wlaa.py
3) type the path where your web access log file locates
4) do web-log-attack-analysis and wait for the result.
5) Search the Payloads to locate,here are some tips for find the location.
Windows: Ctrl+ F,type:SQL injection to locate more details, where it's attacked.
Linux: more report-202101221717-07895239.txt| grep SQL injection

```
`**** Summary of Inspection ****`
`The Report name:  report-202101221748-24926847.txt`
`The file directory: C:\web-log-attack-analysis`
`Number of SQL injection Payloads Found: 1`
`Number of Cross Site Scripting(XSS) Payloads Found: 1`
`Number of Sensitive File Download Payloads Found: 1`
`Number of LDAP Injection Payloads Found: 0`
`Number of Directory Traversal Payloads Found: 2`
`Number of Command Injection Payloads Found: 0`
`Number of XPATH Injection Payloads Found: 0`
`Number of CRLF Injection Payloads Found: 0`
`Number of Abnormal HTTP request Payloads Found: 0`
`Number of Local File Inclusion Payloads Found: 3`
`Number of Web Vulnerable Scanner Payloads Found: 1`
`Number of Zero Day Vulnerable Payloads Found: 0`
`Number of Webshell Invasion Payloads Found: 0`

`search the Payloads to locate,here are some tips for find the location.`
`Windows: Ctrl+ F,type:SQL injection to locate more details, where it's attacked.`
`Linux: more report-202101221717-07895239.txt| grep SQL injection`

`Possible SQL injection web payloads found:`
`10.10.4.88 - - [10/Jul/2020:15:37:56 +0800] "GET /dashboard/?param=-1+UNION+SELECT+GROUP_CONCAT(table_name)+FROM+information_schema.tables HTTP/1.1" 200 7576 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21"`


```

