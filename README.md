# weblogaudit
A python based security auditing tool that can find various injection payloads from web server and application logs

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


# Installation and run 
1) sudo yum install python3
2) python logaudit.py
3) type the path where your web access log file locates
4) waiting for the result