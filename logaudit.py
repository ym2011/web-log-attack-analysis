#!/usr/bin/python3
# coding=utf-8
# authors: ym2011
# time: 2021-01-21
# version: 1.1

import datetime
import pathlib
import os

# SQL  injection
sqli = [
    'SELECT%20',
    '%20union%20',
    'concat%28',
    'concat(',
    'create%20OR%20replace',
    'declare%20',
    'information%5Fschema%2Ecolumns',
    'information_schema.columns',
    'information%5Fschema%2Etables',
    'information_schema.tables',
    '%40%40version*',
    '@@version',
    'sleep(',
    'sleep%28',
    'version%28*',
    'version(',
    'SUBSTRING%28',
    'SUBSTRING(',
    'SUBSTR(',
    'SUBSTR%28',
    'WAITFOR%20'

]

# Cross-Site-Scripting(XSS)
xss = [
    '<script>',
    '%3Cscript%3E',
    'alert(1)',
    'alert%281%29',
    'onactivate=',
    'onactivate%3D',
    'onafterprint=',
    'onafterscriptexecute=',
    'onanimationcancel=',
    'onanimationend=',
    'onanimationiteration=',
    'onanimationstart=',
    'onauxclick=',
    'onbeforeactivate=',
    'onbeforecopy=',
    'onbeforecut=',
    'onbeforedeactivate=',
    'onbeforepaste=',
    'onbeforeprint=',
    'onbeforescriptexecute=',
    'onbeforeunload=',
    'onbegin=',
    'onblur=',
    'onbounce=',
    'oncanplay=',
    'oncanplaythrough=',
    'onchange=',
    'onclick=',
    'oncontextmenu=',
    'oncopy=',
    'oncut=',
    'ondblclick=',
    'ondeactivate=',
    'ondrag=',
    'ondragend=',
    'ondragenter=',
    'ondragleave=',
    'ondragover=',
    'ondragstart=',
    'ondrop=',
    'onend=',
    'onended=',
    'onerror=',
    'onfinish=',
    'onfocus=',
    'onfocusin=',
    'onfocusout=',
    'onfullscreenchange=',
    'onhashchange=',
    'oninput=',
    'oninvalid=',
    'onkeydown=',
    'onkeypress=',
    'onkeyup=',
    'onload=',
    'onloadeddata=',
    'onloadedmetadata=',
    'onloadend=',
    'onloadstart=',
    'onmessage=',
    'onmousedown=',
    'onmouseenter=',
    'onmouseleave=',
    'onmousemove=',
    'onmouseout=',
    'onmouseover=',
    'onmouseup=',
    'onmozfullscreenchange=',
    'onpageshow=',
    'onpaste=',
    'onpause=',
    'onplay=',
    'onplaying=',
    'onpointerdown=',
    'onpointerenter=',
    'onpointerleave=',
    'onpointermove=',
    'onpointerout=',
    'onpointerover=',
    'onpointerrawupdate=',
    'onpointerup=',
    'onpopstate=',
    'onreadystatechange=',
    'onrepeat=',
    'onreset=',
    'onresize=',
    'onscroll=',
    'onsearch=',
    'onseeked=',
    'onseeking=',
    'onselect=',
    'onstart=',
    'onsubmit=',
    'ontimeupdate=',
    'ontoggle=',
    'ontouchend=',
    'ontouchmove=',
    'ontouchstart=',
    'ontransitioncancel=',
    'ontransitionend=',
    'ontransitionrun=',
    'onunhandledrejection=',
    'onunload=',
    'onvolumechange=',
    'onwaiting=',
    'onwebkitanimationend=',
    'onwebkitanimationstart=',
    'onwebkittransitionend=',
    'onwheel=',
    'onafterprint%3D',
    'onafterscriptexecute%3D',
    'onanimationcancel%3D',
    'onanimationend%3D',
    'onanimationiteration%3D',
    'onanimationstart%3D',
    'onauxclick%3D',
    'onbeforeactivate%3D',
    'onbeforecopy%3D',
    'onbeforecut%3D',
    'onbeforedeactivate%3D',
    'onbeforepaste%3D',
    'onbeforeprint%3D',
    'onbeforescriptexecute%3D',
    'onbeforeunload%3D',
    'onbegin%3D',
    'onblur%3D',
    'onbounce%3D',
    'oncanplay%3D',
    'oncanplaythrough%3D',
    'onchange%3D',
    'onclick%3D',
    'oncontextmenu%3D',
    'oncopy%3D',
    'oncut%3D',
    'ondblclick%3D',
    'ondeactivate%3D',
    'ondrag%3D',
    'ondragend%3D',
    'ondragenter%3D',
    'ondragleave%3D',
    'ondragover%3D',
    'ondragstart%3D',
    'ondrop%3D',
    'onend%3D',
    'onended%3D',
    'onerror%3D',
    'onfinish%3D',
    'onfocus%3D',
    'onfocusin%3D',
    'onfocusout%3D',
    'onfullscreenchange%3D',
    'onhashchange%3D',
    'oninput%3D',
    'oninvalid%3D',
    'onkeydown%3D',
    'onkeypress%3D',
    'onkeyup%3D',
    'onload%3D',
    'onloadeddata%3D',
    'onloadedmetadata%3D',
    'onloadend%3D',
    'onloadstart%3D',
    'onmessage%3D',
    'onmousedown%3D',
    'onmouseenter%3D',
    'onmouseleave%3D',
    'onmousemove%3D',
    'onmouseout%3D',
    'onmouseover%3D',
    'onmouseup%3D',
    'onmozfullscreenchange%3D',
    'onpageshow%3D',
    'onpaste%3D',
    'onpause%3D',
    'onplay%3D',
    'onplaying%3D',
    'onpointerdown%3D',
    'onpointerenter%3D',
    'onpointerleave%3D',
    'onpointermove%3D',
    'onpointerout%3D',
    'onpointerover%3D',
    'onpointerrawupdate%3D',
    'onpointerup%3D',
    'onpopstate%3D',
    'onreadystatechange%3D',
    'onrepeat%3D',
    'onreset%3D',
    'onresize%3D',
    'onscroll%3D',
    'onsearch%3D',
    'onseeked%3D',
    'onseeking%3D',
    'onselect%3D',
    'onstart%3D',
    'onsubmit%3D',
    'ontimeupdate%3D',
    'ontoggle%3D',
    'ontouchend%3D',
    'ontouchmove%3D',
    'ontouchstart%3D',
    'ontransitioncancel%3D',
    'ontransitionend%3D',
    'ontransitionrun%3D',
    'onunhandledrejection%3D',
    'onunload%3D',
    'onvolumechange%3D',
    'onwaiting%3D',
    'onwebkitanimationend%3D',
    'onwebkitanimationstart%3D',
    'onwebkittransitionend%3D',
    'onwheel%3D'
]

# sensitive file download
sfd = [
    '.svn',
    '.bak',
    '.rar',
    '.zip',
    '.backup',
    '.sql',
    '.mdb',
    '.nsf',
    '.java',
    'bash',
    'login.inc.php',
    'config.inc.php'

]

# Command_Injection
Command_Injection = [
    '\cmd.exe',
    '/bin/sh',
    '/bin/bash',
    '/usr/bin/id',
    'echo%',
    'ifconfig',
    '/etc/passwd',
    '/etc/shadow',
    '|id',
    ';id',
    ';netstat',
    ';system(',
    '\n/bin/ls',
    '\nid',
    '\nid;',
    '`id`',
    '%26%20ping%20-i',
    '%26%20ping%20-n',
    '%60ping',
    '%7C%20id',
    '%26%20id',
    '%3B%20id',
    '%5Ccmd.exe',
    '%2Fbin%2Fsh',
    '%2Fbin%2Fbash',
    '%5Ccmd.exe',
    '%2Fbin%2Fsh',
    '%2Fbin%2Fbash',
    '%2Fusr%2Fbin%2Fid',
    '%2Fetc%2Fpasswd',
    '%2Fetc%2Fshadow',
    '%7Cid',
    '%3Bid',
    '%3Bnetstat',
    '%3Bsystem%28',
    '%5Cn%2Fbin%2Fls%20',
    '%5Cnid',
    '%5Cnid%3B',
    '%60id%60',
    '`whoami',
    '`pwd',
    '`grep',
    '`uname',
    '%60whoami',
    '%60pwd',
    '%60grep',
    '%60uname',
    '|dir',
    ';dir',
    '%7Cdir',
    '%3Bdir',
    '%7C%20dir',
    '%3B%20dir',
    'eval(',
    'exec(',
    '$_GET[',
    'ipconfig%20',
    'eval%28',
    'exec%28',
    '%24_GET%5B',
    'ls%20-l',
    'net%20view',
    'perl%20-e',
    'phpinfo()',
    'phpversion()',
    '$_SERVER',
    '%24_SERVER',
    ';%20pwd',
    'phpinfo%28%29',
    'phpversion%28%29'

]

# CRLF Injection, http response splitting attack CR，ASCII 13，\r，%0d) LF，ASCII 10，\n，%0a)
crlf = [
    '%0AHeader-Test:BLATRUC',
    '%0A%20Header-Test:BLATRUC',
    '%20%0AHeader-Test:BLATRUC',
    '%23%OAHeader-Test:BLATRUC',
    '%E5%98%8A%E5%98%8DHeader-Test:BLATRUC',
    '%E5%98%8A%E5%98%8D%0AHeader-Test:BLATRUC',
    '%3F%0AHeader-Test:BLATRUC',
    'crlf%0AHeader-Test:BLATRUC',
    'crlf%0A%20Header-Test:BLATRUC',
    'crlf%20%0AHeader-Test:BLATRUC',
    'crlf%23%OAHeader-Test:BLATRUC',
    'crlf%E5%98%8A%E5%98%8DHeader-Test:BLATRUC',
    'crlf%E5%98%8A%E5%98%8D%0AHeader-Test:BLATRUC',
    'crlf%3F%0AHeader-Test:BLATRUC',
    '%0DHeader-Test:BLATRUC',
    '%0D%20Header-Test:BLATRUC',
    '%20%0DHeader-Test:BLATRUC',
    '%23%0DHeader-Test:BLATRUC',
    '%23%0AHeader-Test:BLATRUC',
    '%E5%98%8A%E5%98%8DHeader-Test:BLATRUC',
    '%E5%98%8A%E5%98%8D%0DHeader-Test:BLATRUC',
    '%3F%0DHeader-Test:BLATRUC',
    'crlf%0DHeader-Test:BLATRUC',
    'crlf%0D%20Header-Test:BLATRUC',
    'crlf%20%0DHeader-Test:BLATRUC',
    'crlf%23%0DHeader-Test:BLATRUC',
    'crlf%23%0AHeader-Test:BLATRUC',
    'crlf%E5%98%8A%E5%98%8DHeader-Test:BLATRUC',
    'crlf%E5%98%8A%E5%98%8D%0DHeader-Test:BLATRUC',
    'crlf%3F%0DHeader-Test:BLATRUC',
    '%0D%0AHeader-Test:BLATRUC',
    '%0D%0A%20Header-Test:BLATRUC',
    '%20%0D%0AHeader-Test:BLATRUC',
    '%23%0D%0AHeader-Test:BLATRUC',
    '\r\nHeader-Test:BLATRUC',
    '%5cr%5cnHeader-Test:BLATRUC',
    '%E5%98%8A%E5%98%8DHeader-Test:BLATRUC',
    '%E5%98%8A%E5%98%8D%0D%0AHeader-Test:BLATRUC',
    '%3F%0D%0AHeader-Test:BLATRUC',
    'crlf%0D%0AHeader-Test:BLATRUC',
    'crlf%0D%0A%20Header-Test:BLATRUC',
    'crlf%20%0D%0AHeader-Test:BLATRUC',
    'crlf%23%0D%0AHeader-Test:BLATRUC',
    'crlf\r\nHeader-Test:BLATRUC',
    'crlf%5cr%5cnHeader-Test:BLATRUC',
    'crlf%E5%98%8A%E5%98%8DHeader-Test:BLATRUC',
    'crlf%E5%98%8A%E5%98%8D%0D%0AHeader-Test:BLATRUC',
    'crlf%3F%0D%0AHeader-Test:BLATRUC',
    '%0D%0A%09Header-Test:BLATRUC',
    'crlf%0D%0A%09Header-Test:BLATRUC',
    '%250AHeader-Test:BLATRUC',
    '%25250AHeader-Test:BLATRUC',
    '%%0A0AHeader-Test:BLATRUC',
    '%25%30AHeader-Test:BLATRUC',
    '%25%30%61Header-Test:BLATRUC',
    '%u000AHeader-Test:BLATRUC',
    '//www.google.com/%2F%2E%2E%0D%0AHeader-Test:BLATRUC',
    '/www.google.com/%2E%2E%2F%0D%0AHeader-Test:BLATRUC',
    '/google.com/%2F..%0D%0AHeader-Test:BLATRUC'

]

# Directory Traversal
Directory_Traversal = [
    '/..',
    '%2F..',
    '%2f%2e%2e'
]

# XPATH-Injection
xpath = [
    '//user[',
    '//username[',
    '//pass[',
    '//password[',
    '//employee[',
    '//emp[',
    'child::node()',
    '[position()='
]

# ldap injection
ldap_injection = [
    'C=N',
    '(uid=*',
    '%28uid%3D%2A',
    ')(&))',
    '&(directory=',
    '(objectClass=*',
    '(department=*',
    '(mail=*',
    'admin*)',
    'name()=',
    '%29%28%26%29%29',
    '%26%28directory%3D',
    '%28objectClass%3D%2A',
    '%28department%3D%2A',
    '%28mail%3D%2A',
    'admin%2A%29',
    'name%28%29%3D%27'
]

# Abnormal HTTP request
AHr = [
    'PUT',
    'TRACE',
    'OPTIONS',
    'DELETE',
    'CONNECT'
]

#local File Inclusion
lfi = [
    'web.xml',
    'spring.xml',
    'boot.ini',
    '/etc/passwd',
    'win.ini',
    'ServUDaemon.ini'
]

# web vulnerable scanner
scanner = [
    'WCRTESTINPUT000000',
    'acunetix',
    'acunetix-wvs',
    'Appscan',
    'webinspect',
    'Netsparker',
    'xray',
    'goby',
    'Openvas',
    'vul_webscan',
    'bappsec'
]


timeStamp = datetime.datetime.now().strftime('%Y%m%d%H%M' + '-%S%f')
report = "report-" + timeStamp + ".txt"


class weblogaudit:
    def logaudit(self, keyword, attacktype, log):
        f = open(log, mode='r', encoding='utf-8')
        r = open(report, "a")
        for i in f.readlines():
            if keyword in i:
                r.write("\nPossible " + attacktype + " web payloads found:\n")
                r.write(i)

    def summarize(self):
        with open(report, mode='r+', encoding='utf-8') as f:
            data = f.read()
            f.seek(0)  # 移动文件读取指针到
            print("**** Summary of Inspection ****", timeStamp, file=f)
            print("Report name : ", report, "\nThe file directory :", pathlib.Path.cwd(), file=f)
            print("Number of SQL injection Payloads Found: " + str(data.count("SQL-Injection")), file=f)
            print("Number of Cross Site Scripting Payloads Found: " + str(data.count("Cross-Site-Scripting(XSS)")),
                  file=f)
            print("Number of sensitive file download Payloads Found: " + str(data.count("sensitive file download")),
                  file=f)
            print("Number of LDAP Injection Payloads Found: " + str(data.count("LDAP-Injection")), file=f)
            print("Number of Directory Traversal Payloads Found: " + str(data.count("Directory-Traversal")), file=f)
            print("Number of Command Injection Payloads Found: " + str(data.count("Command-Injection")), file=f)
            print("Number of XPATH Injection Payloads Found: " + str(data.count("XPATH-Injection")), file=f)
            print("Number of CRLF Injection Payloads Found: " + str(data.count("CRLF-Injection")), file=f)
            print("Number of Abnormal HTTP request Found: " + str(data.count("Abnormal HTTP request")), file=f)
            print("Number of local File Inclusion Found: " + str(data.count("local File Inclusion")), file=f)
            print("Number of web vulnerable scanner Found: " + str(data.count("web vulnerable scanner")), file=f)
            print("\nThe attack details are  here : ", file=f)
            f.write(data)


def attacktypeword():
    # SQL-Injection Payloads
    for keyword in sqli:
        weblogaudit().logaudit(keyword, "SQL-Injection", logfile)

    # Cross-Site-Scripting(XSS) Payloads
    for keyword in xss:
        weblogaudit().logaudit(keyword, "Cross-Site-Scripting(XSS)", logfile)

    # sensitive file download Payloads
    for keyword in sfd:
        weblogaudit().logaudit(keyword, "sensitive file download", logfile)

    # Directory-Traversal Payloads
    for keyword in Directory_Traversal:
        weblogaudit().logaudit(keyword, "Directory-Traversal", logfile)

    # Command-Injection Payloads
    for keyword in Command_Injection:
        weblogaudit().logaudit(keyword, "Command-Injection", logfile)

    # LDAP-Injection Payloads
    for keyword in ldap_injection:
        weblogaudit().logaudit(keyword, "LDAP-Injection", logfile)

    # XPATH-Injection Payloads
    for keyword in xpath:
        weblogaudit().logaudit(keyword, "XPATH-Injection", logfile)

    # CRLF-Injection Payloads
    for keyword in crlf:
        weblogaudit().logaudit(keyword, "CRLF-Injection", logfile)

    # Abnormal HTTP request Payloads
    for keyword in AHr:
        weblogaudit().logaudit(keyword, "Abnormal HTTP request", logfile)

    # local File Inclusion Payloads
    for keyword in lfi:
        weblogaudit().logaudit(keyword, "local File Inclusion", logfile)

    # web vulnerable scanner Payloads
    for keyword in scanner :
        weblogaudit().logaudit(keyword, "web vulnerable scanner", logfile)


if __name__ == "__main__":
    print("###########################################################")
    print("\t For finding attack, analyze the web access log such as nginx,openresty,tomcat,apache,iis.")
    print("\t know if someone tried to infiltrate your exposed web server!!!")
    print("\t Author:ym2011")
    print("###########################################################")
    print("Enter your webserver access log path:")
    inputvalue = input("\n>>>")
    my_file = pathlib.Path(inputvalue)
    if my_file.is_file():
        logfile = inputvalue
        sendkeyword = weblogaudit()
        print("\n Audit Log file " + logfile + " ...")
        attacktypeword()
        # Summarize and log to report
        sendkeyword.summarize()
        print("Report name : ", report, "\nThe file directory :", pathlib.Path.cwd())
        print(os.system("pause"))  # fix the bug for exe in windows when the program finished  without any promotion .
    else:
        print("Invalid path, please run again.")
        print(os.system("pause"))  # fix the bug for exe in windows when the program finished  without any promotion .
