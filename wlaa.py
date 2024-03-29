#!/usr/bin/python3
# coding=utf-8
# authors: ym2011
# time: 2021-05-28
# version: 1.3

import datetime
import os
import pathlib
import platform
import re
import time


# SQL injection
sqi = [
    'SELECT%20',
    'select%20',
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

# Cross Site Scripting(XSS)
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

# Sensitive File Download
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
    '.bash',
    'login.inc.php',
    'config.inc.php'
]

# Command Injection
commandi = [
    'cmd.exe',
    '/bin/sh',
    '/bin/bash',
    '/usr/bin/id',
    'echo%',
    'ifconfig',
    '|id',
    ';id',
    ';netstat',
    ';system(',
    '\n/bin/ls',
    '\nid',
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
    'xp_cmdshell',
    'shell_exec'

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
directory_traversal = [
    '/..',
    '%2F..',
    '%2f%2e%2e'
]

# XPATH Injection
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

# Ldap Injection
ldap = [
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
ahr = [
    'PUT',
    'TRACE',
    'OPTIONS',
    'DELETE',
    'CONNECT'
]

# Local File Inclusion
lfi = [
    'web.xml',
    'spring.xml',
    'boot.ini',
    '/etc/passwd',
    'win.ini',
    'ServUDaemon.ini'
]

# Web Vulnerable Scanner
scanner = [
    'sqlmap',
    'acunetix',
    'acunetix-wvs',
    'Appscan',
    'webinspect',
    'Netsparker',
    'xray',
    'goby',
    'Openvas',
    'vul_webscan',
]

# Zero Day Vulnerable
zero_day = [
    'dnslog',
    'java.lang.Runtime',
    '@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS',
    'xwork2.dispatcher.HttpServletRequest',
    'java.lang.Class'
]

# Webshell Invasion
webshell = [
    'webshell',
    'k8cmd',
    'cmd.jsp',
    'mysql.jsp',
    'my_tag.js',
    '90sec.jsp',
    'hello.jsp',
]

# 字典中存储列表
attacktype = {
    'SQL injection': sqi,
    'Cross Site Scripting(XSS)': xss,
    'Sensitive File Download': sfd,
    'Directory Traversal': directory_traversal,
    'Command Injection': commandi,
    'LDAP Injection': ldap,
    'XPATH Injection': xpath,
    'CRLF Injection': crlf,
    'Abnormal HTTP Request': ahr,
    'Local File Inclusion': lfi,
    'Web Vulnerable Scanner': scanner,
    'Zero Day Vulnerable': zero_day,
    'Webshell Invasion': webshell,
}

timenow = datetime.datetime.now().strftime('%Y%m%d%H%M')
report = "report-" + timenow + ".txt"


def logaudit(log):
    f = open(log, mode='r', encoding='utf-8')
    r = open(report, "a")
    for i in f.readlines():
        for k, j in attacktype.items():  # .itmes()，它返回一个键值对列表
            for js in j:
                if js in i:
                    r.write("\nPossible " + k + " web payloads found:\n")
                    r.write(i)


def summarize():
    with open(report, mode='r+', encoding='utf-8') as f:
        data = f.read()
        f.seek(0)  # move the index to the head, in order to insert summary into head of the file.
        print("**** Summary of Inspection ****", file=f)
        print("The Report name: ", report, "\nThe file directory:", pathlib.Path.cwd(), file=f)
        print("Number of SQL injection Payloads Found: ", data.count("SQL injection"), file=f)
        print("Number of Cross Site Scripting(XSS) Payloads Found: " + str(data.count("Cross Site Scripting(XSS)")),
              file=f)
        print("Number of Sensitive File Download Payloads Found: " + str(data.count("Sensitive File Download")),
              file=f)
        print("Number of LDAP Injection Payloads Found: " + str(data.count("LDAP Injection")), file=f)
        print("Number of Directory Traversal Payloads Found: " + str(data.count("Directory Traversal")), file=f)
        print("Number of Command Injection Payloads Found: " + str(data.count("Command Injection")), file=f)
        print("Number of XPATH Injection Payloads Found: " + str(data.count("XPATH Injection")), file=f)
        print("Number of CRLF Injection Payloads Found: " + str(data.count("CRLF Injection")), file=f)
        print("Number of Abnormal HTTP request Payloads Found: " + str(data.count("Abnormal HTTP request")), file=f)
        print("Number of Local File Inclusion Payloads Found: " + str(data.count("Local File Inclusion")), file=f)
        print("Number of Web Vulnerable Scanner Payloads Found: " + str(data.count("Web Vulnerable Scanner")),
              file=f)
        print("Number of Zero Day Vulnerable Payloads Found: " + str(data.count("Zero Day Vulnerable")), file=f)
        print("Number of Webshell Invasion Payloads Found: " + str(data.count("Webshell Invasion")), file=f)
        print("\nsearch the Payloads to locate,here are some tips for find the location.", file=f)
        print("Windows: Ctrl+ F, type:SQL injection to locate more details", file=f)
        print("Linux: more report-202101221717-07895239.txt| grep SQL injection", file=f)
        f.write(data)


def ip_account():
    # IP：4个字符串，每个1到3个数字，由点连接
    ipaddress = r'\.'.join([r'\d{1,3}'] * 4)
    re_ip = re.compile(ipaddress)
    attack_ip_list = {}
    with open(report, mode='r+', encoding='utf-8') as f:
        old = f.read()
        f.seek(0)  # move the index to the head, in order to insert summary into head of the file.
        for line in f:
            match = re_ip.match(line)
            if match:
                ip = match.group()
        # 如果IP存在增加1，否则设置点击率为1
                attack_ip_list[ip] = attack_ip_list.get(ip, 0) + 1
        # value取字典中前n个最大或最小值,n=10,字典转化成list，经过排序，取得前n个值
        lists = sorted(attack_ip_list.items(), key=lambda item: item[1], reverse=True)
        lists_top10 = lists[:10]
        print(lists_top10)
        f.seek(0)  # move the index to the head, in order to insert summary into head of the file.
        print("The most frequently attack IP address and attack Count are: ", file=f)
        print(lists_top10, file=f)
        f.write(old)


def systemtype():
    # fix the bug for exe in windows when the program finished  without any promotion.
    if platform.system() == "Windows":
        print(os.system("pause"))


if __name__ == "__main__":
    print("###########################################################")
    print(" For finding attack, analyze the web access log such as nginx,openresty,tomcat,apache,iis.")
    print(" know if someone tried to infiltrate your exposed web server!!!")
    print(" Author:ym2011, version: v1.3")
    print("###########################################################")
    print("Enter your webserver access log path:")
    inputvalue = input(">>>")
    my_file = pathlib.Path(inputvalue)
    if my_file.is_file():
        logfile = inputvalue
        print("analyze Log file " + logfile + " ...")
        print("please wait for a while, maybe seconds or minutes .....")
        start_time = time.perf_counter()
        # analyze the web attack in the logs.
        logaudit(logfile)
        end_time = time.perf_counter()
        summarize()
        ip_account()
        print("Finished, it costs :", int(end_time - start_time), "s")
        print("\nReport named :", report, "\nThe location :", pathlib.Path.cwd())
        systemtype()
    else:
        print("Invalid path, please run again.")
        systemtype()
