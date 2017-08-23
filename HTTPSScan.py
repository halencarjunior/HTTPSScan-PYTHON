#!/usr/bin/env python

import argparse
import socket, ssl, sys
import OpenSSL
import requests
import codecs

VERSION="1.8.2-PYTHON"
MESSAGE="HTTPSScan Version 1.8.2-PYTHON\n\n"

def ssl2(ip,port):
    print ('==> Checking SSLv2 (CVE-2011-1473) (CVE-2016-0800)')
    packet = "<packet>TEST</packet>"
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.options &= ~ssl.OP_NO_SSLv3
    #context.set_ciphers("RC4")

    #context = ~ssl.OP_NO_SSLv3

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = context.wrap_socket(s)

    try:
        ssl_sock.connect((ip,port))
        print ("  [*] SSLv2 - Server Vulnerable")
        print ("  [*] Used Protocol: " + ssl_sock.version())
        print ("  [*] Used Cipher: " + ssl_sock.cipher()[0] + " - " + ssl_sock.cipher()[1])
    except ssl.SSLError as e:
            if e.errno == ssl.SSLZeroReturnError:
                print ("  [+] SSLv2 - Can't Connect to SSLv2")
            elif e.errno == ssl.SSL_ERROR_SSL:
                print ("  [+] SSLv2 - Server not Vulnerable")
            else:
                print ("  [+] SSLv2 - Server not Vulnerable")

def crime(ip,port):
    print("==> Testing for CRIME (CVE-2012-4929)")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = ssl.wrap_socket(s)

    ssl_sock.connect((ip,port))
    if(str(ssl_sock.compression()) == "None"):
        print("  [+] Not Vulnerable - Crime (No TLS Compression)")
    else:
        print("  [*] Vulnerable - Crime (TLS Compression)")

    return

def rc4(ip,port):
    print("==> Testing for RC4 (CVE-2013-2566)")
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.set_ciphers("RC4")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = context.wrap_socket(s)

    try:
        ssl_sock.connect((ip,port))
        print("  [*] Vulnerable - Ciper: " + ssl_sock.cipher()[0] + " - Protocol Version: " + str(ssl_sock.cipher()[1]) + " " + str(ssl_sock.cipher()[2]) + "bits")
    except ssl.SSLError as e:
            if e.errno == ssl.SSLZeroReturnError:
                print ("  [+] RC4 - Can't Connect")
            elif e.errno == ssl.SSL_ERROR_SSL:
                print ("  [+] RC4 - Server not Vulnerable")
            else:
                print ("  [+] RC4 - Server not Vulnerable")

def heartbleed(ip,port):
    print("==> Testing for Heartbleed (CVE-2014-0160)")
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv2

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((ip,port))
    mensagem =  codecs.decode('16030200310100002d0302500bafbbb75ab83ef0ab9ae3f39c6315334137acfd6c181a2460dc4967c2fd960000040033c01101000000','hex')
    s.send(mensagem)
    # python2.7
    #s.send("16030200310100002d0302500bafbbb75ab83ef0ab9ae3f39c6315334137acfd6c181a2460dc4967c2fd960000040033c01101000000".decode('hex'))

    responsehb = s.recv(8196)
    mensagem2 = codecs.decode('1803020003014000','hex')
    s.send(mensagem2)
    #python2.7
    #s.send("1803020003014000".decode('hex'))
    datahb = s.recv(8196)
    if (datahb[:500] == ''):
        print ("  [+] Heartbleed - Server not Vulnerable")
    else:
        print ("  [+] Heartbleed - Vulnerable")

    ##print(datahb[:500])

    #try:
    #    ssl_sock.connect((ip,port))
    #    ssl_sock.do_handshake()
    #    print(ssl_sock.getpeercert(True))
    #    print(ssl_sock.getsockname())

    #    print("- [*] Vulnerable - Heartbleed: " + ssl_sock.cipher()[0] + " - Protocol Version: " + str(ssl_sock.cipher()[1]) + " " + str(ssl_sock.cipher()[2]) + "bits")
    #except ConnectionError as erro:
    #    print("- [+] Not Vulnerable - Heartbleed" + erro)

def poodle(ip,port):
    print("==> Testing for Poodle (CVE-2014-3566)")
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv2
    #context.verify_mode = ssl.CERT_REQUIRED
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = context.wrap_socket(s)

    try:
        ssl_sock.connect((ip,port))
        ssl_sock.do_handshake()
        print("  [*] Vulnerable to Poodle SSLv3 - Cipher: " + ssl_sock.cipher()[0] + " - Protocol Version: " + str(ssl_sock.cipher()[1]) + " " + str(ssl_sock.cipher()[2]) + "bits")
    except ssl.SSLError as e:
            if e.errno == ssl.SSLZeroReturnError:
                print ("  [+] Poodle - Can't Connect")
            elif e.errno == ssl.SSL_ERROR_SSL:
                print ("  [+] Poodle - Server not Vulnerable")
            else:
                print ("  [+] Poodle - Server not Vulnerable")

def freak(ip,port):
    print("==> Testing for FREAK (CVE-2015-0204)")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = ssl.wrap_socket(s, ciphers="EXPORT")
    try:
        ssl_sock.connect((ip,port))
        if(str(ssl_sock.cipher()[0]) == " "):
            print("  [+] Not Vulnerable - Freak (CVE-2015-0204)")
        else:
            print("  [*] Vulnerable - Freak (CVE-2015-0204)")
            print ("  [*] Used Protocol: " + ssl_sock.version())
            print ("  [*] Used Cipher: " + ssl_sock.cipher()[0] + " - " + ssl_sock.cipher()[1])
    except ssl.SSLError as e:
            if e.errno == ssl.SSLZeroReturnError:
                print ("  [+] Freak - Can't Connect")
            elif e.errno == ssl.SSL_ERROR_SSL:
                print ("  [+] Freak - Server not Vulnerable")
            else:
                print ("  [+] Freak - Server not Vulnerable")

def null(ip,port):
    print("==> Testing for NULL Cipher")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = ssl.wrap_socket(s, ciphers="NULL")
    try:
        ssl_sock.connect((ip,port))
        if(str(ssl_sock.cipher()[0]) == " "):
            print("  [+] Not Vulnerable - Null Cipher")
        else:
            print("  [*] Vulnerable - Null Cipher")
            print ("  [*] Used Protocol: " + ssl_sock.version())
            print ("  [*] Used Cipher: " + ssl_sock.cipher()[0] + " - " + ssl_sock.cipher()[1])
    except ssl.SSLError as e:
            if e.errno == ssl.SSLZeroReturnError:
                print ("  [+] Null Cipher - Can't Connect")
            elif e.errno == ssl.SSL_ERROR_SSL:
                print ("  [+] Null Cipher - Server not Vulnerable")
            else:
                print ("  [+] Null Cipher - Server not Vulnerable")

def weak40(ip,port):
    print("==> Testing for Weak Ciphers - EXPORT40")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = ssl.wrap_socket(s, ciphers="EXPORT40")
    try:
        ssl_sock.connect((ip,port))
        if(str(ssl_sock.cipher()[0]) == " "):
            print("  [+] Not Vulnerable - Weak Ciphers - EXPORT40")
        else:
            print("  [*] Vulnerable - Weak Ciphers - EXPORT40")
            print ("  [*] Used Protocol: " + ssl_sock.version())
            print ("  [*] Used Cipher: " + ssl_sock.cipher()[0] + " - " + ssl_sock.cipher()[1])
    except ssl.SSLError as e:
            if e.errno == ssl.SSLZeroReturnError:
                print ("  [+] Weak Ciphers EXPORT40 - Can't Connect")
            elif e.errno == ssl.SSL_ERROR_SSL:
                print ("  [+] Weak Ciphers EXPORT40 - Server not Vulnerable")
            else:
                print ("  [+] Weak Ciphers EXPORT40 - Server not Vulnerable")

def forward(ip,port):
    print("==> Testing for Forward Secrecy")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    ssl_sock = ssl.wrap_socket(s, ciphers="ECDH:DH")
    try:
        ssl_sock.connect((ip,port))
        if(str(ssl_sock.cipher()[0]) == " " or str(ssl_sock.cipher()[0]) == "(NONE)" ):
            print("  [+] Not Vulnerable - Forward Secrecy")
        else:
            print("  [*] Vulnerable - Forward Secrecy")
            print ("  [*] Used Protocol: " + ssl_sock.version())
            print ("  [*] Used Cipher: " + ssl_sock.cipher()[0] + " - " + ssl_sock.cipher()[1])
    except ssl.SSLError as e:
            if e.errno == ssl.SSLZeroReturnError:
                print ("  [+] Weak Ciphers Forward Secrecy - Can't Connect")
            elif e.errno == ssl.SSL_ERROR_SSL:
                print ("  [+] Weak Ciphers Forward Secrecy - Server not Vulnerable")
            else:
                print ("  [+] Weak Ciphers Forward Secrecy - Server not Vulnerable")

def main():
    parser = argparse.ArgumentParser(prog='HTTPSScan', formatter_class=argparse.RawDescriptionHelpFormatter,
    description='''
:::    ::::::::::::::::::::::::::::::::::  ::::::::  ::::::::  ::::::::     :::    ::::    :::
:+:    :+:    :+:        :+:    :+:    :+::+:    :+::+:    :+::+:    :+:  :+: :+:  :+:+:   :+:
+:+    +:+    +:+        +:+    +:+    +:++:+       +:+       +:+        +:+   +:+ :+:+:+  +:+
+#++:++#++    +#+        +#+    +#++:++#+ +#++:++#+++#++:++#+++#+       +#++:++#++:+#+ +:+ +#+
+#+    +#+    +#+        +#+    +#+              +#+       +#++#+       +#+     +#++#+  +#+#+#
#+#    #+#    #+#        #+#    #+#        #+#    #+##+#    #+##+#    #+##+#     #+##+#   #+#+
###    ###    ###        ###    ###        ########  ########  ######## ###     ######    ####

Version 1.8.2-PYTHON by Alexos Core Labs
Ported to Python by Humberto Jr

Script for testing the SSL/TLS Protocols
Check for SSL/TLS Vulnerabilities

''')
    parser.add_argument('-H', '--host', nargs='?', required=True, help='IP or Hostname of target')
    parser.add_argument('-p', '--port', nargs='?', type=int, help='Port of target. Default=443', default='443')
    parser.add_argument('-a', '--all', action='store_true', help='Use all options')
    parser.add_argument('--ssl2', action='store_true', help='SSLv2 (CVE-2011-1473) (CVE-2016-0800)')
    parser.add_argument('--crime', action='store_true', help='TLS CRIME (CVE-2012-4929)')
    parser.add_argument('--rc4', action='store_true', help='RC4 (CVE-2013-2566)')
    parser.add_argument('--heartbleed', action='store_true', help='Heartbleed (CVE-2014-0160)')
    parser.add_argument('--poodle', action='store_true', help='Poodle (CVE-2014-3566)')
    parser.add_argument('--freak', action='store_true', help='FREAK (CVE-2015-0204)')
    parser.add_argument('--null', action='store_true', help='Search for null')
    parser.add_argument('--weak40', action='store_true', help='Search for weak40')
    parser.add_argument('--forward', action='store_true', help='Search for forward')
    parser.add_argument('--version', action='version', version='%(prog)s 1.8.2-PYTHON')
    args = parser.parse_args()

    hostip = args.host
    hostport = args.port
    #print(MESSAGE)

    if(args.all == True):
        print(parser.description)
        ssl2(hostip,hostport)
        crime(hostip,hostport)
        rc4(hostip,hostport)
        heartbleed(hostip,hostport)
        poodle(hostip,hostport)
        freak(hostip,hostport)
        null(hostip,hostport)
        weak40(hostip,hostport)
        forward(hostip,hostport)
        quit()

    if (args.ssl2 == True):
        print(parser.description)
        ssl2(hostip,hostport)
    if (args.crime == True):
        print(parser.description)
        crime(hostip,hostport)
    if (args.rc4 == True):
        print(parser.description)
        rc4(hostip,hostport)
    if (args.heartbleed == True):
        print(parser.description)
        heartbleed(hostip,hostport)
    if (args.poodle == True):
        print(parser.description)
        poodle(hostip,hostport)
    if (args.freak == True):
        print(parser.description)
        freak(hostip,hostport)
    if (args.null == True):
        print(parser.description)
        null(hostip,hostport)
    if (args.weak40 == True):
        print(parser.description)
        weak40(hostip,hostport)
    if (args.forward == True):
        print(parser.description)
        forward(hostip,hostport)

if __name__ == '__main__':
    main()
