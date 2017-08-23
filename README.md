# HTTPSScan-PYTHON
Conversion of original HTTPSScan coded by Alexos Labs

Shell script for testing the SSL/TLS Protocols

Requirements:
- python2.7
- pyOpenSSL
- requests

  * $ pip install pyopenssl

  * $ pip install requets

  * for OpenSSL 0.9.8: 'pyOpenSSL<17.0' 'cryptography<1.4'

  * for OpenSSL 1.0.0: 'pyOpenSSL<17.1' 'cryptography<1.7'


Check for SSL/TLS Vulnerabilities:

    SSLv2 (CVE-2011-1473) (CVE-2016-0800)
    TLS CRIME (CVE-2012-4929)
    RC4 (CVE-2013-2566)
    Heartbleed (CVE-2014-0160)
    Poodle (CVE-2014-3566)
    FREAK (CVE-2015-0204)
    Weak Ciphers

Usage:

python httpsscan.py [target] [port] [option]

Options:

all, --all, a

ssl2, --ssl2

crime, --crime

rc4, --rc4

heartbleed, --heartbleed

poodle, --poodle

freak, --freak

null, --null

weak40, --weak40

forward, --forward

help, --help, h
