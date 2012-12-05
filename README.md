tykdnscheck
=============
Simple authorative DNS server designed to return the IP of the client that asked it (usually the configured recursive DNS server). This script does not serve actual DNS data.

The script replies with SERVFAIL for all querytypes other than TXT, and it replies with REFUSED for all domains other than the configured one.

tykdnscheck is written in Python, authored by Thomas Steen Rasmussen <thomas@gibfest.dk>. 

Latest version can always be found at https://github.com/tykling/tykdnscheck


Usage
=======
    $ ./tykdnscheck.py -h
    usage: tykdnscheck.py [-h] -p {4,6} -d DOMAIN [-i [IP [IP ...]]]
                          [-g GOODREPLY] [-b BADREPLY] [-l LOGFILE] [-U USER]
                          [-G GROUP]

    optional arguments:
      -h, --help            show this help message and exit
      -p {4,6}, --protocol {4,6}
                            Choose Ipv4 or IPv6 (required)
      -d DOMAIN, --domain DOMAIN
                        The domain name to serve (remember trailing .) (required)
      -i [IP [IP ...]], --ip [IP [IP ...]]
                            One or more "good" IP addresses to trigger the message in --goodreply, leave out to disable check
      -g GOODREPLY, --goodreply GOODREPLY
                            The message to return if the client IP matches --ip
      -b BADREPLY, --badreply BADREPLY
                            The message to return if the client IP doesn't match --ip
      -l LOGFILE, --logfile LOGFILE
                            The logfile to write output to
      -U USER, --user USER  Which user to drop privileges to after logfile open & port bind
      -G GROUP, --group GROUP
                            Which group to drop privileges to after logfile open & port bind


Running the script
===================
    sudo ./tykdnscheck.py -p 4 -d check.censurfridns.dk. -i 89.233.43.71 89.233.43.72 89.233.43.73 89.104.194.142 -g "Congratulations. You are using censurfridns / uncensoreddns" -b "You are NOT using censurfridns / uncensoreddns :("
The above example will start an IPv4 instance of the script, which will check client IP and return an extra message depending on whether the client IP matches one of the ones given in -i:

    $ dig +short check.censurfridns.dk txt
    "Your DNS server IP is 89.233.43.72"
    "Congratulations. You are using censurfridns / uncensoreddns"
    $

If the script was started without -i the reply would only contain a single TXT record with the DNS server IP.


Querying the script
=====================
Using dig:

    $ dig +short check.censurfridns.dk txt
    "Congratulations. You are using censurfridns / uncensoreddns"
    "Your DNS server IP is 89.233.43.72"
    $

Using nslookup:

    C:\>nslookup -type=txt check.censurfridns.dk
    Server:  ns1.censurfridns.dk
    Address:  2002:d596:2a92:1:71:53::
    
    Non-authoritative answer:
    check.censurfridns.dk   text =
    
            "Congratulations. You are using censurfridns / uncensoreddns"
    check.censurfridns.dk   text =
    
            "Your DNS server IP is 89.233.43.72"
    
    check.censurfridns.dk   nameserver = dnscheck.censurfridns.dk
    dnscheck.censurfridns.dk        internet address = 178.63.198.116
    dnscheck.censurfridns.dk        AAAA IPv6 address = 2a01:4f8:121:4c6:178:63:198:116

    C:\>
