Finding your DNS server
=========================
It can sometimes be difficult to know which DNS server you are really using - for various reasons, including:
* DNS traffic hijacking by local malware
* DNS traffic hijacking by your local router/CPE
* DNS traffic hijacking by your ISP
* Complicated corporate resolver forwarding setups

To find out which DNS server is actually doing recursin for you find your operating system below and run the commands:

* Linux/OSX/BSD:
** Using dig (or drill, although it does not support +short):
    $ dig +short check.censurfridns.dk txt
    "Congratulations. You are using censurfridns / uncensoreddns :)"
    "Your DNS server IP is 2002:d596:2a92:1:73:53::"
In this example my configured DNS server is using the IP 2002:d596:2a92:1:73:53:: to do recursion. The message
also tells me that this is one of the IPs used by censurfridns / uncensoreddns. So all is well.

    $ dig @8.8.8.8 +short check.censurfridns.dk txt
    "Your DNS server IP is 2a00:1450:4010:c0e::109"
    "You are NOT using censurfridns / uncensoreddns :("
In this example I am telling the dig command to ask Googles 8.8.8.8 server and I get a different answer. The
IP doing recursion in this case is 2a00:1450:4010:c0e::109 which is not an IP used by censurfridns / uncensoreddns.

* Windows:
** Using nslookup:
    C:\>nslookup -type=txt check.censurfridns.dk
    Server:  ns1.bornfiber.dk
    Address:  185.96.88.32

    Non-authoritative answer:
    check.censurfridns.dk   text = "You are NOT using censurfridns / uncensoreddns :("
    check.censurfridns.dk   text = "Your DNS server IP is 185.96.88.32"

    check.censurfridns.dk   nameserver = dnscheck.censurfridns.dk
    dnscheck.censurfridns.dk        internet address = 178.63.198.116
    dnscheck.censurfridns.dk        AAAA IPv6 address = 2a01:4f8:121:4c6:178:63:198:116
In this example my configured DNS server is using the IP 185.96.88.32 to do recursion. The message
also tells me that IP is not used by censurfridns / uncensoreddns.

    C:\>nslookup -type=txt check.censurfridns.dk 8.8.8.8
    Server:  google-public-dns-a.google.com
    Address:  8.8.8.8

    Non-authoritative answer:
    check.censurfridns.dk   text = "Your DNS server IP is 74.125.73.75"
    check.censurfridns.dk   text = "You are NOT using censurfridns / uncensoreddns :("

    C:\>
In this example I am telling nslookup to ask Googles 8.8.8.8 server instead of my configured DNS server, 
and I get a different answer. IP doing recursion in this case is 74.125.73.75, one of Googles IPs.
