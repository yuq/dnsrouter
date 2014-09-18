# smart router
#
# 1. route DNS query poisoned by GFW through VPN and secure DNS server
# 2. route IP blocked by GFW through VPN
# 3. normal trafic not affected
# 4. blacklist can contain DNS names which are resolved at last time by DNS proxy
#
# http://www.samsonly.us/?p=85
# https://github.com/dboyd13/DSVR

import dnslib
import dnslib.server
import re
import subprocess

DNSBlacklist = (re.compile('(.+\.)?youtube\.com\.'), 
                re.compile('(.+\.)?google\.com\.'))

# TODO: can contain IP and DNS name
IPBlacklist = (re.compile('(.+\.)?youtube\.com\.'), 
               re.compile('(.+\.)?google\.com\.'))

class ProxyResolver(dnslib.server.BaseResolver):
    def dnsMatch(self,name,blacklist):
        for p in blacklist:
            if p.match(name):
                return True
        return False

    def resolve(self,request,handler):
        secureDNS = False
        for q in request.questions:
            if self.dnsMatch(str(q.qname),DNSBlacklist):
                secureDNS = True
                break

        if secureDNS:
            host = '8.8.4.4'
            print 'DNS secure route ' + str(q.qname)
        else:
            host = '172.10.6.3'
        proxy_r = request.send(host)
        reply = dnslib.DNSRecord.parse(proxy_r)

        # route all IP to VPN if one name matches blacklist
        # TODO: not accurate enough, must consider CNAME and DNAME type record
        secureIP = False
        for r in reply.rr:
            if self.dnsMatch(str(r.rname),IPBlacklist):
                secureIP = True
                break
        if secureIP:
            for r in reply.rr:
                if r.rtype == dnslib.QTYPE.A:
                    print 'IP secure route ' + str(r.rdata)
                    subprocess.call(['ipset','add','vpn',str(r.rdata)])
        return reply

if __name__ == '__main__':
    # create ipset for DNSProxy to add IP to, these IP will be routed to VPN
    subprocess.call(['ipset','create','vpn','hash:net'])
    # mark packet match vpn ipset with mark 1
    subprocess.call(['iptables','-t','mangle','-A','PREROUTING','-m','set','--match-set','vpn','dst','-j','MARK','--set-mark','1'])
    # route packet with mark 1 with table 1
    subprocess.call(['ip','rule','add','fwmark','1','table','1'])
    # add rule to table 1, route all to ppp0 and ppp0's gateway, ppp0 is the VPN
    subprocess.call(['ip','route','add','default','via','172.10.36.1','dev','ppp0','table','1'])
    # add secure DNS IP to vpn ipset to route to ppp0
    subprocess.call(['ipset','add','vpn','8.8.4.4'])

    resolver = ProxyResolver()
    server = dnslib.server.DNSServer(resolver,address='127.0.0.1')
    server.start()
