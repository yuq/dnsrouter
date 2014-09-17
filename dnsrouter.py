import dnslib
import dnslib.server
import time

class ProxyResolver(dnslib.server.BaseResolver):
    def resolve(self,request,handler):
        for q in request.questions:
            print 'Q=' + str(q.qname)
        proxy_r = request.send('172.10.6.3')
        reply = dnslib.DNSRecord.parse(proxy_r)
        for r in reply.rr:
            if r.rtype == dnslib.QTYPE.A:
                print 'R=' + str(r.rdata)
        return reply

if __name__ == '__main__':
    resolver = ProxyResolver()
    server = dnslib.server.DNSServer(resolver,address='127.0.0.1')
    server.start()
