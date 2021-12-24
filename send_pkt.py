from winpcapy import WinPcapUtils

def send(src,dst,protocol,data):
    packet = dst+src+protocol+data.encode('hex')+'00'
    print packet
    WinPcapUtils.send_packet("*Ethernet*", packet.decode("hex"))

send('dcfb4898b4a3','ffffffffffff','1234','info')
send('30e1718403f4','bc140141abc5','1234','info')
send('30e1718403f4','bc1401db77e5','1234','info')
send('30e1718403f4','bc1401db77e5','1234','CB\t0\trf 1 n')
send('30e1718403f4','bc1401db77e5','1234','CCU\tip 192.168.84.100 255.255.255.0 192.168.100.20 255.255.255.0')

send('30e1718403f4','bc1401db77e5','1234','CCU\tprelay 3011 vlan11 23 192.168.100.1 23')
send('30e1718403f4','bc1401db77e5','1234','CCU\tprelay 3012 vlan12 23 192.168.100.1 23')
send('30e1718403f4','bc1401db77e5','1234','CCU\tprelay 3013 vlan13 23 192.168.100.1 23')
send('30e1718403f4','bc1401db77e5','1234','CCU\tprelay 3014 vlan14 23 192.168.100.1 23')

send('30e1718403f4','bc1401db77e5','1234','CB\t0\t?')
send('30e1718403f4','bc1401db77e5','1234','CB\t0\tpwr 2')

# "434355097072656c6179203330313120766c616e3131203233203139322e3136382e3130302e3120323300".decode('hex')

from scapy.all import *

sendp(eval("Ether(src='dc:fb:48:98:b4:a3', dst='ff:ff:ff:ff:ff:ff', type=4660)/Raw(load='info')"))
sendp(eval("Ether(src='9c:eb:e8:34:59:3d', dst='ff:ff:ff:ff:ff:ff', type=4660)/Raw(load='info')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:41:ab:c5', type=4660)/Raw(load='info')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='info')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CB\t0\trf 1 n')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CCU\tip 192.168.84.100  255.255.255.0 192.168.100.20 255.255.255.0')"), iface="Ethernet5")

sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CCU\tprelay 3011 vlan11 23 192.168.100.1 23')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CCU\tprelay 3021 vlan11 23 192.168.100.1 23')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CCU\tprelay 3031 vlan11 23 192.168.100.1 23')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CCU\tprelay 3041 vlan11 23 192.168.100.1 23')"))

sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CB\t0\t?')"))
sendp(eval("Ether(src='30:e1:71:84:03:f4', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CB\t0\tpwr 1')"))

sr(eval("Ether(src='50:3e:aa:d3:8d:70', dst='bc:14:01:db:77:e5', type=4660)/Raw(load='CCU\tip 192.168.84.100  255.255.255.0 192.168.100.20 255.255.255.0')"), iface="Ethernet5")
a = sniff(iface="Ethernet5", prn=lambda x: x.show(), timeout=1)

"ip 192.168.84.100  255.255.255.0 192.168.100.20 255.255.255.0"

class AFI:
    def __init__(self,src):
        self.imac, self.iname = iface_ip_get_mac(src)
        self.CCU = {}
        t = AsyncSniffer(iface=self.iname, prn=lambda x: x.show())
        t.start()
        pkt = eval("Ether(src='{}', dst='ff:ff:ff:ff:ff:ff', type=4660)/Raw(load='info')".format(self.imac))
        pkt.load += b'\x00'
        sendp(pkt, iface=self.iname)
        # time.sleep(0.5)
        # sendp(eval("Ether(src='{}', dst='ff:ff:ff:ff:ff:ff', type=4660)/Raw(load='info')".format(self.imac)), iface=self.iname)
        t.stop()
        d = [i.load.decode('utf-8').split('CCU\tinfo\t')[-1] for i in t.results if 'CCU' in i.load.decode('utf-8')]
        for s in d:
            _id, _mac = int(s.split(' ')[0]), s.split(' ')[1]
            self.CCU.update({_id:_mac})
    def sccu(self, idx, cmd):
        t = AsyncSniffer(iface="Ethernet5", prn=lambda x: x.show())
        t.start()
        time.sleep(0.5)
        sendp(eval("Ether(src='{}', dst='{}', type=4660)/Raw(load='CCU\t{}')".format(self.imac,self.CCU[idx],cmd)), iface=self.iname)
        # time.sleep(0.5)
        # sendp(eval("Ether(src='{}', dst='{}', type=4660)/Raw(load='CCU\t{}')".format(self.imac,self.CCU[idx],cmd)), iface=self.iname)
        t.stop()
        try:
            r = [i.load.decode('utf-8') for i in t.results if 'OK' in i.load.decode('utf-8')][0]
            return r[0]
        except:
            return False
  
s = AFI('192.168.84.10')
s.sccu(0,"ip 192.168.84.100  255.255.255.0 192.168.100.20 255.255.255.0")
s.sccu(0,"prelay 69 eth0 69 192.168.84.10 1")
for v_ in range(1,8):
  for p_ in range(1,5):
      s.sccu(0,"prelay 30%s%s vlan%s%s 23 192.168.100.1 23"%(v_,p_,v_,p_))

ifa=iface_ip_get_mac('192.168.100.10')
t = AsyncSniffer(iface=ifa[1], prn=lambda x: x.show(),filter="tcp",lfilter=lambda d: d.dst == '98:fa:9b:44:c2:a2',count=1,timeout=2)
t.start()

b = bytes(Raw(t.results[0]))
h = bytes.hex(b)
hexdump(b)

0000  98 FA 9B 44 C2 A2 90 50 CA D4 5D 22 08 00 45 00  ...D...P..]"..E.
0010  00 34 00 00 40 00 40 06 F1 67 C0 A8 64 01 C0 A8  .4..@.@..g..d...
0020  64 0A 00 17 C2 AD 35 7C 86 74 80 E8 BA FC 80 12  d.....5|.t......
0030  72 10 F8 FA 00 00 02 04 05 B4 01 01 04 02 01 03  r...............
0040  03 06                                            ..

src = h[0:12]
dst = h[12:24]
typ = h[24:28]
vh = h[28:30]
diffSF = h[30:32]
totalen = h[32:36]
iden = h[36:40]
flag = h[40:44]
timelive = h[44:46]
protocal = h[46:48]
headChsm = h[48:52]

head = '45000034022140008006c0a8640ac0a86401'
for i,j in enumerate(head):
    if not i%4:
        print(s)
        s = ''
    s+=j

a = '9050cad45d2298fa9b44c2a2080045000034022140008006af46c0a8640ac0a86401c2ad001780e8bafb000000008002faf02c1a0000020405b40103030801010402'
bytes.fromhex(a)
packet = Raw(bytes.fromhex(a))
sendp(packet,iface=ifa[1])

a = '9050cad45d2298fa9b44c2a2080045000028022240008006af51c0a8640ac0a86401c2ad001780e8bafc135e62b650100100f0b90000'
bytes.fromhex(a)
packet = Raw(bytes.fromhex(a))
sendp(packet,iface=ifa[1])

from scapy.all import *
import codecs

def iface_ip_get_mac(ip):
    for i in list(conf.ifaces.__dict__['data'].values()):
        if conf.ifaces.dev_from_name(i).ip == ip: return (conf.ifaces.dev_from_name(i).mac, conf.ifaces.dev_from_name(i).name)
    return False
    
def decimalToHexadecimal(decimal,length=False):
    # Conversion table of remainders to
    # hexadecimal equivalent
    conversion_table = {0: '0', 1: '1', 2: '2', 3: '3', 4: '4',
                        5: '5', 6: '6', 7: '7',
                        8: '8', 9: '9', 10: 'A', 11: 'B', 12: 'C',
                        13: 'D', 14: 'E', 15: 'F'}
    hexadecimal = ''
    while(decimal > 0):
        remainder = decimal % 16
        hexadecimal = conversion_table[remainder] + hexadecimal
        decimal = decimal // 16
    if not hexadecimal: return '0'
    if len(hexadecimal) < length:
        difflen = length - len(hexadecimal)
        hexadecimal = '0'*difflen + hexadecimal
    return hexadecimal

def arp(self):
    result=[]
    f = iface_ip_get_mac('192.168.100.10')
    p=Ether(dst="ff:ff:ff:ff:ff:ff",src=f[0])/ARP(pdst='192.168.100.1')
    ans,unans=srp(p,iface=f[1],timeout=2)
    for s,r in ans:
        result.append([r[ARP].psrc,r[ARP].hwsrc,r[ARP].pdst])
    return result

dstlist = arp()

class TelnetLayer2:
    def __init__(self,srcip,dstip,dstmac):
        # self.mac, self.iface = iface_ip_get_mac('192.168.100.10')
        self.srcip = srcip
        self.dstip = dstip
        self.srcmac, self.iface = iface_ip_get_mac(srcip)
        self.iden = decimalToHexadecimal(random.randint(0,2**10-1),4)
        self.dstmac = dstmac
        self.type = '0800'
        self.hlen = '4500' # 4 > Version, 5 Header Length
        self.flag = '4000'
        self.ack = '00000000'
        self.seq = decimalToHexadecimal(random.randint(0,2**32-1),8)
        self.srcport = decimalToHexadecimal(random.randint(49152,65535),4)
        self.dstport = decimalToHexadecimal(23,4)
    def getpkt(self):
        ifa=iface_ip_get_mac('192.168.100.10')
        t = AsyncSniffer(iface=ifa[1], prn=lambda x: x.show(),filter="tcp",lfilter=lambda d: d.dst == '98:fa:9b:44:c2:a2')
        t.start()
    def headerchecksum(self,vlist):
        t = 0
        for i in vlist:
            t += int(i,16)
        hext = decimalToHexadecimal(t)
        hext1 = decimalToHexadecimal(int(hext[0],16)+int(hext[1:],16))
        comp = decimalToHexadecimal(int('ffff',16)-int(hext1,16), 4)
        return comp
    def _init(self):
        dst_ = self.dstmac.replace(':','')
        mac_ = self.srcmac.replace(':','')
        option = '020405b40103030801010402'
        totalen_1 = decimalToHexadecimal(int('0028',16) + len(option)/2,4)
        srcip = ''.join([decimalToHexadecimal(int(i),2) for i in self.srcip.split('.')])
        dstip = ''.join([decimalToHexadecimal(int(i),2) for i in self.dstip.split('.')])
        hchsum = self.headerchecksum([self.hlen,totalen_1,self.iden,self.flag,'8006',srcip[:4],srcip[4:],dstip[:4],dstip[4:]])
        cflag = '8002'
        wsize = 'faf0'
        chsum = self.headerchecksum([srcip[:4],srcip[4:],dstip[:4],dstip[4:],'0006','0020',self.srcport,self.dstport,self.seq[:4],self.seq[4:],cflag,wsize,option[:4],option[4:8],option[8:12],option[12:16],option[16:20],option[20:24]])
        pkt1 = dst_+mac_+self.type+self.hlen+totalen_1+self.iden+self.flag+'8006'+hchsum+srcip+dstip+self.srcport+self.dstport+self.seq+self.ack+cflag+wsize+chsum+'0000'+option
        print(pkt1)
        p = bytes.fromhex(pkt1.lower())
        b = bytes(Raw(p))
        print(hexdump(b))
        t = AsyncSniffer(iface=self.iface, prn=lambda x: x.show(),filter="tcp",lfilter=lambda d: d.dst == self.srcmac,count=1,timeout=2)
        t.start()
        time.sleep(0.02)
        packet = Raw(bytes.fromhex(pkt1.lower()))
        sendp(packet,iface=self.iface)
        t.join()
        print(hexdump(t.results[0]))

'98:fa:9b:44:c2:a2'

t = TelnetLayer2('192.168.100.10','192.168.100.1','20:6a:94:57:6e:7b')
t._init()

0101000010111001 50b9
1010111101000110 AF46
