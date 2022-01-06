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
    def __init__(self,srcmac,srcip,dstmac,dstip,iface):
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
    def iden_(self):
        self.iden = decimalToHexadecimal(int(self.iden,16)+1,4)
    def seq_(self,t):
        self.seq = decimalToHexadecimal(t.results[0].ack,8)
    def ack_(self,t):
        self.ack = decimalToHexadecimal(t.results[0].seq+1,8)
    def plen(self,l):
        return decimalToHexadecimal(int('0028',16) + len(l)/2,4)
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
        totalen_1 = self.plen(option)
        srcip = ''.join([decimalToHexadecimal(int(i),2) for i in self.srcip.split('.')])
        dstip = ''.join([decimalToHexadecimal(int(i),2) for i in self.dstip.split('.')])
        hchsum = self.headerchecksum([self.hlen,totalen_1,self.iden,self.flag,'8006',srcip[:4],srcip[4:],dstip[:4],dstip[4:]])
        cflag = '8002'
        wsize = 'faf0'
        chsum = self.headerchecksum([srcip[:4],srcip[4:],dstip[:4],dstip[4:],'0006','0020',self.srcport,self.dstport,self.seq[:4],self.seq[4:],cflag,wsize,option[:4],option[4:8],option[8:12],option[12:16],option[16:20],option[20:24]])
        pkt1 = dst_+mac_+self.type+self.hlen+totalen_1+self.iden+self.flag+'8006'+hchsum+srcip+dstip+self.srcport+self.dstport+self.seq+self.ack+cflag+wsize+chsum+'0000'+option
        print(pkt1)
        # p = bytes.fromhex(pkt1.lower())
        # b = bytes(Raw(p))
        # print(hexdump(b))
        # t = AsyncSniffer(iface=self.iface, prn=lambda x: x.show(),filter="tcp",lfilter=lambda d: d.dst == self.srcmac,count=1,timeout=2)
        # t.start()
        # time.sleep(0.02)
        # packet = Raw(bytes.fromhex(pkt1.lower()))
        # sendp(packet,iface=self.iface)
        # t.join()
        # print(hexdump(t.results[0]))
        # self.iden_()
        # self.seq_(t)
        # self.ack_(t)
        # cflag = '5010'
        # wsize = '0100'
        # option = ''
        # totalen_1 = self.plen(option)
        # hchsum = self.headerchecksum([self.hlen,totalen_1,self.iden,self.flag,'8006',srcip[:4],srcip[4:],dstip[:4],dstip[4:]])
        # chsum = self.headerchecksum([srcip[:4],srcip[4:],dstip[:4],dstip[4:],'0006','0014',self.srcport,self.dstport,self.seq[:4],self.seq[4:],self.ack[:4],self.ack[4:],cflag,wsize])
        # pkt2 = dst_+mac_+self.type+self.hlen+totalen_1+self.iden+self.flag+'8006'+hchsum+srcip+dstip+self.srcport+self.dstport+self.seq+self.ack+cflag+wsize+chsum+'0000'+option
        # print(pkt2)
        # t = AsyncSniffer(iface=self.iface, prn=lambda x: x.show(),filter="tcp",lfilter=lambda d: d.dst == self.srcmac,count=1,timeout=2)
        # t.start()
        # time.sleep(0.12)
        # packet = Raw(bytes.fromhex(pkt2.lower()))
        # sendp(packet,iface=self.iface)
        # t.join()
        # print(hexdump(t.results[0]))


a = '206a94576e7b98fa9b44c2a2080045000034009840008006B0CFC0A8640AC0A86401DE3400177A967202000000008002faf05FDE0000020405b40103030801010402'

ans = sr(Raw(bytes.fromhex(a.lower())),iface='乙太網路')
'98:fa:9b:44:c2:a2'
90:aa:c3:39:7f:62
20:6a:94:57:6e:7b
s = TelnetLayer2('192.168.100.10','192.168.100.1','20:6a:94:57:6e:7b')
t = s._init()

0101000010111001 50b9
1010111101000110 AF46

##### ICMP

a = sr1(IP(dst="192.168.100.1")/ICMP()/Raw(bytes.fromhex(data.lower())),iface='乙太網路',filter='icmp')

b = bytes(Raw(a[1].load))
bytes.hex(b) == data

data = 'd8f45801de1194ad66e4ccfad95e6359a884a7d33ce997e6a0ee7423f0bc0e8981fecb9fcd5f785325c7d0951555ccb3961bb073f69bd2f28805293f0b2e99b7db50001eda8400821c008ad055102f3302d527305ac11d82f3cec0b735810a877fa24ef71bb80432e2465522aec865d1846c62837e91518f7a01930185ed3af105ac0ea2a8335d5a105386033bb64486b497bbe37b444410b555f99814aaffee042696959b2de2f23ede77ec1210a649290e89c86912d0fe3c844af1f9ef337615c7404b0add6bf3039e7e554c0f61137c8925ab6034cc50a644de864ef6ad80d04963390d7dd054f84cf5b401eb4fdb45bfe50477e011ff8c4e0ecf29f54504cd6357d9be43e90eb5a1338448dc489a1b6a2349c64f7502855b3043a226d3fba3cc74a333698f18d153913a3a1a2247974036f567b9d2512a219e5ad3bf305ceb3e120e8525996be51b6550efddb7da51fb767d7056ffe51359af8dd2fa32203d6f8a92cbb1dffe89b1093e7e5ddd4ce0513b5cfa5dd4b5d8bbbc53b80db33e301833a81e4339c954ced37b01d26e94defcdd071c0829ba10ff1b259c318aaf5df265c796147fc5df281d7f8d7341abe0b2b5f8ef8ed6eb54dd267a979f8f695bb378684b5c8ae9c2783fc33d7a2f88812c19a78b26b4403c0d34cac18d9b67c414c4025453302e95768fbe271e0e245722638a080a9ab25f479d8e3134849f2ecda20eca314b8befd967e96496b876fb4ceb1c7d7160395643b93e01cc240931966903c52eb2f9695b1dbb0b1c0477046207d20392deccb9b9e051478d529e672770595c823d6f9ab30bad35e6ca1e0c1c1027b2a6ec631f606b3f1baee65566381289a865c5e61c998936fa2de263a9325f90a1e663f722f2b0819669b827c781a40bc00f215584c4edce722a243f735c4b87e988197f5726098ed0f5a10b21ba7f55beb828b46dee90eeb41369a903522c84a2c5e8f359b3cddee18a78f90d9bfce2b897b4fc6dcdcb0dd921889af1cb5afee3d5a74cbe5355eae05f15ea23db7227c7e69d241d1bf5a4f98c5909d5812e6dc5f02f821fbcf72ae6ae50d5fb34399e02dcb925158e662a2b8cb4ee472bfe4a604e568c13a70d150bad01b32c5ca9bf82b0e1f6ecdf761888597142de80240ccb27f66234cdee236696007b4f0d1b015f9bee903cc67ee5282b69fd323af72c20b3e6fd17e4f2cd109f2626fbfde5dcb0d6b7ea9afcd50a223a7316dd0fcf21742afe5457a5718a21024aabcae661c98f9714fca137d2fe8fbe678575b80564e2c416608ac8c4d3b0f54403527ee63f1117debfe730cf3987ee1d4393eeef6c80b806184905411fd7b1ec252b7eccb7518eeb2a059f243422046d47ce67e7b16740a7752c1442e7ab6e1a09ee9e6ba865351536923c276677362f8abfdc44acaf93d06ecaad1ea24764a7a8'

def QoS_ping(src, dst, count=3, data=''):
    # packet = Ether()/IP(dst=host)/ICMP()/data
    t=0.0
    loss = 0
    for x in range(count):
        time.sleep(0.2)
        try:
            ans=sr(IP(src=src,dst=dst)/ICMP()/Raw(bytes.fromhex(data.lower())),retry=3,iface='乙太網路',filter='icmp',timeout=1)
            delta = ans[0][0].answer.time - ans[0][0].query.time
            b = bytes(Raw(ans[0][0].answer.load))
            print ("Ping:", delta,bytes.hex(b) == data)
            t+=delta
        except:
            loss+=1
        # return ans

print(round((t/count)*1000,2),'ms',(loss/count)*100,'loss')
return round((t/count)*1000,2),(loss/count)*100

e = QoS_ping('192.168.100.10','192.168.100.1', 20, data)

srp(Ether(src='98:fa:9b:44:c2:a2',dst='20:6a:94:57:6e:7b')/IP(src='192.168.100.10',dst='192.168.100.1')/ARP(),retry=3,iface='乙太網路',filter='tcp',timeout=1)
pkt = Ether(src='98:fa:9b:44:c2:a2',dst='20:6a:94:57:6e:7b')/IP(src='192.168.100.10',dst='192.168.100.1',flags=0x2)/TCP(flags=0x2,options=[('MSS', 1460), ('NOP', 0), ('WScale', 8), ('NOP', 0), ('NOP', 0), ('SAckOK', '' )])
pkt['IP'].id = random.randint(0,2**10-1)
# pkt['IP'].id = 545
pkt['IP'].ttl = 128
pkt['IP'].len = 52
pkt['TCP'].sport = random.randint(49152,65535)
# pkt['TCP'].sport = 49837
pkt['TCP'].dport = 23
pkt['TCP'].window = 64240
pkt['TCP'].seq = random.randint(0,2**32-1)

ans, unans = srp(pkt,retry=3,prn=hello(),iface='乙太網路',filter='tcp',timeout=1)
if len(ans):
    pkt1 = Ether(src='98:fa:9b:44:c2:a2',dst='20:6a:94:57:6e:7b')/IP(src='192.168.100.10',dst='192.168.100.1',flags=0x2)/TCP(flags=0x10)
    pkt1['TCP'].seq = ans[0].answer['TCP'].ack
    pkt1['TCP'].ack = ans[0].answer['TCP'].seq + 1
    pkt1['IP'].ttl = 128
    pkt1['IP'].id = ans[0].query['IP'].id + 1 
    pkt1['TCP'].sport = ans[0].query['TCP'].sport
    pkt1['TCP'].dport = ans[0].query['TCP'].dport
    ans, unans = srp(pkt1,retry=3,iface='乙太網路',filter='tcp',timeout=1)

from scapy.all import * 
import codecs

def iface_ip_get_mac(ip):
    for i in list(conf.ifaces.__dict__['data'].values()):
        if conf.ifaces.dev_from_name(i).ip == ip: return (conf.ifaces.dev_from_name(i).mac, conf.ifaces.dev_from_name(i).name)
    return False

class TelnetLayer2:
    def __init__(self,srcmac,srcip,dstmac,dstip,iface):
        self.options = []
        self.iface = iface
        self.pkt = Ether(src=srcmac,dst=dstmac)/IP(src=srcip,dst=dstip,flags=0x2)/TCP(flags=0x2,options=self.options)
        self.pkt['IP'].id = random.randint(0,2**10-1)
        # pkt['IP'].id = 545
        self.pkt['IP'].ttl = 128
        self.pkt['TCP'].sport = random.randint(49152,65535)
        # pkt['TCP'].sport = 49837
        self.pkt['TCP'].dport = 23
        self.pkt['TCP'].window = 64240
        self.pkt['TCP'].seq = random.randint(0,2**32-1)
        self.ans, self.unans = 0, 0
        self.data = ''
        self.sniff = AsyncSniffer(iface=self.iface, prn=lambda x: self.parsing(x),filter="tcp",lfilter=lambda d: d.src == dstmac)
        self.sniff.start()
        time.sleep(0.5)
        self.spkt([('MSS', 1460), ('NOP', 0), ('WScale', 8), ('NOP', 0), ('NOP', 0), ('SAckOK', '' )],0x2)
        time.sleep(1)
    def parsing(self,p):
        self.pkt['TCP'].seq = p['TCP'].ack
        if not p['TCP'].payload:
            self.pkt['TCP'].ack = p['TCP'].seq + 1
        else:
            self.pkt['TCP'].ack = p['TCP'].seq + len(p['TCP'].load)
        self.pkt['IP'].ttl = 128
        self.pkt['TCP'].window = 256
        self.pkt['IP'].id += 1
        if 'Raw' in p and b'\\xff\\xfd\x01\\xff\\xfd!\\xff\\xfb\x01\\xff\\xfb\x03' not in p[Raw].load:
            if b'\xff\xfb\x03' in p[Raw].load:
                self.data += p[Raw].load.split(b'\xff\xfb\x03')[-1].decode()
            else:
                self.data += p[Raw].load.decode()
        if 'Raw' in p and b'\\xff\\xfd\x01\\xff\\xfd!\\xff\\xfb\x01\\xff\\xfb\x03' in p[Raw].load:
            self.spkt([],0x18,'fffb01fffc21fffd01fffd03')
        if p.dataofs==5 and 'Padding' in p:
            pass
        if 'SA' in p[TCP].flags and p.dataofs==8:
            self.spkt([],0x10)
        if 'DF' in p.flags:
            self.spkt([],0x10)
        if 'FA' in p[TCP].flags:
            self.spkt([],0x14)
            self.close()
    def _decorator(foo):
        def update(self, options, flags, payload=''):
            self.pkt['TCP'].options = options
            self.pkt['TCP'].flags = flags
            self.pkt['TCP'].payload = Raw(bytes.fromhex(''))
            if payload:
                self.pkt['TCP'].payload = Raw(bytes.fromhex(payload))
            # print(hexdump(self.pkt))
            self.pkt['IP'].len = len(self.pkt)-14
            foo(self,options, flags, payload)
            # self.options = []
            # self.pkt = Ether(src='98:fa:9b:44:c2:a2',dst='20:6a:94:57:6e:7b')/IP(src='192.168.100.10',dst='192.168.100.1',flags=0x2)/TCP(flags=0x2,options=self.options)
            '''
            if not self.unans:
                self.pkt['TCP'].seq = self.ans[0].answer['TCP'].ack
                if not self.ans[0].answer['TCP'].payload:
                    self.pkt['TCP'].ack = self.ans[0].answer['TCP'].seq + 1
                else:
                    self.pkt['TCP'].ack = self.ans[0].answer['TCP'].seq + len(self.ans[0].answer['TCP'].load)
                self.pkt['IP'].ttl = 128
                self.pkt['TCP'].window = 256
                self.pkt['IP'].id = self.ans[0].query['IP'].id + 1 
                self.pkt['TCP'].sport = self.ans[0].query['TCP'].sport
                self.pkt['TCP'].dport = self.ans[0].query['TCP'].dport
                if self.ans[0].answer.dataofs==5:
                    if b'\xff\xfb\x01\xff\xfb\x03' in self.ans[0].answer['TCP'].load:
                        d = self.ans[0].answer['TCP'].load.replace(b'\xff\xfb\x01\xff\xfb\x03',b'')
                    d = self.ans[0].answer['TCP'].load
                    self.data += d
            '''
        return update
    @_decorator
    def spkt(self,options,flags,payload=''):
        self.options = options
        self.flags = flags
        self.flags = payload
        # self.ans, self.unans = srp(self.pkt,iface='乙太網路',filter='tcp',timeout=1,verbose=False)
        sendp(self.pkt,iface=self.iface,verbose=False)
    def close(self):
        t.spkt([],0x14)
        self.sniff.stop()
        self.data=''
    def __repr__(self):
        return self.data
    def __call__(self):
        return self.data
    def __str__(self):
        return self.data
    def __lshift__(self,data):
        self.spkt([],0x18,codecs.encode("{}\r".format(data).encode(), "hex").decode())
    def __del__(self,data):
        try:
            self.sniff.stop()
        except: pass

srp(Ether(src='98:fa:9b:44:c2:a2',dst='20:6a:94:57:6e:7b')/IP(src='192.168.100.10',dst='192.168.100.1')/ARP(),retry=3,iface='乙太網路',filter='tcp',timeout=1)
srp(Ether(src='98:fa:9b:44:c2:a2',dst='00:50:F1:21:00:10')/IP(src='192.168.100.10',dst='192.168.100.1')/ARP(),retry=3,iface='乙太網路',filter='tcp',timeout=1)

a = srp(Ether(src='98:fa:9b:44:c2:a2', dst='fa:1d:0f:b4:8d:d2')/ARP(hwsrc='98:fa:9b:44:c2:a2', hwdst='fa:1d:0f:b4:8d:d2', psrc='192.168.100.10', pdst='192.168.100.1'), iface='乙太網路', verbose = False)
a[0][ARP].show()

b = srp(Ether(src='98:fa:9b:44:c2:a2', dst='20:6a:94:57:6e:7b')/ARP(hwsrc='98:fa:9b:44:c2:a2', hwdst='20:6a:94:57:6e:7b', psrc='192.168.100.10', pdst='192.168.100.1'), iface='乙太網路', verbose = False)
b[0][ARP].show()

ans, unans = srp(Ether(dst="20:6a:94:57:6e:7b")/ARP(pdst="192.168.100.1"),timeout=2)

t = TelnetLayer2('98:fa:9b:44:c2:a2','192.168.100.10','20:6a:94:57:6e:7b','192.168.100.1','乙太網路')
t1 = TelnetLayer2('98:fa:9b:44:c2:a2','192.168.100.10','fa:1d:0f:b4:8d:d2','192.168.100.1','乙太網路')

def hello(p):
    print(p.dataofs)
    print(hexdump(p))

sniff = AsyncSniffer(iface='乙太網路', prn=lambda x: hello(x),filter="tcp",lfilter=lambda d: d.src == '20:6a:94:57:6e:7b')
sniff.start()
# t._init
# t.spkt([('MSS', 1460), ('NOP', 0), ('WScale', 8), ('NOP', 0), ('NOP', 0), ('SAckOK', '' )],0x2)
# t.spkt([],0x18,'fffb01fffc21fffd01fffd03')
# t.spkt([],0x10)
# t.spkt([],0x18,codecs.encode(b"mso\r", "hex").decode())
# t.spkt([],0x10)
# t.spkt([],0x18,codecs.encode(b"msopassword\r", "hex").decode())
Raw(bytes.fromhex(a))
