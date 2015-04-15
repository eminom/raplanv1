import sys,random
import RapLanV1

def ShakeMePlainText():
    """Shake的UDP净荷(Plain text密文)"""
    #return "1_lbt4_0#128#001E8C97A9FB#0#0#0:1277922188:root:superman:209:" + '\0'  #Original#
    #return "1_lbt4_0#128#001E8C97A9FB#0#0#0:888:root:superman:209:" + '\0'
    return "1_lbt4_0#128#001E8C97A9FB#0#0#0:888:root:superman:209:" + '\0'

def ResolveAddrToMac(dev,ipaddr):
    s = RapLanV1.SendArp(ipaddr)
    if s[0]:
        return s[2]
    if ipaddr in [f['Address'] for f in dev.Addresses]:
        return dev.PhysicalAddr
    return None

def Shake3(dev1,dst_ip,delay):
    print("Shake ",dst_ip,"in",delay,"second(s)...")
    import time
    time.sleep(delay)
    
    src_port = 2425
    dst_port = 2425
    
    from comac import CoMac,CoIPv4
    from comachd import CoMacIpHd,CoIpUdp,CoUdpHd
    from coshake import Latin1ToHexStream,HexStreamToBytes    

    with open('rec_list.txt','r',encoding="Ascii") as fin:
        fs = fin.readlines()
        fs = [f.rstrip() for f in fs]

    mact = {}
    for _tc in range(0,3):
        src_ip = fs[random.randint(0,len(fs)-1)]

        def omac(ip):
            if ip in mact:
                phx = mact[ip]
            else:
                phx = ResolveAddrToMac(dev1,ip)
                if phx:
                    mact[ip] = phx
            return phx
        
        srciphx = omac(src_ip)
        dstiphx = omac(dst_ip)
   
        if srciphx != None and dstiphx != None:
            mH = CoMacIpHd(CoMac(dstiphx),CoMac(srciphx))
            ipH = CoIpUdp(src_ip,dst_ip)
            udpH = CoUdpHd(src_port,dst_port)
            packet = mH.toHexStream() + ipH.toHexStream() + udpH.toHexStream()  + Latin1ToHexStream(ShakeMePlainText())
            w = dev1.Send(HexStreamToBytes(packet ))
            print("Shake from ",src_ip,"to",dst_ip,"with",w)
        else:
            print("Cannot resolve ",src_ip)
    return "Completed"
            

if '__main__' == __name__:
    dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
    print(dev1.FriendlyName)
    print(dev1.AdDesc)

    len(sys.argv) >=3 and print(Shake3(dev1,sys.argv[1],int(sys.argv[2])))
    


    
