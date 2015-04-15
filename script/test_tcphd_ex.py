from comachd import CoUdpHd, CoTcpHd, CoTcpUdpPacketRoot
from comachd import CoMacHd, CoMacIpHd
from comachd import CoIpv4Hd
from comachd import CoUdpTcpHd
import unittest

def PrintCoTcpHd(q):
    assert type(q) ==CoTcpHd
    #
    print(''.rjust(50,'#') )
    print("Seq = ",q.Seq() )    
    print("Ack No = ", q.AckNo() )
    print("Head Size Value = 0x%.2x" % q.HeadSizeValue() )
    print("Flags Value = 0x%.2x" % q.FlagsValue() )
    print("Check Sum = 0x%.4x" %q.CheckSum() )
    print("Urgent Pointer = 0x%.4x" % q.UrgentPointer())
    print("Options (in hex-stream) = ", q.Options())
    

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
    tcp_r.SetFlags( 0,1,0,1,0,0 )
    revd = CoTcpUdpPacketRoot( mac_r , ip_r, tcp_r , raw_pack.Data())
    return revd


if '__main__' == __name__:
    
    class TestTcpEx(unittest.TestCase):
        def runTest(self):
            print(''.rjust(50,'#'))
            p = CoTcpUdpPacketRoot.New("001e8c97a9fb0013d463a6a10800450000401002400040066a14c0a8012bda3d2491068a00507cf168d500000000b002ffff88bb0000020405b4010303030101080a000000000000000001010402")
            print(p)
            print(''.rjust(50,'#'))
            PrintCoTcpHd(  p.TcpUdpHd()  )
            print(''.rjust(50,'$'))
            pr = ConstructRst( p )
            print("\n\n\n")
            print(''.rjust(60,'#'))
            print(p)
            print(''.rjust(60,'-'))
            print(pr)

    # Start
    unittest.main()
    
