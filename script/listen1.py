
# This Listener for UDP
# July.18th.2o1o


from comachd import DeframeError,FrameLengthError
from comachd import CoTcpUdpPacketRoot
from coshake import BytesToHexStream
import RapLanV1


decodeError = 0
tcpCount = 0
udpCount = 0

def ShowUdpPack(din,prompt):
    try:
        if 0>=len(din):
            print(prompt)
        else:
            hs = BytesToHexStream(din)
            packet = CoTcpUdpPacketRoot.New(hs)
            print()
            print(prompt)
            print("from %16s:%6d to %16s:%6d, len = %6d"%(packet.SrcIP(),packet.SrcPort(),packet.DestIP(),packet.DestPort(),packet.TcpUdpLength()))
            if packet.IpProto()== 17:
                global udpCount
                udpCount +=1
            elif packet.IpProto()== 6 :
                global tcpCount
                tcpCount +=1
            
    except DeframeError as e:
        global decodeError
        decodeError+=1
        print(e)
    return True

def SniperGo(cnt,capdur):
    dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0],Timeout=capdur)
    print(dev1.AdDesc)
    rCnt = dev1.ProcessPcap(cnt,ShowUdpPack)
    return rCnt

if '__main__'==__name__:
    import sys
    capTime = 20
    capd = 666
    if len(sys.argv) > 1:
        capTime = int(sys.argv[1])
    if len(sys.argv) > 2:
        capd = int(sys.argv[2])
        
    print("Going to do %d times, timeout set to %d"%(capTime,capd))
    i = SniperGo(capTime,capd)
    print("".ljust(20,'#'))
    print("%d packet(s) retrieved."%i)
    print("%d packet(s) are of TCP" % tcpCount )
    print("%d packet(s) are of UDP" %udpCount )
    print("decode error = %d " % decodeError)
    print("%d timeout(s)"%(capTime-i))
