
#include <winsock2.h>
#include <windows.h>
 #include <python.h>
 #include <strsafe.h>
 #include <stdlib.h>
 #include "netstru.h"
 #include "rapv1.h"

template<int _PROTO_NO>
inline u_long _PrePsHdv4(const in_addr &src_ip, const in_addr & dst_ip, u_short length_field)
{
	const struct _Ls{
		in_addr _src;
		in_addr _dst;
		u_char _zero;
		u_char _proto;
		u_short _length;
	}
	f = {
		src_ip
		,dst_ip
		,0
		,_PROTO_NO
		,htons(length_field)
	};

	//~ Pseudo Head for UPD/TCP is 12 bytes-long.
	assert( sizeof(_Ls) == 12 );	

	u_long res = 0;
	const u_short *ptr = (u_short*)&f;
	for(int i=0;i<sizeof(_Ls);i+=sizeof(u_short)) {
		res += *ptr;
		++ptr;
	}
	return res;
}
 
 
/*This is essentially right. Others are wrong*/
static
u_short _IpCheckSum(u_short *ptr, int size, u_long pre)
{
	u_long cksum = pre;
	
	while(size >1)
	{
		cksum += *ptr++;
		size -= sizeof(u_short);
	}
	
	if(size )
		cksum += *(u_char*)ptr;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (u_short)(~cksum);
}

 //~ July 25th.2o1o
 //~ The Internet Control Management Protocol: the Ping.
bool ProcessPingPacket(IcmpHead *const icmp,int theLength)
{
	if( theLength < sizeof(IcmpPing) - 1 )
	{
		PyErr_SetString(RapperExc,"Corrutped length for ICMP ping.");
		return false;
	}

	IcmpPing *ping = (IcmpPing*)icmp;
	ping->hd._icmpCheckSum = 0;
	const u_short checksum_forPingPacket = _IpCheckSum((u_short*)icmp,theLength, 0);
	ping->hd._icmpCheckSum = checksum_forPingPacket;

	/*
	char buf[1024];
	sprintf_s(buf,sizeof buf,"icmp length =%d, check sum = %.4x\r\n",theLength,checkSum);
	PySys_WriteStdout(buf);
	*/

	return true;
}

 /*

 */

 bool ProcessIcmpPacket(IcmpHead *const icmp,int theLength)
 {
	//PySys_WriteStdout("processing an icmp packet...\r\n"); 
	if( theLength < sizeof(IcmpHead) )
	{
		PyErr_SetString(RapperExc,"Corrupted lengh for ICMP.");
		return false;
	}
	
 	if( 8 == icmp->_type && 0 == icmp->_code )
 	{
 		return ProcessPingPacket(icmp,theLength);
 	}

	return true;		/*Untouched*/
 }


/*
       1.  Adjust the UDP length
       2.  Calculate the UDP checksum automatically
*/

 bool ProcessUdpPacket(UdpHead *const pUdp, const int theUdpLen,const IpHead*const iph)
{	
	/*length covers the whole udp head and udp data	*/
	
	// length excluding UDP head
	const int dataLength = theUdpLen  - sizeof(UdpHead);
	if( dataLength < 0 )
	{
		PyErr_SetString(RapperExc,"Pure UDP data length is less than 0");
		return false;
	}

	//~ Set the UDP length correctly. (There is no length-field in TCP head)
	pUdp->udp_length = htons(theUdpLen);
	pUdp->udp_checksum = 0;	//~ clear
	const u_short checksum_forUDP = _IpCheckSum(
		(u_short*)pUdp,
		theUdpLen, 
		_PrePsHdv4<IPPROTO_UDP>( iph->src_ip, iph->dst_ip, theUdpLen) );
	
	pUdp->udp_checksum = checksum_forUDP;

	/*
	#if _ME_DEBUG
	PrintUdpHead(pUDP);
	#endif
	*/	

	return true;
}

/* August.28th.2o1o */
/* Calcuate the checum sum for this tcp packet.*/
bool ProcessTcpPacket(TcpHead *const pTcp, const int tcpLength, const IpHead *ip)
{
	if( tcpLength < _MIN_TCP_HEAD_LENGTH || tcpLength < 0 )
	{
		PySys_WriteStderr("Tcp head lenth is less than minimum. Fatal error.\n");
		return false;
	}
	const int tcpHeadLength = (((pTcp->tcp_head_length & 0xF0)>>4)<<2);

	/*
	#ifdef _ME_DEBUG
	PySys_WriteStdout("_ME_DEBUG:Tcp Total Length = %d\n",tcpLength);
	PySys_WriteStdout("_ME_DEBUG:Tcp Head Length = %d\n",tcpHeadLength );
	#endif
	*/
	
	const int dataLength = tcpLength - tcpHeadLength;
	if( dataLength < 0 )
	{
		PySys_WriteStdout("Tcp length is corrupted. Fatal error.\n");
		return false;
	}

	pTcp->check_sum = 0;
	const u_short checksum_forTCP = _IpCheckSum(
		(u_short*)pTcp
		,tcpLength
		,_PrePsHdv4<IPPROTO_TCP>( ip->src_ip, ip->dst_ip, tcpLength ));
	pTcp->check_sum = checksum_forTCP;

	/*
	#ifdef _ME_DEBUG
	PrintTcpHead( pTcp );
	PySys_WriteStdout("_ME_DEBUG: Special check: Check Sum is 0x%.4x\n",c_sum);
	#endif
	*/
	return true;
}



/*Intelligent IP packet processor:
  1. Adjust IP packet length in IP head
  2. Calculate checksum for IP head.

 For now, do nothing for TCP packet and else.  
 */
 
bool ProcessIpPacket(char *buffer,const int length)
{
	IpHead *ip = (IpHead*)(buffer + sizeof(MacHead));
	const int ipHeadLength = (ip->headver&0xf) * 4;
	const int ipTotLength = length - sizeof(MacHead);
		
	if( ipHeadLength < sizeof(IpHead) )
	{
		PyErr_SetString(RapperExc,"IP header error");
		return false;
	}

	if( ipTotLength < ipHeadLength )
	{
		PyErr_SetString(RapperExc,"IP header error: IP totaal length less than IP head length.");
		return false;
	}
	
	//Do check sum for IP head
	ip->totLength = htons( (u_short) ipTotLength );
	ip->checksum = 0;
	ip->checksum =_IpCheckSum((u_short*)ip,ipHeadLength,0);
	

	/*
	#if _ME_DEBUG
	PrintIpHeadInfo(ip);
	#endif
	*/
	
	if( IPPROTO_UDP == ip->proto )
	{
		UdpHead *const udpHd = (UdpHead*)((char*)ip + ipHeadLength);
		if( ! ProcessUdpPacket(udpHd, ipTotLength - ipHeadLength,ip) )
			return false;
	}
	else if( IPPROTO_TCP == ip->proto )
	{
		TcpHead *const tcpHd = (TcpHead*)((char*)ip + ipHeadLength);
		if( ! ProcessTcpPacket(tcpHd, ipTotLength - ipHeadLength, ip ) )
			return false;
	}
	else if( IPPROTO_ICMP == ip->proto )
	{
		IcmpHead *const icmpHd = (IcmpHead*)((char*)ip + ipHeadLength);
		if( ! ProcessIcmpPacket(icmpHd,ipTotLength - ipHeadLength) )
			return false;
	}
	return true;
}
