

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <winsock2.h>
#include <windows.h>
#include <strsafe.h>
#include <stddef.h>
#include <comdef.h>
#include "python.h"
#include "netstru.h"
#include <pcap.h>

void PrintSizeOfMyStruct()
{
	PySys_WriteStdout("[Debug.Info] Size of MacHead = %d\n",sizeof(MacHead));
	PySys_WriteStdout("[Debug.Info] Size of IpHead = %d\n",sizeof(IpHead));
	PySys_WriteStdout("[Debug.Info] Sizeo of UdpHead = %d\n",sizeof(UdpHead));
	PySys_WriteStdout("[Debug.Info] Sizeof TcpHead = %d\n",sizeof(TcpHead));
}

void PrintIpHeadInfo(const IpHead* ip)
{
	PySys_WriteStdout("[Debug.Info.IP]************\n");
	PySys_WriteStdout("IP v%u\n",(ip->headver&0xf0)>>4);
	PySys_WriteStdout("IP head len: %u\n",(ip->headver&0x0f)*4);
	PySys_WriteStdout("IP ttl: %u\n",ip->ttl);
	PySys_WriteStdout("IP proto: %u\n",ip->proto);
	PySys_WriteStdout("IP head checksum: %x\n",ip->checksum);
	PySys_WriteStdout("Source IP: %s\n",inet_ntoa(ip->src_ip));
	PySys_WriteStdout("Destination IP: %s\n",inet_ntoa(ip->dst_ip) );
	PySys_WriteStdout("[Debug.Info.IP.End]*************************\n");
}

void PrintUdpHead(const UdpHead *ptr)
{
	PySys_WriteStdout("[Debug.Info.UDP]********\n");
	PySys_WriteStdout("UDP Source Port: %u\n",((ptr->srcPort&0xff)<<8) + ((ptr->srcPort&0xff00)>>8));
	PySys_WriteStdout("UDP Destination Port: %u\n",((ptr->dstPort&0xff)<<8) + ((ptr->dstPort&0xff00)>>8));
	PySys_WriteStdout("UDP Length: %u\n",((ptr->udp_length&0xff)<<8)+((ptr->udp_length&0xff00)>>8));
	PySys_WriteStdout("UDP checksum: %04x\n",ptr->udp_checksum);
	PySys_WriteStdout("*****************\n");
}

void PrintTcpHead(const TcpHead* ptr)
{
	PySys_WriteStdout("_ME_DEBUG:Source Port = %u\n",ntohs(ptr->source_port));
	PySys_WriteStdout("_ME_DEBUG:Destination Port = %u\n",ntohs(ptr->destination_port));
	PySys_WriteStdout("_ME_DEBUG:Sequence Number = %u (0x%.8x)\n",ntohl(ptr->seq),ntohl(ptr->seq));
	PySys_WriteStdout("_ME_DEBUG:Ack Number = %u (0x%.8x)\n",ntohl(ptr->ack_no),ntohl(ptr->ack_no));
	PySys_WriteStdout("_ME_DEBUG:Tcp Head Length = %u\n",  ((ptr->tcp_head_length)>>4)*4 );
	PySys_WriteStdout("_ME_DEBUG:Congestion Window Reduced = %u\n", ((ptr->flags)>>7)&1);
	PySys_WriteStdout("_ME_DEBUG:ECN-Echo = %u\n",((ptr->flags)>>6)&1);
	PySys_WriteStdout("_ME_DEBUG: [ Urg: %u\n",((ptr->flags)>>5)&1);
	PySys_WriteStdout(" Ack: %u",((ptr->flags)>>4)&1);
	PySys_WriteStdout(" Psh: %u",((ptr->flags)>>3)&1);
	PySys_WriteStdout(" Rst: %u",((ptr->flags)>>2)&1);
	PySys_WriteStdout(" Syn: %u",((ptr->flags)>>1)&1);
	PySys_WriteStdout(" Fin: %u ]\n",((ptr->flags)>>0)&1);
	PySys_WriteStdout("_ME_DEBUG:Window Size = %u\n",ntohs(ptr->window_size));
	PySys_WriteStdout("_ME_DEBUG:Check Sum = 0x%.4x\n",ntohs(ptr->check_sum));
	PySys_WriteStdout("_ME_DEBUG:Urgent Pointer = %u\n",ptr->urgent_pointer);
}


#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
const char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

	#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
	#else
	sockaddrlen = sizeof(struct sockaddr_storage);
	#endif


	if(getnameinfo(sockaddr, 
		sockaddrlen, 
		address, 
		addrlen, 
		NULL, 
		0, 
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
#endif /* __MINGW32__ */