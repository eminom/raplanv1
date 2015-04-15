
#ifndef _NET_STRU_DEF
#define _NET_STRU_DEF

#define _MIN_TCP_HEAD_LENGTH		20
#define _MAX_TCP_HEAD_LENGTH	60
#define _TCP_OPTION_PADDING		40

#pragma pack(1)		//compact of compact

struct MacHead
{
	char dstMac[6];
	char srcMac[6];
	short _type;
};

struct IpHead
{
	u_char headver;
	u_char tos;		//type of service
	u_short totLength;
	u_short id;
	u_short fragment_off;	//:16bit 
	u_char ttl;
	u_char proto;	//udp or tcp
	u_short checksum;
	in_addr src_ip;
	in_addr dst_ip;
};

struct UdpHead
{
	u_short srcPort;
	u_short dstPort;
	u_short udp_length;
	u_short udp_checksum;
};

struct IcmpHead
{
	u_char _type;
	u_char _code;
	u_short _icmpCheckSum;
};

struct IcmpPing
{
	IcmpHead hd;
	u_short identifier;
	u_short sequenceNo;
	char data[1];
};

struct TcpHead
{
	u_short source_port;
	u_short destination_port;
	u_int seq;									//~ Sequence ID
	u_int ack_no;							//~ Ack sequence ID
	u_char tcp_head_length;			//~	(m>>4)*4: for 0x80, whose tcp'head length is 32
	u_char flags;							//~ which contains URG/ACK/PSH/RST/SYN/FIN, 6 bits
	u_short window_size;
	u_short check_sum;
	u_short urgent_pointer;
	u_char options[_TCP_OPTION_PADDING];		
};

#pragma pack()			//cancel out


void PrintSizeOfMyStruct();
void PrintIpHeadInfo(const IpHead* ip);
void PrintUdpHead(const UdpHead *ptr);
void PrintTcpHead(const TcpHead* ptr);

const char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);


#endif
