/*...........................................................................
                                 Fragicmp:

   It sends a fragmented ICMP datagram type 8 (Echo Request) into 4 parts 

   --> On first packet:
   Sends a packet with: header IP (20 bytes) + header ICMP (8 bytes) + 
   8 bytes payload filled up with 'A' characters. Total: 36 bytes. 
   MF flag is on and offset is zero.

   --> Second packet:
   Sends a packet with: header IP (20 bytes) + 16 bytes payload filled up with
   'B' characters. Total: 36 bytes.
   MF flag is on and offset is 2.
   OBS: Mount the data on buffer into second octet, cause the first octet has
   'A' characters.

   --> Third packet:
   Sends a packet with: header IP (20 bytes) + 8 bytes payload filled up with  
   'C' characters. Total: 28 bytes.
   MF flag is on and offset is 4, cause the previous packet has payload of
   16 bytes (2 octets) and will be mounted on offset 2 and 3.
   OBS: Mount the data on buffer into fourth octet, cause the first octet has
   'A' characters.

   Now the buffer is complete, but on previous packet the flag MF is on. So
   the TCP stack of the target waits more packets.

   --> Fourth packet:
   Sends a packet with: header IP (20 bytes) + 8 bytes payload filled up with
   'D' characters. Total: 28 bytes.
   MF flag is OFF and offset is 4. Look, here is the overlapping. It overwrote
   the data onto offset 4 with 'D' characters, where the previous content was
   'C' characters. 

   The overlaping will happen on server side buffer at the end of transmission.

   @@ Felipe Ecker <felipe@hexcodes.org>
...........................................................................*/


#include <stdio.h>   	
#include <stdlib.h>	
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>	
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>	
#include <linux/if.h>	

#define uchar	unsigned char
#define uint16	u_int16_t
#define uint32	u_int32_t

#ifdef true
	#undef true
#endif
#ifdef false
	#undef false
#endif
#define true	0
#define false	-1

#undef show
#undef log
#undef pass
#define show(...) fprintf(stdout, __VA_ARGS__)
#define log(...) fprintf(stderr, __VA_ARGS__)

/* Most universal checksum */
inline static uint16 __checksum( uint16 *addr, uint32 len ) {

   register int nleft = len;
   register uint16 *w = addr;
   register int sum = 0;
   uint16 answer = 0;

   while (nleft > 1) {
	  sum += *w++;
	  nleft -= 2;
   }

   if (nleft == 1) {
	  *(uchar *) (&answer) = *(uchar *) w;
	  sum += answer;
   }

   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   answer = ~sum;

   return answer;
}


/* Give us the interface IP address information */
inline static int __fetchIp( const char *__device , char *__ip ) {

   register uint32 sock;
   signed int __ctrl;
   auto struct ifreq eth;

   sock = socket(AF_INET, SOCK_DGRAM, 0);
   eth.ifr_addr.sa_family = AF_INET;
   strncpy(eth.ifr_name, __device, (IFNAMSIZ - 1));
   __ctrl = !ioctl(sock, SIOCGIFADDR, &eth);

   if (__ctrl) {
	  auto struct sockaddr_in *address = (struct sockaddr_in *) &eth.ifr_addr;
	  inet_ntop(AF_INET, &(address->sin_addr), __ip, INET_ADDRSTRLEN);
   }

   return !!__ctrl;
}


const char *interfaces[] = {
	"eth0","eth1","eth2",
	"wlan0","wlan1","wlan2",
	"lo","lo0","lo1"
};

/* Running process... */
static uint32 __run( 	register signed int sock,
							register signed int sockicmp,
							const struct sockaddr_in *srcaddr,
							const struct sockaddr_in *dstaddr,
							uchar *packet) 
{

	register uint32 __size;
	socklen_t sz = sizeof(struct sockaddr_in);
	struct sockaddr_in __remote;
	struct timeval tim;
	fd_set redfs;

	uchar *recvpkt = (uchar *) calloc(1, 0x38);
	if (!recvpkt) {
		log("Runtime Error (memory alloc recv).\n\n");
		free(packet);
		close(sockicmp);
		close(sock);
		return false;
	}

	struct iphdr *ip = (struct iphdr *) packet;
	struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));

	ip->saddr = srcaddr->sin_addr.s_addr;/* Source */
	ip->daddr = dstaddr->sin_addr.s_addr;/* Target */
	ip->version = (0x04);			/* IP Version */
	ip->frag_off= htons(0x2000);	/* MF is on, and offset 0 */
	ip->ihl = 5;					/* Header lenght: 5 Octets */
	ip->ttl = 0x80;					/* Time to live: 0x80 */
	ip->id = rand() % 0xFFFF;		/* Random identification packet */
	ip->protocol = IPPROTO_ICMP;	/* ICMP Protocol */
	ip->tot_len = htons(0x24);		/* Total size of 1o fragment: 36 bytes */
	ip->check = __checksum((uint16 *) ip, sizeof(struct iphdr));

	icmp->type =  0x08;				/* ICMP type 8 - Echo Request */
	icmp->code =  0x0;				/* ICMP code 0 - Echo Request */
	icmp->checksum = 0x0;			/* Checksum zero here */
	icmp->un.echo.id =  rand() % 0xFF;	/* Random identification packet */
	icmp->un.echo.sequence = htons (1);	/* Sequence ID */


	/* We need set the final payload here because of packet checksum . The
	packet's checksum may be calculated before sending, because the server's
	buffer reads the chcksum field before mount the total packet. */

	memset(&packet[28], 'A', 0x8);	/* Sets fragment with 'A' characters */
	memset(&packet[36], 'B', 0x10);	/* Sets fragment with 'B' characters */
	/* memset(packet[52], 'C', 0x8);(FAKE) Sets fragment with 'C' characters*/
	memset(&packet[52], 'D', 0x8);	/*Sets fragment with 'D' characters */

	char address[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(dstaddr->sin_addr), address, INET_ADDRSTRLEN);
	icmp->checksum = __checksum((uint16 *)icmp,((sizeof(struct icmphdr))+32));

	/* .......................(FIRST) Sending 36 bytes.....................*/
	show("Sending ICMP packet (fragment 1) to host [%s]...\n", address);
	if ( sendto(sock, packet, 0x24, 0, (struct sockaddr *) 
	dstaddr, sizeof(struct sockaddr_in)) == false) {
		log("Error on send data.\n\n");
		close(sock);
		close(sockicmp);
		free(packet);
		return false;
	} 
	show("[Done]\n\n");
	sleep(1);

	/* .......................(SECOND) Sending 36 bytes.....................*/
	memset(&packet[20], 'B', 0x10); /* Now we sets the packet to payload 'B' */
	show("Sending ICMP packet (fragment 2) to host [%s]...\n", address);
	ip->frag_off = htons(0x2 | 0x2000); /* Insert on second octet */
	ip->tot_len = htons(0x24); /* Total packet size: 36 bytes */
	ip->check = __checksum((uint16 *) ip, sizeof(struct iphdr));
	if ( sendto(sock, packet, 0x24, 0, (struct sockaddr *)
	dstaddr, sizeof(struct sockaddr_in)) == false) {
		log("Error on send data.\n\n");
		close(sock);
		close(sockicmp);
		free(packet);
		return false;
	}
	show("[Done]\n\n");
	sleep(1);

	/* .......................(THIRD) Sending 28 bytes.....................*/
	memset(&packet[20], 'C', 0x8); /* Now we sets the packet to payload 'C' */
	show("Sending ICMP packet (fragment 3) to host [%s]...\n", address);
	ip->frag_off = htons(0x4 | 0x2000); /* Insert on fourth octet */
	ip->tot_len = htons(0x1C); /* Total packet size: 28 bytes */
	ip->check = __checksum((uint16 *) ip, sizeof(struct iphdr));
	if ( sendto(sock, packet, 0x1C, 0, (struct sockaddr *)
	dstaddr, sizeof(struct sockaddr_in)) == false) {
		log("Error on send data.\n\n");
		close(sock);
		close(sockicmp);
		free(packet);
		return false;
	}
	show("[Done]\n\n");
	sleep(1);

	/* .......................(FOURTH) Sending 28 bytes.....................*/
	memset(&packet[20], 'D', 0x8); /* Now we sets the packet to payload 'D' */
	show("Sending ICMP packet (fragment 4 final) to host [%s]...\n", address);
	ip->frag_off = htons(0x4 | 0x0000); /* Insert on fourth octet. MF is OFF*/
	ip->tot_len = htons(0x1C); /* Total packet size: 28 bytes */
	ip->check = __checksum((uint16 *) ip, sizeof(struct iphdr));
	if ( sendto(sock, packet, 0x1C, 0, (struct sockaddr *)
	dstaddr, sizeof(struct sockaddr_in)) == false) {
		log("Error on send data.\n\n");
		close(sock);
		close(sockicmp);
		free(packet);
		return false;
	}
	show("[Done]\n\n");

	tim.tv_sec= 4;
	tim.tv_usec= 0;
	FD_ZERO(&redfs);
	FD_SET(sockicmp, &redfs);

	if (!select(sockicmp + 1, &redfs, NULL, NULL, &tim)) {
		show("Timeout...\n\n");
		return false;
	}

	ip = (struct iphdr *) recvpkt;
	icmp = (struct icmphdr *) (recvpkt + sizeof(struct iphdr));

    do {
		if ( (__size = recvfrom(sockicmp, recvpkt, 0x38, 0, 
		(struct sockaddr *) &__remote, &sz)) == false) {
			log("Error on received packet reply.\n\n");
		}

	} while(dstaddr->sin_addr.s_addr != __remote.sin_addr.s_addr);

	inet_ntop(AF_INET, &(__remote.sin_addr), address, INET_ADDRSTRLEN);	
    show("Received ICMP Echo Reply from [%s]:  %d bytes and TTL [%d]\n\n",
	address, __size, ip->ttl);

	free(packet);
	free(recvpkt);
	close(sock);
	close(sockicmp);

	return true;
}


/*
Reassembly Fragmentation Policies (Paxson/Shankar model)
........................................................

. BSD --> 
	Favors an original fragment with an offset that is less 
	than or equal to a subsequent fragment.
	Systems: HP JetDirect

. BSD-Right -->
	favors a subsequent fragment when the original fragment
	has an offset that is less than or equal to the subsequent one.
	Systems: AIX 2, 4.3, 8.9.3, FreeBSD, HP-UX B.10.20, 
                IRIX 4.0.5F, 6.2, 6.3, 6.4, NCD Thin Clients, 
                OpenBSD, OpenVMS, OS/2, OSF1, SunOS 4.1.4, 
                Tru64 Unix V5.0A,V5.1,Vax/VMS.

. Linux -->
	Favors an original fragment with an offset that 
	is less than a subsequent fragment.
	Systems: Çnux Kernel 2.x

. First -->
	Favors the original fragment with a given offset.
	Systems: HP-UX 11.00, MacOS (version unknown), 
	SunOS 5.5.1,5.6,5.7,5.8, Windows (95/98/NT4/ME/W2K/XP/2003)

. Last -->
	Favors the subsequent fragment with a given offset.


Obs:
Windows systems machines cannot reply the echo request fragmented, 
because its police fragmentation is "First" (see above). 
But, a Linux system can do it.

Use fragicmp on both, Linux and Windows. So take a look.
*/

int main(int argc, char *argv[]) {

	if ((argc < 3) || (argc > 5)) { 
  
		log("\nUse: \n%s -d (target)\n", argv[0]);
		log("%s -s (source) -d (target)  ", argv[0]);
		log("[optional spoof].\n\n");
		return false;
	}

	char *target=NULL, *source=NULL;
	static char optc[] = "s:d:";
	srand(time(NULL));
	register uint32 opt;

	while((opt = getopt(argc,argv,optc)) != -1)
	switch(opt) {
		case 'd':
			target = optarg;
			break;
		case 's':
			source = optarg;
			break;
		default:
			log("Invalid option.\n");
			return false;
	}

	char __ip[INET_ADDRSTRLEN];
	const char **eth = interfaces;
	if (!source) {
		while(*eth)
			if ( __fetchIp(*eth++, __ip)) break;
			
		if (!(*__ip)) {
			log("No valid IP found on any interfaces.\n");
			log("Use -s <host> otpion.\n");
			return false;
		} else source = __ip;
	}

	register signed int sock		= socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	register signed int sockicmp	= socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if ( (sock < 0) || (sockicmp < 0) ) {
		log("Error on socket create.\n");
		log("(%s).\n\n", (sock < 0 ? "RAW SOCKET" : "ICMP SOCKET"));
		return false;
	}

	signed int setsock= 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL,(char *)&setsock,sizeof(setsock));

	auto struct hostent *host;
	auto struct sockaddr_in __srcaddr;
	if (!(host = (struct hostent *) gethostbyname(source))) {
		log("Error on lookup source hostname: \"%s\".\n\n", source);
		return false;
	}
	memcpy(&(__srcaddr.sin_addr.s_addr),host->h_addr_list[0],host->h_length);
	__srcaddr.sin_family = AF_INET;

	auto struct sockaddr_in __dstaddr;
	if (!(host = (struct hostent *) gethostbyname(target))) {
		log("Error on lookup destination hostname: \"%s\".\n\n", target);
		return false;
	}
	memcpy(&(__dstaddr.sin_addr.s_addr),
	host->h_addr_list[0], host->h_length);
	__dstaddr.sin_family = AF_INET;

	/* Packet size 60 bytes */
	uchar *packet = (uchar *) calloc(1, 60);
	if (!packet) {
		log("Runtime Error (memory alloc).\n\n"); 
		close(sockicmp); 
		close(sock); 
		return false; 
	}

	/* Running the core... */
	return __run(sock, sockicmp, &__srcaddr, &__dstaddr, packet);
}

