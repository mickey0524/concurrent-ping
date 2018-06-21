#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#define PACKET_SIZE 4096
#define MAX_WAIT_TIME 5
#define MAX_SEND_PACKETS 3 // 发包次数

char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
int datalen = 56;

struct sockaddr_in dest_addr;
struct sockaddr_in from;
struct timeval tvrecv;

unsigned short cal_chksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1)
  {
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return answer;
}

int pack(int pack_no, int socketfd) {
  int i, packsize;
  struct icmp *icmp;
  struct timeval *tval;

  icmp = (struct icmp *)sendpacket;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_cksum = 0;
  icmp->icmp_seq = pack_no;
  icmp->icmp_id = socketfd;
  packsize = 8 + datalen;
  tval = (struct timeval *)icmp->icmp_data;
  gettimeofday(tval, NULL);
  icmp->icmp_cksum = cal_chksum((unsigned short *)icmp, packsize);
  
  return packsize;
}

void send_packet(int socketfd) {
  int i = 0;
   
  for (i = 0; i < MAX_SEND_PACKETS; i++) {
    int packetsize = pack(i, socketfd);
    if (sendto(socketfd, sendpacket, packetsize, 0, (struct sockaddr *)&dest_addr,
      sizeof(dest_addr)) < 0) {
      printf("sendto error\n");
    }
  }
}

void tv_sub(struct timeval *out, struct timeval *in) {
  if ((out->tv_usec -= in->tv_usec) < 0) {
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

int unpack(char *buf, int len, int socketfd) {
  int i, iphdrlen;
  struct ip *ip;
  struct icmp *icmp;
  struct timeval *tvsend;
  double rtt;
  ip = (struct ip *)buf;
  iphdrlen = ip->ip_hl << 2;
  icmp = (struct icmp *)(buf + iphdrlen);
  if (icmp->icmp_id != socketfd) {
    return -2;
  }
  len -= iphdrlen;
  if (len < 8) {
    printf("ICMP packets\'s length is less than 8\n");
    return -1;
  }
  if (icmp->icmp_type == ICMP_ECHOREPLY) {
    tvsend = (struct timeval *)icmp->icmp_data;
    tv_sub(&tvrecv, tvsend);
    rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;
    printf("%d byte from %s: icmp_seq=%u ttl=%d time=%.3f ms\n", len,
           inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
    return 0;
  }
  else {
    return -1;
  }
}

void recv_packet(int socketfd)
{
  int n = 0;
  int fromlen = sizeof(from);

  if ((n = recvfrom(socketfd, recvpacket, sizeof(recvpacket), 0,
    (struct sockaddr *)&from, (socklen_t *)&fromlen)) < 0) {
    printf("recvfrom error\n");
  }
  gettimeofday(&tvrecv, NULL);
  if (unpack(recvpacket, n, socketfd) == -1) {
    printf("unpack error\n");
  }
}

void event_loop(int *sockfds, int rfslength) {
  fd_set rfds;
  int maxfd = 0, i;

  while (1) {
    FD_ZERO(&rfds);
    maxfd = 0;

    for (i = 0; i < rfslength; i++) {
      // 把当前连接的文件描述符加入到集合中*/
      FD_SET(sockfds[i], &rfds);
      // 找出文件描述符集合中最大的文件描述符
      if (maxfd < sockfds[i]) {
        maxfd = sockfds[i];
      }
    }

    struct timeval tv;
    tv.tv_sec = MAX_WAIT_TIME;
    tv.tv_usec = 0;

    int retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);

    if (retval == -1) {
      printf("select error\n");
      break;
    }
    else if (retval == 0) {
      continue;
    }
    else {
      for (i = 0; i < rfslength; i++) {
        recv_packet(sockfds[i]);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  struct hostent *host;
  struct protoent *protocol;

  int i;
  int size = 50 * 1024;
  unsigned long inaddr;

  if (argc < 2) {
    printf("usage:%s hostname/IP address\n", argv[0]);
    exit(1);
  }
  if ((protocol = getprotobyname("icmp")) == NULL) {
    printf("getprotobyname error\n");
    exit(1);
  }
  int *socketfds = (int *)malloc(sizeof(int) * (argc - 1));

  for (i = 1; i < argc; i++) {
    if ((socketfds[i - 1] = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0) {
      printf("socket[%d] error\n", i);
      exit(1);
    }
    setsockopt(socketfds[i - 1], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inaddr = inet_addr(argv[i]) == INADDR_NONE;

    if (inaddr) {
      if ((host = gethostbyname(argv[i])) == NULL) {
        printf("gethostbyname error\n");
      }
      memcpy((char *)&dest_addr.sin_addr, host->h_addr, host->h_length);
    }
    else {
      dest_addr.sin_addr.s_addr = inet_addr(argv[i]);
    }
    send_packet(socketfds[i - 1]);
  }
  
  event_loop(socketfds, argc - 1);

  for (i = 0; i < argc - 1; i++) {
    close(socketfds[i]);
  }
  free(socketfds);

  return 0;
}
