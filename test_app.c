#include <stdio.h>
#include "utcp.h"
#include "test_app.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <stdlib.h>
//#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <assert.h>
#include <getopt.h>
#include <sys/select.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "timer.h"

#include "test_app.h"

#define printf

#define SOCK(x) proxy.sock[x]

#define NF_DROP 0
#define MAX_CONN              10//Anuja: chnaged from 1000 to 10 00 
#define MAX_PENDING_PKTS      128       //KEEP A PERFECT POWER OF TWO
#define BUFSIZE               4000
#define MAX_DBUFF             (MAX_CONN*MAX_PENDING_PKTS*2)
# define FAILURE  1
# define SUCCESS 0
#define CONN_INIT 0
#define CONN_CONNECTING 1
#define CONN_CONNECTED 2
#define CONN_RC 3
#define CONN_CC 4
#define APP_BUFLEN 5000
#define MAX_CHARS_IN_DEV_NAME   50

unsigned int g_tot_pkts = 0;
unsigned int g_tot_fpkts = 0;
unsigned int g_enable_fast_path = 1;

typedef struct _interface_info
{
    signed int          txfd;
    signed int          rxfd;
    signed int          inf_id;
    struct sockaddr_ll  osll;
    unsigned char       *name;
    unsigned char       dev_name[MAX_CHARS_IN_DEV_NAME];
    unsigned char       self_mac_addr[6];
    unsigned char       next_hop_mac[6];
} interface_info;

typedef struct _interface_pair
{
    interface_info *cli;
    interface_info *srv;
    int            max_rx_fd;
} interface_pair_info;

typedef struct _conn
{
  int sockd[2];
  //unsigned int curr_pkt_len;
  ip_addr_t src_ipaddr;
  unsigned short src_port;
  ip_addr_t dst_ipaddr;
  unsigned short dst_port;
  int state[2];
  int deferred_close_flag[2];
}conn_t;

typedef struct _data_buf
{
  struct _data_buf *n;
  unsigned int     fin;
  unsigned int     l;
  unsigned int     tcp_len;
  unsigned int     o;
  unsigned char    *iph;
  unsigned char    *th;
  unsigned char    do_frag;
  unsigned char    d[BUFSIZE];
}data_buf;

volatile uint32_t g_exit_indicated = 0;

uint32_t no_proxy_mode = 0;

interface_info          cli_inf_info = {.txfd = -1, .rxfd = -1, .name = "Client"};
interface_info          srv_inf_info = {.txfd = -1, .rxfd = -1, .name = "Server"};
interface_pair_info     inf_pair_info;

data_buf             *free_dbs;
data_buf             *db_list;
struct ipq_handle    *rxh;
conn_t conn_list[20];

int num_flow = 0;

void proxy_app_stack_send(void *tcp_sk, uint8* ippkt, uint16 len, void* packet_out_ptr, void *user_peer_ptr)
{
  psock local_sock = (psock)packet_out_ptr;
  psock peer_sock = (psock)user_peer_ptr;

  printf("PROXY: Sending Packet of len %d\n", len);

  int               sent_bytes = 0;
  int               stack_inst;
  char              *ll_frame;
  struct iphdr      *iph = (struct iphdr *)ippkt;
  unsigned int      ihl = iph->ihl << 2;
  struct tcphdr     *tcph = (struct tcphdr *)(ippkt + ihl);
  interface_info    *inf = NULL;

  if(local_sock == &(SOCK(GN)))
  {
    inf = &cli_inf_info;
  }
  else
  {
    inf = &srv_inf_info;
  }

/*  if (direction == GN) { 
    inf = &cli_inf_info;
  } else {
    inf = &srv_inf_info;
  }*/
  /* Form ethernet frame */
  uint8* buffer = (uint8*)malloc(len + 14);
  
  ll_frame = buffer; 
  ll_frame[0] = inf->next_hop_mac[0]; 
  ll_frame[1] = inf->next_hop_mac[1]; 
  ll_frame[2] = inf->next_hop_mac[2]; 
  ll_frame[3] = inf->next_hop_mac[3]; 
  ll_frame[4] = inf->next_hop_mac[4]; 
  ll_frame[5] = inf->next_hop_mac[5]; 
  ll_frame[6] = inf->self_mac_addr[0];
  ll_frame[7] = inf->self_mac_addr[1];
  ll_frame[8] = inf->self_mac_addr[2];
  ll_frame[9] = inf->self_mac_addr[3];
  ll_frame[10] = inf->self_mac_addr[4];
  ll_frame[11] = inf->self_mac_addr[5];
  ll_frame[12] = 0x08;
  ll_frame[13] = 0x00;
  
  memcpy(buffer+14, ippkt, len);

  sent_bytes = sendto(inf->txfd, ll_frame, len+14 , MSG_DONTWAIT,(const struct sockaddr*)&inf->osll,(socklen_t)sizeof(inf->osll));
  if (sent_bytes < 0){
    perror("PROXY: Sento failed: ");
    return ;
  }
  printf("PROXY: Sent %d bytes to %s side\n",len+14,inf->name);
  return ;
}

void proxy_app_recv(void *tcp_sk, uint8* data, uint16 len, void *pktuserptr, void *data_to_app_ptr, void *user_peer_ptr)
{
  psock local_sock = (psock)data_to_app_ptr;
  psock peer_sock = (psock)user_peer_ptr;

  printf("PROXY: Received Data with Len = %u\n", len);

  /* Use this data to send on the other side */

  uint32 bytes_sent = 0;

  utcp_send(peer_sock->sk, data, len, NULL, &bytes_sent);

  assert(bytes_sent == len);

  return;
}


int proxy_app_init()
{
  memset(&proxy, 0, sizeof(proxy_app_t));
  return 0;
}


int proxy_fork_conn(void)
{
  start_timer();
  /* Create GN side socket */
  SOCK(GN).sk = create_tcp_sk(proxy.srv_ip, proxy.cli_ip, proxy.srv_port, proxy.cli_port);

  utcp_register_data_to_app(SOCK(GN).sk, proxy_app_recv, &SOCK(GN));

  utcp_register_packet_out(SOCK(GN).sk, proxy_app_stack_send, &SOCK(GN));

  /* Create GI side socket */

  SOCK(GI).sk = create_tcp_sk(proxy.cli_ip, proxy.srv_ip, proxy.cli_port,  proxy.srv_port);

  utcp_register_data_to_app(SOCK(GI).sk, proxy_app_recv, &SOCK(GI));

  utcp_register_packet_out(SOCK(GI).sk, proxy_app_stack_send, &SOCK(GI));

  /* Bind the two sockets internally together */
  utcp_bind_peer_socks(SOCK(GI).sk, &SOCK(GI), SOCK(GN).sk, &SOCK(GN), PEER_BIND_ALL);

  /* Migrate the socket */
  migrate_info mig;
  /* Server socket on GN side */
  mig.snduna = proxy.high_seq_to_client+1;
  mig.recvnxt = proxy.high_seq_to_server;
  mig.snd_wscale = proxy.swscale;
  mig.rcv_wscale = proxy.cwscale;
  mig.mss = proxy.mss;

  utcp_migrate_socket(SOCK(GN).sk, &mig);

  mig.snduna = proxy.high_seq_to_server;
  mig.recvnxt = proxy.high_seq_to_client+1;
  mig.snd_wscale = proxy.cwscale;
  mig.rcv_wscale = proxy.swscale;

  utcp_migrate_socket(SOCK(GI).sk, &mig);

  return 0;
}


int proxy_close_conn(void)
{
  utcp_unbind_peer_socks(SOCK(GI).sk);

  delloc_tcp_sk(SOCK(GI).sk);
  SOCK(GI).sk = NULL;

  delloc_tcp_sk(SOCK(GN).sk);
  SOCK(GN).sk = NULL;

  stop_timer();

  return 0;
}

int proxy_bypass(uint8 *pkt, uint16 len, int direction)
{

  struct iphdr *iph = (struct iphdr *)pkt;
  int ip_hlen = IP_HLEN(iph);
  struct tcphdr *tcph = (struct tcphdr *)(pkt + ip_hlen);
  int tcp_hlen = TCP_HLEN(tcph);
  int migrate = FALSE, parse = FALSE;

  /* This function assumes that IP header and TCP header does not contain any
     anamolies */

  if(proxy.state < PROXY)
  {
    switch(proxy.pkt_cnt)
    {
      case 0:
        if(tcph->syn && !tcph->ack && !direction)
        {
          proxy.pkt_cnt++;
          parse = TRUE;
          
          proxy.cli_ip = ntohl(iph->saddr);
          proxy.cli_port = ntohs(tcph->source);
          proxy.srv_ip = ntohl(iph->daddr);
          proxy.srv_port = ntohs(tcph->dest);
        }
        break;
      case 1:
        if(tcph->syn && tcph->ack && direction)
        {
          proxy.pkt_cnt++;
          parse = TRUE;
        }
        break;
      case 2:
        if(!tcph->syn && tcph->ack && !direction)
        {
          proxy.pkt_cnt++;
          parse = TRUE;
          migrate = TRUE;
        }
        break;
      default:
        assert(0);
        break;
    }
  }
  else if(proxy.state > PROXY)
  {
  }

  if(parse)
  {
    uint32 pkt_seq = ntohl(tcph->seq);

    if(direction)
    {
      if(after(pkt_seq, proxy.high_seq_to_client))
      {
        proxy.high_seq_to_client = pkt_seq;
//        proxy.wnd_of_server = ntohs(tcph->window);
      }
      if(!proxy.high_seq_to_client)
        proxy.high_seq_to_client = pkt_seq;
    }
    else
    {
      if(after(pkt_seq, proxy.high_seq_to_server))
      {
        proxy.high_seq_to_server = pkt_seq;
  //      proxy.wnd_of_client = ntohs(tcph->window);
      }
      if(!proxy.high_seq_to_server)
        proxy.high_seq_to_server = pkt_seq;
    }
    int tcp_opt_len = tcp_hlen - 20;
    uint8  *tcp_opt = (uint8*)(((uint8*)tcph) + 20);

    while(tcp_opt_len > 0)
    {
      int opcode = *tcp_opt++;
      int opsize;

      switch (opcode) {
        case TCPOPT_MSS:
          opsize = *tcp_opt++;
          if (opsize == TCPOLEN_MSS) {
            uint16 in_mss = ntohs(*(uint16*)tcp_opt);
            if(proxy.mss)
            {
              proxy.mss = (in_mss < proxy.mss)?in_mss:proxy.mss;
            }
            else
            {
              proxy.mss = in_mss;
            }
          }   
          tcp_opt_len -= opsize;
          tcp_opt += (opsize - 2);
          break;
        case TCPOPT_WINDOW:
          opsize = *tcp_opt++;
          if (opsize == TCPOLEN_WINDOW) {
            uint8 wscale = *(uint8 *)tcp_opt;
            if(direction)
            {
              proxy.swscale = wscale;
            }
            else
            {
              proxy.cwscale = wscale;
            }
          }
          tcp_opt_len -= opsize;
          tcp_opt += (opsize - 2);
          break;
        case TCPOPT_NOP:
          tcp_opt_len--;
          break;
        default:
          opsize = *tcp_opt++;
          tcp_opt_len -= opsize;
          tcp_opt += (opsize - 2);
          break;
      }
    }
    printf("Proxy Pkt Cnt = %d : MSS = %u, Seq to Server = %u, Seq to Client = %u, cwscale = %d, swscale = %d\n", proxy.pkt_cnt, proxy.mss, proxy.high_seq_to_server, proxy.high_seq_to_client, proxy.cwscale, proxy.swscale);
  }

  if(migrate)
  {
    proxy.state = PROXY;
    proxy_fork_conn();
  }

  stack_send(!direction, pkt, len);
}

int stub_incoming_pkt(uint8* pkt, uint16 len, int direction)
{
  void *tcp_sk;
  if(direction)
  {
    tcp_sk = SOCK(GI).sk;
  }
  else
  {
    tcp_sk = SOCK(GN).sk;
  }

  if(proxy.state == PROXY)
  {
    if((((struct tcphdr *)(pkt+20))->fin) || (((struct tcphdr *)(pkt+20))->rst))
    {
      proxy.state = POST_PROXY;
      goto bypass;
    }
    utcp_incoming_packet(pkt, len, tcp_sk);
  }
  else
  {
bypass:
    proxy_bypass(pkt, len, direction);
  }
  return SUCCESS;
}

int handover_pkt_to_stack(data_buf *pkt, unsigned int len, int stack_inst) 
{
  int errorCode;

  printf("In handover_pkt_to_stack \n\n");

  stub_incoming_pkt(pkt->iph, len, stack_inst);

  return SUCCESS;
}

int stack_send(int direction, char *buffer, int bufLen)
{
  int               sent_bytes = 0;
  int               stack_inst;
  char              *ll_frame;
  struct iphdr      *iph = (struct iphdr *)buffer;
  unsigned int      ihl = iph->ihl << 2;
  struct tcphdr     *tcph = (struct tcphdr *)(buffer + ihl);
  interface_info    *inf = NULL;

  if (direction == GN) { 
    inf = &cli_inf_info;
  } else {
    inf = &srv_inf_info;
  }
  /* Form ethernet frame */
  ll_frame = buffer - 14; 
  ll_frame[0] = inf->next_hop_mac[0]; 
  ll_frame[1] = inf->next_hop_mac[1]; 
  ll_frame[2] = inf->next_hop_mac[2]; 
  ll_frame[3] = inf->next_hop_mac[3]; 
  ll_frame[4] = inf->next_hop_mac[4]; 
  ll_frame[5] = inf->next_hop_mac[5]; 
  ll_frame[6] = inf->self_mac_addr[0];
  ll_frame[7] = inf->self_mac_addr[1];
  ll_frame[8] = inf->self_mac_addr[2];
  ll_frame[9] = inf->self_mac_addr[3];
  ll_frame[10] = inf->self_mac_addr[4];
  ll_frame[11] = inf->self_mac_addr[5];
  ll_frame[12] = 0x08;
  ll_frame[13] = 0x00;
  sent_bytes = sendto(inf->txfd, ll_frame, bufLen+14 , MSG_DONTWAIT,(const struct sockaddr*)&inf->osll,(socklen_t)sizeof(inf->osll));
  if (sent_bytes < 0){
    perror("Sento failed: ");
    return FAILURE;
  }
  printf("Sent %d bytes to %s side\n",bufLen+14,inf->name);
  return SUCCESS;
}

void proxy_app(data_buf *data_buff)
{
  unsigned int bufLen = 7000;
  int stack_inst;
  struct iphdr *iph = (struct iphdr *)data_buff->iph;
  struct tcphdr *tcph = (struct tcphdr *)(data_buff->th);

  //####Anuja: !!!HACK just for testing purpose
  conn_list[num_flow].src_ipaddr = iph->saddr;//inet_addr("10.4.83.235");
  conn_list[num_flow].dst_ipaddr = iph->daddr;//inet_addr("10.4.83.221");
  conn_list[num_flow].src_port = tcph->source;
  conn_list[num_flow].dst_port = tcph->dest;

  printf("TCP pkt type: S:%d A:%d F:%d R:%d\n", tcph->syn, tcph->ack, tcph->fin, tcph->rst);		
  printf("TCP sport: %d\t", ntohs(conn_list[num_flow].src_port));		
  printf("TCP dport: %d\n", ntohs(conn_list[num_flow].dst_port));		

  //Anuja: HACK for determining the dir
  if (ntohs(tcph->source) != 80 ) {
    stack_inst = GN;
  } else {
    stack_inst = GI;
  }

  printf(" Packet Direction: %d\n\n", stack_inst);

  if (!no_proxy_mode) {
    if (handover_pkt_to_stack(data_buff, data_buff->l, stack_inst)) {
      printf("handover_pkt_to_stack failed\n");
    }
  } else {
    stack_send(!stack_inst,data_buff->d + 14, data_buff->l);
  }
}

/* MAIN CODE STARTS HERE */

#define alloc_db()      ({data_buf *db = free_dbs; if (db) { free_dbs = db->n; db->fin = 0; db->do_frag = 0; } db; })

void setup_free_pkt_bufs(void)
{
  int i;
  db_list = malloc(sizeof(data_buf)*MAX_DBUFF);
  if (!db_list)
    exit(-1);
  free_dbs = db_list;
  for (i = 0; i < MAX_DBUFF-1; i++)
    free_dbs[i].n = &free_dbs[i+1];
  //free_dbs[i].n = NULL;
  //Anuja: created circular list
  free_dbs[i].n = free_dbs;
}


int rx_n_process (int fd, char *name)
{
  unsigned char  *d = NULL;
  data_buf       *db = NULL;
  struct iphdr   *iph = NULL;
  struct tcphdr  *th = NULL;
  ssize_t            ret = -1;

  db = alloc_db();
  if (!db) {
    printf("failed to allocated data_buf\n");
    return -1;
  }
  ret = recv(fd, (void*)&db->d[14], BUFSIZE - 14, 0);
  if (ret < 0) {
    perror("recv() failed: ");
    printf("rx failed on fd -> %d\n",fd);
    return -1;
  }
  d = db->d + 14 ;               
  iph = (struct iphdr*)(d);
  db->iph = d;    
  db->l = ntohs(iph->tot_len);
  th = (struct tcphdr*)((unsigned char*)iph + (iph->ihl<<2));
  db->th = ((unsigned char*)iph + (iph->ihl<<2));
  //db->tcp_len = db->l - ((((struct tcphdr*)(db->th))->doff << 2) + (iph->ihl<<2));
  printf("Received pkt of len %d from %s\n", db->l,name);                                         
  proxy_app(db);
  return 0;
}

void signalHandler(int cause, siginfo_t *info, void *uctxt)                            
{                                                                                       
  g_exit_indicated = 1;
}                                                                                       

void register_signal_handler() 
{
  struct sigaction sa;

  sa.sa_sigaction = signalHandler;

  sigemptyset(&sa.sa_mask);

  sa.sa_flags = SA_SIGINFO;

  if(sigaction(SIGINT, &sa, 0))
  {
    perror("sigaction");
    exit(1);
  }
}

void recv_data(void) 
{
  int                   ret = 0;
  fd_set                rfds;
  struct timeval        ts = {.tv_sec = 0, .tv_usec = 1000};
  interface_pair_info   *inf_pair = &inf_pair_info;

  FD_ZERO(&rfds);
  FD_SET(inf_pair->cli->rxfd, &rfds);
  FD_SET(inf_pair->srv->rxfd, &rfds);

  ret = select(inf_pair->max_rx_fd +1, (fd_set *)&rfds, NULL, NULL, (struct timeval *)&ts);

  if (ret <= 0) 
    return;

  if (FD_ISSET(inf_pair->cli->rxfd, &rfds)) {
    rx_n_process (inf_pair->cli->rxfd, inf_pair->cli->name);
  }

  if (FD_ISSET(inf_pair->srv->rxfd, &rfds)) {
    rx_n_process (inf_pair->srv->rxfd, inf_pair->cli->name);
  }
}
void check_expiry()
{
    static prev_slot = 0;
    if(twheel.curr_slot != prev_slot)
    {
        prev_slot = twheel.curr_slot;
        execute_timerwheel(TWHEEL_LIST(twheel.curr_slot));
    }

}

void usage (char *argv[])
{
  printf ("Usage:  %s options\n",argv[0]);
  printf (
      "  --gi-dev  <name>     : Mandatory: Name of the interface which is connected to internet side.\n"
      "  --gn-dev  <name>     : Mandatory: Name of the interface which is connected to mobile side.\n"
      "  --gi-nhm  <mac-addr> : Mandatory: Next hop IP's source mac address on internet side.\n"
      "  --gn-nhm  <mac-addr> : Mandatory: Next hop IP's source mac address on mobile side.\n"
      "  --no-proxy           : Optiional: Bypass proxy mode\n"
      "  --no-tcp-hdr-pred    : Optiional: Disable TCP Hdr Pred\n"
      );
}

int parse_cmdline (int argc, char *argv[])
{
  unsigned int mask = 0;
  const struct option lopts[] = 
  {
    {"gi-dev", 1, NULL, 0},
    {"gn-dev", 1, NULL, 1},
    {"gi-nhm", 1, NULL, 2},
    {"gn-nhm", 1, NULL, 3},
    {"no-proxy", 0, NULL, 4},
    {"no-tcp-hdr-pred", 0, NULL, 5}
  };
  interface_info *client = &cli_inf_info;
  interface_info *server = &srv_inf_info;
  do
  {
    int opt_index;
    int c = getopt_long(argc, argv, "", (const struct option*)&lopts, &opt_index);
    if (c == -1) {
      break;
    }
    mask |= 1 << c;
    switch(c)
    {
      case 0:
      case 1:
        {
          unsigned char *name = (c == 0)?server->dev_name:client->dev_name;
          strncpy(name,optarg,MAX_CHARS_IN_DEV_NAME);
          break;
        }
      case 2:
      case 3:
        {
          int mac[6];
          unsigned char *p_mac = (c == 2)?server->next_hop_mac:client->next_hop_mac;
          int ret = sscanf(optarg,"%02x:%02x:%02x:%02x:%02x:%02x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
          if (ret != 6) {
            usage(argv);
            return -1;
          }
          p_mac[0] = mac[0] & 0xff;
          p_mac[1] = mac[1] & 0xff;
          p_mac[2] = mac[2] & 0xff;
          p_mac[3] = mac[3] & 0xff;
          p_mac[4] = mac[4] & 0xff;
          p_mac[5] = mac[5] & 0xff;
          break;
        }
      case 4:
        {
          no_proxy_mode = 1;
          break;
        }
      case 5:
        {
          g_enable_fast_path = 0;
          break;
        }
      default:
        {
          usage(argv);
          return -1;
          break;
        }
    }
  } while(1);
  if ((mask & 0x0f) != 0x0f) {
    usage(argv);
    return -1;
  }
  return 0;
}

int get_inf_mac_addr (char * name, char *addr)
{
  struct ifreq  ifr;
  int           sk;
  if ( 0 > (sk = socket(AF_INET,SOCK_DGRAM,0))) {
    perror("ERROR:: failed to open socket for ioctl: ");
    return -1;
  }
  memset(&ifr,0,sizeof(ifr));
  strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
  if (ioctl(sk, SIOCGIFHWADDR, &ifr) < 0)
  {
    perror("ERROR:: getting mac addr for adapter: ");
    close(sk);
    return -1;
  }
  memcpy((void*)addr,(void *)ifr.ifr_hwaddr.sa_data,6);
  close(sk);
  return 0;
}

int setup_inf_osll (interface_info *inf)
{
  struct ifreq  ifr;
  int           sk;
  if ( 0 > (sk = socket(AF_INET,SOCK_DGRAM,0))) {
    return -1;
  }
  memset(&ifr,0,sizeof(ifr));
  strncpy(ifr.ifr_name, inf->dev_name, IFNAMSIZ - 1);
  if (ioctl(sk, SIOCGIFINDEX, &ifr) < 0)
  {
    perror("ERROR:: getting ifindex for adapter: ");
    close(sk);
    return -1;
  }
  inf->inf_id = ifr.ifr_ifru.ifru_ivalue;
  memset(&inf->osll, 0, sizeof(inf->osll));
  inf->osll.sll_family = AF_PACKET;
  inf->osll.sll_halen = 6;
  inf->osll.sll_ifindex = inf->inf_id;
  close(sk);
  return 0;
}


int init_interface_info (interface_info *inf)
{
  struct sockaddr_ll  addr = { 0 };
  int                 ret = 0;

  /* get interface MAC address */
  ret = setup_inf_osll(inf);
  ret |= get_inf_mac_addr(inf->dev_name,inf->self_mac_addr);
  /* get interface index */
  if ( 0 > ret) {
    return -1;
  }
  /* open tx socket */
  if ( 0 > (inf->txfd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP))) ) {
    return -1;
  }
  /* open rx socket */
  inf->rxfd = socket(PF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
  if (0 > inf->rxfd) {
    perror("rx socket() failed: ");
    close (inf->txfd);
    inf->txfd = -1;
    return -1;
  }
  /* bind rx socket */
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_IP);
  addr.sll_ifindex = inf->inf_id;
  if ( 0 > bind(inf->rxfd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr))) {
    perror("rx socket bind() failed: \n");
    close (inf->rxfd);
    inf->rxfd = -1;
    close (inf->rxfd);
    inf->rxfd = -1;
    return -1;
  }
  printf("opened rxfd %d\n",inf->rxfd);
  return 0;
}

inline int deinit_interface_info (interface_info *inf)
{
  if (inf->rxfd) {
    close(inf->rxfd);
    inf->rxfd = -1;
  }
  if (inf->txfd) {
    close(inf->txfd);
    inf->txfd = -1;
  }
}

inline int open_interfaces (void)
{
  if ( 0 > init_interface_info(&cli_inf_info)) {
    return -1;
  }
  if ( 0 > init_interface_info(&srv_inf_info)) {
    deinit_interface_info(&cli_inf_info);
    return -1;
  }
  return 0;
}

inline void close_interfaces (void) 
{
  deinit_interface_info(&cli_inf_info);
  deinit_interface_info(&srv_inf_info);
}


int main (int argc, char *argv[]) 
{
  int retval = 1;

  if( 0 > parse_cmdline(argc, argv)) {
    return -1;
  }

  setup_free_pkt_bufs();

  retval = open_interfaces();
  if (0 > retval) {
    printf ("failed to open tx interfaces\n");
    return -1;
  }
  inf_pair_info.cli = &cli_inf_info;
  inf_pair_info.srv = &srv_inf_info;
  inf_pair_info.max_rx_fd = (inf_pair_info.cli->rxfd > inf_pair_info.srv->rxfd) ? inf_pair_info.cli->rxfd : inf_pair_info.srv->rxfd;

  if(proxy_app_init())
  {
    printf("Init proxy failed\n");	
    close_interfaces();
    return FAILURE;
  }
  register_signal_handler();

  while(1) 
  {
    if (g_exit_indicated) {
      break;
    }
    recv_data();
    /* timer processing */
    check_expiry();
  }

  if(proxy.state >= PROXY)
   proxy_close_conn();

  close_interfaces();
  fflush(stdout);
  return SUCCESS;	
}

