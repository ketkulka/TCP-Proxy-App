#ifndef __TESTAPP_H__
#define __TESTAPP_H__

#define CLIENT_IP 
#define SERVER_IP 
#define CLIENT_PORT 
#define SERVER_PORT 

#define GN 0
#define GI 1                

#define UPLINK 0
#define DOWNLINK 1

#define TCPOPT_NOP    1 /* Segment size negotiating */
#define TCPOPT_MSS    2 /* Segment size negotiating */
#define TCPOPT_WINDOW   3 /* Window scaling */
#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3

typedef unsigned long ip_addr_t;

enum app_fsm
{
  INIT,
  PROXY,
  POST_PROXY
};

typedef enum app_fsm app_fsm_t;

struct proxy_socket
{
  void *sk;
};

typedef struct proxy_socket proxy_sock;
typedef struct proxy_socket* psock;
typedef struct proxy_socket** ppsock;

struct proxy_app
{
  proxy_sock sock[2];
  app_fsm_t state;
  uint16 pkt_cnt;
  uint32 srv_ip;
  uint32 cli_ip;
  uint16 srv_port;
  uint16 cli_port;
  
  uint32 high_seq_to_client;
  uint32 high_seq_to_server;
  uint16 mss;
  uint16 cwscale;
  uint16 swscale;
  uint16 wnd_of_server;
  uint16 wnd_of_client;
};

typedef struct proxy_app proxy_app_t;
typedef struct proxy_app* pproxy_app;
typedef struct proxy_app** ppproxy_app;

proxy_app_t proxy;


#endif
