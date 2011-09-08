#ifndef __PROXY_TEST_APP_H
#define __PROXY_TEST_APP_H

#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "./treck/include/trsocket.h"
#include "./treck/include/boxer_treck.h"

#define GN 0
#define GI 1

#define TRUE 1
#define FALSE 0
#define USERTCP_MAX_CONN 500
#define UTP_MAX_HASH_INDEX 50
#define TCP_QBUF_SIZE   (64*1000)

//Events
#define UTCP_CB_CONNECT_COMPLT            0x0001
#define UTCP_CB_ACCEPT                    0x0002
#define UTCP_CB_RECV                      0x0004
#define UTCP_CB_RECV_OOB                  0x0008
#define UTCP_CB_SEND_COMPLT               0x0010
#define UTCP_CB_REMOTE_CLOSE              0x0020
#define UTCP_CB_SOCKET_ERROR              0x0040
#define UTCP_CB_RESET                     0x0080
#define UTCP_CB_CLOSE_COMPLT              0x0100
#define UTCP_CB_WRITE_READY               0x0200
#define UTCP_CB_TCPVECT_CLOSE             UTCP_CB_ACCEPT

#define UTCP_INVALID_SOCKET -1
#define UTCP_EINPROGRESS     236

#define SN_ZERO_VARIABLE(var) (memset((&var), 0, sizeof(var)))

#define usertcp_set_context(treckContext) \
    tfSetCurrentContext(treckContext);

#define USER_TCP_SET_CONTEXT(treckContext) \
    usertcp_set_context((treckContext)->treckInstance);\
    g_treckContext_p = (treckContext);

#define IS_CURR_CONTEXT_GN (g_treckContext_p == &g_treckContext[GN])

/*
typedef int (*treckUserSendFn)(void *userData, char *buf, int bufLen);
typedef int (*treckCopyUserInfo)(void **dest, void *src);
typedef int (*treckFreeUserInfo)(void **userinfo);
*/

struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned long seq;
    unsigned long ack_seq;       
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short res1:4;
    unsigned short doff:4;
    unsigned short fin:1;
    unsigned short syn:1;
    unsigned short rst:1;
    unsigned short psh:1;
    unsigned short ack:1;
    unsigned short urg:1;
    unsigned short res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned short doff:4;
    unsigned short res1:4;
    unsigned short res2:2;
    unsigned short urg:1;
    unsigned short ack:1;
    unsigned short psh:1;
    unsigned short rst:1;
    unsigned short syn:1;
    unsigned short fin:1;
#  endif
    unsigned short window;       
    unsigned short check;
    unsigned short urg_ptr;
};


#if 0
//Anuja:commented redundant vars inside treckContext_t
typedef struct treckContext {
	//	unsigned int dynamicmedSendFnUserInfo:1;
		unsigned int isValid;
		unsigned int isDeleting;
	//	unsigned int isIPV6Instance;

	//	unsigned int isConnImportInProgress;
	//	unsigned int importIss;
	//	unsigned int importTimeStamp;
	//	unsigned int userInfoCopy;

		/*Handle to stack instance*/
		void* treckInstance;

		/*Holds instance specific memory block*/
		void *contextPtr;

		/*Pointer to received buffer to be passed from bixer NPU driver*/
		char *recvBuf;

		/*Length of received buffer*/
		int bufLen;

		/*total number of multihome IPs configured*/
	//	int multiHomeCount;

		/*Callback function to send IP packets to NPU*/
		treckUserSendFn SendFn;

		/*Callback function to copy user data*/
		//treckCopyUserInfo copyUserInfoFn------------------------undo;

		/*Callback function to free user data*/
		//treckFreeUserInfo freeUserInfoFn------------------------undo;

		/*Callback function to buffer nw packets*/
		//treckBufferNwPacket bufferNwPacketFn------------------------undo;

		/*boxer user data - contains pointer to boxerUserdata_t*/
		void *userinfo;

		/*User info to be passed to above call back function*/
		void *SendFnUserInfo;
		/*SN timer event handle*/
		void *timerEvent;

		/*Logging related*/
	//	void *logHandle_p;
	//	int lastLogNo;

		/*Memblock cache*/
	//	void *memcache;

		/*last updated msec*/
		unsigned long long msec;

		/* context level stats */
	//	usertcp_context_stats_t *context_stats;

		void (*socApiEntryPtrUserFn)(void *ads, void *socketPtr);

		/* Stack Context */
		char stack_context[5];
		/* Callback function to provide IP packet in case of UDP. Used by TTG */
	//	treckUserRawIpFn userRawIpFn;

		/* 
		 * user session provided by UserApp (TTG). 
		 * userRawIpFn() will provide this back to App (TTG)
		 */
	//	void *utcp_user_session;

} treckContext_t;
#endif

//Anuja: commented var not reqd in the usertcp ctx struct
typedef struct
{
		char profile_name[5];
		unsigned char stack_enabled:1;
		int server_fd;
	//	int server_fd_ipv6;
		void *Interfacehandle;
	//	void *Ipv6_Interfacehandle;
		treckContext_t StackContext;
	//	sn_list_element_t next_context;
}sn_usertcp_ctxt_t;

typedef unsigned long ip_addr_t;

//Function prototypes
int init_proxy(void);
int create_init_stacks(void);
int add_interface(int stack_inst);
int configure_stack(int stack_inst);
void setup_raw_socket(void);
void usertcp_server_event_handler(int sockd, int eventFlags);
int driverOpen();
int driverClose();

int driverSend(ttUserInterface interfaceHandle, char TM_FAR *dataPtr,
	       int dataLength, int flag);

int driverRecv(ttUserInterface interfaceHandle, char TM_FAR **dataPtrPtr,
               int TM_FAR *dataLengthPtr, ttUserBufferPtr userBufferHandlePtr);

int driverFreeRecvBufferFuncPtr(ttUserInterface interfaceHandle,
		                char TM_FAR *dataPtr);

int driverIoctl(ttUserInterface interfaceHandle, int flag, 
		void TM_FAR *optionPtr, int optionLen );

int driverGetPhyAddr(ttUserInterface interfaceHandle, char TM_FAR *physicalAddress);

int treck_send(void *userInfo, char *buffer, int bufLen);
void usertcp_event_handler(int sockfd, void* context, int eventFlags);
void usertcp_tcp_packet_handler(int sockfd, void *userinfo, int eventFlags);
void usertcp_treck_timer_expiry_handler(unsigned long timeInterval, void *context);
void drain_app_send_buff(int sockd, int stack_inst);

//sn_event_timer *sn_event_timer_new(int timeout, gboolean (*callback)(void*), void *userdata);
#endif
