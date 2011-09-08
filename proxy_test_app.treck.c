
void *hist_overhead = NULL;
void *hist_total = NULL;

int g_show_histogram = 0;

//globals
nsigned char        buffer[5000];
//Application buffer for flow control etc 
unsigned char uplink_buff[APP_BUFLEN];
int uplink_buff_len = 0;
char * uplink_buff_send_ptr = uplink_buff;
int do_not_recv_uplink = 0;
unsigned char dnlink_buff[APP_BUFLEN];
int dnlink_buff_len = 0;
char * dnlink_buff_send_ptr = dnlink_buff;
int do_not_recv_dnlink = 0;
int num_flow = 0;
treckContext_t g_treckContext[2];
ttUserContext g_context[2];
ttUserInterface g_interfaceHandle[2];
void *g_treckContext_p; 
extern unsigned long int tvTime;
extern unsigned long int tvTimeRollOver;
unsigned int tvTime_usec = 0;
//keep time elaped in usec
unsigned long gi_clock_tick = 0;
unsigned long gn_clock_tick = 0;
unsigned long next_expiry_tick[2] = {100,100};

//Pre allocate buffers for storing pkts received from the ip Q
void clear_old_flow_data()
{
  USER_TCP_SET_CONTEXT(&g_treckContext[GN]);
  uplink_buff_len = 0;
  uplink_buff_send_ptr = uplink_buff;
  conn_list[num_flow].deferred_close_flag[GN] = 0;
  do_not_recv_uplink = 0;
  
  dnlink_buff_len = 0;
  dnlink_buff_send_ptr = dnlink_buff;
  conn_list[num_flow].deferred_close_flag[GI] = 0;
  do_not_recv_dnlink = 0;

}

#if 0
data_buf *get_pkt_from_ipq(void)
{
  data_buf            *db = NULL;
  int                 ret = 0;
  fd_set              rfds;
  static struct timeval      ts = {.tv_sec = 0, .tv_usec = 1000};
  unsigned long long old_tvTime;

  if (!rxh)
  {
    int reuse = 13107200;
    if(!(rxh = ipq_create_handle(0))) {
        printf(" ipq handle creating failed\n ");
		return NULL;
	}
    if ( 0 > ipq_set_mode(rxh, IPQ_COPY_PACKET, BUFSIZE)) {
        printf("Set mode to copy pkt\n ");
		return NULL;
	}
	/*
    if (tfSetsockopt(rxh->fd, SOL_SOCKET, SO_RCVBUF, (char *)&reuse, sizeof(int)) < 0)
    {
	    printf("setsockopt() failed\n");
	    return NULL;
    }
	*/
  }
  FD_ZERO(&rfds);
  FD_SET(rxh->fd, &rfds);
  ret = select(rxh->fd +1, (fd_set *)&rfds,NULL,NULL,&ts);
  // increment g_clock_tick and tvTime by the amount of time(usec) elapsed during select 

  if ((ret<=0) || !FD_ISSET(rxh->fd, &rfds))
    return NULL;
  if (0 >= (ret = ipq_read(rxh, buffer, 5000, -1)))
    return NULL;
  if (ipq_message_type(buffer) == IPQM_PACKET)
  {
    ipq_packet_msg_t    *m = ipq_get_packet((buffer));
	if (!(db = alloc_db())) {
		printf("alloc_db failed\n");
		return NULL;
	}
	//leaving 14 bytes for src and dst mac and...
    memcpy(db->d + 14,m->payload,m->data_len);
    ipq_set_verdict(rxh, m->packet_id, NF_DROP, 0, NULL);
  }
  return db;
}
#endif








// Proxy application








void show_time_histogram (void)
{
    printf("Total Time Histogram\n");
    dump_histogram(hist_total);
    clear_histogram(hist_total);
    printf("Overhead Time Histogram\n");
    dump_histogram(hist_overhead);
    clear_histogram(hist_overhead);
    fprintf(stdout,"Total Incoming Packets %u\n",g_tot_pkts);
    fprintf(stdout,"Total Fast Path Processed Packets %u\n",g_tot_fpkts);
    g_tot_pkts = 0;
    g_tot_fpkts = 0;
}

void sigusr1_handler(int sig)
{
    g_show_histogram = 1;
}

int main (int argc, char *argv[]) 
{
  int               retval = 1;

  if( 0 > parse_cmdline(argc, argv)) {
      return -1;
  }

  hist_total = alloc_histogram();
  hist_overhead = alloc_histogram();
  if (!hist_total || !hist_overhead) {
      printf("hist allocations failed\n");
      if (hist_total) {
          free_histogram(hist_total);
      }
      if (hist_overhead) {
          free_histogram(hist_overhead);
      }
      return -1;
  }

  signal(SIGUSR1,sigusr1_handler);

  setup_free_pkt_bufs();

  retval = open_interfaces();
  if (0 > retval) {
      printf ("failed to open tx interfaces\n");
      return -1;
  }
  inf_pair_info.cli = &cli_inf_info;
  inf_pair_info.srv = &srv_inf_info;
  inf_pair_info.max_rx_fd = (inf_pair_info.cli->rxfd > inf_pair_info.srv->rxfd) ? inf_pair_info.cli->rxfd : inf_pair_info.srv->rxfd;

  if (init_proxy())
  {
    printf("Init proxy failed\n");	
    close_interfaces();
	return FAILURE;
  }
  register_timer();
  register_signal_handler();

  while(1) 
  {
      if (g_exit_indicated) {
          break;
      }
      recv_data();
      /* timer processing */
      check_expiry();
      if (g_show_histogram) {
          show_time_histogram();
          g_show_histogram = 0;
      }
  }
  close_interfaces();
  fflush(stdout);
  return SUCCESS;	
}


