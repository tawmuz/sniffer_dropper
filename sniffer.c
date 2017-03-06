#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <pcap/pcap.h>
#include "pktheader.h"

/* Pointer to the file where sniffed packet data is written. */
FILE *ptr_fp;

/* Pointer to the file containing time intervals between packet drops. */
FILE *ptr_exp;

/* Command usage variable declaration. */
int cmd_drop;
int drop_type;

/* Callback function - Dissects packet and prints detailed packet information. */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
   // Unused - const struct sniff_ethernet *ethernet;
   const struct sniff_ip *ip;
   const struct sniff_tcp *tcp;
   const u_char *payload;

   /* Variables to hold header lengths of IP packet and TCP segment respectively. */
   int size_ip;
   int size_tcp;
   int size_payload;
   static int packet_count = 0;
   static int packet_drop = 0;
   int fwrite_ret;
   static int drop_toggle = 0;

   static int exponential_setup = 0;
  
   struct timeval tv;
   double packet_time;
   static double drop_time;
   static double next_drop_interval;

   packet_time = header->ts.tv_sec + ((1.0/1000000) * header->ts.tv_usec);

   //printf("Received packet at %f seconds\n", packet_time);
   //printf("Received packet at time %s\n", ctime((const time_t *)(&header->ts.tv_sec)));

   switch((int)(*args))
   {
      case UNIFORM_DROP:
      if ((packet_count % cmd_drop) == 0)
      {
	 drop_toggle = !(drop_toggle); 
      } 
      break;
      case EXPONENTIAL_DROP:
      
      if (!(exponential_setup))
      {
	 gettimeofday(&tv,NULL);
	 drop_time = tv.tv_sec + ((1.0/1000000) * tv.tv_usec);
	 fscanf(ptr_exp, "%lf", &next_drop_interval);
	 drop_time += next_drop_interval;
	 exponential_setup = 1;
      }
      printf("Packet time: %lf\n", packet_time); 
      printf("Drop time:   %lf\n", drop_time);
      if ((packet_time - drop_time) > 0)
      {
	 drop_toggle = !(drop_toggle);
      }
      break;
      case CAPTURE:
      break;
      default:
	 printf("sniffer: Invalid packet drop option.\n");
	 exit(EXIT_FAILURE);
   }

   /* Get Ethernet frame. */
   // Unused - ethernet = (struct sniff_ethernet *)packet;
   
   /* Get IP packet. */
   ip = (struct sniff_ip *)(packet + ETHERNET_HDR_SIZE);
   size_ip = IP_HL(ip) * 4;

   if (size_ip < 20)
   {
      printf("Invalid IP header length: %d \n", size_ip);
      exit(EXIT_FAILURE);
   }

   /* Get TCP segment. */  
   tcp = (struct sniff_tcp *)(packet + ETHERNET_HDR_SIZE + size_ip);
   
   size_tcp = TH_OFF(tcp)*4;

   if (size_tcp < 20) 
   {
      printf("Invalid TCP header length: %u bytes\n", size_tcp);
      exit(EXIT_FAILURE);
   }
   
   /* Compute tcp segment payload offset */
   payload = (u_char *)(packet + ETHERNET_HDR_SIZE + size_ip + size_tcp);

   /* Compute tcp segment payload size */
   size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

   /* Write sniffed packets to new file. */
   if(!(drop_toggle))
   { 
      fwrite_ret = fwrite(payload, size_payload, 1, ptr_fp);
   }
   else
   {
      packet_drop++;
      drop_toggle = !(drop_toggle);
      if (exponential_setup)
      {
	 fscanf(ptr_exp, "%lf", &next_drop_interval);
	 drop_time = packet_time + next_drop_interval;
      }
   }
   
   packet_count++;
   printf("packet count: %d\n", packet_count);
   printf("packet drops: %d\n", packet_drop);
   printf("payload size: %d\n", size_payload);
   printf("------------------------------\n");
   if(fwrite_ret == 0)
   {
      //printf("Payload write to file failed. \n");
   }
   else
   {
      //printf("Payload write to file successful! \n");
   }
}

int check_command(int argCount, char *argv1, char *argv2, char *argv3)
{
   if (argCount == 5)
   {
      if (argv2 != NULL)
      {
	cmd_drop = atoi(argv2); 
      }
      if (argv3 != NULL)
      {
	 if (!strcmp(argv3, "--uniform"))
	 {
	   drop_type = UNIFORM_DROP; 
	 }
	 else if (!strcmp(argv3, "--exponential"))
	 {
	   drop_type = EXPONENTIAL_DROP; 
	 }
	 else if (!strcmp(argv3, "--capture"))
	 {
	   drop_type = CAPTURE; 
	 }
	 else
	 {
	    printf("Incorrect drop option. Use --one or --uniform or --exponential. \n");
	    return 2;
	 }
      }
   }
   else
   {
      printf("Usage: sudo ./sniffer <interface> <drop_count> < --uniform | --exponential > <filename.extension>\n");
      printf("Example: sudo ./sniffer wlan0 50 --uniform media.mp3\n");
      return 2;
   }
   return 0;
}

int create_media_file(char *arg_filename)
{
   char qoe_filename[50];
   char *file_extension;

   strcpy(qoe_filename, "qoe_test");
   file_extension = strchr(arg_filename, '.');
   strcat(qoe_filename, file_extension);

    /* Create file to which sniffed data will be written */ 
   if((ptr_fp = fopen(qoe_filename, "wb")) == NULL)
   {
      printf("Unable to create/open file!\n");
      return 2;
   }
   else 
   {
      printf("Opened file successfully for writing.\n");   
   }

   return 0;
}

int setup_timestamp(pcap_t *handle_p)
{
   int *tstamp_typesp;
   int num_tstamp_types;
   int result_set_tstamp_type = 1;

   tstamp_typesp = malloc(10*sizeof(int));
   num_tstamp_types = pcap_list_tstamp_types(handle_p, &tstamp_typesp);

   if (num_tstamp_types != PCAP_ERROR)
   {
      while (num_tstamp_types > 0)
      {
	 if (*(tstamp_typesp+(num_tstamp_types - 1)) == PCAP_TSTAMP_HOST)
	 {
	    result_set_tstamp_type = pcap_set_tstamp_type(handle_p, PCAP_TSTAMP_HOST);
	    break;
	 }
	 num_tstamp_types--;
      }
   }
   else
   {
      return 2;
   }

   if ((result_set_tstamp_type != 0) || (pcap_set_tstamp_precision(handle_p, PCAP_TSTAMP_PRECISION_MICRO) != 0))
   {
      return 2;
   }

   return 0;
}

void init_exp_drop(void)
{
   if((ptr_exp = fopen("drop_intervals.txt", "r")) == NULL)
   {
      printf("Unable to open drop_intervals.txt\n");
      exit(EXIT_FAILURE);
   }
   else 
   {
      printf("Opened drop_intervals.txt successfully.\n");   
   }

}

int main(int argc, char *argv[])
{
   char *dev = argv[1];                      /* Get device on which to sniff packets. */
   bpf_u_int32 net;			     /* The network address/number of the device being sniffed. */
   bpf_u_int32 mask;			     /* The network mask of the device being sniffed. */
   char errbuf[PCAP_ERRBUF_SIZE];            /* Error string - holds information about error. */
   pcap_t *handle;			     /* pcap session handle. */
   struct bpf_program fp;		     /* pcap filter handle. */
   char filter_exp[] = "tcp src port 20";    /* pcap filter expression. */
   int num_packets_cap = 100;		     /* Number of packets to capture. */

   int activate_result;

   /* Check command structure. */
   if (check_command(argc, argv[1], argv[2], argv[3]) != 0)
      exit(EXIT_FAILURE);

   if (create_media_file(argv[4]) != 0)
      exit(EXIT_FAILURE);

   /* Get device network address and mask. */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
   {
      fprintf(stderr, "Unable to obtain network number and mask from device %s \n", dev);
      net = 0;
      mask = 0;
   }

   /* Create pcap session. */
   handle = pcap_create(dev, errbuf); 
   if (handle == NULL)
   {
      fprintf(stderr, "Device %s could not be opened: %s \n", dev, errbuf);
      exit(EXIT_FAILURE);
   }

   if (setup_timestamp(handle) != 0)
   {
      fprintf(stderr, "Unable to set appropriate timestamp type\n");
   }

   /* Activate pcap session. */
   if ((activate_result = pcap_activate(handle)) < 0)
   {
      fprintf(stderr, "Unable to activate pcap session: %s \n", pcap_statustostr(activate_result));
   }

   /* Check if device provides Ethernet frames. */
   if (pcap_datalink(handle) != DLT_EN10MB)
   {
      fprintf(stderr, "Device %s doesn't provide ethernet frames. Other frame types are unsupported. \n", dev);
      exit(EXIT_FAILURE);
   }

   /* Compile pcap filter. */
   if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1)
   {
      fprintf(stderr, "pcap failed to compile filter expression - %s: %s \n", filter_exp, pcap_geterr(handle));
      exit(EXIT_FAILURE);
   } 

   /* Set pcap filter. */
   if (pcap_setfilter(handle, &fp) == -1)
   {
      fprintf(stderr, "Unable to set filter- %s: %s \n", filter_exp, pcap_geterr(handle));
      exit(EXIT_FAILURE);
   }

   printf("Packet Sniffer initiated on:\n");
   printf("----------------------------\n");
   printf("Device: %s\n", argv[1]);
   printf("Filter Expression: %s\n", filter_exp);

   /* Seeding drand48() to provide random packet drop times. */
   srand48(time(0));

   /* 
    * Initialize file pointer to file containing generated drop intervals
    * if selected drop type is "exponential".  
    */
   if (drop_type == EXPONENTIAL_DROP)
   {
      init_exp_drop();  
   }

   /*
    * Infinite sniffing loop - The program will be killed using an external kill command. 
    * Warning: Do not use this program in isolation or without accompanying shell script.
    */
   while (1) 
   {
      pcap_loop(handle, num_packets_cap, got_packet, (u_char *)(&drop_type));
   }

   /* Close session. */
   pcap_close(handle);
   fclose(ptr_fp);

   return 0;
}
