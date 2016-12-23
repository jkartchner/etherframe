/*##############################################################################
*                                                                              *
*       arpsend.c               July 18, 2013           project eframe         *
*     Contains functions for sending arp packets and provisions for getting    *
*    responses into a buffer other than the arp table. This is desirable       *
*    because a given firewall may inhibit updating the arp table with a ntwrk  *
*    broadcast of arp packets like this. This provides a method to see all     *
*    arp responses (live machines on a LAN) without having to dance with the   *
*    kernel's networking configuration.                                        *
*                                                                              *
*                                                                              *
*#############################################################################*/

     #include "arpsend.h"           // include self
     #include <arpa/inet.h>
     #include <linux/if_packet.h>
     #include <string.h>
     #include <stdlib.h>
     #include <net/if.h>
     #include <netinet/ether.h>

     #include <stdio.h>
     #include <unistd.h>
     #include <net/if.h>  
     #include <netinet/in.h>
     #include <sys/ioctl.h>
     #include <sys/types.h>
     #include <sys/socket.h>
     #include <pthread.h>

     #define MY_DEST_MAC0  0xFF
     #define MY_DEST_MAC1  0xFF
     #define MY_DEST_MAC2  0xFF
     #define MY_DEST_MAC3  0xFF
     #define MY_DEST_MAC4  0xFF
     #define MY_DEST_MAC5  0xFF
       
     int f_reading;   
     

     /* generates one or more arp requests and listens for responses */
     /* prints out responsive ARP packets because some ARP tables drop */
     /* ifName = interface name; ip_1 = target IP; polling = ping nwk flag */
     int ARP_Request(char *ifName, int *ip_1, int f_polling)
     {
         f_reading = 1;              // turn on the reading packets flag 
         int err;
         pthread_t thrd;
         err = pthread_create(&thrd, NULL, &ARP_Listen, NULL);
         if(err != 0)
            printf("thread error: will not have listening socket. Error %d\n", err);

         int sockfd, sockrd, i;
         i = f_polling;              // set this to the flag to count
         i *= 254;     //prefer not to arp request the broadcast addresses, but since I'm searching in inverse for greater speed, I have to have 255 as a possibility to ensure 0 gets searched.
         struct ifreq if_idx;
         struct ifreq if_mac;
         int tx_len = 0;
         char sendbuf[BUF_SIZ];
         struct ether_header *eh = (struct ether_header *) sendbuf;
         struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
         struct sockaddr_ll socket_address;


         /* Open RAW socket to send on */
         if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
             perror("socket");
         }

         /* Get the index of the interface to send on */
         memset(&if_idx, 0, sizeof(struct ifreq));
         strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
         if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
             perror("SIOCGIFINDEX");

         /* Get the MAC address of the interface to send on */
         memset(&if_mac, 0, sizeof(struct ifreq));
         strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
         if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
             perror("SIOCGIFHWADDR");

          // collect source ip only once to avoid waste in the loop   
          int source_ip[4] = { 0, 0, 0, 0 };
          if(Get_IP(ifName, source_ip) != 0)
          {
              printf("Failed to collect IP.\n");
              return -1;
          }
          
          /* Construct the Ethernet header */
          memset(sendbuf, 0, BUF_SIZ);

         /* getting ready to construct the packet */
         /* start the loop, if looping is appropriate */
         for(i += 1; i > -1; i--)
         {          
             tx_len = 0;                // reset the byte counter


             /* Ethernet header */
             eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
             eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
             eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
             eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
             eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
             eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
             eh->ether_dhost[0] = MY_DEST_MAC0;
             eh->ether_dhost[1] = MY_DEST_MAC1;
             eh->ether_dhost[2] = MY_DEST_MAC2;
             eh->ether_dhost[3] = MY_DEST_MAC3;
             eh->ether_dhost[4] = MY_DEST_MAC4;
             eh->ether_dhost[5] = MY_DEST_MAC5;
             /* Ethertype field */
             eh->ether_type = htons(ETHERTYPE_ARP);
             tx_len += sizeof(struct ether_header);

             /* Packet data - all packet data will stay the same between
                an ARP request and ARP reply except the dest MAC address */
             sendbuf[tx_len++] = 0x00; // ethernet protocol 2 bytes
             sendbuf[tx_len++] = 0x01;
             sendbuf[tx_len++] = 0x08; // internet protocol 2 bytes
             sendbuf[tx_len++] = 0x00;

             // mac address length, 1 byte  
             sendbuf[tx_len++] = 0x06;

             // IP address length, 1 byte  
             sendbuf[tx_len++] = 0x04;

             // ARP request or reply 2 bytes
             sendbuf[tx_len++] = 0x00;
             sendbuf[tx_len++] = 0x01; // 1 = request; 2 = reply

             // source MAC address, 6 bytes (as indiated above)
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];

             // source IP address, 4 bytes (as indicated above)
             sendbuf[tx_len++] = source_ip[0];
             sendbuf[tx_len++] = source_ip[1];
             sendbuf[tx_len++] = source_ip[2];
             sendbuf[tx_len++] = source_ip[3];
             /*sendbuf[tx_len++] = 192;
               sendbuf[tx_len++] = 168;
               sendbuf[tx_len++] = 2;
               sendbuf[tx_len++] = 6;*/



             // destination MAC address, 6 bytes (as indicated above)
             // wil remain 0 for an ARP request; will have the MAC for ARP reply
             sendbuf[tx_len++] = 0x00;
             sendbuf[tx_len++] = 0x00;
             sendbuf[tx_len++] = 0x00;
             sendbuf[tx_len++] = 0x00;
             sendbuf[tx_len++] = 0x00;
             sendbuf[tx_len++] = 0x00;

             // destination IP address, 4 bytes (as indicated above)
             // here we poll the network, assuming a class C subnet mask
             if(f_polling == 1)                     // arping will poll network
             {
                 sendbuf[tx_len++] = source_ip[0];
                 sendbuf[tx_len++] = source_ip[1];
                 sendbuf[tx_len++] = source_ip[2];
                 sendbuf[tx_len++] = ~i;        // inverse; start low end high
             }                                  // ntwrk popultn prbly at low
             else                               
             {                                  // otherwise send provided IP
                 sendbuf[tx_len++] = ip_1[0];
                 sendbuf[tx_len++] = ip_1[1];
                 sendbuf[tx_len++] = ip_1[2];
                 sendbuf[tx_len++] = ip_1[3];
             }
             /* Index of the network device */
             socket_address.sll_ifindex = if_idx.ifr_ifindex;
             /* Address length*/
             socket_address.sll_halen = ETH_ALEN;
             /* Destination MAC */
             socket_address.sll_addr[0] = MY_DEST_MAC0;
             socket_address.sll_addr[1] = MY_DEST_MAC1;
             socket_address.sll_addr[2] = MY_DEST_MAC2;
             socket_address.sll_addr[3] = MY_DEST_MAC3;
             socket_address.sll_addr[4] = MY_DEST_MAC4;
             socket_address.sll_addr[5] = MY_DEST_MAC5;

             /* Send packet */
             if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
             {
                 printf("Send failed\n");
                 close(sockfd);
                 return -1;
             } 
             
         }
         // close and shut down the packet
         close(sockfd);
        
         sleep(2);
         
         f_reading = 0;             // turn off the read packets thread
         
         return 0;
     }


    // ARP Header Structure
     struct arp_hdr
     {
         uint16_t hw_type; // hardware type
         uint16_t proto_type; // protocol type
         uint8_t ha_len; // hardware address length
         uint8_t pa_len; // protocol address length
         uint16_t ar_op; // arp opcode
         uint8_t source_mac[ETH_ALEN]; // source mac
         uint8_t source_ip[4]; // source ip; rather use digit than constant
         uint8_t dest_mac[ETH_ALEN]; // destination mac
         uint8_t dest_ip[4]; // destination ip; should be IP_LEN
     };

     void* ARP_Listen()
     {
         int sockrd, i;
         int packetsize = sizeof(struct ethhdr) + sizeof(struct arp_hdr);
         char packet[packetsize];      // buffer for packet reads
         // *ah ties the buffer for reading to eth headers
         struct ethhdr *ah = (struct ethhdr *) packet;
         struct arp_hdr *arp = (struct arp_hdr *)(packet + sizeof(struct ethhdr));
         struct sockaddr_ll socket_address;


         /* Open RAW socket to read on */
         if ((sockrd = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
             perror("socket");
         }
         i = 0;

         printf("reading incoming arp packets on your network....\n");
         while(f_reading == 1)
         {
             /* Incoming ARP reads */
             read(sockrd, packet, packetsize);
             if(ah->h_proto == 1544 && (arp->ar_op == 512))
             {                                             // 2 = ARPOP_REQUEST
                 i++;
                 printf("Incoming response: %d) --MAC %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\t\t", i, ah->h_source[0], ah->h_source[1], ah->h_source[2], ah->h_source[3], ah->h_source[4], ah->h_source[5]);
                 printf("IP %02d.%02d.%02d.%02d\n",/* packet[counter], packet[counter + 1], packet[counter + 2], packet[counter + 3]*/  arp->source_ip[0], arp->source_ip[1], arp->source_ip[2], arp->source_ip[3]); 
             }
         }

         close(sockrd);
     }

