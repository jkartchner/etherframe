/* Got this program at http://stackoverflow.com/questions/4139405/how-to-know-ip-address-for-interfaces-in-c
*/
    #include "efunctions.h"
    #include <arpa/inet.h>
    #include <linux/if_packet.h>
    #include <string.h>
    #include <stdlib.h>
    #include <net/if.h>
    #include <netinet/ether.h>

    #include <stdio.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <sys/ioctl.h>
    #include <sys/types.h>
    #include <sys/socket.h>

    #define INT_TO_ADDR(_addr)\
    (_addr & 0xFF), (_addr >> 8 & 0xFF), \
    (_addr >> 16 & 0xFF), (_addr >> 24 & 0xFF)


    /* takes an input string formatted as an IP address with . sep */
    /* ip = string ip in . notation; ip_array = pointer 4 int array */
    void IPstring2intarray(char *ip, int *ip_array)
    {
        char target[3] = { 0, 0, 0 };  // temp int array to hold 3 digits
        int index = 0;                 // position in the IP string
        int i = 0;                     // position in the int array
        int l = 0;                     // mini-counter 4 betw . calcs
        for(i = 0; i < 4; i++)      
        {
            for(l = 0; l < 3; l++)
            {
                target[l] = ip[index + l]; // pull the number betw the .
                if(ip[index + l] == '.')   // if we hit a . break to atoi
                    break;

            }
            index += l;
            ip_array[i] = atoi(target);    // cast the char array to int
            index++;                       // skip the . in the ip
        }
    }

    /* takes an input string formatted as a MAC address with - or : sep */
    /* mac = string mac in - notation; mac_array = pointer 6 int array */
    void MACstring2intarray(char *mac, int *mac_array)
    {
        char target[3] = { 0, 0, 0 };  // temp int array to hold 3 digits
        int index = 0;                 // position in the MAC string
        int i = 0;                     // position in the int array
        int l = 0;                     // mini-counter 4 betw - calcs
        for(i = 0; i < 6; i++)      
        {
            for(l = 0; l < 3; l++)
            {
                target[l] = mac[index + l]; // pull the number betw the - 
                if(mac[index + l] == '-' || mac[index + l] == ':')   // if we hit a . break to atoi
                    break;

            }
            index += l;
            mac_array[i] = strtol(target, NULL, 16);    // cast the char array to int
            index++;                       // skip the . in the ip
        }
    }

    /* gets the IP for the interface specified (on this machine) */
    /* ifName = interface name (e.g., eth0); target_ip = int array */
    int Get_IP(char ifName[IFNAMSIZ], int *target_ip)
    {
        struct ifconf ifc;
        struct ifreq ifr[10];
        int sd, ifc_num, addr, bcast, mask, network, i, s_flag;
        s_flag = 0;

        /* Create a socket so we can use ioctl on the file 
        * descriptor to retrieve the interface info. 
        */

        sd = socket(PF_INET, SOCK_DGRAM, 0);
        if (sd > 0)
        {
            ifc.ifc_len = sizeof(ifr);
            ifc.ifc_ifcu.ifcu_buf = (caddr_t)ifr;

            if (ioctl(sd, SIOCGIFCONF, &ifc) == 0)
            {
                ifc_num = ifc.ifc_len / sizeof(struct ifreq);
                //printf("%d interfaces found\n", ifc_num);

                for (i = 0; i < ifc_num; ++i)
                {
                    //printf("%s\n", ifName);
                    if(strcmp(ifr[i].ifr_name, ifName) == 0)
                    {
                        if (ifr[i].ifr_addr.sa_family != AF_INET)
                        {
                            continue;
                        }

                       /* display the interface name */
                       //printf("%d) interface: %s\n", i+1, ifr[i].ifr_name);

                       /* Retrieve the IP address, broadcast address, 
                                    and subnet mask. */
                        
                        if (ioctl(sd, SIOCGIFADDR, &ifr[i]) == 0)
                        {
                            addr = ((struct sockaddr_in *)(&ifr[i].ifr_addr))->sin_addr.s_addr;
                            target_ip[0] = addr & 0xFF;
                            target_ip[1] = addr >> 8 & 0xFF;
                            target_ip[2] = addr >> 16 & 0xFF;
                            target_ip[3] = addr >> 24 & 0xFF;
                            s_flag++;
                            //*target_ip = INT_TO_ADDR(addr);
                              //printf("%d) address: %d.%d.%d.%d\n", 
                              //i+1, INT_TO_ADDR(addr));
                        }
                    }
                                /*if (ioctl(sd, SIOCGIFBRDADDR, &ifr[i]) == 0)
                                 {
                                       bcast = ((struct sockaddr_in *)
                                       (&ifr[i].ifr_broadaddr))->sin_addr.
                                       s_addr;
                                       printf("%d) broadcast: 
                                       %d.%d.%d.%d\n", i+1, INT_TO_ADDR(bcast));
                                  }
                                  if (ioctl(sd, SIOCGIFNETMASK, &ifr[i]) == 0)
                                  {
                                      mask = ((struct sockaddr_in *)
                                      (&ifr[i].ifr_netmask))->sin_addr.s_addr;
                                      printf("%d) netmask: %d.%d.%d.%d\n", 
                                      i+1, INT_TO_ADDR(mask));
                                   }*/                

                             /* Compute the current network value 
                             from the address and netmask. */
                               //network = addr & mask;
                               //printf("%d) network: %d.%d.%d.%d\n", 
                               //i+1, INT_TO_ADDR(network));
                }                      
            }

            close(sd);
        }
        if(s_flag)
            return 0;
        else
            return -1;
    }


    void Print_Help()
    {
        printf("Usage: [ -i ] [ interface name ] [ -req ] [ -pois ] [ -mim ] [ -netjack ]\n");
        printf("       [ request IP ] [ dstntn MAC ] [ dstntn IP ] [ pois IP ] [pois MAC ]\n\n");
        printf("         Interface is optional. Must use either -req or -pois.\n\n");
        printf("         -req will send an arp request to the request IP. IP of\n");
        printf("       255.255.255.255 will send an arp request to the entire\n");
        printf("       network, assuming a subnet mask of 255.255.255.0.\n");
        printf("       Network responses will be printed to the screen.\n");
        printf("         -pois will send an arp request to the MAC destination\n");
        printf("       specified. It will spoof your IP with the pois IP given.\n"); 
        printf("         -mim will send a man in the middle attack to two computers.\n");
        printf("       Ideally, request IP, dstntn MAC would be the targeted computer. pois\n");
        printf("       pois IP and pois MAC would be the gateway (or router) for the ntwrk.\n");
        printf("       It then starts a daemon to keep these computers ARP caches poisoned.\n");
        printf("       Remember to turn on IP forwarding, or you will just DOS the target comptr.\n");
        printf("         -netjack will simply start a daemon to spoof all incoming ARP packets.\n");
        printf("       It should hijack the whole network within a short time. Omit destn MAC, \n");
        printf("       pois MAC, pois IP, etc. because it is unnecessary for this mode. Be \n");
        printf("       sure to turn on IP forwarding, or you will DOS the whole network.\n\n");
        printf("Note:  Development on this got too involved, so now only -mim, -pois, -req\n");
        printf("       work. You can capture the whole network: \n");
        printf("       sudo ./eframe -i ethX -req 255.255.255.255\n");
        printf("       sudo ./eframe -i ethX -mim gatewaymac gatewayip targetmac targetip\n");
        printf("       this will run and hold the target and gateway down. Then open a new window: \n");
        printf("       sudo ./eframe -i ethX -pois targetmac targetip\n");
        printf("       do this for each computer found with the network query (255.255.255.255 above\n");
        printf("       See the comments in netjack.c for an explanation of why -netjack won't work now.\n");
    }
