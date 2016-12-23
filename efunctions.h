/*##############################################################################
*       efunctions.h            July 18, 2013                                  *
*   A header file for efunctions.c. Supports functionality for several         *
*   peripheral functions necessary for the arp spoofing suite.                 *
*                                                                              *
*                                                                              *
##############################################################################*/

    #ifndef EFUNCTIONS_H
    #define EFUNCTIONS_H

    #include <net/if.h>

    void IPstring2intarray(char *ip, int *ip_array);
    int Get_IP(char ifName[IFNAMSIZ], int *target_ip);
    void Print_Help();

    #endif
