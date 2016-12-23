/*#############################################################################*
*                                                                              *
*           netjack.h           July 19, 2013           project eframe         *
*      The header file for netjack.c.This header guard will provide function   *
*   ality to the eframe project for the arp request poisoning.                 *
*                                                                              *
*#############################################################################*/

    #ifndef NETJACK_H 
    #define NETJACK_H

    #define BUF_SIZ      1024
    #define IP_ALEN      4

    int ARP_Daemon(char *ifName, int *mac_1, int *ip_1, int *ip_2, int *mac_2, int);

    #endif
