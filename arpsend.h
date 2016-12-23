/*#############################################################################
*                                                                              *
*       arpsend.h               July 18, 2013               project eframe     *
*    Header file for arpsend.c. This include guard file gives the function-    *
*   ality of the arpsend.c file.                                               *
*                                                                              *
*#############################################################################*/


    #ifndef ARPSEND_H
    #define ARPSEND_H

    #define DEFAULT_IF   "eth0"
    #define BUF_SIZ      1024

    int ARP_Request(char *ifName, int *ip_1, int f_polling);
    void* ARP_Listen();

    #endif
