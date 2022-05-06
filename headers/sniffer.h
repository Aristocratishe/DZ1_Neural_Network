#ifndef SNIFFER_H
#define SNIFFER_H

#include<stdio.h>
#include<pcap.h>
#include<string.h>
#include<iostream>

#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>

class SSniffer
{
    public:

    SSniffer();
    
    void start_sniffing();

    private:

    //static FILE *logfile;

    // static struct sockaddr_in source,dest;

    int i,j;    	

    static void processing_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

    static void read_ethernet_header();

    static void print_ethernet_header(const u_char *Buffer, int Size, FILE *);

    static void print_ip_header(const u_char * Buffer, int Size, FILE *, struct sockaddr_in source, struct sockaddr_in dest);

    static void print_tcp_packet(const u_char * Buffer, int Size, FILE *, struct sockaddr_in source, struct sockaddr_in dest);

    static void print_udp_packet(const u_char *Buffer , int Size, FILE *, struct sockaddr_in source, struct sockaddr_in dest);

    static void print_icmp_packet(const u_char * Buffer , int Size, FILE *, struct sockaddr_in source, struct sockaddr_in dest);

    static void PrintData (const u_char * data , int Size, FILE *);

};

#endif