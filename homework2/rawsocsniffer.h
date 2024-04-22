#ifndef _RAWSOCSNIFFER_H
#define _RAWSOCSNIFFER_H

#include "rawsocket.h"

//设置过滤，实现了针对源IP，目的IP和协议类型进行过滤的功能
typedef struct filter
{
    //源IP、目的IP、协议类型
    unsigned long sip;
    unsigned long dip;
    unsigned int protocol;    
} filter;

class rawsocsniffer:public rawsocket//继承自rawsocket类
{
    private:
	filter simfilter;//filter类型的数据结构simfilter用于设置过滤条件
	char *packet;//存储数据报
	const int max_packet_len;//记录最大数据报长度
    public:
	rawsocsniffer(int protocol);
	~rawsocsniffer();
	bool init();
	void setfilter(filter myfilter);//根据传入的参数设置simfilter
	bool testbit(const unsigned int p, int k);//用于测试某一无符号整型变量的指定位是否为1
	void setbit(unsigned int &p,int k);//用于将某一无符号整型变量的指定位置为1
	void sniffer();//启动数据报捕获过程
	void analyze();//对数据包进行解析
	void ParseRARPPacket();//解析RAP包
	void ParseARPPacket();//解析ARP包
	void ParseIPPacket();//解析IP包
	void ParseTCPPacket();//解析TCP包
	void ParseUDPPacket();//解析UDP包
	void ParseICMPPacket();//解析ICMP包
	void print_hw_addr(const unsigned char *ptr);
	void print_ip_addr(const unsigned long ip);
};

#endif