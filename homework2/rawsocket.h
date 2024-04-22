#ifndef _RAWSOCKET_H
#define _RAWSOCKET_H

class rawsocket
{
    private:
	int sockfd;//原始套接字句柄
    public:
	rawsocket(const int protocol);
	~rawsocket() ;

	//对ioctl函数进行了封装，用于设置网卡混杂模式
	bool dopromisc(char *nif);
	
	//对原始套接字的recvfrom ()函数进行了封装，用于捕获数据报
	int receive(char *recvbuf,int buflen,struct sockaddr_in *from,int *addrlen);
};
#endif