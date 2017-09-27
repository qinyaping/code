#pragma once
#include"Method/Base_Method.h"

#include "public/config.h"

class Udp_Handle;
class CRoom;

//Udp通信句柄类
class CRTPMethod : public CSocketBaseMethod
{
public:
    CRTPMethod(Udp_Handle *handler);
    virtual ~CRTPMethod();

public:
    //客户端连接成功-TCP
    virtual  bool OnConnected(string addr) ;
    //客户端断开连接-TCP
    virtual bool OnDisConnected() ;
    //接收数据-TCP
    virtual bool OnReciveData(unsigned char * data,unsigned int len) ;
    //数据发送成功-TCP
    virtual bool OnSendData() ;
    //数据发送接口-TCP
    virtual bool SendData(unsigned char *data,unsigned int len) ;
    //接收数据-DUP
    virtual bool OnReciveData(unsigned char * data,unsigned int len,string SourceAddr,unsigned int SourcePort) ;
    //数据发送接口-DUP
    virtual bool SendData(unsigned char *data,unsigned int len,string SendAddr,unsigned int SendPort) ;

    int GetSocket();
//    void PrintAllocationList();
protected:
    //创建UDP传输通道
    bool CreateChannel(unsigned char *data,unsigned int len,string SourceAddr,unsigned int SourcePort);

private:
    //udp通信句柄
    Udp_Handle *m_pHandler;
//	struct list_head allocation_list;
//	struct list_head account_list;
};
