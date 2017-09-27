#pragma once
#include"Method/Base_Method.h"

#include "public/config.h"

class Udp_Handle;
class CRoom;

//Udpͨ�ž����
class CRTPMethod : public CSocketBaseMethod
{
public:
    CRTPMethod(Udp_Handle *handler);
    virtual ~CRTPMethod();

public:
    //�ͻ������ӳɹ�-TCP
    virtual  bool OnConnected(string addr) ;
    //�ͻ��˶Ͽ�����-TCP
    virtual bool OnDisConnected() ;
    //��������-TCP
    virtual bool OnReciveData(unsigned char * data,unsigned int len) ;
    //���ݷ��ͳɹ�-TCP
    virtual bool OnSendData() ;
    //���ݷ��ͽӿ�-TCP
    virtual bool SendData(unsigned char *data,unsigned int len) ;
    //��������-DUP
    virtual bool OnReciveData(unsigned char * data,unsigned int len,string SourceAddr,unsigned int SourcePort) ;
    //���ݷ��ͽӿ�-DUP
    virtual bool SendData(unsigned char *data,unsigned int len,string SendAddr,unsigned int SendPort) ;

    int GetSocket();
//    void PrintAllocationList();
protected:
    //����UDP����ͨ��
    bool CreateChannel(unsigned char *data,unsigned int len,string SourceAddr,unsigned int SourcePort);

private:
    //udpͨ�ž��
    Udp_Handle *m_pHandler;
//	struct list_head allocation_list;
//	struct list_head account_list;
};
