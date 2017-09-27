#pragma once
#include "Udp_Handler.h"
#include <boost/thread.hpp>

//UDPͨ�ŷ�����
class Udp_Server
{
public:
	Udp_Server();
	~Udp_Server();
public:
    //�󶨶˿ڣ���������
	bool Start(unsigned int port);
    //ֹͣ����
	void Stop();
protected:
    //�����߳�
    void run_rtp();
private:
    //boostͨ�ž��-rtp
    boost::asio::io_service io_service_rtp_;
    //Rtpͨ�ž��
    Udp_Handle *m_pRTPHandler;
    //����������״̬
    bool m_SrvStatus;
};
