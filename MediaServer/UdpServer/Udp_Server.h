#pragma once
#include "Udp_Handler.h"
#include <boost/thread.hpp>

//UDP通信服务器
class Udp_Server
{
public:
	Udp_Server();
	~Udp_Server();
public:
    //绑定端口，启动服务
	bool Start(unsigned int port);
    //停止服务
	void Stop();
protected:
    //工作线程
    void run_rtp();
private:
    //boost通信句柄-rtp
    boost::asio::io_service io_service_rtp_;
    //Rtp通信句柄
    Udp_Handle *m_pRTPHandler;
    //服务器启动状态
    bool m_SrvStatus;
};
