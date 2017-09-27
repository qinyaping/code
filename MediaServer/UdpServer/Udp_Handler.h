#pragma once

#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
//#include "../Method/Base_Method.h"
#include "../TurnServer/turnserver.h"

#define MAX_LEN 1024*2

using boost::asio::ip::udp;
using namespace std;

class Udp_Handle
{
public:
	Udp_Handle(boost::asio::io_service& io_service, short port);

	~Udp_Handle();

public:

	void handle_receive_from(const boost::system::error_code& error,size_t bytes_recvd);

	void handler_receive_relay(const boost::system::error_code& error,size_t bytes_recvd, int peer_relay_socket);

	void handle_send_to(const boost::system::error_code& error,size_t bytes_sent);

	//发送数据到客户端
	void handle_async_write(unsigned char *data,unsigned int len,string SendAddr,unsigned int SendPort);

	//发送数据到客户端
	void handle_async_write(unsigned char *data,unsigned int len);

    //设置通信句柄
//    void handle_set_basemethod(CSocketBaseMethod *pMethod);

    int get_socket() {return socket_.native();}
    boost::asio::io_service& get_ios()  {return ios;}
    const boost::asio::io_service::strand& get_strand() {return strand_;}
private:
	udp::socket socket_;
	udp::endpoint sender_endpoint_;

	char data_[MAX_LEN];
//	CSocketBaseMethod *m_Method;

	boost::asio::io_service& ios;
    boost::asio::io_service::strand strand_;

    TurnServer* m_turnserver;
};
