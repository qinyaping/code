#include "Udp_Handler.h"
#include "../public/log.h"
#include"../public/config.h"
#include "../TurnServer/allocation.h"

Udp_Handle::Udp_Handle(boost::asio::io_service& io_service, short port):ios(io_service),socket_(io_service, udp::endpoint(udp::v4(), port)),strand_(io_service)
{
    ILOG_MESSAGE(LOG_START,"Udp_Server Startup Success,Port:%d",port);
//    m_Method = NULL;
    m_turnserver = new TurnServer(this);

	boost::asio::socket_base::send_buffer_size sendoption(Singleton_IConfig->m_BuffSize);
	socket_.set_option(sendoption);

	boost::asio::socket_base::receive_buffer_size recvoption(Singleton_IConfig->m_BuffSize);
	socket_.set_option(recvoption);

	//udp listen port监控
    socket_.async_receive_from(
        boost::asio::buffer(data_, MAX_LEN), sender_endpoint_,
        strand_.wrap(boost::bind(&Udp_Handle::handle_receive_from, this,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred)));

}


Udp_Handle::~Udp_Handle()
{
    boost::system::error_code ec;
	socket_.close(ec);
}

void Udp_Handle::handle_receive_from(const boost::system::error_code& error,size_t bytes_recvd)
{
	if (!error && bytes_recvd > 0)
	{
		//处理客户端数据请求(包括turn协议以及待relay视频数据)
		m_turnserver->handler_receive_client((unsigned char *)data_,bytes_recvd,sender_endpoint_.address().to_string(),sender_endpoint_.port());
	}

    socket_.async_receive_from(
        boost::asio::buffer(data_, MAX_LEN), sender_endpoint_,
        strand_.wrap(boost::bind(&Udp_Handle::handle_receive_from, this,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred)));

    struct list_head* get = NULL;
    struct list_head* n   = NULL;
    struct sockaddr_storage daddr;
    int daddr_size = sizeof(sockaddr_storage);
    //监控所有的转发端口，当有数据到来时relay到peer
	list_iterate_safe(get, n, &m_turnserver->allocation_list)
	{
		struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);

		getsockname(tmp->relayed_sock, (struct sockaddr*)&daddr, &daddr_size);

		tmp->relayed_socket_ptr->async_receive_from(
		        boost::asio::buffer(data_, MAX_LEN), sender_endpoint_,
		        strand_.wrap(boost::bind(&Udp_Handle::handler_receive_relay, this,
		        boost::asio::placeholders::error,
		        boost::asio::placeholders::bytes_transferred,tmp->relayed_sock)));
	}
	//移除过期的allocation等数据
	m_turnserver->turnserver_expire();

}

void Udp_Handle::handler_receive_relay(const boost::system::error_code& error,size_t bytes_recvd, int peer_relay_socket)
{
	if (!error && bytes_recvd > 0)
	{
		m_turnserver->handler_receive_relay((unsigned char *)data_,bytes_recvd,sender_endpoint_.address().to_string(),sender_endpoint_.port(), peer_relay_socket);
	}
}

void Udp_Handle::handle_send_to(const boost::system::error_code& error,size_t bytes_sent)
{
//    m_Method->OnSendData();
}


void Udp_Handle::handle_async_write(unsigned char *data,unsigned int len)
{
	boost::asio::const_buffer SendBuff(data,len);

	socket_.async_send_to(
		boost::asio::buffer(SendBuff), sender_endpoint_,
        strand_.wrap(
            boost::bind(&Udp_Handle::handle_send_to, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred)));
}

void Udp_Handle::handle_async_write(unsigned char *data,unsigned int len,string SendAddr,unsigned int SendPort)
{
	boost::asio::const_buffer SendBuff(data,len);

	boost::asio::ip::address addr = boost::asio::ip::address::from_string(SendAddr);
	udp::endpoint _endpoint_(addr,SendPort);

	socket_.async_send_to(
		boost::asio::buffer(SendBuff), _endpoint_,
        strand_.wrap(
            boost::bind(&Udp_Handle::handle_send_to, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred)));
}


//void Udp_Handle::handle_set_basemethod(CSocketBaseMethod *pMethod)
//{
//    m_Method = pMethod;
//}
