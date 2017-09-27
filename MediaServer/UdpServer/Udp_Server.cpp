#include "Udp_Server.h"
//#include"../RtpHandler_Method.h"
#include"../public/config.h"

Udp_Server::Udp_Server()
{
    m_SrvStatus = false;
    m_pRTPHandler = NULL;
}

Udp_Server::~Udp_Server()
{
   Stop();
}

bool Udp_Server::Start(unsigned int port)
{
    if(m_SrvStatus){return true;}

    try
    {
        m_pRTPHandler = new Udp_Handle(io_service_rtp_,port);
        if(m_pRTPHandler == NULL)
        {
 //           CSocketBaseMethod * pRTP = new CRTPMethod(m_pRTPHandler);
 //           m_pRTPHandler->handle_set_basemethod(pRTP);
        	return false;
        }
    }
    catch(boost::system::system_error &ec){return false;}

    m_SrvStatus = true; //for simple test of turnserver
    for(int i = 0; i < 1/*Singleton_IConfig->m_nThread*/; i++)
    {
        boost::thread thrdrtp(boost::bind(&Udp_Server::run_rtp, this));
    }

    return true;
    //thrd.join();
}

void Udp_Server::Stop()
{
    if(!m_SrvStatus){return;}

	io_service_rtp_.stop();
    m_SrvStatus = false;

    if(m_pRTPHandler != NULL)
    {
        delete m_pRTPHandler;
        m_pRTPHandler = NULL;
    }
}

void Udp_Server::run_rtp()
{
	io_service_rtp_.run();
}
