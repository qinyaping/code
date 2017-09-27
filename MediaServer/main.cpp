#include <iostream>
#include <malloc.h>
#include "public/config.h"
#include "public/log.h"
//#include "client/center_handler.h"
#include "UdpServer/Udp_Server.h"
//#include "client/client_pool.h"
//#include "Monitor/monitor_server.h"
#include "public/ipid_method.h"


using namespace std;

//����������״̬
bool ServerStatus = true;
void Handler_ServerClose( int nSigal);

void Handler_Mallopt();
int Handler_KBHit();
int turnserver_start_main(int argc, char** argv);

int main(int argc,char *argv[])
{
    //�������в������ -d�����ػ�����ģʽ ���������̨����
    if(argc == 2 && ( (strcmp("-d",argv[1]) == 0) || (strcmp("-D",argv[1]) == 0) ))
    {
        ILOG_PRINTF(LOG_INFO,"˼����Ƶý��������ѳɹ�����.");
        if(daemon(1,0) < 0){ILOG_PRINTF(LOG_ERROR,"Create Daemon Failed.");return false;}
    }
    //-stopֹͣ����
    else if(argc == 2 && ( (strcmp("-k",argv[1]) == 0) || (strcmp("-K",argv[1]) == 0) ))
    {
        int stop_pid = 0;if(CIpid_method::get_pid("mediaserver.pid",stop_pid))
        {if(kill(stop_pid,SIGKILL) == 0){ILOG_PRINTF(LOG_INFO,"˼����Ƶý��������ѳɹ�ֹͣ.");}}return true;
    }
    //������������
    else if(argc >= 2){ILOG_PRINTF(LOG_ERROR,"Parameter Error, Using The Following Parameters:");
    ILOG_PRINTF(LOG_ERROR,"Service Start: -d or -D ,Service Stop:-k or -K");return 0;}

    //ע��ر��źŻص�����
    signal(SIGINT, Handler_ServerClose);//Handler_Mallopt();

    //��ȡ�����ļ�
    if(!Singleton_IConfig->start("TChatMediaServer.xml"))
    {ILOG_PRINTF(LOG_ERROR,"TChatMediaServer Read Config File Failed.");return false;}

    //�����첽��־����
    Singleton_ILog->ilog_start("TChatMediaServer",Singleton_IConfig->m_level);

    //turnserver������
//    turnserver_start_main(argc, argv);

    //Udp������
    Udp_Server udpSrv;if(!udpSrv.Start(Singleton_IConfig->m_MediaPort))
    {ILOG_PRINTF(LOG_ERROR,"Udp_Server Startup Failed. The Port Is Bind.");return false;}

//    //tcp�ͻ���
//    tcp_client client;
//    client.start(Singleton_IConfig->m_CsServerIP,Singleton_IConfig->m_CsServerPort);
//
    //���ӳ�
//    Singleton_ClientPool->start(Singleton_IConfig->m_SsServerIP,Singleton_IConfig->m_SsServerPort);
//
//    //��ط�����
//    IMonitor_Server monitor;if(!monitor.Start("",Singleton_IConfig->m_monitorPort,60))
//    {ILOG_PRINTF(LOG_ERROR,"Monitor_Server Startup Failed.");return false;}
//
//    //���з��������ɹ�����¼����ID
//    if(!CIpid_method::set_pid("mediaserver.pid",getpid()))
//    {ILOG_MESSAGE(LOG_ERROR,"CIpid_method::set_pid Failed.");return false;}

    ILOG_PRINTF(LOG_START,"˼����Ƶý��������ѳɹ�����.");

    //���߳̽��ձ�׼����
    while(ServerStatus){char get_char = Handler_KBHit();
    if(get_char == 'q' || get_char == 'Q'){break;}sleep(1);}

    //��Դ�ͷ�
//    udpSrv.Stop();

 //   client.stop();
 //   Singleton_ClientPool->stop();

 //   monitor.Stop();
    //�ͷ�protobuf��Դ
//    google::protobuf::ShutdownProtobufLibrary();

    ILOG_PRINTF(LOG_INFO,"˼����Ƶý��������ѳɹ�ֹͣ.");
    Singleton_ILog->ilog_stop();
    return 0;
}


void Handler_ServerClose(int nSigal)
{
    if(nSigal == SIGINT)
    {ILOG_PRINTF(LOG_INFO,"TChatMediaServer Will Be Shut Down.");ServerStatus = false;}
}


void Handler_Mallopt()
{
    //���̺߳ܺ������ڴ�����
    //������̴�����һ���̲߳����ڸ��߳��ڷ���һ����С���ڴ�1k���������������ڴ���������64M
    //glibcΪ�˷����ڴ�����ܵ����⣬ʹ���˺ܶ����arena��memory pool,
    //ȱʡ������64bit������ÿһ��arenaΪ64M��һ�����̿�������� cpu������ * 8��arena
    //glibc �汾����2.11 �ر��ڴ��Ż�����ѡ��
    mallopt(M_ARENA_MAX, 1);
}


int Handler_KBHit()
{
    struct termios oldt, newt;int ch = 0,oldf = 0;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;newt.c_lflag &= ~(ICANON | ECHO);

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

    ch = getchar();tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);
    if(ch != EOF){return ch;}

    return 0;
}
