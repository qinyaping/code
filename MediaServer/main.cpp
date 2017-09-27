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

//服务器运行状态
bool ServerStatus = true;
void Handler_ServerClose( int nSigal);

void Handler_Mallopt();
int Handler_KBHit();
int turnserver_start_main(int argc, char** argv);

int main(int argc,char *argv[])
{
    //服务运行参数检测 -d开启守护进程模式 启动服务后台运行
    if(argc == 2 && ( (strcmp("-d",argv[1]) == 0) || (strcmp("-D",argv[1]) == 0) ))
    {
        ILOG_PRINTF(LOG_INFO,"思迪视频媒体服务器已成功启动.");
        if(daemon(1,0) < 0){ILOG_PRINTF(LOG_ERROR,"Create Daemon Failed.");return false;}
    }
    //-stop停止服务
    else if(argc == 2 && ( (strcmp("-k",argv[1]) == 0) || (strcmp("-K",argv[1]) == 0) ))
    {
        int stop_pid = 0;if(CIpid_method::get_pid("mediaserver.pid",stop_pid))
        {if(kill(stop_pid,SIGKILL) == 0){ILOG_PRINTF(LOG_INFO,"思迪视频媒体服务器已成功停止.");}}return true;
    }
    //其他参数处理
    else if(argc >= 2){ILOG_PRINTF(LOG_ERROR,"Parameter Error, Using The Following Parameters:");
    ILOG_PRINTF(LOG_ERROR,"Service Start: -d or -D ,Service Stop:-k or -K");return 0;}

    //注册关闭信号回调函数
    signal(SIGINT, Handler_ServerClose);//Handler_Mallopt();

    //读取配置文件
    if(!Singleton_IConfig->start("TChatMediaServer.xml"))
    {ILOG_PRINTF(LOG_ERROR,"TChatMediaServer Read Config File Failed.");return false;}

    //启动异步日志服务
    Singleton_ILog->ilog_start("TChatMediaServer",Singleton_IConfig->m_level);

    //turnserver服务器
//    turnserver_start_main(argc, argv);

    //Udp服务器
    Udp_Server udpSrv;if(!udpSrv.Start(Singleton_IConfig->m_MediaPort))
    {ILOG_PRINTF(LOG_ERROR,"Udp_Server Startup Failed. The Port Is Bind.");return false;}

//    //tcp客户端
//    tcp_client client;
//    client.start(Singleton_IConfig->m_CsServerIP,Singleton_IConfig->m_CsServerPort);
//
    //连接池
//    Singleton_ClientPool->start(Singleton_IConfig->m_SsServerIP,Singleton_IConfig->m_SsServerPort);
//
//    //监控服务器
//    IMonitor_Server monitor;if(!monitor.Start("",Singleton_IConfig->m_monitorPort,60))
//    {ILOG_PRINTF(LOG_ERROR,"Monitor_Server Startup Failed.");return false;}
//
//    //所有服务启动成功，记录进程ID
//    if(!CIpid_method::set_pid("mediaserver.pid",getpid()))
//    {ILOG_MESSAGE(LOG_ERROR,"CIpid_method::set_pid Failed.");return false;}

    ILOG_PRINTF(LOG_START,"思迪视频媒体服务器已成功启动.");

    //主线程接收标准输入
    while(ServerStatus){char get_char = Handler_KBHit();
    if(get_char == 'q' || get_char == 'Q'){break;}sleep(1);}

    //资源释放
//    udpSrv.Stop();

 //   client.stop();
 //   Singleton_ClientPool->stop();

 //   monitor.Stop();
    //释放protobuf资源
//    google::protobuf::ShutdownProtobufLibrary();

    ILOG_PRINTF(LOG_INFO,"思迪视频媒体服务器已成功停止.");
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
    //多线程很耗虚拟内存问题
    //如果进程创建了一个线程并且在该线程内分配一个很小的内存1k，整个进程虚拟内存立马增加64M
    //glibc为了分配内存的性能的问题，使用了很多叫做arena的memory pool,
    //缺省配置在64bit下面是每一个arena为64M，一个进程可以最多有 cpu核心数 * 8个arena
    //glibc 版本大于2.11 关闭内存优化分配选项
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
