#pragma once
#include <ModelSingleton.h>
#include"../xml/tinyxml.h"
#include <string>

using namespace std;

class CIConfig_method
{
public:
    CIConfig_method();
    virtual ~CIConfig_method();

public:
    bool start(string strConfName);

    string current_time();
protected:

    bool ReadXmlFile(string strConfName);

    bool get_Iface_name(char *iface_name, int len);

    string get_local_ip(string iface_nam);

    string& replace_all(string& strSrc,const string& old_value,const string& new_value);

public:
    //中心控制服务器地址
    string m_CsServerIP;
    int m_CsServerPort;
    //视频存储服务器地址
    string m_SsServerIP;
    int m_SsServerPort;

    int m_MediaPort;           //媒体转发服务监听端口
    int m_monitorPort;         //服务运行状态监听端口

    int64_t m_nodeid;          //服务ID
    int m_level;               //日志打印等级
    int m_nTime;               //心跳时间间隔
    int m_nThread;             //网络数据工作线程数
    int m_BuffSize;            //网络数据缓冲区大小
    bool m_RsStatus;           //录像服务状态

    string m_MediaSrv_lanIp;   //媒体服务器提供服务内网地址
    string m_MediaSrv_wanIp;   //媒体服务器提供服务公网地址
    int m_MediaSrv_wanPort;    //媒体服务器提供服务公网端口

    string m_strLogPath;        //日志文件路径

    //服务器信息
    string m_server_starttime;  //服务器启动时间
    string m_server_name;       //服务器名称
    string m_server_version;    //当前服务器版本
    int m_server_type;          //服务器类型

    //turn相关配置信息
    int m_life_time;			//allocation 生命周期
    int m_max_port;				//最大端口
    int m_min_port;				//最小端口
    int m_max_relay_per_username;
    int m_bandwidth_per_allocation;
    int m_restricted_bandwidth;
    string m_nonce_key;
    string m_realm;
};


#define Singleton_IConfig Singleton<CIConfig_method>::GetInstance()
