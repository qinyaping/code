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
    //���Ŀ��Ʒ�������ַ
    string m_CsServerIP;
    int m_CsServerPort;
    //��Ƶ�洢��������ַ
    string m_SsServerIP;
    int m_SsServerPort;

    int m_MediaPort;           //ý��ת����������˿�
    int m_monitorPort;         //��������״̬�����˿�

    int64_t m_nodeid;          //����ID
    int m_level;               //��־��ӡ�ȼ�
    int m_nTime;               //����ʱ����
    int m_nThread;             //�������ݹ����߳���
    int m_BuffSize;            //�������ݻ�������С
    bool m_RsStatus;           //¼�����״̬

    string m_MediaSrv_lanIp;   //ý��������ṩ����������ַ
    string m_MediaSrv_wanIp;   //ý��������ṩ��������ַ
    int m_MediaSrv_wanPort;    //ý��������ṩ�������˿�

    string m_strLogPath;        //��־�ļ�·��

    //��������Ϣ
    string m_server_starttime;  //����������ʱ��
    string m_server_name;       //����������
    string m_server_version;    //��ǰ�������汾
    int m_server_type;          //����������

    //turn���������Ϣ
    int m_life_time;			//allocation ��������
    int m_max_port;				//���˿�
    int m_min_port;				//��С�˿�
    int m_max_relay_per_username;
    int m_bandwidth_per_allocation;
    int m_restricted_bandwidth;
    string m_nonce_key;
    string m_realm;
};


#define Singleton_IConfig Singleton<CIConfig_method>::GetInstance()
