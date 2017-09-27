#include"config.h"
#include<iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

CIConfig_method::CIConfig_method()
{
    //���Ŀ��Ʒ�������ַ
    m_CsServerIP = "127.0.0.1";
    m_CsServerPort = 9000;
    //��Ƶ�洢��������ַ
    m_SsServerIP = "127.0.0.1";
    m_SsServerPort = 12345;

    m_MediaPort = 9100;        //ý��ת����������˿�
    m_monitorPort = 9105;      //��������״̬�����˿�

    m_nodeid = 1270019100;     //����ID
    m_level = 1;               //��־��ӡ�ȼ�
    m_nTime = 30;              //����ʱ����
    m_nThread = 10;            //�������ݹ����߳���
    m_BuffSize = 32*1024*1024; //�������ݻ�������С
    m_RsStatus = false;        //¼�����״̬

    m_MediaSrv_lanIp = "";     //ý��������ṩ����������ַ
    m_MediaSrv_wanIp = "";     //ý��������ṩ��������ַ
    m_MediaSrv_wanPort = 0;    //ý��������ṩ�������˿�


    m_server_starttime = current_time();    //����������ʱ��
    m_server_name = "TChatMediaServer";     //����������
    m_server_version = "V1.0.1";            //��ǰ�������汾
    m_server_type = 2002;                   //����������
}

CIConfig_method::~CIConfig_method()
{

}


bool CIConfig_method::start(string strConfName)
{
    return ReadXmlFile(strConfName);
}


bool CIConfig_method::ReadXmlFile(string strConfName)
{
    try
    {
        //ͨ���ļ�����XML
        TiXmlDocument *spXmlDoc = new TiXmlDocument(strConfName.c_str());
        if(!spXmlDoc->LoadFile()){return false;}

        const char *pContent = NULL;
        TiXmlNode* pRoot = NULL;TiXmlNode* pNode = NULL;TiXmlElement *spElement = NULL;

        pRoot = spXmlDoc->FirstChild("SDConfig");if(NULL == pRoot){return false;}
        pRoot = pRoot->FirstChild("Setting");if(NULL == pRoot){return false;}

        //�ڵ�ID
        pNode = pRoot->FirstChild("ServiceID");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_nodeid = strtol(pContent,NULL,10);}

        //����ʱ����(��)
        pNode = pNode->NextSibling("TimeOut");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_nTime = atoi(pContent);if(m_nTime > 180){m_nTime = 180;}if(m_nTime < 3){m_nTime = 3;}}

        //��־��ӡ�ȼ�
        pNode = pNode->NextSibling("Loglevel");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_level = atoi(pContent);if(m_level > 3 || m_level < 0){m_level = 2;}}

        //��������С(MB)
        pNode = pNode->NextSibling("BuffSize");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_BuffSize = atoi(pContent);if(m_BuffSize > 128 || m_BuffSize <= 0){m_BuffSize = 128;}m_BuffSize = m_BuffSize*1024*1024;}

        //¼�������״̬
        pNode = pNode->NextSibling("RsStatus");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){int nStatus = atoi(pContent);if(nStatus == 1){m_RsStatus = true;}}

        //��־�ļ�·��
        pNode = pNode->NextSibling("LogPath");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){if(pContent == "" || pContent == "."){pContent = "./";}m_strLogPath = pContent;
        m_strLogPath = replace_all(m_strLogPath,"\\","/");}

        //��ȡ NetInfo�ڵ���Ϣ
        pNode = pRoot->NextSibling("NetInfo");if(NULL == pNode){return false;}

        //ý��ת����������˿�
        pNode = pNode->FirstChild("MediaPort");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_MediaPort = atoi(pContent);if(m_MediaPort <= 0 || m_MediaPort >=65535){m_MediaPort = 9100;}}

        //��������״̬�����˿�
        pNode = pNode->NextSibling("MonitorPort");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_monitorPort = atoi(pContent);if(m_monitorPort <= 0 || m_monitorPort >= 65535){m_monitorPort = 9105;}}

        //���Ŀ��Ʒ�������ַ
        pNode = pNode->NextSibling("CsServerIP");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_CsServerIP = pContent;}

        //���Ŀ��Ʒ������˿�
        pNode = pNode->NextSibling("CsServerPort");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_CsServerPort = atoi(pContent);}

        //¼���������ַ
        pNode = pNode->NextSibling("RsServerIP");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_SsServerIP = pContent;}

        //¼��������˿�
        pNode = pNode->NextSibling("RsServerPort");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_SsServerPort = atoi(pContent);}

        //ý��������ṩ����������ַ
        pNode = pNode->NextSibling("MsLanServerIP");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_MediaSrv_lanIp = pContent;}

        //ý��������ṩ��������ַ
        pNode = pNode->NextSibling("MsWanServerIP");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_MediaSrv_wanIp = pContent;}

        //ý��������ṩ�������˿�
        pNode = pNode->NextSibling("MsWanServerPort");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_MediaSrv_wanPort = atoi(pContent);}

        //��ȡ turnserver��Ϣ
        pNode = pRoot->NextSibling("TurnServer");if(NULL == pNode){return false;}

        //allocation����������
        pNode = pNode->FirstChild("life_time");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_life_time = atoi(pContent);}

        //���˿�
        pNode = pNode->NextSibling("max_port");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_max_port = atoi(pContent);}

        //��С�˿�
        pNode = pNode->NextSibling("min_port");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_min_port = atoi(pContent);}

        //ÿ��client���relay��peer����
        pNode = pNode->NextSibling("max_relay_per_username");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_max_relay_per_username = atoi(pContent);}

		//������
        pNode = pNode->NextSibling("bandwidth_per_allocation");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_bandwidth_per_allocation = atoi(pContent);}

		//�������û�������
        pNode = pNode->NextSibling("restricted_bandwidth");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_restricted_bandwidth = atoi(pContent);}

		//nonce
        pNode = pNode->NextSibling("nonce_key");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_nonce_key = pContent;}

		//realm
        pNode = pNode->NextSibling("realm");if(NULL == pNode){return false;}
        spElement = pNode->ToElement();pContent = spElement->GetText();
        if(pContent != NULL){m_realm = pContent;}

        //�����߳���
        m_nThread =  sysconf(_SC_NPROCESSORS_CONF);
        if(m_nThread <= 0){m_nThread = 3;}m_nThread = m_nThread*2;

        //��ȡ������ַ
        char netname[128] = {0};string strTemp = "";
        if(get_Iface_name(netname,sizeof(netname))){strTemp = get_local_ip(netname);}

        if(strTemp != ""){if(m_CsServerIP == "127.0.0.1" || m_CsServerIP == ""){m_CsServerIP = strTemp;}
        if(m_SsServerIP == "127.0.0.1" || m_SsServerIP == ""){m_SsServerIP = strTemp;}
        if(m_MediaSrv_lanIp == "127.0.0.1" || m_MediaSrv_lanIp == ""){m_MediaSrv_lanIp = strTemp;}
        if(m_MediaSrv_wanIp == "127.0.0.1" || m_MediaSrv_wanIp == ""){m_MediaSrv_lanIp = strTemp;}}

        delete spXmlDoc; spXmlDoc = NULL;
    }
    catch(...){return false;}

    return true;
}


string CIConfig_method::current_time()
{
    char szCurTime[32] = {0};
    time_t rawtime;struct tm * timeinfo;

    time (&rawtime);timeinfo = localtime(&rawtime );
    sprintf(szCurTime,"%04d-%02d-%02d %02d:%02d:%02d",timeinfo->tm_year+1900,timeinfo->tm_mon+1,timeinfo-> tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);

    return szCurTime;
}


bool CIConfig_method::get_Iface_name(char *iface_name, int len)
{
    int r = -1;char devname[20] = {0};FILE *fp = NULL;
    int flgs, ref, use, metric, mtu, win, ir;
    unsigned long int d = 0, g = 0, m = 0;

    if((fp = fopen("/proc/net/route","r")) == NULL) {return false;}

    if (fscanf(fp, "%*[^\n]\n") < 0) {fclose(fp);return false;}

    while (1)
    {
        r = fscanf(fp,"%19s%lx%lx%X%d%d%d%lx%d%d%d\n",
                 devname, &d, &g, &flgs, &ref, &use,
                 &metric, &m, &mtu, &win, &ir);

        if (r != 11) {
        if ((r < 0) && feof(fp)){break;}
        continue;}

        strncpy(iface_name, devname, len);
        fclose(fp);
        return true;
    }
    fclose(fp);
    return false;
}

string CIConfig_method::get_local_ip(string iface_nam)
{
    char ipaddr[50] = {0};int sock_get_ip = 0;
    struct sockaddr_in *sin = NULL;struct ifreq ifr_ip;

    if((sock_get_ip=socket(AF_INET, SOCK_STREAM, 0)) == -1){return "";}

    memset(&ifr_ip, 0, sizeof(ifr_ip));
    strncpy(ifr_ip.ifr_name,iface_nam.c_str(), sizeof(ifr_ip.ifr_name) - 1);

    if(ioctl( sock_get_ip, SIOCGIFADDR, &ifr_ip) < 0 ){return "";}

    sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
    strcpy(ipaddr,inet_ntoa(sin->sin_addr));
    close(sock_get_ip);

    return ipaddr;
}


string& CIConfig_method::replace_all(string& strSrc,const string& old_value,const string& new_value)
{
    while(true)
    {
        string::size_type pos(0);

        if((pos = strSrc.find(old_value))!= string::npos)
            strSrc.replace(pos,old_value.length(),new_value);
        else break;
    }

    return strSrc;
}
