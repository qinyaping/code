#pragma once
#include "protocol/protocol_header.h"
#include"protocol/sd.data_define.pb.h"
#include"protocol/sd.data_structure.pb.h"
#include <boost/thread/thread.hpp>
#include<string>
#include"public/data_type.h"

using namespace std;


class CSession;

class CTcpHandler
{
public:
	CTcpHandler();
	virtual ~CTcpHandler();

public:

	bool Start();

	bool Stop();
public:
    //�ͻ������ӳɹ�
    bool OnConnected(CSession *pSession,string SrvIP,int Port) ;
    //�ͻ��˶Ͽ�����
    bool OnDisConnected() ;
    //��������
    bool OnReciveData(unsigned char * data,unsigned int len) ;
    //���ݷ��ͳɹ�
    bool OnSendData() ;
    //��������
    bool SendData(unsigned char * data,unsigned int len) ;

public:
    //ע�����
    bool Handler_RegisterService();
    //��������
    bool Handler_SendHeartbeat();
    //��������
    bool Handler_CreateRoom(Message &msg);
    //ɾ������
    bool Handler_DeleteRoom(Message &msg);
    //�û����뷿��
    bool Handler_EnterRoom(Message &msg);
    //�û��뿪����
    bool Handler_LeaveRoom(Message &msg);
    //ע�������Ӧ
    bool Handler_RegisterServiceResp(Message &msg);
    //�����߳�
    void Handler_Run();
    //��ʼ¼��
    bool Handler_StartRecordReq(Message &msg);
    //��ʼ¼����Ӧ
    bool Handler_StartRecordResp(Message &msg);
    //ֹͣ¼��
    bool Handler_StopRecord(Message &msg);
    //����¼�����
    bool Handler_SetVideo(Message &msg);
    //�û���Ƶ����
    bool Handler_OperateVideoReq(Message &msg);
    //�û���Ƶ����
    bool Handler_OperateAudioReq(Message &msg);
    //����P2Pͨ������
    bool Handler_P2PChannelReq(Message &msg);
private:
    //ͨ�ž��
    CSession * m_pSession;
    //������Ip
    string m_ServerIP;
    //�������˿�
    int m_ServerPort;
    //�Ƿ����ӷ�����
    bool m_isConnect;
    //�Ƿ�ע�ᵽ������
    bool m_isRegister;
    //�߳̽�����־
    bool m_isActive;
};

//����ģʽ
#define Singleton_CTcpHandler Singleton<CTcpHandler>::GetInstance()
