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
    //客户端连接成功
    bool OnConnected(CSession *pSession,string SrvIP,int Port) ;
    //客户端断开连接
    bool OnDisConnected() ;
    //接收数据
    bool OnReciveData(unsigned char * data,unsigned int len) ;
    //数据发送成功
    bool OnSendData() ;
    //发送数据
    bool SendData(unsigned char * data,unsigned int len) ;

public:
    //注册服务
    bool Handler_RegisterService();
    //发送心跳
    bool Handler_SendHeartbeat();
    //创建房间
    bool Handler_CreateRoom(Message &msg);
    //删除房间
    bool Handler_DeleteRoom(Message &msg);
    //用户进入房间
    bool Handler_EnterRoom(Message &msg);
    //用户离开房间
    bool Handler_LeaveRoom(Message &msg);
    //注册服务响应
    bool Handler_RegisterServiceResp(Message &msg);
    //工作线程
    void Handler_Run();
    //开始录像
    bool Handler_StartRecordReq(Message &msg);
    //开始录像响应
    bool Handler_StartRecordResp(Message &msg);
    //停止录像
    bool Handler_StopRecord(Message &msg);
    //设置录像参数
    bool Handler_SetVideo(Message &msg);
    //用户视频操作
    bool Handler_OperateVideoReq(Message &msg);
    //用户音频操作
    bool Handler_OperateAudioReq(Message &msg);
    //建立P2P通道请求
    bool Handler_P2PChannelReq(Message &msg);
private:
    //通信句柄
    CSession * m_pSession;
    //服务器Ip
    string m_ServerIP;
    //服务器端口
    int m_ServerPort;
    //是否连接服务器
    bool m_isConnect;
    //是否注册到服务器
    bool m_isRegister;
    //线程结束标志
    bool m_isActive;
};

//单列模式
#define Singleton_CTcpHandler Singleton<CTcpHandler>::GetInstance()
