#pragma once
#include <string>

//最大接收数据长度
#define MAX_RECIVE_LEN 1024*5
//接收数据缓冲区长度
#define RECIVE_BUFFER_LEN 1024

//接收单个数据包最大长度
#define MAX_PACK_LEN 1024*4
//发送单个数据包最大长度
#define MAX_SEND_LEN 1024*5
//服务器包头长度
#define HEADER_PACKET_LEN 8
//udp通道数据长度
#define UDP_CHANNEL_PACKET 26

using namespace std;

enum ERROR_CODE
{
    CODE_OPERATE_SUCCESS			      = 0,      //操作成功

    // 系统错误
    CODE_SYSTEM_UNKNOWN		              =-1,      //未知错误
    CODE_SYSTEM_MEMORYFAIL	              = 1,      //内存不足
    CODE_SYSTEM_BUSY	                  = 2,      //内存不足

    // 连接部分
    CODE_CONNECT_AUTHFAIL                 = 103,    //连接服务器认证失败
    CODE_CONNECT_OLDVERSION               = 104,    //版本太旧，不允许连接
    CODE_CONNECT_MAXSIZE                  = 105,    //连接数量已超过最大限制

    // 登录部分
    CODE_CERTIFY_FAIL		              = 200,    //认证失败
    CODE_VISITOR_DENY		              = 201,    //游客登录被禁止
    CODE_ALRADY_LOGIN		              = 202,    //用户已登录
    CODE_ERROR_USERTYPE		              = 203,    //不支持的用户类型

    // 房间部分
    CODE_WRONG_PASSWORD		              = 300,    //房间密码错误，禁止进入
    CODE_ROOM_PEOPLE_FULL	              = 301,    //房间已满员，不能进入
    CODE_ROOM_ENTERFAIL		              = 302,    //禁止进入房间
    CODE_ERROR_ROOMID		              = 303,    //房间ID错误
    CODE_ROOM_ALREADYIN	                  = 304,    //用户已在房间内
    CODE_NO_ROOM                          = 305,    //房间不存在
    CODE_MAX_ROOM_NUMBER                  = 306,    //已达服务器最大支持房间数

    // 用户部分
    CODE_USER_NOTINROOM		              = 400,    //用户不在房间内
    CODE_USER_OFFLINE		              = 401,    //用户不在线
    CODE_ERROR_USER_ID		              = 402,    //用户ID错误

    // 呼叫部分
    CODE_ERROR_VIDEO_BUSY		          = 601,    //对方繁忙
    CODE_STOP_VIDEO_ERROR		          = 603,    //用户没有进行视频，停止视频失败

    // 媒体部分
    CODE_ERROR_CREATE_CHANNEL		      = 701,    //用户没有建立音视频数据通道
    CODE_USER_NOOPEN_CAMERA		          = 700,    //用户没有打开音视频

    // 录像部分
    CODE_RECORD_CREATEFAIL                = 800,    //创建录像任务失败

    //服务部分
    CODE_SERVICE_REGIST                   = 900,    //服务已经注册
    CODE_NO_FORWARD_SERVER                = 901,    //没有在线的转发服务器
};

//用户获取数据类型
enum Data_Type
{
    TYPE_AUDIO_DATA = 1,  //音频数据
    TYPE_VIDEO_DATA = 2,  //视频数据
};

//用户IP/PORT信息结构定义
typedef struct User_Address_
{
    string client_ip;
    int client_port;
    bool is_audio_data;  //是否获取音频数据
    bool is_video_data;  //是否获取视频数据
    bool is_channel;     //是否打开通道

    User_Address_()
    {
        client_ip = "";
        client_port = 0;
        is_audio_data = false;
        is_video_data = false;
        is_channel = false;
    }
}User_Address;
