#pragma once
#include <string>

//���������ݳ���
#define MAX_RECIVE_LEN 1024*5
//�������ݻ���������
#define RECIVE_BUFFER_LEN 1024

//���յ������ݰ���󳤶�
#define MAX_PACK_LEN 1024*4
//���͵������ݰ���󳤶�
#define MAX_SEND_LEN 1024*5
//��������ͷ����
#define HEADER_PACKET_LEN 8
//udpͨ�����ݳ���
#define UDP_CHANNEL_PACKET 26

using namespace std;

enum ERROR_CODE
{
    CODE_OPERATE_SUCCESS			      = 0,      //�����ɹ�

    // ϵͳ����
    CODE_SYSTEM_UNKNOWN		              =-1,      //δ֪����
    CODE_SYSTEM_MEMORYFAIL	              = 1,      //�ڴ治��
    CODE_SYSTEM_BUSY	                  = 2,      //�ڴ治��

    // ���Ӳ���
    CODE_CONNECT_AUTHFAIL                 = 103,    //���ӷ�������֤ʧ��
    CODE_CONNECT_OLDVERSION               = 104,    //�汾̫�ɣ�����������
    CODE_CONNECT_MAXSIZE                  = 105,    //���������ѳ����������

    // ��¼����
    CODE_CERTIFY_FAIL		              = 200,    //��֤ʧ��
    CODE_VISITOR_DENY		              = 201,    //�ο͵�¼����ֹ
    CODE_ALRADY_LOGIN		              = 202,    //�û��ѵ�¼
    CODE_ERROR_USERTYPE		              = 203,    //��֧�ֵ��û�����

    // ���䲿��
    CODE_WRONG_PASSWORD		              = 300,    //����������󣬽�ֹ����
    CODE_ROOM_PEOPLE_FULL	              = 301,    //��������Ա�����ܽ���
    CODE_ROOM_ENTERFAIL		              = 302,    //��ֹ���뷿��
    CODE_ERROR_ROOMID		              = 303,    //����ID����
    CODE_ROOM_ALREADYIN	                  = 304,    //�û����ڷ�����
    CODE_NO_ROOM                          = 305,    //���䲻����
    CODE_MAX_ROOM_NUMBER                  = 306,    //�Ѵ���������֧�ַ�����

    // �û�����
    CODE_USER_NOTINROOM		              = 400,    //�û����ڷ�����
    CODE_USER_OFFLINE		              = 401,    //�û�������
    CODE_ERROR_USER_ID		              = 402,    //�û�ID����

    // ���в���
    CODE_ERROR_VIDEO_BUSY		          = 601,    //�Է���æ
    CODE_STOP_VIDEO_ERROR		          = 603,    //�û�û�н�����Ƶ��ֹͣ��Ƶʧ��

    // ý�岿��
    CODE_ERROR_CREATE_CHANNEL		      = 701,    //�û�û�н�������Ƶ����ͨ��
    CODE_USER_NOOPEN_CAMERA		          = 700,    //�û�û�д�����Ƶ

    // ¼�񲿷�
    CODE_RECORD_CREATEFAIL                = 800,    //����¼������ʧ��

    //���񲿷�
    CODE_SERVICE_REGIST                   = 900,    //�����Ѿ�ע��
    CODE_NO_FORWARD_SERVER                = 901,    //û�����ߵ�ת��������
};

//�û���ȡ��������
enum Data_Type
{
    TYPE_AUDIO_DATA = 1,  //��Ƶ����
    TYPE_VIDEO_DATA = 2,  //��Ƶ����
};

//�û�IP/PORT��Ϣ�ṹ����
typedef struct User_Address_
{
    string client_ip;
    int client_port;
    bool is_audio_data;  //�Ƿ��ȡ��Ƶ����
    bool is_video_data;  //�Ƿ��ȡ��Ƶ����
    bool is_channel;     //�Ƿ��ͨ��

    User_Address_()
    {
        client_ip = "";
        client_port = 0;
        is_audio_data = false;
        is_video_data = false;
        is_channel = false;
    }
}User_Address;
