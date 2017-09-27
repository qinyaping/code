#ifndef _IO_NET_BUFFER_
#define _IO_NET_BUFFER_

#include <stdlib.h>
#include <string.h>
#include <Lock.h>
#include <queue>

class IO_ReadBuffer
{
public:
    IO_ReadBuffer();
    virtual ~IO_ReadBuffer();

public:
    //�ӻ�����β��д������
    int Write(void * pData,int data_len);
    //�ӻ�����ͷ����ȡ����
    int Read(void * pData,int data_len);
    //�ӻ�����ͷ����������
    int Insert(void * pData,int data_len);
    //���û�����
    int ClearData();
protected:
    bool Create_Buffer(int data_len);

private:
    //�������ݻ�������ַ
    char *m_pBuffer;
    //��������С
    int m_Buffer_Size;
    //���ݴ�С
    int m_Data_Size;
};


struct Send_Data
{
    char * m_pBuffer;int m_len;
    Send_Data(){m_pBuffer = NULL;m_len = 0;}
};

class IO_SendBuffer
{
public:
    IO_SendBuffer();
    virtual ~IO_SendBuffer();

public:

    bool Write(void * pData,int data_len,Send_Data &data);

    bool Read(Send_Data &data,int data_len);
    //���û�����
    bool ClearData();

private:
    //ͬ����
    CMutex m_lock;
    //���Ͷ���
    std::queue<Send_Data> m_send_list;
};

#endif // _IO_NET_BUFFER_


