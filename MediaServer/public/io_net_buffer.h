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
    //从缓冲区尾部写入数据
    int Write(void * pData,int data_len);
    //从缓冲区头部读取数据
    int Read(void * pData,int data_len);
    //从缓冲区头部插入数据
    int Insert(void * pData,int data_len);
    //重置缓冲区
    int ClearData();
protected:
    bool Create_Buffer(int data_len);

private:
    //接收数据缓冲区地址
    char *m_pBuffer;
    //缓冲区大小
    int m_Buffer_Size;
    //数据大小
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
    //重置缓冲区
    bool ClearData();

private:
    //同步锁
    CMutex m_lock;
    //发送队列
    std::queue<Send_Data> m_send_list;
};

#endif // _IO_NET_BUFFER_


