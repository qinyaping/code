#include "io_net_buffer.h"
#include "data_type.h"

/*==================接收数据缓冲区实现==================*/
IO_ReadBuffer::IO_ReadBuffer()
{
    //接收数据缓冲区地址
    m_pBuffer = NULL;
    //缓冲区大小
    m_Buffer_Size = 0;
    //数据大小
    m_Data_Size = 0;
}

IO_ReadBuffer::~IO_ReadBuffer()
{
    if(m_pBuffer != NULL && m_Buffer_Size > 0)
    {
        free(m_pBuffer);
        m_pBuffer = NULL;
        m_Buffer_Size = 0;
        m_Data_Size = 0;
    }
}



bool IO_ReadBuffer::Create_Buffer(int data_len)
{
    data_len =  data_len + m_Data_Size;
    if(data_len <= m_Buffer_Size){return true;}

    char *pTemp_Buff = (char *)malloc(data_len);
    if(pTemp_Buff == NULL){return false;}
    memset(pTemp_Buff,0,data_len);

    //第一次分配内存空间
    if(m_pBuffer == NULL && m_Buffer_Size == 0)
    {
        m_pBuffer = pTemp_Buff;m_Buffer_Size = data_len;return true;
    }

    if(m_Data_Size > 0){memcpy(pTemp_Buff,m_pBuffer,m_Data_Size);}

    free(m_pBuffer);m_pBuffer = NULL;
    m_pBuffer = pTemp_Buff;m_Buffer_Size = data_len;

    return true;
}


int IO_ReadBuffer::Write(void * pData,int data_len)
{
    if(pData == NULL || data_len <= 0){return 0;}

    if(!Create_Buffer(data_len)){return 0;}

    memcpy(m_pBuffer + m_Data_Size,pData,data_len);
    m_Data_Size += data_len;

    return data_len;
}


int IO_ReadBuffer::Read(void * pData,int data_len)
{
    if(pData == NULL || data_len <= 0){return 0;}

    if(data_len > m_Data_Size){data_len = m_Data_Size;}

    memcpy(pData,m_pBuffer,data_len);
    m_Data_Size -= data_len;

    if(m_Data_Size > 0){memmove(m_pBuffer,m_pBuffer + data_len,m_Data_Size);}
    return data_len;
}

int IO_ReadBuffer::Insert(void * pData,int data_len)
{
    if(pData == NULL || data_len <= 0){return 0;}

    if(!Create_Buffer(data_len)){return 0;}

    if(m_Data_Size > 0){memmove(m_pBuffer + data_len,m_pBuffer,m_Data_Size);}

    memcpy(m_pBuffer,pData,data_len);m_Data_Size += data_len;

    return data_len;
}


int IO_ReadBuffer::ClearData()
{
    if(m_pBuffer != NULL && m_Buffer_Size > 0)
    {
        memset(m_pBuffer,0,m_Buffer_Size);
        m_Data_Size = 0;
    }
    return m_Buffer_Size;
}








/*==================发送数据缓冲区实现==================*/
IO_SendBuffer::IO_SendBuffer()
{

}


IO_SendBuffer::~IO_SendBuffer()
{
    ClearData();
}

bool IO_SendBuffer::Write(void * pData,int data_len,Send_Data &data)
{
    Autolock lock(m_lock);
    if(m_send_list.empty())
    {
        if(data_len > MAX_SEND_LEN || data_len <= 0){return false;}

        char *pBuff = new char[data_len];
        if(pBuff == NULL){return false;}

        memset(pBuff,0,data_len);
        memcpy(pBuff,pData,data_len);

        data.m_pBuffer = pBuff;data.m_len = data_len;
        m_send_list.push(data);
        return true;
    }
    else
    {
        if(data_len > MAX_SEND_LEN || data_len <= 0){return false;}

        char *pBuff = new char[data_len];
        if(pBuff == NULL){return false;}

        memset(pBuff,0,data_len);
        memcpy(pBuff,pData,data_len);

        Send_Data send;
        send.m_pBuffer = pBuff;send.m_len = data_len;
        m_send_list.push(send);
    }
    return false;
}

bool IO_SendBuffer::Read(Send_Data &data,int data_len)
{
    Autolock lock(m_lock);
    if(m_send_list.empty()){return false;}

    Send_Data send;
    send = m_send_list.front();
    m_send_list.pop();

    if(send.m_pBuffer != NULL && send.m_len == data_len)
    {delete[] send.m_pBuffer;send.m_pBuffer = NULL;}

    if(m_send_list.empty()){return false;}
    data = m_send_list.front();

    return true;
}

bool IO_SendBuffer::ClearData()
{
    Autolock lock(m_lock);
    while(!m_send_list.empty())
    {
        Send_Data send;
        send = m_send_list.front();
        m_send_list.pop();

        if(send.m_pBuffer != NULL)
        {delete[] send.m_pBuffer;send.m_pBuffer = NULL;}
    }
    return true;
}

