#pragma once
#include <fstream>

using namespace std;



class CIpid_method
{
public:
    CIpid_method();
    virtual ~CIpid_method();

public:
    //服务器启动，生存pid文件，记录当前进程pid
    static bool set_pid(const char *file_name,int pid)
    {
        ofstream m_out_file;

        m_out_file.open(file_name,ios::out|ios::trunc);
        if(!m_out_file.is_open()){return false;}

        m_out_file.write((char*)&pid,sizeof(int));m_out_file.close();return true;
    }

    //获取pid文件中，进程ID
    static bool get_pid(const char *file_name,int &pid)
    {
        ifstream m_in_file;

        m_in_file.open(file_name,ios::in);
        if(!m_in_file.is_open()){return false;}

        m_in_file.read((char*)&pid,sizeof(int));m_in_file.close();

        remove(file_name);return true;
    }
};
