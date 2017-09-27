#pragma once
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <fstream>
#include <ModelSingleton.h>

//输出带颜色日志信息
#define NONE                 "\e[0m"
#define L_RED                "\e[1;31m"
#define BROWN                "\e[0;33m"
#define GREEN                "\e[0;32m"
#define L_GREEN              "\e[1;32m"
#define PURPLE               "\e[0;35m"
#define L_PURPLE             "\e[1;35m"

//日志类型
enum Log_Type{LOG_DEBUG = 0,LOG_INFO,LOG_WARNING,LOG_ERROR,LOG_START};

//日志信息结构
struct ilog_buff
{
    int type;int line;
    char file[64];
    char ilog[1024];

    ilog_buff()
    {
        type = LOG_DEBUG;line = 0;
        memset(file,0,sizeof(file));
        memset(ilog,0,sizeof(ilog));
    }
};

using namespace std;
class CIlog_method
{
public:
    CIlog_method();
    virtual ~CIlog_method();

public:
    bool ilog_start(const char *log_name,int log_level);

    bool ilog_stop();

public:
    bool ilog_message(int log_type,const char *p_file,unsigned int log_line,const char* p_format,...);

    bool ilog_printf(int log_type,const char *p_log);
protected:
    static void* ilog_run(void* pParam);

protected:
    bool ilog_show();

    bool ilog_save(string ilog);

    bool ilog_start_show();

    string ilog_current_time();

    string ilog_current_date();

private:
    pthread_t m_pthread_id;

    bool m_thread_status;

    int m_ilog_level;

    string m_ilog_path;
};
#define Singleton_ILog Singleton<CIlog_method>::GetInstance()

//日志输出宏定义
#define IFILE_NAME_(x) strrchr(x,'/')?strrchr(x,'/')+1:x
#define ILOG_MESSAGE(level,format...) Singleton_ILog->ilog_message(level,IFILE_NAME_(__FILE__),__LINE__,format)
#define ILOG_PRINTF(level,log) Singleton_ILog->ilog_printf(level,log)
