#include "log.h"
#include <boost/lockfree/queue.hpp>
#include <sys/ioctl.h>
#include "config.h"

boost::lockfree::queue<ilog_buff> ilog_queue(0);

CIlog_method::CIlog_method()
{
    m_thread_status = false;
    m_ilog_level = 0;
    m_ilog_path = "";
}

CIlog_method::~CIlog_method()
{

}

bool CIlog_method::ilog_start(const char *log_name,int log_level)
{
    if(m_thread_status){return false;}

    string str_file_path = log_name;
    m_ilog_path = Singleton_IConfig->m_strLogPath + "/" + str_file_path + "_";

    string str_dir_path = "mkdir -p " + Singleton_IConfig->m_strLogPath + "/";

    int isCreate = system(str_dir_path.c_str());if(isCreate != 0){return false;}

    m_ilog_level = log_level;m_thread_status = true;
    if(pthread_create(&m_pthread_id,NULL,ilog_run,this)){return false;}

    ilog_start_show();
    return true;
}

bool CIlog_method::ilog_stop()
{
    if(!m_thread_status){return false;}m_thread_status = false;
    pthread_join(m_pthread_id, NULL);
    return true;
}

bool CIlog_method::ilog_message(int log_type,const char *p_file,unsigned int log_line,const char* p_format, ...)
{
    if(!m_thread_status || log_type < m_ilog_level){return false;}
    char szTmp[1024] = {0};va_list	vaParam;va_start(vaParam,p_format);
	vsnprintf(szTmp,sizeof(szTmp),p_format,vaParam);va_end(vaParam);

    ilog_buff ilog;ilog.type = log_type;ilog.line = log_line;
    snprintf(ilog.file,sizeof(ilog.file),p_file);
    snprintf(ilog.ilog,sizeof(ilog.ilog),szTmp);

    ilog_queue.push(ilog);
    return true;
}


void* CIlog_method::ilog_run(void* pParam)
{
    CIlog_method *ilog = (CIlog_method *)pParam;
    while(ilog->m_thread_status)
    {
        if(ilog->ilog_show())
        {usleep(50);}else{sleep(1);}
    }
    return NULL;
}


bool CIlog_method::ilog_show()
{
    ilog_buff ilog;if(!ilog_queue.pop(ilog)){return false;}

    char temp_buff[1024] = {0};
    switch(ilog.type)
    {
        case LOG_DEBUG:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [DEBUG] %s",ilog_current_time().c_str(),ilog.ilog);
            printf("%s\n",temp_buff);ilog_save(temp_buff);break;
        }
        case LOG_INFO:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [INFO] %s",ilog_current_time().c_str(),ilog.ilog);
            printf("%s\n",temp_buff);ilog_save(temp_buff);break;
        }
        case LOG_WARNING:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [WARN] %s[%s:%2u]",ilog_current_time().c_str(),ilog.ilog,ilog.file,ilog.line);
            printf(BROWN "%s\n" NONE,temp_buff);ilog_save(temp_buff);break;
        }
        case LOG_ERROR:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [ERROR] %s[%s:%2u]",ilog_current_time().c_str(),ilog.ilog,ilog.file,ilog.line);
            printf(L_RED "%s\n" NONE,temp_buff);ilog_save(temp_buff);break;
        }
        case LOG_START:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [START] %s",ilog_current_time().c_str(),ilog.ilog);
            printf(L_PURPLE "%s\n" NONE,temp_buff);ilog_save(temp_buff);break;
        }
        default:
            break;
    }
    return true;
}



bool CIlog_method::ilog_printf(int log_type,const char *p_log)
{
    char temp_buff[1024] = {0};
    switch(log_type)
    {
        case LOG_DEBUG:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [DEBUG] %s",ilog_current_time().c_str(),p_log);
            printf("%s\n",temp_buff);break;
        }
        case LOG_INFO:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [INFO] %s",ilog_current_time().c_str(),p_log);
            printf("%s\n",temp_buff);break;
        }
        case LOG_WARNING:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [WARN] %s",ilog_current_time().c_str(),p_log);
            printf(BROWN "%s\n" NONE,temp_buff);break;
        }
        case LOG_ERROR:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [ERROR] %s",ilog_current_time().c_str(),p_log);
            printf(L_RED "%s\n" NONE,temp_buff);break;
        }
        case LOG_START:
        {
            snprintf(temp_buff,sizeof(temp_buff),"%s [START] %s",ilog_current_time().c_str(),p_log);
            printf(L_PURPLE "%s\n" NONE,temp_buff);ilog_save(temp_buff);break;
        }
        default:
            break;
    }
    return true;
}


bool CIlog_method::ilog_start_show()
{
    printf("********************************************************************************\n");
    printf("**                                                                            **\n");
    printf("**                    欢迎使用思迪视频平台媒体服务器(V1.0)                    **\n");
    printf("**                                                                            **\n");
    printf("********************************************************************************\n");

    return true;

    char temp_buf[1024] = {0};char time_buff[1024] = {0};
    struct winsize size;ioctl(STDIN_FILENO,TIOCGWINSZ,&size); //宽 size.ws_col 高：size.ws_row
    string str_welcome = "WelCome To Thinkive TChatMediaServer";
    string str_version = "TChatMediaServer Version : " + Singleton_IConfig->m_server_version;
    string str_compiletime = "";

    sprintf(time_buff,"TChatMediaServer Compile Time : %s %s",__DATE__,__TIME__);
    str_compiletime = time_buff;

    int tsize = size.ws_col - 20;if(tsize <= 0 || tsize > 130){tsize = 60;}
    for(int i = 0;i < tsize;i++){sprintf(temp_buf+i,"*");}
    ILOG_PRINTF(LOG_START,temp_buf);

    memset(temp_buf,0,sizeof(temp_buf));
    for(int i = 0;i < tsize;i++)
    {
        int j = (tsize - str_welcome.size())/2;
        if(i < j){if(i == 0){sprintf(temp_buf+i,"*");}else{sprintf(temp_buf+i,"-");}}
        else if(i > j){
        if(i == tsize-1){sprintf(temp_buf+i,"*");}else{sprintf(temp_buf+i,"-");}}
        else{
        sprintf(temp_buf+i,"%s",str_welcome.c_str());i+=str_welcome.size();sprintf(temp_buf+i,"%s","-");}
    }ILOG_PRINTF(LOG_START,temp_buf);

    memset(temp_buf,0,sizeof(temp_buf));
    for(int i = 0;i < tsize;i++)
    {
        int j = (tsize - str_welcome.size())/4;
        if(i < j){if(i == 0){sprintf(temp_buf+i,"*");}else{sprintf(temp_buf+i,"-");}}
        else if(i > j){
        if(i == tsize-1){sprintf(temp_buf+i,"*");}else{sprintf(temp_buf+i,"-");}}
        else{
        sprintf(temp_buf+i,"%s",str_version.c_str());i+=str_version.size();sprintf(temp_buf+i,"%s","-");}
    }ILOG_PRINTF(LOG_START,temp_buf);

    memset(temp_buf,0,sizeof(temp_buf));
    for(int i = 0;i < tsize;i++)
    {
        int j = (tsize - str_welcome.size())/4;
        if(i < j){if(i == 0){sprintf(temp_buf+i,"*");}else{sprintf(temp_buf+i,"-");}}
        else if(i > j){
        if(i == tsize-1){sprintf(temp_buf+i,"*");}else{sprintf(temp_buf+i,"-");}}
        else{
        sprintf(temp_buf+i,"%s",str_compiletime.c_str());i+=str_compiletime.size();sprintf(temp_buf+i,"%s","-");}
    }ILOG_PRINTF(LOG_START,temp_buf);

    memset(temp_buf,0,sizeof(temp_buf));
    for(int i = 0;i < tsize;i++){sprintf(temp_buf+i,"*");}
    ILOG_PRINTF(LOG_START,temp_buf);

    return true;
}

bool CIlog_method::ilog_save(string ilog)
{
    ofstream m_out_file;string str_file_path = "";

    str_file_path = m_ilog_path + ilog_current_date() + ".log";
    m_out_file.open(str_file_path.c_str(),ios::out|ios::app);
    if(!m_out_file.is_open()){return false;}

    m_out_file<<ilog<<endl;m_out_file.close();
    return true;
}


string CIlog_method::ilog_current_time()
{
    char szCurTime[9] = {0};
    time_t rawtime;struct tm * timeinfo;

    time (&rawtime);timeinfo = localtime(&rawtime );
    sprintf(szCurTime,"%02d:%02d:%02d",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);

    return szCurTime;
}


string CIlog_method::ilog_current_date()
{
    char szCurTime[16] = {0};
    time_t rawtime;struct tm * timeinfo;

    time (&rawtime);timeinfo = localtime(&rawtime);
    sprintf(szCurTime,"%04d%02d%02d",timeinfo->tm_year+1900,timeinfo->tm_mon+1,timeinfo-> tm_mday);

    return szCurTime;
}
