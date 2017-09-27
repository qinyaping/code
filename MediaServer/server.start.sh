#! /bin/sh
cs_server_name="TChatCenterServer"                    # 进程名
vs_server_name="TChatMediaServer"                     # 进程名
cs_pid=0
vs_pid=0

cs_proc_id()                                              # 进程号  
{  
	cs_pid=`ps -ef | grep $cs_server_name | grep -v grep | awk '{print $2}'`  
} 

vs_proc_id()                                              # 进程号  
{  
	vs_pid=`ps -ef | grep $vs_server_name | grep -v grep | awk '{print $2}'`  
} 

cs_proc_num()                                            # 计算进程数  
{  
	cs_num=`ps -ef | grep $cs_server_name | grep -v grep | wc -l`  
	return $cs_num  
}  

vs_proc_num()                                            # 计算进程数  
{  
	vs_num=`ps -ef | grep $vs_server_name | grep -v grep | wc -l`  
	return $vs_num  
}

cs_proc_num
number=$?  
if [ $number -eq 0 ]     # 判断进程是否存在  
then
	nohup ./$cs_server_name >/dev/null 2>&1 &
	sleep 1
	cs_proc_id
	echo Start $cs_server_name-${cs_pid}, Time:`date`
fi


vs_proc_num
number=$?  
if [ $number -eq 0 ]     # 判断进程是否存在  
then
	nohup ./$vs_server_name >/dev/null 2>&1 &
	sleep 1
	vs_proc_id
	echo Start $vs_server_name-${vs_pid}, Time:`date`
fi


