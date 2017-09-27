#! /bin/sh
cs_server_name="TChatCenterServer"
vs_server_name="TChatMediaServer"

cs_pid=0
vs_pid=0

cs_proc_id()		#进程ID
{
	cs_pid=`ps -ef | grep $cs_server_name | grep -v grep | awk '{print $2}'`
}

cs_proc_num()		# 计算进程数  
{  
	num=`ps -ef | grep $cs_server_name | grep -v grep | wc -l`  
	return $num 
} 


vs_proc_id()		# 获取进程id 
{
	vs_pid=`ps -ef | grep $vs_server_name | grep -v grep | awk '{print $2}'`
}


vs_proc_num()		# 计算进程数  
{  
	num=`ps -ef | grep $vs_server_name | grep -v grep | wc -l`  
	return $num 
} 


cs_proc_num
number=$?
if [ $number != 0 ]
then
	cs_proc_id
	kill $cs_pid
	echo Close $cs_server_name:${cs_pid}, Time:`date`
fi


vs_proc_num
number=$?
if [ $number != 0 ]
then
	vs_proc_id
	kill $vs_pid
	echo Close $vs_server_name:${vs_pid}, Time:`date`
fi

