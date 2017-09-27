/*
 * Handler_Redis.h
 *
 *  Created on: 2017Äê8ÔÂ2ÈÕ
 *      Author: thinkive
 */

#ifndef HANDLER_REDIS_H_
#define HANDLER_REDIS_H_

#include <string>
#include <hiredis/hiredis.h>

class Handler_Redis{
public:
	Handler_Redis();
	virtual ~Handler_Redis();

	redisContext* GetRedisConnect();
	redisReply* ExeRedisCommand(redisContext* context, const std::string& sql);


protected:
	void Init();
};


#endif /* HANDLER_REDIS_H_ */
