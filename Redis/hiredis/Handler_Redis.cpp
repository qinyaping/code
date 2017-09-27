/*
 * Handler_Redis.cpp
 *
 *  Created on: 2017Äê8ÔÂ2ÈÕ
 *      Author: thinkive
 */

#include "Handler_Redis.h"

Handler_Redis::Handler_Redis() {

}

Handler_Redis::~Handler_Redis() {

}

redisContext* Handler_Redis::GetRedisConnect() {
	redisContext* c = redisConnect("127.0.0.1", 6379);
	if (c->err) {
		redisFree(c);
		printf("Connect to redisServer faile\n");
		return;
	}
	return c;
}

redisReply* Handler_Redis::ExeRedisCommand(
		const std::string& sql) {

	redisContext* c = redisConnect("127.0.0.1", 6379);
	if (c->err) {
		redisFree(c);
		printf("Connect to redisServer faile\n");
		return;
	}

	redisReply* r = (redisReply*) redisCommand(c, command1);
	if (NULL == r) {
		printf("Execut command1 failure\n");
		redisFree( c);
		return;
	}
	redisFree(c);
	return r;
}
