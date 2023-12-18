#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#include "myfw.h"

void usage(char* program)
{
	printf("%s debug\n", program);
	printf("%s debug debug_level\n", program);
	printf("%s rule add src_ip src_port dst_ip dst_port protocol a|r\n", program);
	printf("%s rule del rule_number\n", program);
	printf("%s rule\n", program);
}

void printError(char* msg)
{
	printf("%s error %d: %s\n", msg, errno, strerror(errno));
}

void printSuccess(char* msg)
{
	printf("%s success\n", msg);
}

unsigned int str2Ip(char* ipstr)
{
	unsigned int ip;
	if (!strcmp(ipstr, "any"))
	{
		ip = 0;
	}
	else
	{
		inet_pton(AF_INET, ipstr, &ip);
	}
	return ip;
}

char* ip2Str(unsigned int ip, char buf[32])
{
	if (ip)
	{
		unsigned char* c = (unsigned char*)&ip;
		sprintf(buf, "%d.%d.%d.%d", *c, *(c + 1), *(c + 2), *(c + 3));
	}
	else
	{
		sprintf(buf, "any");
	}
	return buf;
}

unsigned short str2Port(char* portstr)
{
	unsigned short port;
	if (!strcmp(portstr, "any"))
	{
		port = 0;
	}
	else
	{
		port = atoi(portstr);
	}
	return port;
}

char* port2Str(unsigned short port, char buf[16])
{
	if (port)
	{
		sprintf(buf, "%d", port);
	}
	else
	{
		sprintf(buf, "any");
	}
	return buf;
}

char* protocol2Str(unsigned short protocol, char buf[16])
{
	switch (protocol)
	{
	case 0:
		strcpy(buf, "any");
		break;
	case SPFW_ICMP:
		strcpy(buf, "ICMP");
		break;
	case SPFW_TCP:
		strcpy(buf, "TCP");
		break;
	case SPFW_UDP:
		strcpy(buf, "UDP");
		break;
	default:
		strcpy(buf, "Unknown");
	}
	return buf;
}

unsigned short str2Protocol(char* protstr)
{
	unsigned short protocol = 0;

	if (!strcmp(protstr, "any"))
	{
		protocol = 0;
	}
	else if (!strcmp(protstr, "ICMP"))
	{
		protocol = SPFW_ICMP;
	}
	else if (!strcmp(protstr, "TCP"))
	{
		protocol = SPFW_TCP;
	}
	else if (!strcmp(protstr, "UDP"))
	{
		protocol = SPFW_UDP;
	}

	return protocol;
}

int parseArgs(int argc, char** argv, int* cmd, void* val, int* val_len) {
	int ret = 0;

	//若用户近输入了两个参数，则一定是查看命令
	if (argc == 2) {
		if (!strcmp(argv[1], "debug")) {
			*cmd = CMD_DEBUG;
			ret = -1;
		}
		else if (!strcmp(argv[1], "rule")) {
			*cmd = CMD_RULE;
			ret = -1;
		}
	}
	// 若用户输入的参数大于2，则应该是添加规则Rule、删除规则Rule、修改debug等级其中之一
	else if (argc > 2) {
		//若argc等于3且第2个参数为 debug，则应为修改debug等级
		if (!strcmp(argv[1], "debug") && argc == 3) {
			*cmd = CMD_DEBUG;
			*(int*)val = atoi(argv[2]);
			*val_len = sizeof(int);
			ret = 1;
		}
		// 判断是否是与规则的添加和删除有关的命令
		else if (!strcmp(argv[1], "rule")) {
			//若输入的参数数量为4，则只可能是规则删除指令
			if (argc == 4) {
				if (!strcmp(argv[2], "del")) {
					*cmd = CMD_RULE_DEL;
					*(int*)val = atoi(argv[3]);
					ret = 1;
				}
			}
			//若输入的参数数量为9，则只可能是添加规则Rule的指令
			else if (argc == 9) {
				if (!strcmp(argv[2], "add")) {
					*cmd = CMD_RULE;
					Rule* r = (Rule*)val;
					*val_len = sizeof(Rule);
					r->src_ip = str2Ip(argv[3]);
					r->src_port = str2Port(argv[4]);
					r->dst_ip = str2Ip(argv[5]);
					r->dst_port = str2Port(argv[6]);
					r->protocol = str2Protocol(argv[7]);
					r->action = strcmp(argv[8], "a") ? 0 : 1;
					ret = 1;
				}
			}
		}
	}
	return ret;
}

void printRuleTable(RuleTable* rtb)
{
	char src_ip[32], dst_ip[32], src_port[16], dst_port[16], protocol[16];
	Rule* r = &(rtb->rule);
	printf("Rules count: %d\n", rtb->count);
	for (int i = 0; i < rtb->count; i++)
	{
		ip2Str(r->src_ip, src_ip);
		ip2Str(r->dst_ip, dst_ip);
		port2Str(r->src_port, src_port);
		port2Str(r->dst_port, dst_port);
		protocol2Str(r->protocol, protocol);
		printf("%d\t%s:%s -> %s:%s, %s is %s\n", i + 1, src_ip, src_port, dst_ip, dst_port, protocol, r->action ? "allow" : "reject");
		r = r + 1;
	}
}

int set(int cmd, void* val, int val_len, int sockfd) {
	int ret = -1;

	if (setsockopt(sockfd, IPPROTO_IP, cmd, val, val_len))
	{
		printError("setsockopt()");
	}
	else
	{
		printf("setsockopt() success\n");
		ret = 0;
	}

	return ret;
}

int get(int cmd, int sockfd) {
	int ret = -1;
	int val_len = 1024 * 1024;
	void* val = malloc(val_len);
	if (getsockopt(sockfd, IPPROTO_IP, cmd, val, &val_len))
	{
		printError("getsockopt");
	}
	else
	{
		switch (cmd)
		{
		case CMD_DEBUG:
			printf("debug level=%d\n", *(int*)val);
			break;
		case CMD_RULE:
			printRuleTable((RuleTable*)val);
			break;
		}
	}
	return ret;
}

int main(int argc, char** argv) {
	int ret = -1;
	int cmd;				//记录用户输入的命令的值
	char val[sizeof(Rule)];	//存储用户输入相关数据	规则、debug等级或者规则索引
	int val_len = 0;		//记录相关数据长度
	int get_set = parseArgs(argc, argv, &cmd, &val, &val_len);
	if (get_set) {
		int sockfd;
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			printError("socket()");
		}
		else {
			// get_set > 0, 表示需要向内核中发送数据
			if (get_set > 0) {
				ret = set(cmd, val, val_len, sockfd);
			}
			else {
				ret = get(cmd, sockfd);
			}
		}
		close(sockfd);
	}
	else {
		usage(argv[0]);
	}
	return ret;
}
