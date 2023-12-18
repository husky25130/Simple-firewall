#define CMD_MIN		0X6000

#define CMD_DEBUG		CMD_MIN+1
#define CMD_RULE		CMD_MIN+2
#define CMD_RULE_DEL	CMD_MIN+3

#define CMD_MAX		0X6100

#define SPFW_ICMP	1	//IPPROTO_ICMP
#define SPFW_TCP	2	//IPPROTO_TCP
#define SPFW_UDP	3	//TPPROTO_UDP


typedef struct{
    unsigned int src_ip;	//源IP地址
    unsigned int dst_ip;	//目标IP地址
    unsigned short src_port;	//源端口
    unsigned short dst_port;	//目的端口
    unsigned int protocol;		//使用的协议号
    int action;		//动作是否允许
} Rule;

typedef struct{
    unsigned int count;
    Rule rule;
}RuleTable;
