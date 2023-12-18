#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "myfw.h"

static struct nf_hook_ops nfhoLocalIn;		//设置NF_INET_LOCAL_IN的hook点函数
static struct nf_hook_ops nfhoLocalOut;		//设置NF_INET_LOCAL_OUT的hook点函数
static struct nf_hook_ops nfhoPreRouting;	//设置NF_INET_PRE_ROUTING的hook点函数
static struct nf_hook_ops nfhoForward;		//设置NF_INET_FORWARD的hook点函数
static struct nf_hook_ops nfhoPostRouting;	//设置NF_INET_POST_ROUTING的hook点函数

static struct nf_sockopt_ops nfhoSockopt;	//设置 Socket Option 的属性

static int debug_level = 0;
static int nfcount = 0;

static Rule* g_rules;			//规则数组的头地址
static int g_rules_cnt = 0;		//记录当前定义的规则数

void addRule(Rule* rule) {
	int cnt = g_rules_cnt + 1;	//记录添加一条规则后的规则总数
	Rule* rules_t = (Rule*)vmalloc(cnt * sizeof(Rule));	//开辟一个必规则数量大 1 的空间, 使之能够添加一条规则
	memcpy(rules_t, rule, sizeof(Rule));	//将新的规则先添加到开辟的空间中
	if (g_rules_cnt > 0) {
		memcpy(rules_t + 1, g_rules, g_rules_cnt * sizeof(Rule));	//再将原先的规则也添加的新开辟的空间中
		vfree(g_rules);		//释放原先的规则空间
	}
	g_rules = rules_t;	//令规则数组的首地址为新开辟的空间
	g_rules_cnt = cnt;	//更新规则数
}

void delRule(int rule_num) {
	int i;
	//判断规则序号是否存在
	if (rule_num > 0 && rule_num < g_rules_cnt) {
		//存在则将该序号及其以后的规则用下一条规则的内容覆盖
		for (i = rule_num; i < g_rules_cnt; i++) {
			memcpy(g_rules + i - 1, g_rules + i, sizeof(Rule));
		}
		g_rules_cnt++;	//规则数减 1
	}
}

int matchRule_IP_PROTOCOL(struct iphdr* iph) {
	int action = 1;
	int i;
	Rule* r;
	//对规则进行逐一检查, 若存在相应的规则则返回相应的动作
	for (i = 0; i < g_rules_cnt; i++) {
		r = g_rules + i;
		//若规则中未定义源IP和目的IP, 则默认规则值为0
		if ((!r->src_ip || r->src_ip == iph->saddr) &&
			(!r->dst_ip || r->dst_ip == iph->daddr) &&
			(!r->protocol || r->protocol == iph->protocol))
		{
			action = r->action;
			break;
		}
	}
	return action;
}

int matchRule_IP_PORT_PROTOCOL(struct iphdr* iph) {
	int action = 1;
	int i;
	Rule* r;
	for (i = 0; i < g_rules_cnt; i++) {
		r = g_rules + i;
		//判断是否符合源、目的地址IP地址
		if ((!r->src_ip || r->src_ip == iph->saddr) &&
			(!r->dst_ip || r->dst_ip == iph->daddr)) {
			if (!r->protocol) {
				action = r->action;
			}
			else {
				//ICMP协议不需要过滤端口
				if (r->protocol == SPFW_ICMP) {
					action = r->action;
					break;
				}
				//对TCP协议的端口过滤
				else if (r->protocol == SPFW_TCP) {
					struct tcphdr* tcph = (struct tcphdr*)((unsigned char*)iph + iph->ihl * 4);	// 获取TCP头
					if ((!r->src_port || r->src_port == ntohs(tcph->source)) &&
						(!r->dst_port || r->dst_port == ntohs(tcph->dest))) {
						action = r->action;
					}
					break;
				}
				//对UDP协议的端口过滤
				else if (r->protocol == SPFW_UDP) {
					struct udphdr* udph = (struct udphdr*)((unsigned char*)iph + iph->ihl * 4);	// 获取UDP头
					if ((!r->src_port || r->src_port == ntohs(udph->source)) &&
						(!r->dst_port || r->dst_port == ntohs(udph->dest))) {
						action = r->action;
					}
					break;
				}
				//若规则的协议未非TCP、UDP、ICMP其中之一, 则丢弃该数据包
				else {
					action = 0;
					break;
				}
			}
		}
	}
	return action;
}

int whiteListFilterRule(struct iphdr* iph) {
	int action = 0;
	int i;
	Rule* r;
	//匹配所有规则, 若存在规则允许数据包通过则允许该数据包通过, 否则丢弃该数据包
	for (i = 0; i < g_rules_cnt; i++) {
		r = g_rules + i;
		//判断是否符合源、目的地址IP地址
		if ((!r->src_ip || r->src_ip == iph->saddr) &&
			(!r->dst_ip || r->dst_ip == iph->daddr)) {
			if (!r->protocol) {
				action = r->action;
			}
			else {
				//ICMP协议不需要过滤端口
				if (r->protocol == SPFW_ICMP) {
					action = r->action;
				}
				//对TCP协议的端口过滤
				else if (r->protocol == SPFW_TCP) {
					struct tcphdr* tcph = (struct tcphdr*)((unsigned char*)iph + iph->ihl * 4);	// 获取TCP头
					if ((!r->src_port || r->src_port == ntohs(tcph->source)) &&
						(!r->dst_port || r->dst_port == ntohs(tcph->dest))) {
						action = r->action;
					}
				}
				//对UDP协议的端口过滤
				else if (r->protocol == SPFW_UDP) {
					struct udphdr* udph = (struct udphdr*)((unsigned char*)iph + iph->ihl * 4);	// 获取UDP头
					if ((!r->src_port || r->src_port == ntohs(udph->source)) &&
						(!r->dst_port || r->dst_port == ntohs(udph->dest))) {
						action = r->action;
					}
				}
			}
		}
		if (action == 1)
			break;
	}
	return action;
}

void setDebug_Level(int level) {
	debug_level = level;
}

void debugInfo(char* msg)
{
	if (debug_level)
	{
		nfcount++;
		printk("%s, nfcount: %d\n", msg, nfcount);
	}
}


unsigned int hookLocalIn(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	unsigned int ret = NF_ACCEPT;
	//将数据包结构体skb转换成struct iphdr
	struct iphdr* iph = ip_hdr(skb);
	//与规则逐一匹配, 判断规则是否拦截该数据包, 默认数据包不被拦截
	//黑名单过滤方式
	if (matchRule_IP_PORT_PROTOCOL(iph) <= 0) {
		printk("NF_INET_LOCAL_IN过滤了数据包");
		ret = NF_DROP;
	}
	debugInfo("hookLocalIn");
	return ret;
}

unsigned int hookLocalOut(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	unsigned int ret = NF_DROP;
	//将数据包结构体skb转换成struct iphdr
	struct iphdr* iph = ip_hdr(skb);
	//与规则逐一匹配, 判断规则是否拦截该数据包, 默认数据包不被拦截
	//白名单过滤方式
	if (whiteListFilterRule(iph) >= 1) {
		printk("NF_INET_LOCAL_OUT允许通过了数据包");
		ret = NF_ACCEPT;
	}
	debugInfo("hookLocalOut");
	return ret;
}

unsigned int hookPreRouting(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	unsigned int ret = NF_ACCEPT;
	struct iphdr* iph = ip_hdr(skb);
	//判断IP数据包是否为IPv4版本数据包, 不是则丢弃
	if (iph->version != 4) {
		printk("NF_INET_PRE_ROUTING过滤了数据包");
		ret = NF_DROP;
	}
	//校验 IPv4 数据报头的正确性, 不正确则丢弃
	if (iph->check) {
		if (ip_fast_csum((unsigned char*)iph, iph->ihl)) {
			ret = NF_DROP;
		}
	}
	debugInfo("hookPreRouting");
	return ret;
}

unsigned int hookForward(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	unsigned int ret = NF_ACCEPT;
	//将数据包结构体skb转换成struct iphdr
	struct iphdr* iph = ip_hdr(skb);
	//与规则逐一匹配, 判断规则是否拦截该数据包, 默认数据包不被拦截
	//黑名单过滤方式
	if (matchRule_IP_PROTOCOL(iph) <= 0) {
		printk("NF_INET_FORWARD过滤了数据包");
		ret = NF_DROP;
	}
	debugInfo("hookForwoad");
	return ret;
}

unsigned int hookPostRouting(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	debugInfo("hookPostRouting");
	return NF_ACCEPT;
}

int hookSockoptSet(struct sock* sock,
	int cmd,
	void __user* user,
	unsigned int len)
{
	int ret = 0;
	int level;
	Rule r;
	int r_num;

	debugInfo("hookSockoptSet");
	//根据 cmd 的不同，接受不同大小的数据，并执行相应的操作
	switch (cmd) {
	case CMD_DEBUG:
		//从用户空间中拷贝接收用户设置的用户等级，即一个整形int数据
		ret = copy_from_user(&level, user, sizeof(debug_level));
		setDebug_Level(level);	//执行debug等级修改函数
		printk("set debug level to %d", debug_level);
		break;
	case CMD_RULE:
		//从用户空间中拷贝接收用户设置的规则Rule内容
		ret = copy_from_user(&r, user, sizeof(Rule));
		addRule(&r);	//执行添加规则函数
		printk("add rule!");
		break;
	case CMD_RULE_DEL:
		//从用户空间中拷贝接收用户所需要删除的规则序号，一个整形int数据
		ret = copy_from_user(&r_num, user, sizeof(r_num));
		delRule(r_num);	//执行删除规则函数
		printk("del rule");
		break;
	}

	if (ret != 0) {
		printk("copy_from_user error!");
		ret = -EINVAL;
	}
	return ret;
}

int hookSockoptGet(struct sock* sock,
	int cmd,
	void __user* user,
	int* len)
{
	int ret;

	debugInfo("hookSockoptGet");
	//根据用户的命令，向用户空间发送相应的数据
	switch (cmd) {
	case CMD_DEBUG:
		//向用户空间发送debug_level
		ret = copy_to_user(user, &debug_level, sizeof(debug_level));
		break;
	case CMD_RULE:
		//向用户空间发送规则条数
		ret = copy_to_user(user, &g_rules_cnt, sizeof(g_rules_cnt));
		//向用户空间发送规则数组（注意：由于规则条数发送过一次数据，所以再次发送数据需要添加已发送的数据偏移）
		ret = copy_to_user(user + sizeof(g_rules_cnt), g_rules, g_rules_cnt * sizeof(Rule));
		break;
	}

	if (ret != 0) {
		ret = -EINVAL;
		debugInfo("copy_to_user error");
	}

	return ret;
}

int init_module() {
	//将 hookLocalIn 函数注册到 NF_INET_LOCAL_IN 的 hook 钩子点
	nfhoLocalIn.hook = hookLocalIn;
	nfhoLocalIn.hooknum = NF_INET_LOCAL_IN;
	nfhoLocalIn.pf = PF_INET;
	nfhoLocalIn.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalIn);
	//将 hookLocalOut 函数注册到 NF_INET_LOCAL_OUT 的 hook 钩子点
	nfhoLocalOut.hook = hookLocalOut;
	nfhoLocalOut.hooknum = NF_INET_LOCAL_OUT;
	nfhoLocalOut.pf = PF_INET;
	nfhoLocalOut.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalOut);
	//将 hookPreRouting 函数注册到 NF_INET_PRE_ROUTING 的 hook 钩子点
	nfhoPreRouting.hook = hookPreRouting;
	nfhoPreRouting.hooknum = NF_INET_PRE_ROUTING;
	nfhoPreRouting.pf = PF_INET;
	nfhoPreRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPreRouting);
	//将 hookForward 函数注册到 NF_INET_FORWARD 的 hook 钩子点
	nfhoForward.hook = hookForward;
	nfhoForward.hooknum = NF_INET_FORWARD;
	nfhoForward.pf = PF_INET;
	nfhoForward.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoForward);
	//将 hookPostRouting 函数注册到 NF_INET_POST_ROUTING 的 hook 钩子点
	nfhoPostRouting.hook = hookPostRouting;
	nfhoPostRouting.hooknum = NF_INET_POST_ROUTING;
	nfhoPostRouting.pf = PF_INET;
	nfhoPostRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPostRouting);

	//注册nfhoSockopt
	nfhoSockopt.pf = PF_INET;
	nfhoSockopt.set_optmin = CMD_MIN;
	nfhoSockopt.set_optmax = CMD_MAX;
	nfhoSockopt.set = hookSockoptSet;
	nfhoSockopt.get_optmin = CMD_MIN;
	nfhoSockopt.get_optmax = CMD_MAX;
	nfhoSockopt.get = hookSockoptGet;
	nf_register_sockopt(&nfhoSockopt);

	printk("simpleFw started!\n");
	return 0;
}

void cleanup_module() {
	nf_unregister_net_hook(&init_net, &nfhoLocalIn);
	nf_unregister_net_hook(&init_net, &nfhoLocalOut);
	nf_unregister_net_hook(&init_net, &nfhoPreRouting);
	nf_unregister_net_hook(&init_net, &nfhoForward);
	nf_unregister_net_hook(&init_net, &nfhoPostRouting);

	nf_unregister_sockopt(&nfhoSockopt);

	printk("simpleFw stopped!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("o_o'");
MODULE_DESCRIPTION("It's a simple software filter firewall!");
MODULE_VERSION("0.0.1");
