#include "net.h"
#include "netlink.h"
#include "util.h"
#include <linux/bitmap.h>
#include <linux/gfp.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// TODO:
// 实现调整这个链表的一系列方法
LIST_HEAD(policys);
DEFINE_RWLOCK(lock);

// TODO:
// 策略数据结构内存的分配释放
static struct net_policy_t *net_policy_alloc(void)
{
	struct net_policy_t *policy;
	return policy;
}

static void net_policy_free(struct net_policy_t *policy)
{
}

static int net_policy_protocol_hit(const struct sk_buff *skb,
				   const struct net_policy_t *policy)
{
	struct iphdr *iph;
	iph = ip_hdr(skb);
	if (iph->protocol < policy->protocol.begin)
		return 0;
	if (iph->protocol >= policy->protocol.end)
		return 0;
	return 1;
}

static int net_policy_addr_hit(const struct sk_buff *skb,
			       const struct net_policy_t *policy)
{
	struct iphdr *iph;
	iph = ip_hdr(skb);
	if (iph->saddr < policy->addr.source.begin)
		return 0;
	if (iph->saddr >= policy->addr.source.end)
		return 0;
	if (iph->daddr < policy->addr.dest.begin)
		return 0;
	if (iph->daddr >= policy->addr.dest.end)
		return 0;
	return 1;
}

static int net_policy_tcp_port_hit(const struct sk_buff *skb,
				   const struct net_policy_t *policy)
{
	struct tcphdr *tcph;
	tcph = tcp_hdr(skb);

	if (tcph->source < policy->port.source.begin)
		return 0;
	if (tcph->source >= policy->port.source.end)
		return 0;
	if (tcph->dest < policy->port.dest.begin)
		return 0;
	if (tcph->dest >= policy->port.dest.end)
		return 0;
	return 1;
}

static int net_policy_udp_port_hit(const struct sk_buff *skb,
				   const struct net_policy_t *policy)
{
	struct udphdr *udph;
	udph = udp_hdr(skb);

	if (udph->source < policy->port.source.begin)
		return 0;
	if (udph->source >= policy->port.source.end)
		return 0;
	if (udph->dest < policy->port.dest.begin)
		return 0;
	if (udph->dest >= policy->port.dest.end)
		return 0;
	return 1;
}

static int net_policy_port_hit(const struct sk_buff *skb,
			       const struct net_policy_t *policy)
{
	struct iphdr *iph;

	iph = ip_hdr(skb);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (!net_policy_tcp_port_hit(skb, policy))
			goto miss;
		break;
	case IPPROTO_UDP:
		if (!net_policy_udp_port_hit(skb, policy))
			goto miss;
		break;
	default:
		// 不支持的协议认为端口号命中
		break;
	}
	return 1; //hit
miss:
	return 0; //miss
}

static int net_policy_hit(const struct sk_buff *skb,
			  const struct net_policy_t *policy,
			  response_t *response)
{
	if (!policy->enabled)
		goto miss;
	if (!net_policy_protocol_hit(skb, policy))
		goto miss;
	if (!net_policy_addr_hit(skb, policy))
		goto miss;
	if (!net_policy_port_hit(skb, policy))
		goto miss;

	*response = policy->response;
	return 1; //hit
miss:
	return 0; //miss
}

// TODO:
// 这个地方可能需要上报日志,只有这里能区分
static unsigned int net_policy_hook(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	response_t response = NF_ACCEPT;
	struct net_policy_t *policy = NULL;

	read_lock(&lock);
	list_for_each_entry (policy, &policys, list) {
		if (net_policy_hit(skb, policy, &response))
			break;
	}
	read_unlock(&lock);

	return response;
}

static const struct nf_hook_ops net_policy_ops[] = {
	{
		.hook = net_policy_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = net_policy_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST,
	},
};

static int enable_net_protect(void)
{
	nf_register_net_hooks(&init_net, net_policy_ops,
			      ARRAY_SIZE(net_policy_ops));
	return 0;
}

static int disable_net_protect(void)
{
	return 0;
}

void exit_net_protect(void)
{
	disable_net_protect();
}

int net_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}