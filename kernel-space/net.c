#include "net.h"
#include "comlayer.h"
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

struct nla_policy net_policy[NET_A_MAX + 1] = {
	[NET_A_STATUS_CODE] = { .type = NLA_S32 },
	[NET_A_OP_TYPE] = { .type = NLA_U8 },
	[NET_A_ID] = { .type = NLA_S32 },
	[NET_A_PRIORITY] = { .type = NLA_S8 },

	[NET_A_ADDR_SRC_BEGIN] = { .type = NLA_U32 },
	[NET_A_ADDR_SRC_END] = { .type = NLA_U32 },
	[NET_A_ADDR_DST_BEGIN] = { .type = NLA_U32 },
	[NET_A_ADDR_DST_END] = { .type = NLA_U32 },

	[NET_A_PORT_SRC_BEGIN] = { .type = NLA_U16 },
	[NET_A_PORT_SRC_END] = { .type = NLA_U16 },
	[NET_A_PORT_DST_BEGIN] = { .type = NLA_U16 },
	[NET_A_PORT_DST_END] = { .type = NLA_U16 },

	[NET_A_PROTOCOL_BEGIN] = { .type = NLA_U8 },
	[NET_A_PROTOCOL_END] = { .type = NLA_U8 },

	[NET_A_RESPONSE] = { .type = NLA_U32 },
	[NET_A_ENABLED] = { .type = NLA_S32 },
};

LIST_HEAD(policys);
DEFINE_RWLOCK(lock);

static struct net_policy_t *net_policy_alloc(void)
{
	struct net_policy_t *policy;
	policy = kmalloc(sizeof(struct net_policy_t), GFP_KERNEL);
	return policy;
}

static void net_policy_free(struct net_policy_t *policy)
{
	kfree(policy);
}

int net_policy_insert(struct net_policy_t *policy)
{
	struct net_policy_t *new;
	struct net_policy_t *pos, *n;
	if (!policy)
		return -EINVAL;

	new = net_policy_alloc();
	if (!new)
		return -ENOMEM;

	memcpy(new, policy, sizeof(struct net_policy_t));

	write_lock(&lock);
	list_for_each_entry_safe (pos, n, &policys, list) {
		if (new->priority > pos->priority)
			continue;
		break;
	}
	list_add_tail(&new->list, &pos->list);
	write_unlock(&lock);
	return 0;
}

int net_policy_delete(policy_id_t id)
{
	struct net_policy_t *pos, *n;
	write_lock(&lock);
	list_for_each_entry_safe (pos, n, &policys, list) {
		if (pos->id != id)
			continue;
		list_del(&pos->list);
		net_policy_free(pos);
	}
	write_unlock(&lock);
	return 0;
}

static int net_policy_clear(void)
{
	struct net_policy_t *pos, *n;
	write_lock(&lock);
	list_for_each_entry_safe (pos, n, &policys, list) {
		list_del(&pos->list);
		net_policy_free(pos);
	}
	write_unlock(&lock);
	return 0;
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
	if (iph->saddr < policy->addr.src.begin)
		return 0;
	if (iph->saddr >= policy->addr.src.end)
		return 0;
	if (iph->daddr < policy->addr.dst.begin)
		return 0;
	if (iph->daddr >= policy->addr.dst.end)
		return 0;
	return 1;
}

static int net_policy_tcp_port_hit(const struct sk_buff *skb,
				   const struct net_policy_t *policy)
{
	struct tcphdr *tcph;
	tcph = tcp_hdr(skb);

	if (tcph->source < policy->port.src.begin)
		return 0;
	if (tcph->source >= policy->port.src.end)
		return 0;
	if (tcph->dest < policy->port.dst.begin)
		return 0;
	if (tcph->dest >= policy->port.dst.end)
		return 0;
	return 1;
}

static int net_policy_udp_port_hit(const struct sk_buff *skb,
				   const struct net_policy_t *policy)
{
	struct udphdr *udph;
	udph = udp_hdr(skb);

	if (udph->source < policy->port.src.begin)
		return 0;
	if (udph->source >= policy->port.src.end)
		return 0;
	if (udph->dest < policy->port.dst.begin)
		return 0;
	if (udph->dest >= policy->port.dst.end)
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

int enable_net_protect(void)
{
	nf_register_net_hooks(&init_net, net_policy_ops,
			      ARRAY_SIZE(net_policy_ops));
	return 0;
}

int disable_net_protect(void)
{
	net_policy_clear();
	nf_unregister_net_hooks(&init_net, net_policy_ops,
				ARRAY_SIZE(net_policy_ops));
	return 0;
}
