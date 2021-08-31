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
	[NET_A_FLAGS] = { .type = NLA_S32 },
};

LIST_HEAD(policys);
DEFINE_RWLOCK(policys_lock);

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

	write_lock(&policys_lock);
	list_for_each_entry_safe (pos, n, &policys, list) {
		if (new->priority > pos->priority)
			continue;
		break;
	}
	list_add_tail(&new->list, &pos->list);
	write_unlock(&policys_lock);
	return 0;
}

int net_policy_delete(policy_id_t id)
{
	struct net_policy_t *pos, *n;
	write_lock(&policys_lock);
	list_for_each_entry_safe (pos, n, &policys, list) {
		if (pos->id != id)
			continue;
		list_del(&pos->list);
		net_policy_free(pos);
	}
	write_unlock(&policys_lock);
	return 0;
}

static int net_policy_clear(void)
{
	struct net_policy_t *pos, *n;
	write_lock(&policys_lock);
	list_for_each_entry_safe (pos, n, &policys, list) {
		list_del(&pos->list);
		net_policy_free(pos);
	}
	write_unlock(&policys_lock);
	return 0;
}

static int net_policy_protocol_hit(const struct hknf_buff *buff,
				   const struct net_policy_t *policy)
{
	struct iphdr *iph;
	iph = ip_hdr(buff->skb);
	if (iph->protocol < policy->protocol.begin)
		return NET_POLICY_MISS;
	if (iph->protocol > policy->protocol.end)
		return NET_POLICY_MISS;
	return NET_POLICY_HIT;
}

static int net_policy_addr_hit(const struct hknf_buff *buff,
			       const struct net_policy_t *policy)
{
	struct iphdr *iph;
	addr_t src, dst;

	iph = ip_hdr(buff->skb);
	src = ntohl(iph->saddr);
	dst = ntohl(iph->daddr);

	if (src < policy->addr.src.begin)
		return NET_POLICY_MISS;
	if (src > policy->addr.src.end)
		return NET_POLICY_MISS;
	if (dst < policy->addr.dst.begin)
		return NET_POLICY_MISS;
	if (dst > policy->addr.dst.end)
		return NET_POLICY_MISS;
	return NET_POLICY_HIT;
}

static int net_policy_tcp_port_hit(const struct hknf_buff *buff,
				   const struct net_policy_t *policy)
{
	struct tcphdr *tcph;
	port_t src, dst;

	tcph = tcp_hdr(buff->skb);
	src = ntohs(tcph->source);
	dst = ntohs(tcph->dest);

	if (src < policy->port.src.begin)
		return NET_POLICY_MISS;
	if (src > policy->port.src.end)
		return NET_POLICY_MISS;
	if (dst < policy->port.dst.begin)
		return NET_POLICY_MISS;
	if (dst > policy->port.dst.end)
		return NET_POLICY_MISS;
	return NET_POLICY_HIT;
}

static int net_policy_udp_port_hit(const struct hknf_buff *buff,
				   const struct net_policy_t *policy)
{
	struct udphdr *udph;
	port_t src, dst;

	udph = udp_hdr(buff->skb);
	src = ntohs(udph->source);
	dst = ntohs(udph->dest);

	if (src < policy->port.src.begin)
		return NET_POLICY_MISS;
	if (src > policy->port.src.end)
		return NET_POLICY_MISS;
	if (dst < policy->port.dst.begin)
		return NET_POLICY_MISS;
	if (dst > policy->port.dst.end)
		return NET_POLICY_MISS;
	return NET_POLICY_HIT;
}

static int net_policy_port_hit(const struct hknf_buff *buff,
			       const struct net_policy_t *policy)
{
	struct iphdr *iph;

	iph = ip_hdr(buff->skb);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (!net_policy_tcp_port_hit(buff, policy))
			goto miss;
		break;
	case IPPROTO_UDP:
		if (!net_policy_udp_port_hit(buff, policy))
			goto miss;
		break;
	default:
		// 不支持的协议认为端口号命中
		break;
	}
	return NET_POLICY_HIT;
miss:
	return NET_POLICY_MISS;
}
static int net_policy_bound_hit(const struct hknf_buff *buff,
				const struct net_policy_t *policy)
{
	switch (buff->state->hook) {
	case NF_INET_LOCAL_IN:
		return HKNP_INBOUND(policy->flags);
	case NF_INET_LOCAL_OUT:
		return HKNP_OUTBOUND(policy->flags);
	}
	return NET_POLICY_MISS;
}

static int net_policy_hit(const struct hknf_buff *buff,
			  const struct net_policy_t *policy,
			  response_t *response)
{
	if (!net_policy_bound_hit(buff, policy))
		goto miss;
	if (!net_policy_protocol_hit(buff, policy))
		goto miss;
	if (!net_policy_addr_hit(buff, policy))
		goto miss;
	if (!net_policy_port_hit(buff, policy))
		goto miss;

	*response = policy->response;
	return NET_POLICY_HIT;
miss:
	return NET_POLICY_MISS;
}

// TODO:
// 这个地方可能需要上报日志,只有这里能区分
static response_t net_policy_hook(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	response_t response = NF_ACCEPT;
	struct net_policy_t *policy = NULL;
	struct hknf_buff buff = { .skb = skb, .state = state };

	read_lock(&policys_lock);
	list_for_each_entry (policy, &policys, list) {
		/** 
		 * 只有策略命中的时候,才会修改response的值,如果没有策略命中,
		 * response将保留默认值 NF_ACCEPT,此时会被放行
		 */
		if (net_policy_hit(&buff, policy, &response))
			break;
	}
	read_unlock(&policys_lock);

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

static bool hooked = false;
static DEFINE_RWLOCK(nf_lock);
int enable_net_protect(void)
{
	write_lock(&nf_lock);
	if (!hooked) {
		if (!nf_register_net_hooks(&init_net, net_policy_ops,
					   ARRAY_SIZE(net_policy_ops)))
			hooked = true;
	}
	write_unlock(&nf_lock);
	return 0;
}

int disable_net_protect(void)
{
	write_lock(&nf_lock);
	if (hooked) {
		net_policy_clear();
		nf_unregister_net_hooks(&init_net, net_policy_ops,
					ARRAY_SIZE(net_policy_ops));
		hooked = false;
	}
	write_unlock(&nf_lock);
	return 0;
}

int net_protect_init(void)
{
	return 0;
}

int net_protect_destory(void)
{
	return disable_net_protect();
}
