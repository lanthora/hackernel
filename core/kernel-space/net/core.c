/* SPDX-License-Identifier: GPL-2.0-only */
#include "hackernel/log.h"
#include "hackernel/net.h"
#include "hackernel/netlink.h"
#include "hackernel/watchdog.h"
#include <linux/bitmap.h>
#include <linux/gfp.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

LIST_HEAD(policies);
DEFINE_RWLOCK(policies_lock);

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

	write_lock(&policies_lock);
	list_for_each_entry_safe (pos, n, &policies, list) {
		if (new->priority > pos->priority)
			continue;
		break;
	}
	list_add_tail(&new->list, &pos->list);
	write_unlock(&policies_lock);
	return 0;
}

int net_policy_delete(policy_id_t id)
{
	struct net_policy_t *pos, *n;
	write_lock(&policies_lock);
	list_for_each_entry_safe (pos, n, &policies, list) {
		if (pos->id != id)
			continue;
		list_del(&pos->list);
		net_policy_free(pos);
	}
	write_unlock(&policies_lock);
	return 0;
}

int net_policy_clear(void)
{
	struct net_policy_t *pos, *n;
	write_lock(&policies_lock);
	list_for_each_entry_safe (pos, n, &policies, list) {
		list_del(&pos->list);
		net_policy_free(pos);
	}
	write_unlock(&policies_lock);
	return 0;
}

static int net_policy_protocol(const struct net_policy_match *match)
{
	struct iphdr *iph;
	iph = ip_hdr(match->skb);

	match->event->protocol = iph->protocol;

	if (iph->protocol < match->policy->protocol.begin)
		return NET_POLICY_MISS;
	if (iph->protocol > match->policy->protocol.end)
		return NET_POLICY_MISS;
	return NET_POLICY_CONTINUE;
}

static int net_policy_addr(const struct net_policy_match *match)
{
	struct iphdr *iph;
	addr_t src, dst;

	iph = ip_hdr(match->skb);
	src = ntohl(iph->saddr);
	dst = ntohl(iph->daddr);

	match->event->saddr = src;
	match->event->daddr = dst;

	if (src < match->policy->addr.src.begin)
		return NET_POLICY_MISS;
	if (src > match->policy->addr.src.end)
		return NET_POLICY_MISS;
	if (dst < match->policy->addr.dst.begin)
		return NET_POLICY_MISS;
	if (dst > match->policy->addr.dst.end)
		return NET_POLICY_MISS;
	return NET_POLICY_CONTINUE;
}

static int net_policy_tcp_header_only(const struct net_policy_match *match)
{
	if (!(FLAG_TCP_HEADER_ONLY & match->policy->flags))
		return NET_POLICY_CONTINUE;

	if (tcp_hdrlen(match->skb) == ip_transport_len(match->skb))
		return NET_POLICY_CONTINUE;

	return NET_POLICY_MISS;
}

static int net_policy_tcp_handshake_only(const struct net_policy_match *match)
{
	struct tcphdr *tcph;

	if (!(FLAG_TCP_HANDSHAKE & match->policy->flags))
		return NET_POLICY_CONTINUE;

	tcph = tcp_hdr(match->skb);
	if (tcph->syn == 1 && tcph->ack == 0)
		return NET_POLICY_CONTINUE;

	return NET_POLICY_MISS;
}

static int net_policy_tcp_port(const struct net_policy_match *match)
{
	struct tcphdr *tcph;
	port_t src, dst;

	tcph = tcp_hdr(match->skb);
	src = ntohs(tcph->source);
	dst = ntohs(tcph->dest);

	match->event->sport = src;
	match->event->dport = dst;

	if (src < match->policy->port.src.begin)
		return NET_POLICY_MISS;
	if (src > match->policy->port.src.end)
		return NET_POLICY_MISS;
	if (dst < match->policy->port.dst.begin)
		return NET_POLICY_MISS;
	if (dst > match->policy->port.dst.end)
		return NET_POLICY_MISS;
	return NET_POLICY_CONTINUE;
}

static int net_policy_udp_port(const struct net_policy_match *match)
{
	struct udphdr *udph;
	port_t src, dst;

	udph = udp_hdr(match->skb);
	src = ntohs(udph->source);
	dst = ntohs(udph->dest);

	match->event->sport = src;
	match->event->dport = dst;

	if (src < match->policy->port.src.begin)
		return NET_POLICY_MISS;
	if (src > match->policy->port.src.end)
		return NET_POLICY_MISS;
	if (dst < match->policy->port.dst.begin)
		return NET_POLICY_MISS;
	if (dst > match->policy->port.dst.end)
		return NET_POLICY_MISS;
	return NET_POLICY_CONTINUE;
}

static int net_policy_extra(const struct net_policy_match *match)
{
	struct iphdr *iph;

	iph = ip_hdr(match->skb);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (!net_policy_tcp_header_only(match))
			goto miss;
		if (!net_policy_tcp_handshake_only(match))
			goto miss;
		if (!net_policy_tcp_port(match))
			goto miss;
		break;
	case IPPROTO_UDP:
		if (!net_policy_udp_port(match))
			goto miss;
		break;
	default:
		/* 不支持的协议认为端口号命中 */
		break;
	}
	return NET_POLICY_CONTINUE;
miss:
	return NET_POLICY_MISS;
}

static int net_policy_bound(const struct net_policy_match *match)
{
	switch (match->state->hook) {
	case NF_INET_PRE_ROUTING:
		return FLAG_INBOUND & match->policy->flags;
	case NF_INET_POST_ROUTING:
		return FLAG_OUTBOUND & match->policy->flags;
	}
	return NET_POLICY_MISS;
}

static int net_policy_response(const struct net_policy_match *match)
{
	match->event->policy = match->policy->id;

	if (!net_policy_bound(match))
		goto miss;
	if (!net_policy_protocol(match))
		goto miss;
	if (!net_policy_addr(match))
		goto miss;
	if (!net_policy_extra(match))
		goto miss;

	return NET_POLICY_CONTINUE;
miss:
	return NET_POLICY_MISS;
}

static response_t net_policy_hook(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	static const u32 NF_MASK = 1;
	static const u32 REPORT_MASK = 2;

	response_t response = NET_POLICY_ACCEPT;
	struct net_event_t event = {};
	struct net_policy_match match = {
		.skb = skb,
		.state = state,
		.event = &event,
	};

	if (!conn_check_living())
		return response;

	read_lock(&policies_lock);
	list_for_each_entry (match.policy, &policies, list) {
		if (!net_policy_response(&match))
			continue;

		response = match.policy->response;

		if (response & REPORT_MASK)
			net_protect_report_event(&event);

		break;
	}
	read_unlock(&policies_lock);
	return response & NF_MASK;
}

static const struct nf_hook_ops net_policy_ops[] = {
	{
		.hook = net_policy_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = net_policy_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
};

static bool hooked = false;
static DEFINE_RWLOCK(nf_lock);

static void net_protect_enable_unlocked(void)
{
	static const unsigned int n = ARRAY_SIZE(net_policy_ops);

	if (hooked)
		return;
	if (nf_register_net_hooks(&init_net, net_policy_ops, n))
		return;
	hooked = true;
}

static void net_protect_disable_unlocked(void)
{
	static const unsigned int n = ARRAY_SIZE(net_policy_ops);

	if (!hooked)
		return;
	nf_unregister_net_hooks(&init_net, net_policy_ops, n);
	hooked = false;
}

// FIXME: 启动有可能失败,但是目前没有体现出来
int net_protect_enable(void)
{
	write_lock(&nf_lock);
	net_protect_enable_unlocked();
	write_unlock(&nf_lock);
	return 0;
}

int net_protect_disable(void)
{
	write_lock(&nf_lock);
	net_protect_disable_unlocked();
	write_unlock(&nf_lock);
	return 0;
}

int net_protect_init(void)
{
	return 0;
}

int net_protect_destory(void)
{
	net_policy_clear();
	net_protect_disable();
	return 0;
}
