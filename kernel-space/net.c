#include "net.h"
#include "netlink.h"
#include "util.h"
#include <linux/bitmap.h>
#include <linux/gfp.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

unsigned long *tcp_in_drop_bitmap = NULL;
unsigned long *tcp_out_drop_bitmap = NULL;
unsigned long *udp_in_drop_bitmap = NULL;
unsigned long *udp_out_drop_bitmap = NULL;

static struct nf_hook_ops *inet_in_hook_ops = NULL;
static struct nf_hook_ops *inet_out_hook_ops = NULL;

static unsigned int inet_in_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	iph = ip_hdr(skb);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = tcp_hdr(skb);
		if (test_bit(ntohs(tcph->dest), tcp_in_drop_bitmap))
			return NF_DROP;
		break;
	case IPPROTO_UDP:
		udph = udp_hdr(skb);
		if (test_bit(ntohs(udph->dest), udp_in_drop_bitmap))
			return NF_DROP;
		break;
	default:
		break;
	}
	return NF_ACCEPT;
}

static unsigned int inet_out_hook(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	iph = ip_hdr(skb);
	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = tcp_hdr(skb);
		if (test_bit(ntohs(tcph->dest), tcp_out_drop_bitmap))
			return NF_DROP;
		break;
	case IPPROTO_UDP:
		udph = udp_hdr(skb);
		if (test_bit(ntohs(udph->dest), udp_out_drop_bitmap))
			return NF_DROP;
		break;
	default:
		break;
	}
	return NF_ACCEPT;
}

static int register_port_block_hook(unsigned int hooknum, nf_hookfn *fn,
				    struct nf_hook_ops **ops)
{
	if (*ops)
		return -EPERM;

	*ops = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (!*ops)
		goto errout;

	(*ops)->hook = (nf_hookfn *)fn;
	(*ops)->hooknum = hooknum;
	(*ops)->pf = PF_INET;
	(*ops)->priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, *ops);
	return 0;

errout:
	kfree(*ops);
	return -ENOMEM;
}

static void unregister_port_block_hook(struct nf_hook_ops **ops)
{
	if (!*ops)
		return;

	nf_unregister_net_hook(&init_net, *ops);
	kfree(*ops);
	*ops = NULL;
}

static int init_bitmap(unsigned long **bitmap)
{
	const unsigned int nbits = 1 << 16;
	if (*bitmap)
		return -EPERM;

	*bitmap = bitmap_zalloc(nbits, GFP_KERNEL);
	if (!*bitmap)
		return -ENOMEM;
	return 0;
}

static void destory_bitmap(unsigned long **bitmap)
{
	if (!bitmap)
		return;
	bitmap_free(*bitmap);
	*bitmap = NULL;
}

static int enable_net_protect(void)
{
	int error;

	error = init_bitmap(&tcp_in_drop_bitmap);
	if (error)
		return error;

	error = init_bitmap(&tcp_out_drop_bitmap);
	if (error)
		return error;

	error = init_bitmap(&udp_in_drop_bitmap);
	if (error)
		return error;

	error = init_bitmap(&udp_out_drop_bitmap);
	if (error)
		return error;

	error = register_port_block_hook(NF_INET_LOCAL_IN, inet_in_hook,
					 &inet_in_hook_ops);
	if (error)
		return error;

	error = register_port_block_hook(NF_INET_LOCAL_OUT, inet_out_hook,
					 &inet_out_hook_ops);
	if (error)
		return error;
	return 0;
}

static int disable_net_protect(void)
{
	unregister_port_block_hook(&inet_in_hook_ops);
	unregister_port_block_hook(&inet_out_hook_ops);
	destory_bitmap(&tcp_in_drop_bitmap);
	destory_bitmap(&tcp_out_drop_bitmap);
	destory_bitmap(&udp_in_drop_bitmap);
	destory_bitmap(&udp_out_drop_bitmap);
	return 0;
}

void exit_net_protect(void)
{
	disable_net_protect();
}

static inline int net_perm_tcp_in_disabled(net_perm_t perm)
{
	return perm & (1 << 0);
}

static inline int net_perm_tcp_out_disabled(net_perm_t perm)
{
	return perm & (1 << 1);
}

static inline int net_perm_udp_in_disabled(net_perm_t perm)
{
	return perm & (1 << 2);
}

static inline int net_perm_udp_out_disabled(net_perm_t perm)
{
	return perm & (1 << 3);
}

static int net_perm_set(net_port_t port, net_perm_t perm)
{
	if (!tcp_in_drop_bitmap || !tcp_out_drop_bitmap)
		return -EAGAIN;

	if (net_perm_tcp_in_disabled(perm))
		bitmap_set(tcp_in_drop_bitmap, port, 1);
	else
		bitmap_clear(tcp_in_drop_bitmap, port, 1);

	if (net_perm_tcp_out_disabled(perm))
		bitmap_set(tcp_out_drop_bitmap, port, 1);
	else
		bitmap_clear(tcp_out_drop_bitmap, port, 1);

	if (net_perm_udp_in_disabled(perm))
		bitmap_set(udp_in_drop_bitmap, port, 1);
	else
		bitmap_clear(udp_in_drop_bitmap, port, 1);

	if (net_perm_udp_out_disabled(perm))
		bitmap_set(udp_out_drop_bitmap, port, 1);
	else
		bitmap_clear(udp_out_drop_bitmap, port, 1);

	return 0;
}

int net_protect_handler(struct sk_buff *skb, struct genl_info *info)
{
	int error = 0;
	int code = 0;
	u8 type;
	struct sk_buff *reply = NULL;
	void *head = NULL;

	if (portid != info->snd_portid)
		return -EPERM;

	if (!info->attrs[HACKERNEL_A_OP_TYPE]) {
		code = -EINVAL;
		goto response;
	}

	type = nla_get_u8(info->attrs[HACKERNEL_A_OP_TYPE]);
	switch (type) {
	case NET_PROTECT_ENABLE: {
		code = enable_net_protect();
		goto response;
	}
	case NET_PROTECT_DISABLE: {
		code = disable_net_protect();
		goto response;
	}
	case NET_PROTECT_SET: {
		net_port_t port;
		net_perm_t perm;

		if (!info->attrs[HACKERNEL_A_PORT]) {
			code = -EINVAL;
			goto response;
		}

		if (!info->attrs[HACKERNEL_A_PERM]) {
			code = -EINVAL;
			goto response;
		}

		port = nla_get_u16(info->attrs[HACKERNEL_A_PORT]);
		perm = nla_get_s32(info->attrs[HACKERNEL_A_PERM]);
		code = net_perm_set(port, perm);
		break;
	}
	default: {
		LOG("Unknown file protect command");
	}
	}

response:

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (unlikely(!reply)) {
		LOG("genlmsg_new failed");
		goto errout;
	}

	head = genlmsg_put_reply(reply, info, &genl_family, 0,
				 HACKERNEL_C_NET_PROTECT);
	if (unlikely(!head)) {
		LOG("genlmsg_put_reply failed");
		goto errout;
	}

	error = nla_put_s32(reply, HACKERNEL_A_OP_TYPE, type);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	error = nla_put_s32(reply, HACKERNEL_A_STATUS_CODE, code);
	if (unlikely(error)) {
		LOG("nla_put_s32 failed");
		goto errout;
	}

	genlmsg_end(reply, head);

	error = genlmsg_reply(reply, info);
	if (unlikely(error))
		LOG("genlmsg_reply failed");

	return 0;
errout:
	nlmsg_free(reply);
	return 0;
}