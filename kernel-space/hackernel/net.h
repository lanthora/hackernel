/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef HACKERNEL_NET_H
#define HACKERNEL_NET_H

#include <net/genetlink.h>

enum {
	NET_A_UNSPEC,
	NET_A_SESSION,

	NET_A_STATUS_CODE,
	NET_A_OP_TYPE,
	NET_A_ID,
	NET_A_PRIORITY,
	NET_A_ADDR_SRC_BEGIN,
	NET_A_ADDR_SRC_END,
	NET_A_ADDR_DST_BEGIN,
	NET_A_ADDR_DST_END,
	NET_A_PORT_SRC_BEGIN,
	NET_A_PORT_SRC_END,
	NET_A_PORT_DST_BEGIN,
	NET_A_PORT_DST_END,
	NET_A_PROTOCOL_BEGIN,
	NET_A_PROTOCOL_END,
	NET_A_RESPONSE,
	NET_A_FLAGS,
	__NET_A_MAX,
};
#define NET_A_MAX (__NET_A_MAX - 1)

typedef u32 addr_t;
typedef u16 port_t;
typedef u8 protocol_t;
typedef u32 response_t;
typedef u32 policy_id_t;
typedef s8 priority_t;

#define NET_POLICY_DROP NF_DROP /* 0 */
#define NET_POLICY_ACCEPT NF_ACCEPT /* 1 */
#define NET_POLICY_CONTINUE 1
#define NET_POLICY_MISS 0

/**
 * 优先级(priority)相同的情况下, 后添加的优先命中
 * 多个net_policy_t可以有相同的id, 根据id可以批量删除
 */

struct hknp_addr_range_t {
	addr_t begin;
	addr_t end;
};

struct hknp_port_range_t {
	port_t begin;
	port_t end;
};

struct hknp_protocol_range_t {
	protocol_t begin;
	protocol_t end;
};

struct hknp_addr_t {
	struct hknp_addr_range_t src;
	struct hknp_addr_range_t dst;
};

struct hknp_port_t {
	struct hknp_port_range_t src;
	struct hknp_port_range_t dst;
};

struct hknp_flags_t {
	int inbound : 1;
	int outbound : 1;
};

struct net_policy_t {
	struct list_head list;
	policy_id_t id;
	priority_t priority;
	struct hknp_addr_t addr;
	struct hknp_port_t port;
	struct hknp_protocol_range_t protocol;
	response_t response;
	s32 flags;
};

#define FLAG_INBOUND (1U << 0)
#define FLAG_OUTBOUND (1U << 1)
#define FLAG_TCP_HANDSHAKE (1U << 2)
#define FLAG_TCP_HEADER_ONLY (1U << 3)

struct hknf_buff {
	const struct sk_buff *skb;
	const struct nf_hook_state *state;
};

/* 内部会复制policy,需要自行释放入参的内存 */
int net_policy_insert(struct net_policy_t *policy);
int net_policy_delete(policy_id_t id);

int net_protect_enable(void);
int net_protect_disable(void);
int net_protect_init(void);
int net_protect_destory(void);

enum {
	NET_PROTECT_UNSPEC,
	NET_PROTECT_ENABLE,
	NET_PROTECT_DISABLE,
	NET_PROTECT_INSERT,
	NET_PROTECT_DELETE,
};
int net_protect_handler(struct sk_buff *skb, struct genl_info *info);

#endif
