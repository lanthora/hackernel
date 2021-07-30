#ifndef HACKERNEL_NET_H
#define HACKERNEL_NET_H

#include <linux/kernel.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <uapi/linux/types.h>

enum {
	NET_A_UNSPEC,
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

	NET_A_ENABLED,

	__NET_A_MAX,
};
#define NET_A_MAX (__NET_A_MAX - 1)

typedef __be32 addr_t;
typedef __be16 port_t;
typedef __u8 protocol_t;
typedef u32 response_t;
typedef u32 policy_id_t;
typedef s8 priority_t;

/**
 * 优先级(priority)相同的情况下, 后添加的优先命中
 * 多个net_policy_t可以有相同的id, 根据id可以批量删除
 */
struct net_policy_t {
	struct list_head list;

	policy_id_t id;
	priority_t priority;

	struct {
		struct {
			addr_t begin;
			addr_t end;
		} src;
		struct {
			addr_t begin;
			addr_t end;
		} dst;
	} addr;

	struct {
		struct {
			port_t begin;
			port_t end;
		} src;
		struct {
			port_t begin;
			port_t end;
		} dst;
	} port;

	struct {
		protocol_t begin;
		protocol_t end;
	} protocol;

	response_t response;
	int enabled;
};

// 内部会复制policy,需要自行释放入参的内存
int net_policy_insert(struct net_policy_t *policy);
int net_policy_delete(policy_id_t id);

int enable_net_protect(void);
int disable_net_protect(void);

#define NET_POLICY_HIT 1
#define NET_POLICY_MISS 0

#endif
