#include <linux/kernel.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <uapi/linux/types.h>

typedef __be32 addr_t;
typedef __be16 port_t;
typedef __u8 protocol_t;
typedef unsigned int response_t;
typedef int policy_id_t;

enum {
	NET_PROTECT_UNSPEC,
	NET_PROTECT_REPORT,
	NET_PROTECT_ENABLE,
	NET_PROTECT_DISABLE,
	NET_PROTECT_SET
};

// [begin, end)
struct net_policy_t {
	struct list_head list;

	policy_id_t id;

	struct {
		struct {
			addr_t begin;
			addr_t end;
		} source;
		struct {
			addr_t begin;
			addr_t end;
		} dest;
	} addr;

	struct {
		struct {
			port_t begin;
			port_t end;
		} source;
		struct {
			port_t begin;
			port_t end;
		} dest;
	} port;

	struct {
		protocol_t begin;
		protocol_t end;
	} protocol;

	response_t response;
	int enabled;
};

int net_protect_handler(struct sk_buff *skb, struct genl_info *info);
void exit_net_protect(void);