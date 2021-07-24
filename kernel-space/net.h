#include <linux/kernel.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <uapi/linux/types.h>

typedef __be32 addr_t;
typedef __be16 port_t;
typedef __u8 protocol_t;
typedef unsigned int response_t;
typedef int policy_id_t;

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

int enable_net_protect(void);
int disable_net_protect(void);
