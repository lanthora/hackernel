#include "netlink.h"
#include "comlayer.h"
#include "file.h"
#include "net.h"
#include "process.h"
#include "syscall.h"
#include "util.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/netlink.h>

u32 portid = 0;

static struct nla_policy nla_policy[HACKERNEL_A_MAX + 1] = {
	[HACKERNEL_A_STATUS_CODE] = { .type = NLA_S32 },
	[HACKERNEL_A_OP_TYPE] = { .type = NLA_U8 },
	[HACKERNEL_A_SYS_CALL_TABLE_HEADER] = { .type = NLA_U64 },
	[HACKERNEL_A_NAME] = { .type = NLA_STRING },
	[HACKERNEL_A_PERM] = { .type = NLA_S32 },
	[HACKERNEL_A_EXECVE_ID] = { .type = NLA_S32 },
	[HACKERNEL_A_PORT] = { .type = NLA_U16 },
};

static struct genl_small_ops genl_small_ops[] = {
	{
		.cmd = HACKERNEL_C_HANDSHAKE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = handshake_handler,
	},
	{
		.cmd = HACKERNEL_C_PROCESS_PROTECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = process_protect_handler,
	},
	{
		.cmd = HACKERNEL_C_FILE_PROTECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = file_protect_handler,
	},
	{
		.cmd = HACKERNEL_C_NET_PROTECT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = net_protect_handler,
	},
};

// TODO:
// 参考 net/ethtool/netlink.c:700 的 ethtool_genl_ops
// 把现在的small_ops重构为ops
struct genl_family genl_family = {
	.hdrsize = 0,
	.name = HACKERNEL_FAMLY_NAME,
	.version = HACKERNEL_FAMLY_VERSION,
	.module = THIS_MODULE,
	.small_ops = genl_small_ops,
	.n_small_ops = ARRAY_SIZE(genl_small_ops),
	.maxattr = HACKERNEL_A_MAX,
	.policy = nla_policy,
};

void netlink_kernel_start(void)
{
	int error = 0;

	error = genl_register_family(&genl_family);
	if (error)
		LOG("genl_register_family failed");
}

void netlink_kernel_stop(void)
{
	int error = 0;

	error = genl_unregister_family(&genl_family);
	if (error)
		LOG("genl_unregister_family failed");
}
