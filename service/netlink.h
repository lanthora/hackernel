#ifndef HACKERNEL_NETLINK_USER_SPACE
#define HACKERNEL_NETLINK_USER_SPACE

#ifdef __cplusplus
extern "C" {
#endif

/* 模仿内核对 ARRAY_SIZE 宏的实现 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* 定义FAMLY：用字符串找到特定的famly,用来代替有限的netlink协议(不超过32个) */
#define HACKERNEL_FAMLY_NAME "HACKERNEL"

/* 定义协议版本 */
#define HACKERNEL_FAMLY_VERSION 1

/* 定义属性：内核空间与用户空间之间通过属性传递数据 */
enum {
  HACKERNEL_A_UNSPEC,
  HACKERNEL_A_CODE,
  HACKERNEL_A_SCTH,
  HACKERNEL_A_NAME,
  HACKERNEL_A_PERM,
  __HACKERNEL_A_MAX,
};
#define HACKERNEL_A_MAX (__HACKERNEL_A_MAX - 1)

/* 定义命令：在框架里被分发到不同的回调函数 */
enum {
  HACKERNEL_C_UNSPEC,
  HACKERNEL_C_HANDSHAKE,
  HACKERNEL_C_PROCESS_PROTECT,
  HACKERNEL_C_FILE_PROTECT,
  __HACKERNEL_C_MAX,
};
#define HACKERNEL_C_MAX (__HACKERNEL_C_MAX - 1)

#define FILE_PROTECT_ENABLE 1
#define FILE_PROTECT_DISABLE 2
#define FILE_PROTECT_SET 3
#define FILE_PROTECT_NOTIFY 4

void netlink_user_start(void);
void netlink_user_stop(void);

extern struct genl_ops hackernel_genl_ops;

#ifdef __cplusplus
}
#endif

#endif
