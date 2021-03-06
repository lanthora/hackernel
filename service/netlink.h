#ifndef HACKERNEL_NETLINK_USER_SPACE
#define HACKERNEL_NETLINK_USER_SPACE

/* 模仿内核对 ARRAY_SIZE 宏的实现 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* 定义FAMLY：用字符串找到特定的famly,用来代替有限的netlink协议(不超过32个) */
#define HACKERNEL_FAMLY_NAME "HACKERNEL"

/* 定义协议版本 */
#define HACKERNEL_FAMLY_VERSION 1

/* 定义属性：内核空间与用户空间之间通过属性传递数据 */
enum {
  HACKERNEL_A_UNSPEC,
  HACKERNEL_A_MSG,
  __HACKERNEL_A_MAX,
};
#define HACKERNEL_A_MAX (__HACKERNEL_A_MAX - 1)

/* 定义命令：在框架里被分发到不同的回调函数 */
enum {
  HACKERNEL_C_UNSPEC,
  HACKERNEL_C_HANDSHAKE,
  __HACKERNEL_C_MAX,
};
#define HACKERNEL_C_MAX (__HACKERNEL_C_MAX - 1)

void netlink_user_start(void);
void netlink_user_stop(void);

#endif
