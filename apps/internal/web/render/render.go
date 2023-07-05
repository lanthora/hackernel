// SPDX-License-Identifier: GPL-2.0-only
package render

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	StatusSuccess = iota + 0
	StatusUnknownError
	StatusInvalidArgument
)

const (
	StatusUserNotLoggedIn = iota + 100
	StatusUserPermissionDenied
	StatusUserLoginFaild
	StatusUserCreateUserFailed
	StatusUserQueryUserFailed
	StatusUserUpdateUserFailed
	StatusUserDeleteUserFailed
)

const (
	StatusProcessEnableFailed = iota + 200
	StatusProcessDisableFailed
	StatusProcessUpdateJudgeFailed
	StatusProcessUpdatePolicyFailed
	StatusProcessQueryEventFailed
	StatusProcessTrustUpdateFailed
	StatusProcessGetTrustStatusFailed
)

const (
	StatusFileEnableFailed = iota + 300
	StatusFileDisableFailed
	StatusFileAddPolicyConflict
	StatusFileAddPolicyFileNotExist
	StatusFileAddPolicyFailed
	StatusFileDeletePolicyFailed
	StatusFileQueryPolicyListFailed
	StatusFileQueryPolicyByIdFailed
	StatusFileQueryEventListFailed
	StatusFileDeleteEventFailed
	StatusFileUpdatePolicyConflict
	StatusFileUpdatePolicyFileNotExist
	StatusFileUpdatePolicyFailed
	StatusFileUpdateEventStatusFailed
	StatusFileQueryEventFailed
)

const (
	StatusNetEnableFailed = iota + 400
	StatusNetDisableFailed
	StatusNetAddPolicyFailed
	StatusNetAddPolicyDatabaseFailed
	StatusNetDeletePolicyFailed
	StatusNetDeletePolicyDatabaseFailed
	StatusNetQueryPolicyListFailed
	StatusNetPolicyNotExist
	StatusNetQueryEventFailed
	StatusNetDeleteEventFailed
	StatusNetUpdateEventStatusFailed
)

var messages = map[int]string{
	StatusSuccess:                       "成功",
	StatusUnknownError:                  "未知错误",
	StatusInvalidArgument:               "无效参数",
	StatusUserNotLoggedIn:               "未登录",
	StatusUserPermissionDenied:          "无权限",
	StatusUserLoginFaild:                "登录失败",
	StatusUserCreateUserFailed:          "创建用户失败",
	StatusUserQueryUserFailed:           "查询用户失败",
	StatusUserUpdateUserFailed:          "更新用户失败",
	StatusUserDeleteUserFailed:          "删除用户失败",
	StatusProcessEnableFailed:           "启动进程防护模块失败",
	StatusProcessDisableFailed:          "关闭进程防护模块失败",
	StatusProcessUpdateJudgeFailed:      "更新进程防护模式失败",
	StatusProcessUpdatePolicyFailed:     "更新进程策略失败",
	StatusProcessQueryEventFailed:       "查询进程事件失败",
	StatusProcessTrustUpdateFailed:      "更新进程默认信任状态失败",
	StatusProcessGetTrustStatusFailed:   "获取进程默认信任状态失败",
	StatusFileEnableFailed:              "启动文件防护模块失败",
	StatusFileDisableFailed:             "关闭文件防护模块失败",
	StatusFileAddPolicyConflict:         "添加文件策略冲突",
	StatusFileAddPolicyFileNotExist:     "添加文件策略文件不存在",
	StatusFileAddPolicyFailed:           "添加文件策略失败",
	StatusFileDeletePolicyFailed:        "删除文件策略失败",
	StatusFileQueryPolicyListFailed:     "查询文件策略列表失败",
	StatusFileQueryPolicyByIdFailed:     "查询文件策略失败",
	StatusFileQueryEventListFailed:      "查询文件事件列表失败",
	StatusFileDeleteEventFailed:         "删除文件事件失败",
	StatusFileUpdatePolicyConflict:      "更新文件策略冲突",
	StatusFileUpdatePolicyFileNotExist:  "更新文件策略文件不存在",
	StatusFileUpdatePolicyFailed:        "更新文件策略失败",
	StatusFileUpdateEventStatusFailed:   "更新文件事件状态失败",
	StatusFileQueryEventFailed:          "查询文件事件失败",
	StatusNetEnableFailed:               "启动网络防护模块失败",
	StatusNetDisableFailed:              "关闭网络防护模块失败",
	StatusNetAddPolicyFailed:            "添加网络策略失败",
	StatusNetAddPolicyDatabaseFailed:    "添加网络策略数据库失败",
	StatusNetDeletePolicyFailed:         "删除网络策略失败",
	StatusNetDeletePolicyDatabaseFailed: "删除网络策略数据库失败",
	StatusNetQueryPolicyListFailed:      "查询网络策略列表失败",
	StatusNetPolicyNotExist:             "网络策略不存在",
	StatusNetQueryEventFailed:           "查询网络事件失败",
	StatusNetDeleteEventFailed:          "网络事件删除失败",
	StatusNetUpdateEventStatusFailed:    "更新网络事件状态失败",
}

func Success(context *gin.Context, data interface{}) {
	response := struct {
		Status  int         `json:"status"`
		Message string      `json:"message"`
		Data    interface{} `json:"data"`
	}{
		Status:  StatusSuccess,
		Message: messages[StatusSuccess],
		Data:    data,
	}
	context.JSON(http.StatusOK, response)
}

func Status(context *gin.Context, status int) {
	response := struct {
		Status  int    `json:"status"`
		Message string `json:"message"`
	}{
		Status:  status,
		Message: messages[status],
	}
	context.JSON(http.StatusOK, response)
}
