// SPDX-License-Identifier: GPL-2.0-only
package telegram

import (
	"encoding/json"
	"fmt"
)

func RenderAuditProcReport(text string) (richText string) {
	doc := map[string]interface{}{}

	json.Unmarshal([]byte(text), &doc)
	if doc["type"].(string) != "audit::proc::report" {
		return
	}
	judge := doc["judge"].(float64)

	workdir := doc["workdir"].(string)
	binary := doc["binary"].(string)
	argv := doc["argv"].(string)

	richText += "<b>进程审计</b>\n\n"
	richText += "工作目录: "
	richText += fmt.Sprintf("<u>%s</u>\n\n", workdir)
	richText += "可执行程序: "
	richText += fmt.Sprintf("<u>%s</u>\n\n", binary)
	richText += "参数列表: "
	richText += fmt.Sprintf("<u>%s</u>\n\n", argv)
	richText += "状态: "
	if judge == 1 {
		richText += "<u>成功</u>\n"
	} else {
		richText += "<u>失败</u>\n"
	}

	return
}

func RenderUserMsgSub(text string) (rich string) {
	doc := map[string]interface{}{}

	json.Unmarshal([]byte(text), &doc)
	if doc["type"].(string) != "user::msg::sub" {
		return
	}

	code := doc["code"].(float64)
	section := doc["section"].(string)

	rich += "<b>消息订阅</b>\n\n"
	rich += "字段: "
	rich += fmt.Sprintf("<u>%s</u>\n\n", section)
	rich += "状态: "
	if code == 0 {
		rich += "<u>成功</u>\n"
	} else {
		rich += "<u>失败</u>\n"
	}
	return
}

func RenderUserMsgUnsub(text string) (rich string) {
	doc := map[string]interface{}{}

	json.Unmarshal([]byte(text), &doc)
	if doc["type"].(string) != "user::msg::unsub" {
		return
	}

	code := doc["code"].(float64)
	section := doc["section"].(string)

	rich += "<b>消息退订</b>\n\n"
	rich += "字段: "
	rich += fmt.Sprintf("<u>%s</u>\n\n", section)
	rich += "状态: "
	if code == 0 {
		rich += "<u>成功</u>\n"
	} else {
		rich += "<u>失败</u>\n"
	}
	return
}

func RenderKernelProcEnable(text string) (rich string) {
	doc := map[string]interface{}{}

	json.Unmarshal([]byte(text), &doc)
	if doc["type"].(string) != "kernel::proc::enable" {
		return
	}

	code := doc["code"].(float64)
	rich += "<b>开启进程保护</b>\n\n"

	rich += "状态: "
	if code == 0 {
		rich += "<u>成功</u>\n"
	} else {
		rich += "<u>失败</u>\n"
	}
	return
}

func RenderKernelProcDisable(text string) (rich string) {
	doc := map[string]interface{}{}

	json.Unmarshal([]byte(text), &doc)
	if doc["type"].(string) != "kernel::proc::disable" {
		return
	}

	code := doc["code"].(float64)
	rich += "<b>关闭进程保护</b>\n\n"

	rich += "状态: "
	if code == 0 {
		rich += "<u>成功</u>\n"
	} else {
		rich += "<u>失败</u>\n"
	}
	return
}
