// SPDX-License-Identifier: GPL-2.0-only
package net

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/lanthora/hackernel/apps/internal/config"
	"github.com/lanthora/hackernel/apps/internal/web/render"
	"github.com/lanthora/hackernel/apps/internal/web/user"
	"github.com/lanthora/hackernel/apps/pkg/net"
	"github.com/sirupsen/logrus"
)

type Worker struct {
	db *sql.DB

	config *config.Config
}

func Init(router *gin.Engine, db *sql.DB) (err error) {
	config, err := config.New(db)
	if err != nil {
		return
	}
	w := &Worker{
		db:     db,
		config: config,
	}

	netGroup := router.Group("/net")
	netGroup.Use(user.AuthMiddleware())

	netGroup.POST("/enableModule", w.enableModule)
	netGroup.POST("/disableModule", w.disableModule)
	netGroup.POST("/showModuleStatus", w.showModuleStatus)

	netGroup.POST("/addPolicy", w.addPolicy)
	netGroup.POST("/deletePolicy", w.deletePolicy)
	netGroup.POST("/listPolicies", w.listPolicies)

	netGroup.POST("/updateEventStatus", w.updateEventStatus)
	netGroup.POST("/deleteEvent", w.deleteEvent)
	netGroup.POST("/listEvents", w.listEvents)

	return
}

func (w *Worker) showModuleStatus(context *gin.Context) {
	status, err := w.config.GetInteger(config.NetModuleStatus)
	if err != nil {
		status = net.StatusDisable
	}

	policyCount, err := w.queryNetPolicyCount()
	if err != nil {
		policyCount = 0
	}
	unreadEventCount, err := w.queryNetUnreadEventCount()
	if err != nil {
		unreadEventCount = 0
	}

	response := struct {
		Status           int `json:"status"`
		PolicyCount      int `json:"policyCount"`
		UnreadEventCount int `json:"unreadEventCount"`
	}{
		Status:           status,
		PolicyCount:      policyCount,
		UnreadEventCount: unreadEventCount,
	}

	render.Success(context, response)
}

func (w *Worker) enableModule(context *gin.Context) {
	if err := w.config.SetInteger(config.NetModuleStatus, net.StatusEnable); err != nil {
		render.Status(context, render.StatusProcessEnableFailed)
		return
	}
	ok := net.Enable()
	if !ok {
		render.Status(context, render.StatusNetEnableFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) disableModule(context *gin.Context) {
	if err := w.config.SetInteger(config.NetModuleStatus, net.StatusDisable); err != nil {
		render.Status(context, render.StatusNetDisableFailed)
		return
	}
	ok := net.Disable()
	if !ok {
		render.Status(context, render.StatusNetDisableFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) addPolicy(context *gin.Context) {
	request := net.Policy{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	id, err := w.insertNetPolicy(&request)
	if err != nil {
		render.Status(context, render.StatusNetAddPolicyDatabaseFailed)
		return
	}

	request.ID = id
	if ok := net.AddPolicy(request); !ok {
		render.Status(context, render.StatusNetAddPolicyFailed)
		return
	}

	render.Status(context, render.StatusSuccess)
}

func (w *Worker) deletePolicy(context *gin.Context) {
	request := struct {
		ID int `json:"id" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	err := w.deleteNetPolicyById(request.ID)
	if err == net.ErrorPolicyNotExist {
		render.Status(context, render.StatusNetPolicyNotExist)
		return
	}

	if err != nil {
		render.Status(context, render.StatusNetDeletePolicyDatabaseFailed)
		return
	}

	ok := net.DeletePolicy(request.ID)
	if !ok {
		render.Status(context, render.StatusNetDeletePolicyFailed)
		return
	}

	render.Status(context, render.StatusSuccess)
}

func (w *Worker) listPolicies(context *gin.Context) {
	request := struct {
		Limit  int `json:"limit" binding:"number"`
		Offset int `json:"offset" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	policies, err := w.queryNetPolicyLimitOffset(request.Limit, request.Offset)
	if err != nil {
		logrus.Error(err)
		render.Status(context, render.StatusNetQueryPolicyListFailed)
		return
	}
	render.Success(context, policies)
}

func (w *Worker) listEvents(context *gin.Context) {
	request := struct {
		Limit  int `json:"limit" binding:"number"`
		Offset int `json:"offset" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	events, err := w.queryNetEventOffsetLimit(request.Limit, request.Offset)
	if err != nil {
		render.Status(context, render.StatusNetQueryEventFailed)
		return
	}
	render.Success(context, events)
}

func (w *Worker) deleteEvent(context *gin.Context) {
	request := struct {
		ID int `json:"id" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	err := w.deleteNetEventById(request.ID)
	if err != nil {
		render.Status(context, render.StatusNetDeleteEventFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) updateEventStatus(context *gin.Context) {
	request := struct {
		Status int `json:"status" binding:"number"`
		ID     int `json:"id" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	err := w.updateNetEventStatusById(request.Status, request.ID)
	if err != nil {
		render.Status(context, render.StatusNetUpdateEventStatusFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}
