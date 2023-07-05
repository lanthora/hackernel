// SPDX-License-Identifier: GPL-2.0-only
package file

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/lanthora/hackernel/apps/internal/config"
	"github.com/lanthora/hackernel/apps/internal/web/render"
	"github.com/lanthora/hackernel/apps/internal/web/user"
	"github.com/lanthora/hackernel/apps/pkg/file"
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

	fileGroup := router.Group("/file")
	fileGroup.Use(user.AuthMiddleware())

	fileGroup.POST("/enableModule", w.enableModule)
	fileGroup.POST("/disableModule", w.disableModule)
	fileGroup.POST("/showModuleStatus", w.showModuleStatus)

	fileGroup.POST("/addPolicy", w.addPolicy)
	fileGroup.POST("/updatePolicy", w.updatePolicy)
	fileGroup.POST("/deletePolicy", w.deletePolicy)
	fileGroup.POST("/clearPolicies", w.clearPolicies)
	fileGroup.POST("/listPolicies", w.listPolicies)
	fileGroup.POST("/showPolicy", w.showPolicy)

	fileGroup.POST("/updateEventStatus", w.updateEventStatus)
	fileGroup.POST("/deleteEvent", w.deleteEvent)
	fileGroup.POST("/listEvents", w.listEvents)
	return
}

func (w *Worker) showModuleStatus(context *gin.Context) {
	status, err := w.config.GetInteger(config.FileModuleStatus)
	if err != nil {
		status = file.StatusDisable
	}
	policyCount, err := w.queryFileNormalPolicyCount()
	if err != nil {
		policyCount = 0
	}
	unreadEventCount, err := w.queryFileUnreadEventCount()
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
	if err := w.config.SetInteger(config.FileModuleStatus, file.StatusEnable); err != nil {
		render.Status(context, render.StatusProcessEnableFailed)
		return
	}
	ok := file.Enable()
	if !ok {
		render.Status(context, render.StatusProcessEnableFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) disableModule(context *gin.Context) {
	if err := w.config.SetInteger(config.FileModuleStatus, file.StatusDisable); err != nil {
		render.Status(context, render.StatusFileDisableFailed)
		return
	}
	ok := file.Disable()
	if !ok {
		render.Status(context, render.StatusFileDisableFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) addPolicy(context *gin.Context) {
	request := struct {
		Path string `json:"path" binding:"required"`
		Perm int    `json:"perm" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}
	fsid, ino, status, err := file.SetPolicy(request.Path, request.Perm, file.FlagNew)
	if err != nil || status == file.StatusPolicyUnknown {
		render.Status(context, render.StatusUnknownError)
		return
	}

	if status == file.StatusPolicyConflict {
		render.Status(context, render.StatusFileAddPolicyConflict)
		return
	}

	if status == file.StatusPolicyConflict {
		render.Status(context, render.StatusFileAddPolicyFileNotExist)
		return
	}

	err = w.insertFilePolicy(request.Path, fsid, ino, request.Perm, file.StatusPolicyNormal)
	if err != nil {
		render.Status(context, render.StatusFileAddPolicyFailed)
		return
	}

	render.Status(context, render.StatusSuccess)
}

func (w *Worker) updatePolicy(context *gin.Context) {
	request := struct {
		ID   int `json:"id" binding:"number"`
		Perm int `json:"perm" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	policy, err := w.queryFilePolicyById(request.ID)
	if err != nil {
		render.Status(context, render.StatusUnknownError)
		return
	}

	fsid, ino, status, err := file.SetPolicy(policy.Path, request.Perm, file.FlagUpdate)
	if err != nil || status == file.StatusPolicyUnknown {
		render.Status(context, render.StatusUnknownError)
		return
	}

	if status == file.StatusPolicyConflict {
		render.Status(context, render.StatusFileUpdatePolicyConflict)
		return
	}

	if status == file.StatusPolicyConflict {
		render.Status(context, render.StatusFileUpdatePolicyFileNotExist)
		return
	}

	err = w.updateFilePolicyById(fsid, ino, request.Perm, file.StatusPolicyNormal, request.ID)
	if err != nil {
		logrus.Error(err)
		render.Status(context, render.StatusFileUpdatePolicyFailed)
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

	policy, err := w.queryFilePolicyById(request.ID)
	if err != nil {
		render.Status(context, render.StatusUnknownError)
		return
	}

	_, _, _, err = file.SetPolicy(policy.Path, 0, file.FlagAny)
	if err != nil {
		render.Status(context, render.StatusUnknownError)
		return
	}

	err = w.deleteFilePolicyById(request.ID)
	if err != nil {
		render.Status(context, render.StatusFileDeletePolicyFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

// TODO: 清空配置列表
func (w *Worker) clearPolicies(context *gin.Context) {
	render.Status(context, render.StatusUnknownError)
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

	policies, err := w.queryFilePolicyLimitOffset(request.Limit, request.Offset)
	if err != nil {
		logrus.Error(err)
		render.Status(context, render.StatusFileQueryPolicyListFailed)
		return
	}
	render.Success(context, policies)
}

func (w *Worker) showPolicy(context *gin.Context) {
	request := struct {
		ID int `json:"id" binding:"number"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	policy, err := w.queryFilePolicyById(request.ID)
	if err != nil {
		render.Status(context, render.StatusFileQueryPolicyByIdFailed)
		return
	}
	render.Success(context, policy)
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

	events, err := w.queryFileEventOffsetLimit(request.Limit, request.Offset)
	if err != nil {
		render.Status(context, render.StatusFileQueryEventFailed)
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

	err := w.deleteFileEventById(request.ID)
	if err != nil {
		render.Status(context, render.StatusFileDeleteEventFailed)
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

	err := w.updateFileEventStatusById(request.Status, request.ID)
	if err != nil {
		render.Status(context, render.StatusFileUpdateEventStatusFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}
