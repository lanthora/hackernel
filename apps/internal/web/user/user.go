// SPDX-License-Identifier: GPL-2.0-only
package user

import (
	"database/sql"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/lanthora/hackernel/apps/internal/web/render"
)

var loggedUser *lru.Cache[string, User]
var userDB *sql.DB
var bootstrapMu sync.Mutex

type Worker struct {
	db *sql.DB

	onlineUserMax int
}

func Init(router *gin.Engine, db *sql.DB) (err error) {
	userDB = db
	onlineUserMax := 10
	loggedUser, err = lru.New[string, User](onlineUserMax)
	if err != nil {
		return
	}

	w := &Worker{
		onlineUserMax: onlineUserMax,
		db:            db,
	}

	authGroup := router.Group("/auth")
	authGroup.Use(AuthMiddleware())
	authGroup.POST("/login", w.login)
	authGroup.POST("/showCurrentUserInfo", w.showCurrentUserInfo)
	authGroup.POST("/logout", w.logout)

	adminGroup := router.Group("/admin")
	adminGroup.Use(AuthMiddleware())
	adminGroup.POST("/addUser", w.addUser)
	adminGroup.POST("/deleteUser", w.deleteUser)
	adminGroup.POST("/updateUserInfo", w.updateUserInfo)
	adminGroup.POST("/listAllUsers", w.listAllUsers)

	if err = w.initUserTable(); err != nil {
		return
	}
	return

}

type User struct {
	UserID      int64  `json:"userID"`
	Username    string `json:"username"`
	AliasName   string `json:"aliasName"`
	Permissions string `json:"permissions"`
}

func AuthMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		// 不校验登录接口
		if context.Request.URL.Path == "/auth/login" {
			context.Next()
			return
		}
		session, err := context.Cookie("session")
		if err != nil {
			render.Status(context, render.StatusUserNotLoggedIn)
			context.Abort()
			return
		}

		user, ok := loggedUser.Get(session)
		if !ok {
			render.Status(context, render.StatusUserNotLoggedIn)
			context.Abort()
			return
		}

		var current User
		if err := lookupUser(user.UserID, &current); err != nil {
			loggedUser.Remove(session)
			render.Status(context, render.StatusUserNotLoggedIn)
			context.Abort()
			return
		}
		loggedUser.Add(session, current)
		context.Set("authenticatedUserID", current.UserID)
		if context.Request.URL.Path == "/auth/showCurrentUserInfo" || context.Request.URL.Path == "/auth/logout" {
			context.Next()
			return
		}
		g, err := glob.Compile(current.Permissions)
		if err != nil {
			render.Status(context, render.StatusUserPermissionDenied)
			context.Abort()
			return
		}
		if !g.Match(context.Request.URL.Path) {
			render.Status(context, render.StatusUserPermissionDenied)
			context.Abort()
			return
		}
		context.Next()
	}
}

func (w *Worker) login(context *gin.Context) {
	request := struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}{}
	deleteSession(context)

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	bootstrapMu.Lock()
	if w.noUser() {
		if err := w.createUser(request.Username, request.Password, request.Username, `{*}`); err != nil {
			bootstrapMu.Unlock()
			render.Status(context, render.StatusUserCreateUserFailed)
			return
		}
	}

	bootstrapMu.Unlock()
	ok, err := w.checkUserPassword(request.Username, request.Password)
	if err == sql.ErrNoRows {
		render.Status(context, render.StatusUserLoginFaild)
		return
	}

	if err != nil {
		render.Status(context, render.StatusUnknownError)
		return
	}

	if !ok {
		render.Status(context, render.StatusUserLoginFaild)
		return
	}

	response, err := w.queryUserByUsername(request.Username)
	if err != nil {
		render.Status(context, render.StatusUnknownError)
		return
	}
	session := uuid.NewString()
	loggedUser.Add(session, response)
	updateSession(context, session)
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) showCurrentUserInfo(context *gin.Context) {
	session, err := context.Cookie("session")
	if err != nil {
		render.Status(context, render.StatusUserNotLoggedIn)
		return
	}

	current, ok := loggedUser.Get(session)
	if !ok {
		render.Status(context, render.StatusUserNotLoggedIn)
		return
	}
	updateSession(context, session)
	render.Success(context, current)
}

func (w *Worker) logout(context *gin.Context) {
	session, _ := context.Cookie("session")
	loggedUser.Remove(session)

	deleteSession(context)
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) addUser(context *gin.Context) {
	request := struct {
		Username    string `json:"username" binding:"required"`
		Password    string `json:"password" binding:"required"`
		AliasName   string `json:"aliasName" binding:"required"`
		Permissions string `json:"permissions" binding:"required"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	if err := w.createUser(request.Username, request.Password, request.AliasName, request.Permissions); err != nil {
		render.Status(context, render.StatusUserCreateUserFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) listAllUsers(context *gin.Context) {
	users, err := w.queryAllUser()
	if err != nil {
		render.Status(context, render.StatusUserQueryUserFailed)
		return
	}
	render.Success(context, users)
}

func (w *Worker) deleteUser(context *gin.Context) {
	request := struct {
		UserID int64 `json:"userID" binding:"required,gt=0"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}
	session, _ := context.Cookie("session")
	current, _ := loggedUser.Get(session)
	if current.UserID == request.UserID {
		render.Status(context, render.StatusInvalidArgument)
		return
	}
	if ok := w.deleteUserByID(request.UserID); !ok {
		render.Status(context, render.StatusUserDeleteUserFailed)
		return
	}
	render.Status(context, render.StatusSuccess)
}

func (w *Worker) updateUserInfo(context *gin.Context) {
	request := struct {
		UserID      int64  `json:"userID" binding:"required,gt=0"`
		Username    string `json:"username" binding:"required"`
		Password    string `json:"password" binding:"required"`
		AliasName   string `json:"aliasName" binding:"required"`
		Permissions string `json:"permissions" binding:"required"`
	}{}

	if err := context.ShouldBindJSON(&request); err != nil {
		render.Status(context, render.StatusInvalidArgument)
		return
	}

	if ok := w.updateUserInfoByID(request.UserID, request.Username, request.Password, request.AliasName, request.Permissions); !ok {
		render.Status(context, render.StatusUserUpdateUserFailed)
		return
	}
	session, _ := context.Cookie("session")
	current, err := w.queryUserByUsername(request.Username)
	if err == nil {
		// Only preserve the caller's session when they edited their own account.
		if caller, ok := context.Get("authenticatedUserID"); ok && caller == request.UserID {
			loggedUser.Add(session, current)
		}
	}
	render.Status(context, render.StatusSuccess)
}

func updateSession(context *gin.Context, session string) {
	context.SetSameSite(http.SameSiteStrictMode)
	context.SetCookie("session", session, 0, "/", "", context.Request.TLS != nil, true)
}

func deleteSession(context *gin.Context) {
	if old, err := context.Cookie("session"); err == nil {
		loggedUser.Remove(old)
	}
	context.SetSameSite(http.SameSiteStrictMode)
	context.SetCookie("session", "deleted", -1, "/", "", context.Request.TLS != nil, true)
}

func lookupUser(id int64, current *User) error {
	return userDB.QueryRow("select id,username,alias,permissions from user where id=?", id).Scan(&current.UserID, &current.Username, &current.AliasName, &current.Permissions)
}
