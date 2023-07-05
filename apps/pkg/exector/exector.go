package exector

import (
	"sync"
	"time"

	"github.com/lanthora/hackernel/apps/pkg/connector"
)

var conn = connector.New()
var mutex sync.Mutex

func Exec(request string, timeout time.Duration) (response string, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	if err = conn.Connect(); err != nil {
		return
	}
	defer conn.Close()

	if err = conn.Send(request); err != nil {
		return
	}

	if err = conn.Shutdown(time.Now().Add(timeout)); err != nil {
		return
	}

	response, err = conn.Recv()
	return
}
