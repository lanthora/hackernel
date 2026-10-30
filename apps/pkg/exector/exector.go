package exector

import (
	"sync"
	"time"

	"github.com/lanthora/hackernel/apps/pkg/connector"
)

// ControlTimeout allows kernel hook removal to finish its RCU grace periods.
// Keep this below the HTTP client timeout used by the management console.
const ControlTimeout = 10 * time.Second

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
