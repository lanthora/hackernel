// SPDX-License-Identifier: GPL-2.0-only
package logger

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

type logFormatter struct{}

var (
	BuildDir string = "Undefined"
)

func InitLogrusFormat() {
	logrus.SetReportCaller(true)
	logrus.SetFormatter(&logFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func (f *logFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	if entry.Buffer != nil {
		b = entry.Buffer
	}

	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	msg := ""
	file := strings.TrimPrefix(entry.Caller.File, BuildDir)
	if entry.HasCaller() {
		msg = fmt.Sprintf("[%s] [%s] [%s:%d] %s\n",
			timestamp, entry.Level, file, entry.Caller.Line, entry.Message)
	} else {
		msg = fmt.Sprintf("[%s] [%s] %s\n", timestamp, entry.Level, entry.Message)
	}
	b.WriteString(msg)
	return b.Bytes(), nil
}
