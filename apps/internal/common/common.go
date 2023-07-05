// SPDX-License-Identifier: GPL-2.0-only
package common

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func GetDataSourceNameFromConfig(config *viper.Viper) (dataSourceName string) {
	dbFile := strings.TrimPrefix(config.GetString("db"), "file:")

	if strings.ContainsAny(dbFile, "?=&") {
		logrus.Fatal("Path contains invalid characters")
		return
	}

	if dbFile == ":memory:" {
		logrus.Info("Currently using an in-memory database, data will be lost when the process exits")
	} else {
		os.MkdirAll(filepath.Dir(dbFile), os.ModePerm)
	}

	dbOptions := "?cache=shared&mode=rwc&_journal_mode=WAL"
	dataSourceName = "file:" + dbFile + dbOptions
	return
}
