// SPDX-License-Identifier: GPL-2.0-only
package config

import (
	"database/sql"
)

const (
	sqlCreateConfigTable = `create table if not exists config(id integer primary key autoincrement, key text not null unique, integer integer, real real, text text)`
	sqlInsertInteger     = `insert into config(key,integer) values(?,?)`
	sqlUpdateInteger     = `update config set integer=? where key=?`
	sqlQueryInteger      = `select integer from config where key=?`
	sqlInsertReal        = `insert into config(key,real) values(?,?)`
	sqlUpdateReal        = `update config set real=? where key=?`
	sqlQueryReal         = `select real from config where key=?`
	sqlInsertText        = `insert into config(key,text) values(?,?)`
	sqlUpdateText        = `update config set text=? where key=?`
	sqlQueryText         = `select text from config where key=?`
)

const (
	ProcessModuleStatus     = "process module status"
	ProcessProtectionMode   = "process protection mode"
	ProcessCmdDefaultStatus = "process cmd default status"
	FileModuleStatus        = "file module status"
	NetModuleStatus         = "net module status"
)

type Config struct {
	db *sql.DB
}

func New(db *sql.DB) (c *Config, err error) {
	c = &Config{
		db: db,
	}

	_, err = db.Exec(sqlCreateConfigTable)
	if err != nil {
		return
	}
	return
}

func (c *Config) SetInteger(key string, value int) (err error) {
	stmt, err := c.db.Prepare(sqlUpdateInteger)
	if err != nil {
		return
	}
	defer stmt.Close()
	result, err := stmt.Exec(value, key)
	if err != nil {
		return
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 0 {
		return
	}

	stmt, err = c.db.Prepare(sqlInsertInteger)
	if err != nil {
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(key, value)
	if err != nil {
		return
	}

	return
}

func (c *Config) GetInteger(key string) (value int, err error) {
	stmt, err := c.db.Prepare(sqlQueryInteger)
	if err != nil {
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(key).Scan(&value)
	return
}

func (c *Config) SetReal(key string, value float64) (err error) {
	stmt, err := c.db.Prepare(sqlUpdateReal)
	if err != nil {
		return
	}
	defer stmt.Close()
	result, err := stmt.Exec(value, key)
	if err != nil {
		return
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 0 {
		return
	}

	stmt, err = c.db.Prepare(sqlInsertReal)
	if err != nil {
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(key, value)
	if err != nil {
		return
	}

	return
}

func (c *Config) GetReal(key string) (value float64, err error) {
	stmt, err := c.db.Prepare(sqlQueryReal)
	if err != nil {
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(key).Scan(&value)
	return
}

func (c *Config) SetText(key string, value string) (err error) {
	stmt, err := c.db.Prepare(sqlUpdateText)
	if err != nil {
		return
	}
	defer stmt.Close()
	result, err := stmt.Exec(value, key)
	if err != nil {
		return
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 0 {
		return
	}

	stmt, err = c.db.Prepare(sqlInsertText)
	if err != nil {
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(key, value)
	if err != nil {
		return
	}

	return
}

func (c *Config) GetText(key string) (value string, err error) {
	stmt, err := c.db.Prepare(sqlQueryText)
	if err != nil {
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(key).Scan(&value)
	return
}
