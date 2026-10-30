// SPDX-License-Identifier: GPL-2.0-only
package web

var testSchema = []string{
	`create table if not exists process_event(id integer primary key autoincrement, workdir text not null, binary text not null, argv text not null, count integer not null, judge integer not null, status integer not null)`,
	`create table if not exists file_policy(id integer primary key autoincrement, path text not null, fsid integer, ino integer, perm integer not null, timestamp integer not null, status integer not null)`,
	`create table if not exists file_event(id integer primary key autoincrement, path text not null, fsid integer, ino integer, perm integer not null, timestamp integer not null, policy integer not null, status integer not null)`,
	`create table if not exists net_policy(id integer primary key autoincrement, priority integer, addr_src_begin text, addr_src_end text, addr_dst_begin text, addr_dst_end text, protocol_begin integer, protocol_end integer, port_src_begin integer, port_src_end integer, port_dst_begin integer, port_dst_end integer, flags integer, response integer)`,
	`create table if not exists net_event(id integer primary key autoincrement, protocol integer, saddr text, daddr text, sport integer, dport integer, timestamp integer not null, policy integer, status integer not null)`,
}
