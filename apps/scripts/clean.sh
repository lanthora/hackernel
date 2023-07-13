#!/bin/bash
root=$(dirname $(cd $(dirname $0);pwd))

for module in `ls $root/cmd`
do
        path="$root/cmd/$module"
        cd $path
        bin="$path/hackernel-$module"
        printf "[%s][remove] %s\n" $(date +"%H:%M:%S") $bin
        rm $bin
done

rm -rf $root/internal/web/webui/*
