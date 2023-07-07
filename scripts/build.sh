#/bin/bash
set -e
workdir=$(dirname $(dirname $(readlink -f "$0")))

cd $workdir/core/kernel-space/
make

cd $workdir/core/user-space/build/
cmake $workdir/core/user-space/ -DCMAKE_BUILD_TYPE=Release
make

cd $workdir/webui
npm install
npm run build
rm -rf $workdir/apps/internal/web/webui/*
cp -r $workdir/webui/dist/* $workdir/apps/internal/web/webui/

cd $workdir/apps
make
