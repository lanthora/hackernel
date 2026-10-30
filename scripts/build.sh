#/bin/bash
set -e
workdir=$(dirname $(dirname $(readlink -f "$0")))

cd $workdir/core/kernel-space/
make

cd $workdir/core/user-space/build/
cmake $workdir/core/user-space/ -DCMAKE_BUILD_TYPE=Release
make

cd $workdir/webui
npm ci
npm run build:embed

cd $workdir/apps
make
