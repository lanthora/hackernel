#/bin/bash
set -e
workdir=$(dirname $(dirname $(readlink -f "$0")))

cd $workdir/core/user-space/build/
cmake $workdir/core/user-space/ -DCMAKE_BUILD_TYPE=Release
make

cd $workdir/apps
make
