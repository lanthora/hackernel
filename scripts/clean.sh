workdir=$(dirname $(dirname $(readlink -f "$0")))

cd $workdir/core/kernel-space/
make clean

rm -rf $workdir/core/user-space/build/*

cd $workdir/apps
make
