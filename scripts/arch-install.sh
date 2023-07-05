#/bin/bash
set -e
workdir=$(dirname $(dirname $(readlink -f "$0")))

cd $workdir/core/kernel-space/
make clean
DRIVER_VERSION=$(grep -Po '(?<=^PACKAGE_VERSION=")(.*)(?="$)' dkms.conf)
mkdir -p $DESTDIR/usr/src/hackernel-$DRIVER_VERSION
cp -r $workdir/core/kernel-space/* $DESTDIR/usr/src/hackernel-$DRIVER_VERSION

mkdir -p $DESTDIR/usr/bin/
cp $workdir/core/user-space/build/hackernel $DESTDIR/usr/bin/hackernel
cp $workdir/apps/cmd/sample/hackernel-sample $DESTDIR/usr/bin/hackernel-sample
cp $workdir/apps/cmd/telegram/hackernel-telegram $DESTDIR/usr/bin/hackernel-telegram
cp $workdir/apps/cmd/web/hackernel-web $DESTDIR/usr/bin/hackernel-web
cp $workdir/apps/cmd/notify/hackernel-notify $DESTDIR/usr/bin/hackernel-notify

mkdir -p $DESTDIR/etc/hackernel/
cp $workdir/apps/configs/telegram.yaml $DESTDIR/etc/hackernel/telegram.yaml
cp $workdir/apps/configs/web.yaml $DESTDIR/etc/hackernel/web.yaml
cp $workdir/apps/configs/notify.yaml $DESTDIR/etc/hackernel/notify.yaml

mkdir -p $DESTDIR/etc/modules-load.d/
mkdir -p $DESTDIR/usr/lib/systemd/system/
mkdir -p $DESTDIR/usr/lib/systemd/user/
cp $workdir/core/configs/modules-load/hackernel.conf $DESTDIR/etc/modules-load.d/hackernel.conf
cp $workdir/core/configs/systemd/hackernel.service $DESTDIR/usr/lib/systemd/system/hackernel.service
cp $workdir/apps/init/hackernel-telegram.service $DESTDIR/usr/lib/systemd/system/hackernel-telegram.service
cp $workdir/apps/init/hackernel-web.service $DESTDIR/usr/lib/systemd/system/hackernel-web.service
cp $workdir/apps/init/hackernel-notify.service $DESTDIR/usr/lib/systemd/user/hackernel-notify.service
