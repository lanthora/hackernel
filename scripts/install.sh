#/bin/bash
workdir=$(dirname $(dirname $(readlink -f "$0")))

cp $workdir/core/kernel-space/hackernel.ko /lib/modules/$(uname -r)/hackernel.ko
depmod

mkdir -p /usr/bin/
cp $workdir/core/user-space/build/hackernel /usr/bin/hackernel
cp $workdir/apps/cmd/sample/hackernel-sample /usr/bin/hackernel-sample
cp $workdir/apps/cmd/telegram/hackernel-telegram /usr/bin/hackernel-telegram
cp $workdir/apps/cmd/web/hackernel-web /usr/bin/hackernel-web
cp $workdir/apps/cmd/notify/hackernel-notify /usr/bin/hackernel-notify

mkdir -p /etc/hackernel/
cp $workdir/apps/configs/telegram.yaml /etc/hackernel/telegram.yaml
cp $workdir/apps/configs/web.yaml /etc/hackernel/web.yaml

mkdir -p /etc/modules-load.d/
mkdir -p /usr/lib/systemd/system/
mkdir -p /usr/lib/systemd/user/
cp $workdir/core/configs/modules-load/hackernel.conf /etc/modules-load.d/hackernel.conf
cp $workdir/core/configs/systemd/hackernel.service /usr/lib/systemd/system/hackernel.service
cp $workdir/apps/init/hackernel-telegram.service /usr/lib/systemd/system/hackernel-telegram.service
cp $workdir/apps/init/hackernel-web.service /usr/lib/systemd/system/hackernel-web.service
cp $workdir/apps/init/hackernel-notify.service /usr/lib/systemd/user/hackernel-notify.service
