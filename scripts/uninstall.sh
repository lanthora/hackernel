#/bin/bash
rm /lib/modules/$(uname -r)/hackernel.ko
depmod

rm /usr/bin/hackernel
rm /usr/bin/hackernel-sample
rm /usr/bin/hackernel-telegram
rm /usr/bin/hackernel-web

rm /etc/hackernel/telegram.yaml
rm /etc/hackernel/web.yaml
rmdir /etc/hackernel

rm /etc/modules-load.d/hackernel.conf
rm /usr/lib/systemd/system/hackernel.service
rm /usr/lib/systemd/system/hackernel-telegram.service
rm /usr/lib/systemd/system/hackernel-web.service
