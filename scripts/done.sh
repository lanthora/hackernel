#/bin/bash
set -e
workdir=$(dirname $(dirname $(readlink -f "$0")))

echo "========================= SUCCESS ========================"
echo "[1] $workdir/core/kernel-space/hackernel.ko"
echo "[2] $workdir/core/user-space/build/hackernel"
echo "[3] $workdir/apps/cmd/sample/hackernel-sample"
echo "[4] $workdir/apps/cmd/telegram/hackernel-telegram"
echo "[5] $workdir/apps/cmd/web/hackernel-web"
echo "[6] $workdir/apps/cmd/notify/hackernel-notify"
echo "=========================================================="
