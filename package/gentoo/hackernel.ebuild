# Copyright 2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="Host Intrusion Detection and Prevention System"
HOMEPAGE="https://github.com/lanthora/hackernel"
SRC_URI="https://github.com/lanthora/hackernel/archive/refs/tags/v1.7.1.tar.gz"

LICENSE="GPL"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~arm"

DEPEND="
	dev-libs/libnl
	sys-kernel/dkms
"
RDEPEND="${DEPEND}"
BDEPEND="
	dev-util/cmake
	sys-devel/make
	dev-lang/go
	dev-cpp/nlohmann_json
"

src_compile(){
	make gentoo-build
}

src_install(){
	DRIVER_VERSION=$(grep -Po '(?<=^PACKAGE_VERSION=")(.*)(?="$)' core/kernel-space/dkms.conf)
	insinto /usr/src/hackernel-${DRIVER_VERSION}
	doins -r core/kernel-space/*
	dobin core/user-space/build/hackernel
	dobin apps/cmd/sample/hackernel-sample
	dobin apps/cmd/telegram/hackernel-telegram
	dobin apps/cmd/web/hackernel-web
	insinto /etc/hackernel
	doins apps/configs/telegram.yaml
	doins apps/configs/web.yaml
	insinto /etc/modules-load.d
	doins core/configs/modules-load/hackernel.conf
	insinto /usr/lib/systemd/system
	doins core/configs/systemd/hackernel.service
	doins apps/init/hackernel-telegram.service
	doins apps/init/hackernel-web.service
}
