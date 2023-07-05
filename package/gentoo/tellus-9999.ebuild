# Copyright 2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit git-r3

DESCRIPTION="Host Intrusion Detection and Prevention System Based on Kernel Module"
HOMEPAGE="https://github.com/lanthora/hackernel"
EGIT_REPO_URI="${HOMEPAGE}"

LICENSE="GPL"
SLOT="0"
KEYWORDS="~amd64 ~arm64 ~arm"

DEPEND="dev-libs/libnl
		sys-kernel/dkms
		"
RDEPEND="${DEPEND}"
BDEPEND="
	dev-vcs/git
	dev-util/cmake
	sys-devel/make
	dev-lang/go
	dev-cpp/nlohmann_json
"

src_unpack() {
	git-r3_src_unpack
	pushd "${S}"/apps || die
	go mod tidy || die
	go mod vendor || die
	popd || die
}

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
	doins hackernel/scripts/modules-load/hackernel.conf
	insinto /usr/lib/systemd/system
	doins hackernel/scripts/systemd/hackernel.service
	doins apps/init/hackernel-telegram.service
	doins apps/init/hackernel-web.service
}
