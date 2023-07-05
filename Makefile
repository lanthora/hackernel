default:
	@scripts/update-submodule.sh
	@scripts/build.sh
	@scripts/done.sh

init:
	@scripts/update-submodule.sh

build:
	@scripts/build.sh

install:
	@scripts/install.sh

clean:
	@scripts/clean.sh

uninstall:
	@scripts/uninstall.sh

arch-build:
	@scripts/arch-build.sh

arch-install:
	@scripts/arch-install.sh

gentoo-build:
	@scripts/gentoo-build.sh

update-aur:
	@scripts/update-aur.sh

PHONY: default init build install uninstall arch-build arch-install gentoo-build
