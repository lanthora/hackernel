build:
	@scripts/build.sh
	@scripts/done.sh

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

PHONY: build install clean uninstall arch-build arch-install gentoo-build
