#
# Makefile for dirt
#
# Authors: Dirk Tennie <dirk@tarsal.co>
#          Barrett Lyon <blyon@tarsal.co>
#
# Copyright 2024 (c) Tarsal, Inc
#

OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BINDIR := ../bin/
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL := $(shell uname -r)
BPFTOOL := $(abspath ../vmlinux/$(ARCH)/bpftool)
ifeq ($(CROSS_COMPILE),aarch64-linux-gnu-)
    ARCH := arm64
endif
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
GIT_VERSION := $(shell git describe --abbrev=4 --dirty --always --tags | cut -d '-' -f 1,2,4 | sed 's/-/./1')
GLIBC_VERSION := ${shell ldd --version | head -n 1 | cut -d ')' -f2}
CLANG_VERSION := ${shell clang --version | head -n 1 | sed 's/[^0-9.]*\([0-9.]*\).*/\1/'}
LIBBPF_VERSION := ${shell pkg-config --modversion libbpf}
DATETIME := $(shell date +'%b-%d-%Y_%H:%M:%S%z')
INCLUDES := -I$(OUTPUT) -I$(dir $(VMLINUX))
CFLAGS := -Wextra -g -std=gnu99 -Wall -DDATETIME=\"$(DATETIME)\" -DVERSION=\"$(GIT_VERSION)\" -DKERNEL=\"$(KERNEL)\"\
          -D ARCH=\"$(ARCH)\" -DCLANG_VERSION=\"$(CLANG_VERSION)\" -DLIBBPF_VERSION=\"$(LIBBPF_VERSION)\"
CLANG_CHECKS := --checks=-*,clang-analyzer-*,-clang-analyzer-cplusplus* --warnings-as-errors=*
LDFLAGS := -ldl -lbpf
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = dirt

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'\
		      "$(1)"\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(BINDIR) *.deb *.rpm

.PHONY: check
check: $(APPS)
	$(call msg,CHECK, dirt.c $(CLANG_CHECKS))
	$(Q)clang-tidy dirt.c $(CLANG_CHECKS) -- $(CFLAGS) $(INCLUDES)

.PHONY: test
test:
	$(call msg,TEST)
	$(Q)echo | sudo ./dirt | timeout 60 grep -m1 InfoSequenceNumber

.PHONY: ctags
ctags:
	$(call msg,CTAGS, $(shell pwd) /usr/include/ --exclude=vmlinux.h)
	$(Q)ctags -R $(shell pwd) /usr/include/ --exclude=vmlinux.h

define NFPM
name: dirt
arch: $(PACKAGE_ARCH)
platform: linux
version: $(GIT_VERSION)
provides:
- dirt
maintainer: "Dirk Tennie <dirk@tarsal.co>"
description: |
  dirt by Tarsal.co
  Kernel-based process monitoring for Linux via eBPF
vendor: Tarsal.co
homepage: https://www.tarsal.co
license: "GPL 2.0"
contents:
- src: ../bin/dirt
  dst: /usr/local/bin/dirt
- src: ../src/dirt.service
  dst: /etc/systemd/system/dirt.service
  type: config|noreplace
scripts:
  preinstall: ./preinstall.sh
  postinstall: ./postinstall.sh
endef
define NFPM_PRE
#!/bin/sh
echo "Stopping dirt systemd service if running"
systemctl stop dirt || true
endef
define NFPM_POST
#!/bin/sh
echo "\nOnly on initial installation perform the following steps:"
echo "- Configure UDP server(s) in systemd service file, e.g.
    sudo vim /etc/systemd/system/dirt.service
      ExecStart=/usr/local/bin/dirt -o json -v -c -u 1.2.3.4:2056,127.0.0.1:2057 -d"
    sudo systemctl daemon-reload
echo "- Enable dirt systemd service to start automatically after reboot
    sudo systemctl enable dirt\n"
echo "- Start dirt systemd service and check status with the following commands:
    sudo systemctl start dirt
    sudo systemctl status dirt
    sudo journalctl -fe -u dirt\n"
endef
export NFPM
export NFPM_PRE
export NFPM_POST

rpm deb: $(APPS)
	$(eval PACKAGE_ARCH := $(shell echo $(ARCH) | if test 'deb' = 'deb'; then sed 's/x86/amd64/'; else sed 's/x86/x86_64/' | sed 's/arm64/aarch64/'; fi))
	$(Q)echo "$$NFPM" > nfpm.yaml
	$(Q)echo "$$NFPM_PRE" > preinstall.sh
	$(Q)echo "$$NFPM_POST" > postinstall.sh
	$(Q)chmod 755 preinstall.sh
	$(Q)chmod 755 postinstall.sh
	$(Q)nfpm package --packager $@
	$(Q)rm *.yaml *.sh

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c *.h $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c *.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o | $(OUTPUT)
	$(Q)mkdir -p $(BINDIR)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $(BINDIR)$@
	$(call msg,VERSION,$(GIT_VERSION) ($(ARCH), clang $(CLANG_VERSION), glibc $(GLIBC_VERSION), libbpf $(LIBBPF_VERSION)))
	$(call msg,BINARY,$(BINDIR)$@)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

