include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/bpf.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/version.mk

PKG_NAME := mimic
PKG_VERSION := 0.7.1
PKG_RELEASE := 5

commit := 5fe6a06ce46771b33f7b835310553e8c549cd1dc
PKG_BUILD_DIR := $(BUILD_DIR)/mimic-$(commit)
PKG_SOURCE := $(commit).tar.gz
PKG_SOURCE_URL := https://github.com/tracyhatemice/mimic/archive/
PKG_HASH := 61c9b46617d1370129eee56d4c3b624871818dd5a035766ce2899abf189c9926

PKG_BUILD_DEPENDS := argp-standalone bpf-headers bpftool/host

# This should be added to bpftool/host upstream
PKG_BUILD_DEPENDS += binutils/host

include $(INCLUDE_DIR)/package.mk

define Package/mimic
	SECTION := net
	CATEGORY := Network
	TITLE := eBPF TCP -> UDP Obfuscator
	URL := https://github.com/hack3ric/mimic
	DEPENDS := +libbpf +libffi +kmod-sched-core +kmod-sched-bpf
endef

define Package/mimic/description
  Mimic is a lightweight eBPF-based tool that obfuscates UDP traffic
  (e.g. WireGuard) as TCP by transparently rewriting packet headers at
  TC/XDP hooks. This fork adds the anti_gro setting.
endef

define KernelPackage/mimic
	SECTION := net
	SUBMENU := Network Support
	TITLE := eBPF TCP -> UDP Obfuscator - Kernel Module
	FILES := $(PKG_BUILD_DIR)/kmod/mimic.ko
endef

define KernelPackage/mimic/description
  Kernel module for Mimic providing the kprobe-based checksum fixup
  for the eBPF packet rewriting. Optional: most NICs do not require
  checksum hacks, and Mimic works without the kernel module.
endef

mimic_compat_flags :=
ifneq ($(findstring 6.1.,$(LINUX_VERSION)),)
  mimic_compat_flags := COMPAT_LINUX_6_1=1
else ifneq ($(findstring 6.6.,$(LINUX_VERSION)),)
  mimic_compat_flags := COMPAT_LINUX_6_6=1
endif

mimic_kmod_flags := \
	KERNEL_DIR="$(LINUX_DIR)" \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	M="$(PKG_BUILD_DIR)/kmod" \
	V="$(V)" \
	CHECKSUM_HACK=kprobe \
	$(mimic_compat_flags)

mimic_cli_flags := \
	MODE=release \
	BPF_CC="$(CLANG)" \
	BPFTOOL="$(STAGING_DIR_HOST)/usr/sbin/bpftool" \
	BPF_TARGET="$(BPF_TARGET)" \
	LLVM_STRIP="$(LLVM_STRIP)" \
	ARGP_STANDALONE=1 \
	CHECKSUM_HACK=kprobe \
	RUNTIME_DIR=/var/run/mimic \
	$(mimic_compat_flags) \
    STRIP_BTF_EXT=1 \
	USE_LIBXDP=0

export BPF_CFLAGS := \
	-I$(BPF_HEADERS_DIR)/user_headers/include \
	-I$(STAGING_DIR)/usr/include \
	$(if $(CONFIG_mips)$(CONFIG_mipsel)$(CONFIG_mips64),-D__MIPS$(if $(CONFIG_BIG_ENDIAN),EB,EL)__)

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" $(mimic_kmod_flags) modules
	$(call Build/Compile/Default,build-cli $(mimic_cli_flags))
endef

define Package/mimic/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/out/mimic $(1)/usr/bin

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/mimic $(1)/etc/init.d/mimic

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/mimic $(1)/etc/config/mimic
endef

define Package/mimic/conffiles
/etc/config/mimic
endef

define Package/mimic/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/mimic enable
fi
exit 0
endef

define Package/mimic/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/mimic stop
	/etc/init.d/mimic disable
fi
exit 0
endef

$(eval $(call BuildPackage,mimic))
$(eval $(call KernelPackage,mimic))
