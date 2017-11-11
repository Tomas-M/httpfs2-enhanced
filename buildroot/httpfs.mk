################################################################################
#
# httpfs
#
################################################################################

HTTPFS_VERSION = master
HTTPFS_SOURCE = master.tar.gz
HTTPFS_SITE = https://github.com/Tomas-M/httpfs2-enhanced/archive
HTTPFS_LICENSE = GPLv2+, LGPLv2+
HTTPFS_DEPENDENCIES = host-pkgconf libfuse


define HTTPFS_BUILD_CMDS
    cat $(HTTPFS_DIR)/buildroot/Makefile.buildroot.static > $(HTTPFS_DIR)/Makefile
    $(MAKE) $(TARGET_CONFIGURE_OPTS) -C $(@D) all
endef

define LIBFOO_INSTALL_TARGET_CMDS
    $(INSTALL) -D -m 0755 $(@D)/httpfs2 $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))
