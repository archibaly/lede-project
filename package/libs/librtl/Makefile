#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=librtl
PKG_VERSION:=0.9.7
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=jacky <qianqiangliu@hotmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=c run time library
endef

define Package/$(PKG_NAME)/description
 This is c run time library
endef

define Build/Prepare
	mkdir $(PKG_BUILD_DIR)/include
	mkdir $(PKG_BUILD_DIR)/lib
	mkdir $(PKG_BUILD_DIR)/src
	$(CP) include/* $(PKG_BUILD_DIR)/include
	$(CP) src/*.c $(PKG_BUILD_DIR)/src
	$(CP) src/Makefile $(PKG_BUILD_DIR)/src
endef

SONAME:=librtl.so.0
TARGET_CFLAGS += -I$(PKG_BUILD_DIR)/include -fPIC
TARGET_LDFLAGS += -Wl,-soname,$(SONAME) -shared

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		all
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/ $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/include/* $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/lib/* $(1)/usr/lib/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/lib/$(PKG_NAME).so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,librtl))
