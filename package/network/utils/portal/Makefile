#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=portal
PKG_VERSION:=1.0.3
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/
PKG_BUILD_PARALLEL:=1
PKG_LICENSE:=GPL-2.0+

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SUBMENU:=Captive Portals
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libpthread +iptables-mod-ipopt
	TITLE:=Open public network gateway daemon
endef

define Package/$(PKG_NAME)/description
	Portal offers a simple way to open a free hotspot providing
	restricted access to an internet connection.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC=$(TARGET_CC) \
		CFLAGS="$(TARGET_CFLAGS) -Wall -Ilibhttpd" \
		LDFLAGS="$(TARGET_LDFLAGS) -pthread"
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/portal $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ptlctl $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/portal.init $(1)/etc/init.d/portal
	$(INSTALL_DIR) $(1)/etc/$(PKG_NAME)
	$(INSTALL_CONF) files/portal.conf $(1)/etc/$(PKG_NAME)/

	$(INSTALL_DIR) $(1)/etc/$(PKG_NAME)/htdocs/images
	$(CP) files/portal.html $(1)/etc/$(PKG_NAME)/htdocs/
	$(CP) files/infoskel.html $(1)/etc/$(PKG_NAME)/htdocs/
	$(CP) files/portal.jpg $(1)/etc/$(PKG_NAME)/htdocs/images/
endef

define Package/$(PKG_NAME)/conffiles
	/etc/$(PKG_NAME)/portal.conf
endef

$(eval $(call BuildPackage,portal))
