/*
 * Pronetway PRO10 board support
 *
 * Copyright (c) 2012 Qualcomm Atheros
 * Copyright (c) 2016-09-06 xddmahe <dingyongtian@p2w.net.cn>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <linux/irq.h>
#include <linux/platform_device.h>
#include <linux/ar8216_platform.h>

#include <asm/mach-ath79/ar71xx_regs.h>

#include "pci.h"
#include "common.h"
#include "dev-ap9x-pci.h"
#include "dev-gpio-buttons.h"
#include "dev-eth.h"
#include "dev-leds-gpio.h"
#include "dev-m25p80.h"
#include "dev-usb.h"
#include "dev-wmac.h"
#include "machtypes.h"

#define PRO10_GPIO_LED_WLAN		12

#define PRO10_GPIO_LED_WAN		4
#define PRO10_GPIO_LED_LAN1		16
#define PRO10_GPIO_LED_LAN2		15
#define PRO10_GPIO_LED_LAN3		14
#define PRO10_GPIO_LED_LAN4		11

#define PRO10_GPIO_BTN_RESET		17

#define PRO10_KEYS_POLL_INTERVAL	20	/* msecs */
#define PRO10_KEYS_DEBOUNCE_INTERVAL	(3 * PRO10_KEYS_POLL_INTERVAL)

#define PRO10_MAC0_OFFSET		0x00
#define PRO10_MAC1_OFFSET		0x06
#define PRO10_WMAC_CALDATA_OFFSET	0x1000

#define PRO10_ART_SIZE			0x1000

static struct gpio_led pro10_leds_gpio[] __initdata = {
	{
		.name		= "pro10:green:wan",
		.gpio		= PRO10_GPIO_LED_WAN,
		.active_low	= 1,
	},
	{
		.name		= "pro10:green:lan1",
		.gpio		= PRO10_GPIO_LED_LAN1,
		.active_low	= 1,
	},
	{
		.name		= "pro10:green:lan2",
		.gpio		= PRO10_GPIO_LED_LAN2,
		.active_low	= 1,
	},
	{
		.name		= "pro10:green:lan3",
		.gpio		= PRO10_GPIO_LED_LAN3,
		.active_low	= 1,
	},
	{
		.name		= "pro10:green:lan4",
		.gpio		= PRO10_GPIO_LED_LAN4,
		.active_low	= 1,
	},
	{
		.name		= "pro10:green:wlan",
		.gpio		= PRO10_GPIO_LED_WLAN,
		.active_low	= 1,
	},
};

static struct gpio_keys_button pro10_gpio_keys[] __initdata = {
	{
		.desc		= "reset",
		.type		= EV_KEY,
		.code		= KEY_RESTART,
		.debounce_interval = PRO10_KEYS_DEBOUNCE_INTERVAL,
		.gpio		= PRO10_GPIO_BTN_RESET,
		.active_low	= 1,
	},
};

static void __init common_setup(void)
{
	u8 *art = (u8 *) KSEG1ADDR(0x1fff0000);
	u8 *mac = (u8 *) KSEG1ADDR(0x1fff0000);

	ath79_register_m25p80(NULL);

	ath79_setup_ar933x_phy4_switch(false, false);

	ath79_register_mdio(0, 0x0);

	/* LAN */
	ath79_eth0_data.duplex = DUPLEX_FULL;
	ath79_eth0_data.phy_if_mode = PHY_INTERFACE_MODE_MII;
	ath79_eth0_data.speed = SPEED_100;
	ath79_eth0_data.phy_mask = BIT(4);
	ath79_init_mac(ath79_eth0_data.mac_addr, mac + PRO10_MAC0_OFFSET, 0);
	ath79_register_eth(0);

	/* WAN */
	ath79_switch_data.phy4_mii_en = 1;
	ath79_eth1_data.duplex = DUPLEX_FULL;
	ath79_eth1_data.phy_if_mode = PHY_INTERFACE_MODE_GMII;
	ath79_eth1_data.speed = SPEED_1000;
	ath79_switch_data.phy_poll_mask |= BIT(4);
	ath79_init_mac(ath79_eth1_data.mac_addr, mac + PRO10_MAC1_OFFSET, 0);
	ath79_register_eth(1);

	ath79_register_wmac(art + PRO10_WMAC_CALDATA_OFFSET, NULL);

	ath79_register_usb();
}

static void __init pro10_setup(void)
{
	common_setup();

	ath79_register_leds_gpio(-1,
				ARRAY_SIZE(pro10_leds_gpio),
				pro10_leds_gpio);

	ath79_register_gpio_keys_polled(-1,
					PRO10_KEYS_POLL_INTERVAL,
					ARRAY_SIZE(pro10_gpio_keys),
					pro10_gpio_keys);
}

MIPS_MACHINE(ATH79_MACH_PRO10, "PRO10", "Pronetway PRO10", pro10_setup);
