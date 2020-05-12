#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x644ce4d1, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0xf4c14fe8, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x6c2e3320, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x9f984513, __VMLINUX_SYMBOL_STR(strrchr) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xb99578fc, __VMLINUX_SYMBOL_STR(strncpy_from_user) },
	{ 0x505a018, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0x3096be16, __VMLINUX_SYMBOL_STR(names_cachep) },
	{ 0xeff639af, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x707291ba, __VMLINUX_SYMBOL_STR(current_task) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

