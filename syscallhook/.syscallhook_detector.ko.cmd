cmd_/root/mod/syscallhook/syscallhook_detector.ko := ld -r -m elf_i386 -T ./scripts/module-common.lds --build-id  -o /root/mod/syscallhook/syscallhook_detector.ko /root/mod/syscallhook/syscallhook_detector.o /root/mod/syscallhook/syscallhook_detector.mod.o
