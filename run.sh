#!/bin/bash
set -xue

# objcopy
OBJCOPY=/usr/bin/llvm-objcopy

# QEMU 실행 파일 경로
QEMU=qemu-system-riscv32

# clang 경로와 컴파일 옵션
CC=/usr/bin/clang
CFLAGS="-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32-unknown-elf -fuse-ld=lld -fno-stack-protector -ffreestanding -nostdlib"

# application 실행 가능한 elf 파일 생성
$CC $CFLAGS -Wl,-Tuser.ld -Wl,-Map=shell.map -o shell.elf shell.c user.c common.c
# 바이너리 shell.bin을 C언어에 임베드 할 수 있는 object 파일 생성
$OBJCOPY --set-section-flags .bss=alloc,contents -O binary shell.elf shell.bin
$OBJCOPY -Ibinary -Oelf32-littleriscv shell.bin shell.bin.o

# kenel 빌드
$CC $CFLAGS -Wl, -Tkernel.ld -Wl,-Map=kernel.map -o kernel.elf \
	kernel.c common.c shell.bin.o

# QEMU 실행
$QEMU -machine virt -bios default -nographic -serial mon:stdio --no-reboot \
    -d unimp,guest_errors,int,cpu_reset -D qemu.log \
    -drive id=drive0,file=lorem.txt,format=raw,if=none \
    -device virtio-blk-device,drive=drive0,bus=virtio-mmio-bus.0 \
	-kernel kernel.elf
