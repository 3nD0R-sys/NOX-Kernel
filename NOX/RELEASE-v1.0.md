# NØX Kernel v1.0

## BUILD #001 - FIRST WORKING ROOT

Date: 2026-11-10
Status: Experimental

### Device
- Samsung Galaxy S9 SM-G960F
- Codename: starlte
- LineageOS 20 / Android 13
- Linux kernel 4.9.124+
- KernelSU Next integration

### Milestone

First NØX kernel build successfully booted
with functional KernelSU root access.

Root access was confirmed using Root Checker Pro.

### Technical changes

- Custom Exynos9810 kernel build
- KernelSU Next integration
- Legacy seccomp handling adjustment
- KernelSU root compatibility improvements

### Build configuration

NOX/configs/starlte-v1.config

### Source attribution

Based on:
https://github.com/v0lk3n/nethunter_kernel_samsung_exynos9810

Contains KernelSU Next source code.

Original copyright notices and applicable
open-source licenses remain in effect.

### Important

This is an experimental development build.

Tested on one Samsung Galaxy S9 SM-G960F.
Other devices and firmware versions are not verified.

Back up the original boot partition before flashing.

This source repository does not include private
device backups or rollback images.
