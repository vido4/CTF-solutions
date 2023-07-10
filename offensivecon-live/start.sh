#!/bin/sh

cd sources
sh build.sh
cd ..

SHARED=$PWD/mysharedfolder

qemu-system-x86_64 \
  -m 48 \
  -cpu kvm64,+smep,+smap \
  -kernel bzImage \
  -nographic \
  -virtfs local,path=$SHARED,mount_tag=shared0,security_model=mapped,id=shared0 \
  -append "console=ttyS0 quiet kaslr kpti=1" \
  -initrd initramfs.cpio \
  -monitor /dev/null
