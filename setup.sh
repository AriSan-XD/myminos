MINOS="/home/arisan/HDD/workspace/myminos"
LINUX="/home/arisan/HDD/src/linux-4.14.59"
IMG="/home/arisan/HDD/workspace/myminos/virtio-sd.img"
cd $MINOS
mount -o loop,offset=32256 $IMG /mnt
make -j10
# rm -r $LINUX/drivers/minos
# cp -r $MINOS/generic/minos-linux-driver $LINUX/drivers/minos
# cd $LINUX
# make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j10 Image
# cd $MINOS
dtc qemu-virt.dts > qemu-virt.dtb
cd $MINOS/tools/mkrmd
make
cd $MINOS
$MINOS/tools/mkrmd/mkrmd -f ramdisk.bin $LINUX/arch/arm64/boot/Image $MINOS/qemu-virt.dtb
cp $MINOS/minos.bin /mnt/kernel.bin
cp $MINOS/dtbs/qemu-arm64.dtb /mnt
cp $MINOS/ramdisk.bin /mnt
umount /mnt
cp $MINOS/generic/minos-linux-driver/minos_hypercall.h /home/arisan/HDD/Arm/testcase/minos/minos_hypercall.h