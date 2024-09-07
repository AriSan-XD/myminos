MINOS="/home/arisan/HDD/workspace/myminos"
LINUX="/home/arisan/HDD/src/linux-6.1.38"
IMG="/home/arisan/HDD/workspace/myminos/arch_large.img"
cd $MINOS
make -j10
# rm -r $LINUX/drivers/minos
# cp -r $MINOS/generic/minos-linux-driver $LINUX/drivers/minos
cd $LINUX
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j10 Image
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules -j10
mount -o loop,offset=104889856 $IMG /mnt
sudo make modules_install INSTALL_MOD_PATH=/mnt ARCH=arm64
umount /mnt
cd $MINOS
dtc qemu-virt.dts > qemu-virt.dtb
# cd $MINOS/tools/mkrmd
# make
cd $MINOS
$MINOS/tools/mkrmd/mkrmd -f ramdisk-6.1.bin $LINUX/arch/arm64/boot/Image $MINOS/qemu-virt.dtb
mount -o loop,offset=32256 $IMG /mnt
cp $MINOS/minos.bin /mnt/kernel.bin
cp $MINOS/dtbs/qemu-arm64.dtb /mnt
cp $MINOS/ramdisk-6.1.bin /mnt/ramdisk.bin
umount /mnt
# cp $MINOS/generic/minos-linux-driver/minos_hypercall.h /home/arisan/HDD/Arm/testcase/minos/minos_hypercall.h