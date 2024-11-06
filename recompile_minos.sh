MINOS="/home/arisan/HDD/workspace/myminos"
IMG="/home/arisan/HDD/workspace/myminos/arch.img"
cd $MINOS
make
sudo mount -o loop,offset=32256 $IMG /mnt
sudo cp $MINOS/minos.bin /mnt/kernel.bin
sudo umount /mnt
