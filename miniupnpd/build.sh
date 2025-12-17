make clean
./configure --firewall=nftables && make
cp miniupnpd miniupnpd-custom/usr/sbin/
dpkg-deb --build miniupnpd-custom
