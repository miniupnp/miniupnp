apt install git
apt install make
apt install build-essential
apt install uuid-dev
apt install pkg-config libuuid1 uuid-dev libxtables-dev
apt install libiptc0 libiptc-dev
apt-get install libxtables-dev libiptc-dev
apt install libmnl-dev libnetfilter-conntrack-dev
apt-get install libcap-ng-dev
apt-get install libnftnl-dev libmnl-dev
apt-get install libnetfilter-conntrack-dev
make clean
./configure --firewall=nftables && make
cp miniupnpd miniupnpd-custom/usr/sbin/
dpkg-deb --build miniupnpd-custom
