#!/bin/sh

rpm -q rpm-build || yum -y install rpm-build

base="/opt/mu/lib/extras/openssl_rpm"

for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS;do
  mkdir -p ~/rpmbuild/$d
done
cd ~/rpmbuild

echo "Temporarily deleting /usr/local/openssl-current so rpmbuild can create it"
link="`readlink /usr/local/openssl-current`"
rm -f /usr/local/openssl-current
env -i PATH="/bin:/usr/bin" /usr/bin/rpmbuild -ba $base/mussl.spec
find ~/rpmbuild/ -type f -name 'mussl*' -exec ls -la {} \;
if [ "$link" != "" ];then
  ln -s "$link" /usr/local/openssl-current
fi
