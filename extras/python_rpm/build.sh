#!/bin/sh

rpm -q rpm-build || yum -y install rpm-build

base="/opt/mu/lib/extras/python_rpm"

for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS;do
  mkdir -p ~/rpmbuild/$d
done
cd ~/rpmbuild

echo "Temporarily deleting /usr/local/python-current so rpmbuild can create it"
link="`readlink /usr/local/python-current`"
rm -f /usr/local/python-current
/usr/bin/rpmbuild -ba $base/muthon.spec
find ~/rpmbuild/ -type f -name 'muthon*' -exec ls -la {} \;
if [ "$link" != "" ];then
  ln -s "$link" /usr/local/python-current
fi
