#!/bin/sh

rpm -q rpm-build || yum -y install rpm-build

base="/opt/mu/lib/extras/python_rpm"

for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS;do
  mkdir -p /root/rpmbuild/$d
done
cd /root/rpmbuild

echo "Temporarily deleting /usr/local/python-current so rpmbuild can create it"
link="`readlink /usr/local/python-current`"
rm -f /usr/local/python-current
chmod 000 /usr/bin/python # otherwise this brain-dead build system tries to compile parts of itself with the wrong executable
env -i HOME=/root PATH="/bin:/usr/bin" /usr/bin/rpmbuild -ba $base/muthon.spec
chmod 755 /usr/bin/python
find /root/rpmbuild/ -type f -name 'muthon*' -exec ls -la {} \;
if [ "$link" != "" ];then
  ln -s "$link" /usr/local/python-current
fi
