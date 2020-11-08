#!/bin/sh

rpm -q rpm-build || yum -y install rpm-build

base="/opt/mu/lib/extras/sqlite_rpm"

for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS;do
  mkdir -p ~/rpmbuild/$d
done
cd ~/rpmbuild

echo "Temporarily deleting /usr/local/sqlite-current so rpmbuild can create it"
link="`readlink /usr/local/sqlite-current`"
rm -f /usr/local/sqlite-current
env -i PATH="/bin:/usr/bin" /usr/bin/rpmbuild -ba $base/muqlite.spec
find ~/rpmbuild/ -type f -name 'muqlite*' -exec ls -la {} \;
if [ "$link" != "" ];then
  ln -s "$link" /usr/local/sqlite-current
fi
