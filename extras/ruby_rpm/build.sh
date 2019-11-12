#!/bin/sh

rpm -q rpm-build || yum -y install rpm-build

base="/opt/mu/lib/extras/ruby_rpm"

for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS;do
  mkdir -p ~/rpmbuild/$d
done
cd ~/rpmbuild

echo "Temporarily deleting /usr/local/ruby-current so rpmbuild can create it"
oldlink="`readlink /usr/local/ruby-current`"
rm -f /usr/local/ruby-current
/usr/bin/rpmbuild -ba $base/muby.spec
find ~/rpmbuild/ -type f -name 'muby*' -exec ls -la {} \;
ln -s "$oldlink" /usr/local/ruby-current
