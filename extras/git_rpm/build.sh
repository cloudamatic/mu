#!/bin/sh

rpm -q rpm-build || yum -y install rpm-build

base="/opt/mu/lib/extras/git_rpm"

for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS;do
  mkdir -p ~/rpmbuild/$d
done
cd ~/rpmbuild

echo "Temporarily deleting /usr/local/git-current so rpmbuild can create it"
link="`readlink /usr/local/git-current`"
rm -f /usr/local/git-current
env -i PATH="/bin:/usr/bin" /usr/bin/rpmbuild -ba $base/mugit.spec
find ~/rpmbuild/ -type f -name 'mugit*' -exec ls -la {} \;
if [ "$link" != "" ];then
  ln -s "$link" /usr/local/git-current
fi
