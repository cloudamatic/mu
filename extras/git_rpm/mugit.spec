Summary: Git for Mu on RHEL7-compatible systems
BuildArch: x86_64
Name: mugit
Version: 2.30.0
Release: 1%{dist}
Group: Development/Languages
License: https://git-scm.com/about/free-and-open-source
URL: https://git-scm.com/
Prefix: /opt/git
Source: https://github.com/git/git.git

AutoReq: yes

%description
I was surprisingly chill when I wrote this spec file
    
%prep
rm -rf $RPM_BUILD_DIR/git-%{version}
rm -rf $RPM_SOURCE_DIR/git*
rm -rf %{prefix}
test -f $RPM_SOURCE_DIR/git-%{version}/GIT-VERSION-GEN || ( cd $RPM_SOURCE_DIR && git clone https://github.com/git/git.git )
cd $RPM_SOURCE_DIR && mv git $RPM_BUILD_DIR/git-%{version}
mkdir -p $RPM_BUILD_ROOT%{prefix}
rm -rf $RPM_BUILD_ROOT%{prefix}/git-%{version}
ln -s %{prefix}/git-%{version} $RPM_BUILD_ROOT%{prefix}/git-%{version}
    
%build
cd $RPM_BUILD_DIR/git-%{version}
mkdir -p %{prefix}/git-%{version}
env -i PATH="/bin:/usr/bin" git checkout v%{version}
env -i PATH="/bin:/usr/bin" rm -rf .git
env -i PATH="/bin:/usr/bin" make configure
env -i PATH="/bin:/usr/bin" ./configure --prefix=%{prefix}/git-%{version}
env -i PATH="/bin:/usr/bin" make all

%install
cd $RPM_BUILD_DIR/git-%{version}
env -i PATH="/bin:/usr/bin" make install
mkdir -p $RPM_BUILD_ROOT%{prefix}
mv %{prefix}/git-%{version} $RPM_BUILD_ROOT%{prefix}/
mkdir -p $RPM_BUILD_ROOT/usr/local/
ln -s %{prefix}/git-%{version} $RPM_BUILD_ROOT/usr/local/git-current
# some idiot utility expects this to be present because reasons
touch /rpmbuild/SOURCES/git.git

%clean
cd $RPM_BUILD_DIR/git-%{version}
make clean
rm -f /rpmbuild/SOURCES/git.git
    
%files
%{prefix}/git-%{version}/*
/usr/local/git-current
