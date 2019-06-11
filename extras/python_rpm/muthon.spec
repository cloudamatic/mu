Summary: Python for Mu
BuildArch: x86_64
Name: muthon
Version: 2.7.16
Release: 1%{dist}
Group: Development/Languages
License: Ruby License/GPL - see COPYING
URL: https://www.python.org/
Prefix: /opt/pythons
Source: https://www.python.org/ftp/python/%{version}/Python-%{version}.tgz

# auto-require inserts nonsensical things, like a dependency on our own
# executable, so I guess we'll declare dependencies by package ourselves
AutoReq: no
# XXX these don't work for some reason
#%global __requires_exclude ^/usr/local/bin/python$
#%global __requires_exclude ^/opt/pythons/Python-%{version}/bin/python.*$

BuildRequires: zlib-devel
BuildRequires: tcl-devel
BuildRequires: gdbm-devel
BuildRequires: openssl-devel
BuildRequires: sqlite-devel
BuildRequires: tk-devel
Requires: zlib
Requires: gdbm
Requires: tcl
Requires: openssl
Requires: glibc
Requires: ncurses-libs
Requires: sqlite
Requires: tk

%description
I was sober when I wrote this spec file
    
%prep
rm -rf $RPM_BUILD_DIR/Python-%{version}
rm -rf %{prefix}
test -f $RPM_SOURCE_DIR/Python-%{version}.tgz || ( cd $RPM_SOURCE_DIR && curl -O https://www.python.org/ftp/python/%{version}/Python-%{version}.tgz )
curl https://bootstrap.pypa.io/get-pip.py -o $RPM_SOURCE_DIR/get-pip.py
tar -xzvf $RPM_SOURCE_DIR/Python-%{version}.tgz
mkdir -p $RPM_BUILD_ROOT%{prefix}
rm -rf $RPM_BUILD_ROOT%{prefix}/Python-%{version}
ln -s %{prefix}/Python-%{version} $RPM_BUILD_ROOT%{prefix}/Python-%{version}
    
%build
cd $RPM_BUILD_DIR/Python-%{version}
mkdir -p %{prefix}/Python-%{version}
env -i PATH="/bin:/usr/bin" ./configure --prefix=%{prefix}/Python-%{version} --exec-prefix=%{prefix}/Python-%{version} --enable-shared LDFLAGS=-Wl,-rpath=%{prefix}/Python-%{version}/lib
env -i PATH="/bin:/usr/bin" make

%install
cd $RPM_BUILD_DIR/Python-%{version}
env -i PATH="/bin:/usr/bin" make install
%{prefix}/Python-%{version}/bin/python $RPM_SOURCE_DIR/get-pip.py --prefix %{prefix}/Python-%{version}/
mkdir -p $RPM_BUILD_ROOT%{prefix}
mv %{prefix}/Python-%{version} $RPM_BUILD_ROOT%{prefix}/
mkdir -p $RPM_BUILD_ROOT/usr/local/
ln -s %{prefix}/Python-%{version} $RPM_BUILD_ROOT/usr/local/python-current

%clean
cd $RPM_BUILD_DIR/Python-%{version}
make clean
    
%files
%{prefix}/Python-%{version}/*
/usr/local/python-current
