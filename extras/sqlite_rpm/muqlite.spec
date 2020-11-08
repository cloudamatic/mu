Summary: SQLite for Mu on RHEL6-compatible systems
BuildArch: x86_64
Name: muqlite
Version: 3.33
Release: 1%{dist}
Group: Development/Languages
License: https://www.sqlite.org/copyright.html
URL: https://sqlite.org/
Prefix: /opt/sqlite
Source: https://www.sqlite.org/src/tarball/sqlite.tar.gz?r=branch-%{version}

AutoReq: yes

%description
I was surprisingly chill when I wrote this spec file
    
%prep
rm -rf $RPM_BUILD_DIR/sqlite-%{version}
rm -rf %{prefix}
test -f $RPM_SOURCE_DIR/sqlite.tar.gz?r=branch-%{version} || ( cd $RPM_SOURCE_DIR && curl -O https://www.sqlite.org/src/tarball/sqlite.tar.gz?r=branch-%{version} )
tar -xzvf $RPM_SOURCE_DIR/sqlite.tar.gz?r=branch-%{version}
mv sqlite sqlite-%{version}
mkdir -p $RPM_BUILD_ROOT%{prefix}
rm -rf $RPM_BUILD_ROOT%{prefix}/sqlite-%{version}
ln -s %{prefix}/sqlite-%{version} $RPM_BUILD_ROOT%{prefix}/sqlite-%{version}
    
%build
cd $RPM_BUILD_DIR/sqlite-%{version}
mkdir -p %{prefix}/sqlite-%{version}
env -i PATH="/bin:/usr/bin" ./configure --prefix=%{prefix}/sqlite-%{version}
env -i PATH="/bin:/usr/bin" make

%install
cd $RPM_BUILD_DIR/sqlite-%{version}
env -i PATH="/bin:/usr/bin" make install
mkdir -p $RPM_BUILD_ROOT%{prefix}
mv %{prefix}/sqlite-%{version} $RPM_BUILD_ROOT%{prefix}/
mkdir -p $RPM_BUILD_ROOT/usr/local/
ln -s %{prefix}/sqlite-%{version} $RPM_BUILD_ROOT/usr/local/sqlite-current

%clean
cd $RPM_BUILD_DIR/sqlite-%{version}
make clean
    
%files
%{prefix}/sqlite-%{version}/*
/usr/local/sqlite-current
