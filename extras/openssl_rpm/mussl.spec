Summary: OpenSSL for Mu on RHEL6-compatible systems
BuildArch: x86_64
Name: mussl
Version: 1.1.1h
Release: 1%{dist}
Group: Development/Languages
License: https://www.openssl.org/source/license-openssl-ssleay.txt
URL: https://www.openssl.org/
Prefix: /opt/openssl
Source: https://www.openssl.org/source/openssl-%{version}.tar.gz

AutoReq: yes

%description
I was agitated when I wrote this spec file
    
%prep
rm -rf $RPM_BUILD_DIR/openssl-%{version}
rm -rf %{prefix}
test -f $RPM_SOURCE_DIR/openssl-%{version}.tar.gz || ( cd $RPM_SOURCE_DIR && curl -O https://www.openssl.org/source/openssl-%{version}.tar.gz )
tar -xzvf $RPM_SOURCE_DIR/openssl-%{version}.tar.gz
mkdir -p $RPM_BUILD_ROOT%{prefix}
rm -rf $RPM_BUILD_ROOT%{prefix}/openssl-%{version}
ln -s %{prefix}/openssl-%{version} $RPM_BUILD_ROOT%{prefix}/openssl-%{version}
    
%build
cd $RPM_BUILD_DIR/openssl-%{version}
mkdir -p %{prefix}/openssl-%{version}
env -i PATH="/bin:/usr/bin" ./config --prefix=%{prefix}/openssl-%{version}
env -i PATH="/bin:/usr/bin" make

%install
cd $RPM_BUILD_DIR/openssl-%{version}
env -i PATH="/bin:/usr/bin" make install
mkdir -p $RPM_BUILD_ROOT%{prefix}
mv %{prefix}/openssl-%{version} $RPM_BUILD_ROOT%{prefix}/
mkdir -p $RPM_BUILD_ROOT/usr/local/
ln -s %{prefix}/openssl-%{version} $RPM_BUILD_ROOT/usr/local/openssl-current

%clean
cd $RPM_BUILD_DIR/openssl-%{version}
make clean
    
%files
%{prefix}/openssl-%{version}/*
/usr/local/openssl-current
