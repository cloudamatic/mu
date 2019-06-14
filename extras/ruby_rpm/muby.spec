Summary: Ruby for Mu(by)
BuildArch: x86_64
Name: muby
Version: 2.5.5
Release: 1%{dist}
Group: Development/Languages
License: Ruby License/GPL - see COPYING
URL: http://www.ruby-lang.org/
Prefix: /opt/rubies
Source: https://cache.ruby-lang.org/pub/ruby/2.5/ruby-%{version}.tar.gz

BuildRequires: zlib
BuildRequires: zlib-devel
BuildRequires: openssl

%description
I was drunk when I wrote this spec file
    
%prep
rm -rf $RPM_BUILD_DIR/ruby-%{version}
rm -rf %{prefix}
test -f $RPM_SOURCE_DIR/ruby-%{version}.tar.gz || ( cd $RPM_SOURCE_DIR && curl -O https://cache.ruby-lang.org/pub/ruby/2.5/ruby-%{version}.tar.gz )
tar -xzvf $RPM_SOURCE_DIR/ruby-%{version}.tar.gz
mkdir -p $RPM_BUILD_ROOT%{prefix}
ln -s %{prefix}/ruby-%{version} $RPM_BUILD_ROOT%{prefix}/ruby-%{version}
    
%build
cd $RPM_BUILD_DIR/ruby-%{version}
./configure --prefix=%{prefix}/ruby-%{version}  --enable-load-relative --enable-shared
make

%install
cd $RPM_BUILD_DIR/ruby-%{version}
make install
mkdir -p %{prefix}
%{prefix}/ruby-%{version}/bin/gem install bundler
mkdir -p $RPM_BUILD_ROOT%{prefix}
mv %{prefix}/ruby-%{version} $RPM_BUILD_ROOT%{prefix}/
mkdir -p $RPM_BUILD_ROOT/usr/local/
ln -s %{prefix}/ruby-%{version} $RPM_BUILD_ROOT/usr/local/ruby-current

%clean
cd $RPM_BUILD_DIR/ruby-%{version}
make clean
    
%files
%{prefix}/ruby-%{version}/*
/usr/local/ruby-current
