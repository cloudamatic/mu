name 'mu-php54'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
depends 'build-essential', '~> 8.0'
depends 'mu-utility'
depends 'simple_iptables'
depends 'apache2', '< 4.0'
depends 'mysql'
depends 'yum-epel'
description 'Installs/Configures php'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)

%w( centos ubuntu ).each do |os|
	supports os
end

version '0.3.0'
