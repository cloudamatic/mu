name 'mu-php54'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'

description 'Installs/Configures php'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 14.0' if respond_to?(:chef_version)
version '0.3.1'

%w( centos ubuntu ).each do |os|
	supports os
end

depends 'mu-utility'
depends 'simple_iptables', '~> 0.8.0'
depends 'mysql', '~> 8.5.1'
depends 'yum-epel', '~> 3.2.0'
