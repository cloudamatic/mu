name 'mu-php54'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'

description 'Installs/Configures php'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.3.0'

%w( centos ubuntu ).each do |os|
	supports os
end

depends 'build-essential', '~> 8.2.1'
depends 'mu-utility'
depends 'simple_iptables', '~> 0.8.0'
depends 'apache2', '~> 5.2.1'
depends 'mysql', '~> 8.5.1'
depends 'yum-epel', '~> 3.2.0'