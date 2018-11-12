name 'mu-openvpn'
maintainer 'eGlobalTech, Inc'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Installs/Configures mu-openvpn'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.1.0'

%w( centos redhat ).each do |os|
	supports os
end

depends 'chef-vault', '~> 3.1.1'
depends 'mu-utility'
depends 'mu-firewall'
