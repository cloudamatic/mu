name 'mu-openvpn'
maintainer 'eGlobalTech, Inc'
maintainer_email 'mu-developers@googlegroups.com'
license 'All rights reserved'
description 'Installs/Configures mu-openvpn'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.1.0'
depends 'chef-vault', '< 3.0'
depends 'mu-utility'
depends 'mu-firewall'
