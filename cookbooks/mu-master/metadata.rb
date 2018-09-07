name 'mu-master'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Installs/Configures mu-master'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.9.0'

%w( centos ).each do |os|
	supports os
end

depends 'nagios'
depends 'nrpe'
depends 'mu-utility'
depends 'mu-tools'
depends 'mu-activedirectory'
depends 's3fs'
depends 'postfix'
depends 'bind'
depends 'bind9-ng'
depends 'mu-firewall'
depends 'vault-cluster'
depends 'consul-cluster'
depends 'hostsfile'
depends 'chef-vault', '< 3.0'
depends 'apache2', '< 4.0'