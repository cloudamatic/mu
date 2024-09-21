name 'mu-master'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Installs/Configures mu-master'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.9.9'

%w( centos amazon redhat ).each do |os|
	supports os
end

depends 'nagios'
depends 'nrpe', '~> 2.0.3'
depends 'mu-utility'
depends 'mu-tools'
depends 'mu-activedirectory'
depends 's3fs'
depends 'postfix', '~> 5.3.1'
depends 'bind', '~> 2.2.0'
depends 'bind9-ng', '~> 0.1.0'
depends 'mu-firewall'
#depends 'vault-cluster', '~> 2.1.0'
#depends 'consul-cluster', '~> 2.0.0'
depends 'chef-sugar' # undeclared dependency of consul 2.1, which can't be upgraded without creating a conflict with consul-cluster and vault-cluster -zr2d2
depends 'hostsfile', '~> 3.0.1'
depends 'chef-vault', '~> 3.1.1'
depends 'apache2', '~> 9.0.3'
