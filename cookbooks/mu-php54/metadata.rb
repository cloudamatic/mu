name 'mu-php54'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'

description 'Installs/Configures php'
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 14.0'
version '0.3.1'

%w( centos ubuntu ).each do |os|
	supports os
end

depends 'mu-utility'
depends 'simple_iptables', '~> 0.8.0'
depends 'mysql', '~> 8.5.1'
depends 'yum-epel', '~> 5.0.8'
depends 'apache2', '~> 9.0.3'
