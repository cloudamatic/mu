name 'mu-tools'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Mu-specific platform capabilities'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 14.0' if respond_to?(:chef_version)
version '1.1.1'

%w( amazon centos redhat windows ).each do |os|
	supports os
end

depends "oracle-instantclient", '~> 1.1.0'
depends "nagios"
depends "database", '~> 6.1.1'
depends "postgresql", '~> 7.1.0'
depends "mu-utility"
depends "java", '~> 2.2.0'
depends "windows", '~> 5.1.1'
depends "mu-splunk"
depends "chef-vault", '~> 3.1.1'
#depends "poise-python", '~> 1.7.0'
depends "yum-epel", '~> 5.0.8'
depends "mu-firewall"
depends "mu-activedirectory"
depends "chocolatey"
depends 'selinux', '~> 3.0.0'
