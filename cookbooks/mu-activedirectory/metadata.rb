name 'mu-activedirectory'
maintainer 'eGlobalTech,'
maintainer_email 'ecap-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Installs/Configures mu-activedirectory'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 14.0' if respond_to?(:chef_version)
version '0.2.0'
depends "windows", '~> 5.1.1'
depends "chef-vault", '~> 3.1.1'
depends "yum-epel", '~> 5.0.8'

%w( amazon centos redhat windows ).each do |os|
	supports os
end
