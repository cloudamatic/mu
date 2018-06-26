name 'mu-activedirectory'
maintainer 'eGlobalTech,'
maintainer_email 'ecap-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Installs/Configures mu-activedirectory'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.2.0'
depends "windows", '= 3.2.0'
depends "chef-vault", '< 3.0'
depends "yum-epel"
depends "build-essential", '~> 8.0'

%w( amazon centos redhat windows ).each do |os|
	supports os
end