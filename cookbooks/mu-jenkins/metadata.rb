name 'mu-jenkins'
maintainer 'eGlobalTech, Inc'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Installs/Configures mu-jenkins'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.6.0'

%w( amazon centos redhat windows ).each do |os|
	supports os
end

depends 'java'
depends 'jenkins', '~> 5.0.1'
depends 'chef-vault', '< 3.0'
depends 'mu-master'
depends 'mu-utility'
depends 'mu-tools'
