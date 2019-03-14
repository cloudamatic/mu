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

depends 'java', '~> 2.2.0'
depends 'jenkins', '~> 6.2.0'
depends 'chef-vault', '~> 3.1.1'
depends 'mu-master'
depends 'mu-utility'
depends 'mu-tools'
