name 'mu-mongo'
maintainer 'John Stange'
maintainer_email 'john.stange@eglobaltech.com'
license 'BSD-3-Clause'
description 'Installs/Configures a Mongo DB cluster'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.5.0'

%w( centos ).each do |os|
	supports os
end

depends 'mongodb', '~> 0.16.2'
depends 'chef-vault', '~> 3.1.1'