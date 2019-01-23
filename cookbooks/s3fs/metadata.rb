name 's3fs'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Installs/Configures s3fs'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 14.0' if respond_to?(:chef_version)
version '0.2.0'

%w( amazon centos redhat windows ).each do |os|
	supports os
end

depends "mu-utility"
