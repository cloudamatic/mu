name 'awscli'
maintainer 'Shlomo Swidler'
maintainer_email 'shlomo.swidler@orchestratus.com'
license 'BSD-3-Clause'
description 'Installs the AWS command line tools'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '0.2.1'

# Mod by rpc to depend on epel recipe.

recipe "default", "Install AWS CLI tools"

%w{redhat centos fedora amazon scientific debian ubuntu}.each do |plat|
  supports plat
end

#depends    'mu-utility::epel'
