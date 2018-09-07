name 'mu-splunk'
maintainer 'eGlobalTech'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Manage Splunk Enterprise or Splunk Universal Forwarder. Forked chef-splunk (https://github.com/chef-cookbooks/chef-splunk)'
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '1.3.0'

%w( amazon centos redhat windows ).each do |os|
	supports os
end

# for secrets management in setup_auth recipe
depends 'chef-vault', '~> 3.1.1'
depends 'windows', '~> 5.1.1'