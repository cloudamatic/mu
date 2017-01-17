name 'mu-splunk'
maintainer 'eGlobalTech'
maintainer_email 'mu-developers@googlegroups.com'
license 'Apache 2.0'
description 'Manage Splunk Enterprise or Splunk Universal Forwarder. Forked chef-splunk (https://github.com/chef-cookbooks/chef-splunk)'
version '1.3.0'

# for secrets management in setup_auth recipe
depends 'chef-vault', '>= 1.0.4'
depends 'windows'
