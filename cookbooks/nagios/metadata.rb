name              'nagios'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license           'BSD-3-Clause'
description       'Installs and configures Nagios server'
long_description  IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version           '7.2.7'
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version     '>= 14.0' if respond_to?(:chef_version)

recipe 'default', 'Installs Nagios server.'
recipe 'nagios::pagerduty', 'Integrates contacts w/ PagerDuty API'

depends 'apache2', '< 4.0'
depends 'php', '< 6.0'
depends 'zap', '>= 0.6.0'

%w(chef_nginx nginx_simplecgi yum-epel nrpe ).each do |cb|
  depends cb
end

%w( debian ubuntu redhat centos fedora scientific amazon oracle).each do |os|
  supports os
end
