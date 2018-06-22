name 'mu-tools'
maintainer 'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license 'BSD-3-Clause'
description 'Mu-specific platform capabilities'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 12.1' if respond_to?(:chef_version)
version '1.0.4'
depends "oracle-instantclient"
depends "nagios"
depends "database"
depends "postgresql"
depends "build-essential", '~> 8.0'
depends "mu-utility"
depends "java"
depends "windows", '= 3.2.0'
depends "mu-splunk"
depends "chef-vault"
depends "poise-python"
depends "yum-epel"
depends "mu-firewall"
depends "mu-activedirectory"
