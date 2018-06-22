name 'mu-activedirectory'
maintainer 'eGlobalTech,'
maintainer_email 'ecap-developers@googlegroups.com'
license 'All rights reserved'
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
