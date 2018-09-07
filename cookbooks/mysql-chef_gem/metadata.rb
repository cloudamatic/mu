name 'mysql-chef_gem'
maintainer 'Chef Software, Inc.'
maintainer_email 'cookbooks@getchef.com'
license 'BSD-3-Clause'
description 'Provides the mysql_chef_gem resource'
source_url 'https://github.com/cloudamatic/mu'
issues_url 'https://github.com/cloudamatic/mu/issues'
chef_version '>= 14.0' if respond_to?(:chef_version)
version '0.0.5'

supports 'amazon'
supports 'redhat'
supports 'centos'
supports 'scientific'
supports 'fedora'
supports 'debian'
supports 'ubuntu'
supports 'smartos'
# supports          'omnios'

depends 'mysql'
