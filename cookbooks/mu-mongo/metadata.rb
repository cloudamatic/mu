name 'mu-mongo'
maintainer 'John Stange'
maintainer_email 'john.stange@eglobaltech.com'
license 'All rights reserved'
description 'Installs/Configures a Mongo DB cluster'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version '0.5.0'
depends 'mongodb', '~> 0.16.2'
depends 'chef-vault', '< 3.0'