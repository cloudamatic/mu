name             'demo'
maintainer       'Mu'
maintainer_email 'mu-developers@googlegroups.com'
license          '# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
## Licensed under the BSD-3 license (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License in the root of the project or at
##
##     http://egt-labs.com/mu/LICENSE.html
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.'
description      'Installs/Configures demo application'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version          '0.2.0'
depends          'git'
depends          'application'
depends          'application_python', '~> 3.0'
depends          'nginx'
depends          'application_ruby'
depends          'ruby_build'
depends          'nodejs'
depends          'php'
depends          'mysql'
