# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

default["tmp_directory"] = "/tmp/chef_tmp"
default["wordpress"]["global"]["ports"] = %w{80 443}

############################################################
####################### DEVELOPMENT ########################
############################################################

$environment="development"

# CREDENTIALS
default[$environment]["credentials"]["aws_access"] = ""
default[$environment]["credentials"]["aws_secret"] = ""
default[$environment]["credentials"]["aws_account_number"] = ""

# DB Service
$service="dbservice"
default[$environment][$service]["s3"]["mount_device"] = "mount_bucket:/dbservice"
default[$environment][$service]["s3"]["mount_dir"] = "/apps/public"
default[$environment][$service]["ebs"]["mount_device"] = "/dev/sdl"
default[$environment][$service]["ebs"]["mount_dir"] = "/apps"

default[$environment][$service]["application"]["github_repo"] = "digitalpresence/app-database-service.git"
default[$environment][$service]["application"]["github_repo_name"] = "app-database-service"

default[$environment][$service]["apps_dir"] = "/var/www/html/dbservice"

# DB


# Portal
$service="portal"
default[$environment][$service]["s3"]["mount_device"] = "mount_bucket:/portal"
default[$environment][$service]["s3"]["mount_dir"] = "/apps/public"
default[$environment][$service]["ebs"]["mount_device"] = "/dev/xvdh"
default[$environment][$service]["ebs"]["mount_dir"] = "/apps"

default[$environment][$service]["application"]["github_repo"] = "digitalpresence/app-portal.git"
default[$environment][$service]["application"]["github_repo_name"] = "app-portal"

default[$environment][$service]["apps_dir"] = "/var/www/portal"

############################################################
########################### DEV ############################
############################################################

$environment = 'dev'

# rails
$service = 'rails'
default[$environment][$service]["apps_dir"] = "/apps"
default[$environment][$service]["application"]["rails_repo"] = "concerto/concerto.git"
default[$environment][$service]["application"]["version"] = "2.3.5"

# Django
$service = 'django'
default[$environment][$service]["application"]["django_repo"] = "zr2d2/django-demo.git"
default[$environment][$service]["application"]["django_repo_name"] = "app-django"
default[$environment][$service]["apps_dir"] = "/apps/django"

# Flask
$service = 'flask'
default[$environment][$service]["apps_dir"] = "/apps/flask"

############################################################
####################### PRDOUCTION #########################
############################################################



############################################################
####################### SUPERVISOR #########################
############################################################
default['supervisor']['version']='3.3.3'
default['supervisor']['unix_http_server']['chmod'] = '700'
default['supervisor']['unix_http_server']['chown'] = 'root:root'
default['supervisor']['inet_port'] = nil
default['supervisor']['inet_username'] = nil
default['supervisor']['inet_password'] = nil
case node['platform_family']
when "smartos"
  default['supervisor']['dir'] = '/opt/local/etc/supervisor.d'
  default['supervisor']['conffile'] = '/opt/local/etc/supervisord.conf'
else
  default['supervisor']['dir'] = '/etc/supervisor.d'
  default['supervisor']['conffile'] = '/etc/supervisord.conf'
end
default['supervisor']['log_dir'] = '/var/log/supervisor'
default['supervisor']['logfile_maxbytes'] = '50MB'
default['supervisor']['logfile_backups'] = 10
default['supervisor']['loglevel'] = 'info'
default['supervisor']['minfds'] = 1024
default['supervisor']['minprocs'] = 200
default['supervisor']['nocleanup'] = false
default['supervisor']['socket_file'] = '/var/run/supervisor.sock'
default['supervisor']['ctlplugins'] = {}
