# Cookbook Name:: mu-master
# Recipe:: ssl-certs
#
# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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

# This recipe is meant to be invoked standalone, by chef-apply. It can safely
# be invoked during a regular chef-client run.
#
# When modifying this recipe, DO NOT ADD EXTERNAL DEPENDENCIES. That means no
# references to other cookbooks, no include_recipes, no cookbook_files, no
# templates.

include_recipe 'mu-master::firewall-holes'
service_certs = ["rsyslog", "mommacat", "ldap", "consul", "vault"]

directory $MU_CFG['datadir']
directory "#{$MU_CFG['datadir']}/ssl"
template "#{$MU_CFG['datadir']}/ssl/openssl.cnf" do
  source "openssl.cnf.erb"
  mode 0644
  variables(
    :mu_ssl_dir => "#{$MU_CFG['datadir']}/ssl",
    # XXX I feel like including localhost here is bad but I can't justify that
    # feeling, and 389ds really wants it, so for now it stays.
    :alt_names => [$MU_CFG['public_address'], "localhost", "127.0.0.1", node['fqdn'], node['hostname'], node['local_hostname'], node['local_ipv4'], node['public_hostname'], node['public_ipv4']].uniq
  )
  notifies :delete, "file[#{$MU_CFG['datadir']}/ssl/Mu_CA.pem]", :immediately
end
execute "generate SSL CA key" do
  command "openssl genrsa -out Mu_CA.key 4096"
  cwd "#{$MU_CFG['datadir']}/ssl"
  not_if { ::File.exist?("#{$MU_CFG['datadir']}/ssl/Mu_CA.key") }
  notifies :delete, "file[#{$MU_CFG['datadir']}/ssl/CA-command.txt]", :immediately
end
file "#{$MU_CFG['datadir']}/ssl/Mu_CA.key" do
  mode 0400
end
execute "create internal SSL CA" do
  command "openssl req -subj \"/CN=#{$MU_CFG['public_address']}/OU=Mu Server #{$MU_CFG['public_address']}/O=eGlobalTech/C=US\" -x509 -new -nodes -key Mu_CA.key -days 1024 -out Mu_CA.pem -sha512 -extensions v3_ca -config #{$MU_CFG['datadir']}/ssl/openssl.cnf"
  cwd "#{$MU_CFG['datadir']}/ssl"
  action :nothing
  service_certs.each { |cert|
    notifies :delete, "file[#{$MU_CFG['datadir']}/ssl/#{cert}.crt]", :immediately
  }
end
file "remove CA-command.txt if Mu_CA.pem is empty or missing" do
  path "#{$MU_CFG['datadir']}/ssl/CA-command.txt"
  action :delete
  not_if { ::File.size?("#{$MU_CFG['datadir']}/ssl/Mu_CA.pem") }
end
file "#{$MU_CFG['datadir']}/ssl/CA-command.txt" do
  content "openssl req -subj \"/CN=#{$MU_CFG['public_address']}/OU=Mu Server #{$MU_CFG['public_address']}/O=eGlobalTech/C=US\" -x509 -new -nodes -key Mu_CA.key -days 1024 -out Mu_CA.pem -sha512 -extensions v3_ca -config #{$MU_CFG['datadir']}/ssl/openssl.cnf"
  mode 0400
  notifies :run, "execute[create internal SSL CA]", :immediately
end

execute "update CA store" do
  command "/usr/bin/update-ca-trust force-enable; /usr/bin/update-ca-trust extract"
  action :nothing
end
file "#{$MU_CFG['datadir']}/ssl/Mu_CA.pem" do
  mode 0444
end
remote_file "/etc/pki/ca-trust/source/anchors/Mu_CA.pem" do
  source "file://#{$MU_CFG['datadir']}/ssl/Mu_CA.pem"
  notifies :run, "execute[update CA store]", :immediately
end
remote_file "#{$MU_CFG['installdir']}/lib/cookbooks/mu-tools/files/default/Mu_CA.pem" do
  source "file://#{$MU_CFG['datadir']}/ssl/Mu_CA.pem"
end
execute "chcon -t httpd_config_t #{$MU_CFG['datadir']}/ssl/Mu_CA.pem" do
  not_if "ls -aZ #{$MU_CFG['datadir']}/ssl/Mu_CA.pem | grep 'object_r:httpd_config_t'"
end

service_certs.each { |cert|
  bash "generate service cert for #{cert}" do
    code <<-EOH
      set -e
      echo "Generating #{cert}.key"
      openssl genrsa -out #{cert}.key 4096
      echo "Generating #{cert}.csr"
      openssl req -subj "/CN=#{$MU_CFG['public_address']}/OU=Mu #{cert}/O=eGlobalTech/C=US" -new -key #{cert}.key -out #{cert}.csr -sha512 -extensions v3_ca -config #{$MU_CFG['datadir']}/ssl/openssl.cnf
      echo "Signing #{cert}.csr => #{cert}.crt"
      openssl x509 -req -in #{cert}.csr -CA Mu_CA.pem -CAkey Mu_CA.key -CAcreateserial -out #{cert}.crt -days 500 -sha512 -extensions v3_req -extfile #{$MU_CFG['datadir']}/ssl/openssl.cnf
      cat Mu_CA.pem >> #{cert}.crt
      openssl pkcs12 -export -inkey #{cert}.key -in #{cert}.crt -out #{cert}.p12 -nodes -name "#{cert}" -passout pass:""
    EOH
    cwd "#{$MU_CFG['datadir']}/ssl"
    not_if { ::File.size?("#{$MU_CFG['datadir']}/ssl/#{cert}.crt") }
  end

  %w{key crt p12}.each do |type|
    file "#{$MU_CFG['datadir']}/ssl/#{cert}.#{type}" do
      mode 0400
    end
    execute "chcon -t httpd_config_t #{$MU_CFG['datadir']}/ssl/#{cert}.#{type}" do
      not_if "ls -aZ #{$MU_CFG['datadir']}/ssl/#{cert}.#{type} | grep 'object_r:httpd_config_t'"
    end
  end

  file "#{$MU_CFG['datadir']}/ssl/#{cert}.csr" do
    action :delete
  end
}
