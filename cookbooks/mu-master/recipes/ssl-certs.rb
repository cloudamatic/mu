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

service_certs = ["rsyslog", "mommacat", "ldap"]

execute "generate SSL CA key" do
  command "openssl genrsa -out Mu_CA.key 4096"
  cwd "#{MU_BASE}/var/ssl"
  not_if { ::File.exists?("#{MU_BASE}/var/ssl/Mu_CA.key") }
  notifies :delete, "file[#{MU_BASE}/var/ssl/CA-command.txt]", :immediately
end
file "#{MU_BASE}/var/ssl/Mu_CA.key" do
  mode 0400
end
execute "create internal SSL CA" do
  command "openssl req -subj \"/CN=#{$MU_CFG['public_address']}/OU=Mu Server #{$MU_CFG['public_address']}/O=eGlobalTech/C=US\" -x509 -new -nodes -key Mu_CA.key -days 1024 -out Mu_CA.pem -sha512"
  cwd "#{MU_BASE}/var/ssl"
  action :nothing
  service_certs.each { |cert|
    notifies :delete, "file[#{MU_BASE}/var/ssl/#{cert}.crt]", :immediately
  }
end
file "#{MU_BASE}/var/ssl/CA-command.txt" do
  content "openssl req -subj \"/CN=#{$MU_CFG['public_address']}/OU=Mu Server #{$MU_CFG['public_address']}/O=eGlobalTech/C=US\" -x509 -new -nodes -key Mu_CA.key -days 1024 -out Mu_CA.pem -sha512"
  mode 0400
  notifies :run, "execute[create internal SSL CA]", :immediately
end

execute "update CA store" do
  command "/usr/bin/update-ca-trust force-enable; /usr/bin/update-ca-trust extract"
  action :nothing
end
remote_file "/etc/pki/ca-trust/source/anchors/Mu_CA.pem" do
  source "#{MU_BASE}/var/ssl/Mu_CA.pem"
  notifies :run, "execute[update CA store]", :immediately
end
remote_file "#{MU_BASE}/lib/cookbooks/mu-tools/files/default/Mu_CA.pem" do
  source "#{MU_BASE}/var/ssl/Mu_CA.pem"
end

service_certs.each { |cert|
  bash "generate service cert for #{cert}" do
    code <<-EOH
      openssl req -subj "/CN=#{$MU_CFG['public_address']}/OU=Mu #{cert}/O=eGlobalTech/C=US" -new -key #{cert}.key -out #{cert}.csr -sha512
      openssl x509 -req -in #{cert}.csr -CA Mu_CA.pem -CAkey Mu_CA.key -CAcreateserial -out #{cert}.crt -days 500 -sha512
      cat Mu_CA.pem >> #{cert}.crt
      openssl pkcs12 -export -inkey #{cert}.key -in #{cert}.crt -out #{cert}.p12 -nodes -name "#{cert}" -passout pass:""
    EOH
    cwd "#{MU_BASE}/var/ssl"
    not_if { ::File.exists?("#{MU_BASE}/var/ssl/#{cert}.crt") }
  end
  file "#{MU_BASE}/var/ssl/#{cert}.crt" do
    mode 0400
  end
  file "#{MU_BASE}/var/ssl/#{cert}.p12" do
    mode 0400
  end
  file "#{MU_BASE}/var/ssl/#{cert}.csr" do
    action :delete
  end
}
