# Cookbook Name:: mu-tools
# Recipe:: nrpe
#
# Copyright:: Copyright (c) 2016 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and

case node[:platform]
  when "centos"

    ['nrpe', 'nagios-plugins-disk'].each do |pkg|
      package pkg 
    end

    service "nrpe" do
      action [:enable, :start]
    end

    template "/etc/nagios/nrpe.cfg" do
      source "nrpe.cfg.erb"
      mode 0644
      notifies :restart, "service[nrpe]", :immediately
    end

    bash "Allow Nagios server through iptables" do
      user "root"
      not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:5666($| )'"
      code <<-EOH
        /sbin/iptables -I INPUT -s 10.0.0.0/8 -p tcp --dport 5666 -j ACCEPT
        /sbin/iptables -I INPUT -s 52.0.111.223 -p tcp --dport 5666 -j ACCEPT
        service iptables save
      EOH
    end

    directory "/etc/nagios/nrpe.d" do
      owner "nrpe"
      group "nrpe"
      mode 0755
    end

    execute "/usr/bin/chcon -R -t nrpe_etc_t /etc/nagios/nrpe.d/" do
      notifies :restart, "service[nrpe]", :immediately
    end

    if Dir.exists?("/gluster/dev/md0")
      execute "chmod go+rx /gluster /gluster/dev /gluster/dev/md0"
    end

    file "/etc/sudoers.d/nrpe" do
      content "nagios          ALL=(ALL) NOPASSWD: /usr/lib/nagios/plugins/\n"
    end
end
