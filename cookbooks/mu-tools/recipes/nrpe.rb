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

if !node[:application_attributes][:skip_recipes].include?('nrpe')
  case node[:platform_family]
    when "rhel"

      ['nrpe', 'nagios-plugins-disk', 'nagios-plugins-nrpe', 'nagios-plugins-ssh'].each do |pkg|
        package pkg 
      end
  
      service "nrpe" do
        action [:enable, :start]
      end
  
      master_ips = ["127.0.0.1"]
      master = search(:node, "name:MU-MASTER")
      master.each { |server|
        master_ips << server.ec2.public_ipv4 if !server.ec2.public_ipv4.nil? and !server.ec2.public_ipv4.empty?
        master_ips << server.ec2.local_ipv4 if !server.ec2.local_ipv4.nil? and !server.ec2.local_ipv4.empty?
      }
  
      include_recipe "mu-tools::set_local_fw"
  
      master_ips.each { |ip|
        bash "Allow NRPE through iptables from #{ip}" do
          user "root"
          not_if "/sbin/iptables -nL | egrep '^ACCEPT.*#{ip}.*dpt:5666($| )'"
          if node['platform_version'].to_i < 7
            code <<-EOH
              /sbin/iptables -I INPUT -s #{ip} -p tcp --dport 5666 -j ACCEPT
              service iptables save
            EOH
          else
            code <<-EOH
  #            /bin/firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="#{ip}/32" port protocol="tcp" port="5666" accept'
              /bin/firewall-cmd --reload
            EOH
          end
        end
      }
  
      template "/etc/nagios/nrpe.cfg" do
        source "nrpe.cfg.erb"
        mode 0644
        variables(
          :master_ips => master_ips
        )
        notifies :restart, "service[nrpe]", :delayed
      end
  
      directory "/etc/nagios/nrpe.d" do
        owner "nrpe"
        group "nrpe"
        mode 0755
      end
  
      cookbook_file "nrpe_disk.pp" do
        path "#{Chef::Config[:file_cache_path]}/nrpe_disk.pp"
      end
      
      execute "Allow NRPE disk checks through SELinux" do
        command "/usr/sbin/semodule -i nrpe_disk.pp"
        cwd Chef::Config[:file_cache_path]
        not_if "/usr/sbin/semodule -l | grep nrpe_disk"
        notifies :restart, "service[nrpe]", :delayed
      end
  
      # don't trip up on devices created by our basic gluster recipes
      if Dir.exists?("/gluster/dev/md0")
        execute "chmod go+rx /gluster /gluster/dev /gluster/dev/md0"
      end
  
      nrpe_check "check_disk" do
        command "#{node['nrpe']['plugin_dir']}/check_disk"
        warning_condition '15%'
        critical_condition '5%'
        action :add
        notifies :restart, "service[nrpe]", :delayed
      end
      execute "chmod o+r /etc/nagios/nrpe.d/check_disk.cfg"
      execute "/usr/bin/chcon -R -t nrpe_etc_t /etc/nagios/nrpe.d/" do
        notifies :restart, "service[nrpe]", :delayed
      end
  end
end
