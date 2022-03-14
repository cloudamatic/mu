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

if !node['application_attributes']['skip_recipes'].include?('nrpe')
  case node['platform_family']
    when "rhel", "amazon"
    package ['nrpe', 'nagios-plugins-disk', 'nagios-plugins-nrpe', 'nagios-plugins-ssh'] 
    master_ips = get_mu_master_ips
    master_ips << "127.0.0.1"
    master_ips.uniq!
  
    include_recipe "mu-tools::set_local_fw"
  
    template "/etc/nagios/nrpe.cfg" do
      source "nrpe.cfg.erb"
      mode 0644
      variables(
        :master_ips => master_ips
      )
      notifies :restart, "service[nrpe]", :delayed
    end
  
    service "nrpe" do
      action [:enable, :start]
    end
  
    directory "/etc/nagios/nrpe.d" do
      owner "nrpe"
      group "nrpe"
      mode 0755
    end
  
    case elversion
    when 7
      %w{nrpe_file.pp nrpe_file.te nrpe_check_disk.te nrpe_check_disk.pp nrpe_conf_d.pp}.each { |f|
        cookbook_file "#{Chef::Config[:file_cache_path]}/#{f}" do
          source f
        end
      }
  
      execute "Allow NRPE checks through SELinux" do
        command "/usr/sbin/semodule -i nrpe_file.pp"
        cwd Chef::Config[:file_cache_path]
        not_if "/usr/sbin/semodule -l | grep nrpe_file"
        notifies :restart, "service[nrpe]", :delayed
      end
  
      execute "Allow NRPE check_disk through SELinux" do
        command "/usr/sbin/semodule -i nrpe_check_disk.pp"
        cwd Chef::Config[:file_cache_path]
        not_if "/usr/sbin/semodule -l | grep nrpe_check_disk"
        notifies :restart, "service[nrpe]", :delayed
      end
  
      execute "Allow NRPE to read /etc/nagios/nrpe.d through SELinux" do
        command "/usr/sbin/semodule -i nrpe_conf_d.pp"
        cwd Chef::Config[:file_cache_path]
        not_if "/usr/sbin/semodule -l | grep nrpe_conf_d"
        notifies :restart, "service[nrpe]", :delayed
      end

      package "nagios-plugins-check-updates"
      nrpe_check "check_updates" do
        command "#{node['nrpe']['plugin_dir']}/check_updates --security-only"
        action :add
        notifies :run, 'execute[selinux permissions]', :immediately if node['platform'] != 'amazon'
        notifies :restart, "service[nrpe]", :delayed
      end
    when 6
      if node['platform'] != 'amazon'
        cookbook_file "nrpe_disk.pp" do
          path "#{Chef::Config[:file_cache_path]}/nrpe_disk.pp"
        end
    
        execute "Allow NRPE disk checks through SELinux" do
          command "/usr/sbin/semodule -i nrpe_disk.pp"
          cwd Chef::Config[:file_cache_path]
          not_if "/usr/sbin/semodule -l | grep nrpe_disk"
          notifies :restart, "service[nrpe]", :delayed
        end
      end
    end
  
    service "nrpe" do
      action [:enable, :start]
    end

    # Workaround for Amazon Linux/Chef 14 problem in nrpe cookbook
    # https://github.com/sous-chefs/nrpe/issues/96
    node.normal['nrpe']['plugin_dir'] = "/usr/lib64/nagios/plugins"
    node.save

    nrpe_check "check_disk" do
      command "#{node['nrpe']['plugin_dir']}/check_disk"
      warning_condition '15%'
      critical_condition '5%'
      action :add
      notifies :run, 'execute[selinux permissions]', :immediately if node['platform'] != 'amazon'
      notifies :restart, "service[nrpe]", :delayed
    end

    # execute "chmod o+r /etc/nagios/nrpe.d/check_disk.cfg"
    # file "/etc/nagios/nrpe.d/check_disk.cfg" do
      # mode 0640
      # owner "nagios"
      # group "nagios"
    # end
  
    # don't run this every time so it won't restart the NRPE service on every chef run
    if node['platform'] != 'amazon'
      execute "selinux permissions" do
        command "/usr/bin/chcon -R -t nrpe_etc_t /etc/nagios/nrpe.d/"
        notifies :restart, "service[nrpe]", :delayed
        action :nothing
      end
    end

    execute "restorecon -Rv /etc/nagios/nrpe.d"
    service "nrpe" do
      action [:enable, :start]
    end
  end
end
