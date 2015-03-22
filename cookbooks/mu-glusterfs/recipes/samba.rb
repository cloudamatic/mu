#
# Cookbook Name:: mu-glusterfs
# Recipe:: samba
#
# Copyright 2014, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

::Chef::Recipe.send(:include, Chef::Mixin::ShellOut)

case node[:platform]
    when "centos"

    %w{samba-vfs-glusterfs samba-client samba}.each do |pkg|
      package pkg
    end

		service "smb"

		["137", "139", "445"].each { |port|
			bash "Allow #{port} through iptables" do
				user "root"
				not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:#{port}($| )'"
				code <<-EOH
					iptables -I INPUT -s 10.0.0.0/8 --dport #{port} -j ACCEPT
					service iptables save
				EOH
			end
		}
		
		directory "/etc/samba/includes"
		template "/etc/samba/includes/smb.gluster.conf" do
			source "smb.conf.erb"
			owner "root"
			group "root"
			mode 0644
			cookbook "mu-glusterfs"
			notifies :restart, "service[smb]", :immediately
		end
		execute "setsebool -P samba_run_unconfined on" do
                        not_if "getsebool samba_run_unconfined | grep ' on$'"
                end
                execute "setsebool -P samba_export_all_rw on" do
                        not_if "getsebool samba_export_all_rw | grep ' on$'"
                end


		directory "/run/samba" 

    else
        Chef::Log.info("Unsupported platform #{node[:platform]}")
end
