#
# Cookbook Name:: mu-glusterfs
# Recipe:: server
#
# Copyright 2014, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

::Chef::Recipe.send(:include, Chef::Mixin::ShellOut)


case node[:platform]
  when "centos"
		include_recipe "mu-glusterfs"
	  $nodeclass = node.gluster_node_class

        %w{xfsprogs mdadm glusterfs-server samba-vfs-glusterfs samba-client}.each do |pkg|
            package pkg
        end
		
		if node.glusterfs.server.raid
			def raid_no_spare(mount_dev, level, num_devices, devices)
				execute "yes | mdadm -Cv #{mount_dev} -l#{level} -n#{num_devices} #{devices}" do
					not_if "mdadm --detail #{mount_dev}"
				end
			end
			def raid_with_spare(mount_dev, level, num_devices, devices, spare_device)
				execute "yes | mdadm -Cv #{mount_dev} -l#{level} -n#{num_devices} #{devices} -x1 #{spare_device}" do
					not_if "mdadm --detail #{mount_dev}"
				end
			end

			if node.glusterfs.server.raid_level == 10
				array1, array2 = node.glusterfs.server.devices.each_slice(node.glusterfs.server.devices.size/2).to_a
				if node.glusterfs.server.raid_spare_vol
					array1_spare_device = array1.pop
					array2_spare_device = array2.pop
					raid_with_spare("/dev/md1", 1, array1.size, array1.join(" "), array1_spare_device)
					raid_with_spare("/dev/md2", 1, array2.size, array2.join(" "), array2_spare_device)
				else
					raid_no_spare("/dev/md1", 1, array1.size, array1.join(" "))
					raid_no_spare("/dev/md2", 1, array2.size, array2.join(" "))
				end
				raid_no_spare("/dev/md0", 0, 2, "/dev/md1 /dev/md2")
			else
				node.glusterfs.server.raid_levels_map.each do |type|
					if node.glusterfs.server.raid_spare_vol
						if type['level'] == node.glusterfs.server.raid_level and type['spare'] == node.glusterfs.server.raid_spare_vol and node.glusterfs.server.devices.size >= type['min_devcies'] 
							spare_device = node.glusterfs.server.devices.pop
							raid_with_spare(node.glusterfs.server.raid_dev, node.glusterfs.server.raid_level, node.glusterfs.server.devices.size, node.glusterfs.server.devices.join(" "), spare_device)
						end
					else
						if type['level'] == node.glusterfs.server.raid_level and type['spare'] == node.glusterfs.server.raid_spare_vol and node.glusterfs.server.devices.size >= type['min_devcies']
							raid_no_spare(node.glusterfs.server.raid_dev, node.glusterfs.server.raid_level, node.glusterfs.server.devices.size, node.glusterfs.server.devices.join(" "))
						end
					end
				end
			end

			execute "mdadm --detail --scan >> /etc/mdadm.conf" do
				not_if { File.exists?("/etc/mdadm.conf") }
			end

			execute "mkfs -t xfs -i size=512 #{node.glusterfs.server.raid_dev}" do
				not_if "xfs_info #{node.glusterfs.server.raid_dev}"
			end
			
			$gluster_mnt_pt = "#{node.glusterfs.server.brick_base_mount_path}#{node.glusterfs.server.raid_dev}"
			
			directory $gluster_mnt_pt do
				recursive true
			end
			mount $gluster_mnt_pt do
				device node.glusterfs.server.raid_dev
				fstype "xfs"
				action [ :mount, :enable ]
			end
			directory "#{$gluster_mnt_pt}/brick"
			
		else
			$gluster_mnt_pts []
			node.glusterfs.server.devices.each do |dev|
				execute "mkfs -t xfs -i size=512 #{dev}" do
					not_if "xfs_info -l #{dev}"
				end
				directory "#{node.glusterfs.server.brick_base_mount_path}#{dev}" do
					recursive true
				end
				mount "#{node.glusterfs.server.brick_base_mount_path}#{dev}" do
					device dev
					fstype "xfs"
					action [ :mount, :enable ]
				end
				directory "#{node.glusterfs.server.brick_base_mount_path}#{dev}/brick"
				
				$gluster_mnt_pts << "#{node.glusterfs.server.brick_base_mount_path}#{dev}"
			end
		end
		
		node.glusterfs.fw.each do |rule|
			bash "Allow TCP #{rule['port_range']} through iptables" do
				user "root"
				not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpts:#{rule['port_range']}($| )'"
				code <<-EOH
					iptables -I INPUT -p tcp --dport #{rule['port_range']} -j ACCEPT
					service iptables save
				EOH
			end
		end
		
		service "glusterd" do
			action [ :enable, :start ]
		end

		found_master = false
		i_am_master = false
		node.deployment.servers[$nodeclass].each_pair { |name, data|
			if data['gluster_master']
			  found_master = true
				if name == Chef::Config[:node_name]
					i_am_master = true
				end
			end
		} rescue NoMethodError
		if !found_master
			node.normal['deployment']['servers'][$nodeclass][Chef::Config[:node_name]]['gluster_master'] = true
			i_am_master = true
		end
		node.normal.glusterfs_is_server = true
		node.save

		if i_am_master
			ips = []
			node.deployment.servers[$nodeclass].each_pair do |name, data|
				next if data['private_ip_address'].nil? or data['private_ip_address'].empty?
				execute "gluster peer probe #{data['private_ip_address']}" do
					not_if {data['private_ip_address'] == node.ipaddress}
				end
				ips << data['private_ip_address']
			end
			
			if ips.size >= node.glusterfs.server.num_replicas
				bricks = []
				ips.each do |ip|
					if node.glusterfs.server.raid
						bricks << "#{ip}:#{$gluster_mnt_pt}/brick"
					else
						$gluster_mnt_pts.each do |mount_point|
							bricks << "#{ip}:#{mount_point}/brick"
						end
					end
				end

				bash "Create gluster volume #{node.glusterfs.server.volume}" do
					not_if "gluster volume info #{node.glusterfs.server.volume}"
					code "gluster volume create #{node.glusterfs.server.volume} #{node.glusterfs.server.volume_type} #{node.glusterfs.server.num_replicas} transport tcp #{bricks.join(" ")}"
				end
				
				bash "Start gluster volume #{node.glusterfs.server.volume}" do
					not_if "gluster volume info #{node.glusterfs.server.volume} | grep Started"
					code "gluster volume start #{node.glusterfs.server.volume}"
				end
				
				# gluster_vol_exists = shell_out("gluster volume info #{node.glusterfs.server.volume}")
				# if gluster_vol_exists.stderr.empty? and !gluster_vol_exists.stdout.empty?
					# ips.each do |ip|
						# bash "Remove failed brick/instance fro GlusterFS Cluster" do
							# not_if "gluster volume info #{node.glusterfs.server.volume} | grep #{ip}"
							# code <<-EOH
								# "gluster peer status | grep -B 2 Disconnected | grep #{old_instnace}"
								# "gluster volume replace-brick #{node.glusterfs.server.volume} #{old_instnace}:/gluster/dev/md0/brick #{new_instance}:/gluster/dev/md0/brick start force"
								# "gluster volume replace-brick #{node.glusterfs.server.volume} #{old_instnace}:/gluster/dev/md0/brick #{new_instance}:/gluster/dev/md0/brick commit force"
								# "gluster peer detach #{old_instnace}"
							# EOH
						# end
					# end
				# end
			end
		else
			node.deployment.servers[$nodeclass].each_pair do |name, data|
				execute "gluster peer probe #{data['private_ip_address']}" do
					not_if {data['private_ip_address'] == node.ipaddress}
				end
			end
		end
		execute "skip glusterfs packages during automated yum updates" do
			command "echo 'exclude=gluster*' >> /etc/yum.conf"
			not_if "grep ^exclude=gluster /etc/yum.conf"
		end

    else
        Chef::Log.info("Unsupported platform #{node[:platform]}")
end
