
property :mountpoint, String, name_property: true
property :device, String, required: true
property :delete_on_termination, :kind_of => [TrueClass, FalseClass], default: true
property :preserve_data, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
property :reboot_after_create, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
property :size, Integer, default: 8

actions :create # ~FC092
default_action :create

action :create do
  devicepath = new_resource.device
  path = new_resource.mountpoint
  devicename = devicepath.dup

  if set_gcp_cfg_params
    devicename= devicename.gsub(/.*?\//, "")
    devicepath = "/dev/disk/by-id/google-"+devicename
  end

#  if devicename =~ /^\/dev\/(?:sd|xvd)([a-z])/
#    if nvme?
#      map = attached_nvme_disks
#      if map[devicename]
#        devicepath = map[devicename]
#      end
#    end
#  end

  mu_tools_mommacat_request "create #{devicepath} for #{path}" do
    request "add_volume"
    passparams(
      :dev => devicename,
      :size => new_resource.size,
      :delete_on_termination => new_resource.delete_on_termination
    )
    not_if { ::File.exist?(real_devicepath(devicepath)) }
  end

#  if nvme? and device.nil?
#    map = attached_nvme_disks
#    if map[devicename]
#      devicepath = map[devicename]
#    else
#      Chef::Application.fatal!("In NVME mode and attempted to allocate disk #{devicename}, but didn't find it in metadata of any of our NVME block devices (#{map.values.join(", ")})")
#    end
#  end

  reboot "Rebooting after adding #{path}" do
    action :nothing
  end

  backupname = path.gsub(/[^a-z0-9]/i, "_")
  directory "/mnt#{backupname}" do
    action :nothing
  end
  mount "/mnt#{backupname}" do
    device real_devicepath(devicepath)
    options "nodev"
    action :nothing
    notifies :create, "directory[/mnt#{backupname}]", :before
  end
  execute "back up #{backupname}" do
    # also expunge files so we don't eat up a bunch of disk space quietly
    # underneath our new mount
    command "( cd #{path} && tar -cpf - . | su -c 'cd /mnt#{backupname}/ && tar -xpf -' ) && find #{path}/ -type f -exec rm -f {} \\;"
    only_if { ::Dir.exist?(path) and ::Dir.exist?("/mnt#{backupname}") }
    action :nothing
  end

  fstype = node['platform_version'].to_i == 6 ? "ext4" : "xfs"
  mkfs_cmd = fstype == "xfs" ? "mkfs.xfs -i size=512" : "mkfs.ext4 -F"
  have_fs_cmd = fstype == "xfs" ? "xfs_admin -l " : "tune2fs -l"

  ruby_block "format #{path} by its real device name" do
    block do
      guard_cmd = have_fs_cmd+" "+real_devicepath(devicepath)
      format_cmd = mkfs_cmd+" "+real_devicepath(devicepath)

      %x{#{guard_cmd}}
      if $?.exitstatus != 0
        %x{#{format_cmd}}
      end
    end
    not_if "grep ' #{path} ' /etc/mtab"
  end

  ruby_block "mount #{path} by its real device name" do
    block do
      have = false
      ::File.read("/etc/fstab").each_line { |l|
        if l =~ /^#{real_devicepath(devicepath)}\s+#{path}\s+#{fstype}\s+/
          have = true
          break
        end
      }

      if !have
        ::File.open("/etc/fstab", "a") { |f|
          f.puts "#{real_devicepath(devicepath)} #{path} #{fstype} nodev 0 2"
        }
      end
      %x{/bin/mount -a}
    end
    not_if "grep ' #{path} ' /etc/mtab && grep ' #{path} ' /etc/fstab"
  end

#  execute "format #{devicename}" do
#    command (node['platform_version'].to_i == 6 ? "mkfs.ext4 -F #{real_devicepath(devicepath)}" : "mkfs.xfs -i size=512 #{real_devicepath(devicepath)}")
#    if new_resource.preserve_data
#      notifies :mount, "mount[/mnt#{backupname}]", :immediately
#      notifies :run, "execute[back up #{backupname}]", :immediately
#      notifies :unmount, "mount[/mnt#{backupname}]", :immediately
#    end
#    if new_resource.reboot_after_create
#      notifies :request_reboot, "reboot[Rebooting after adding #{path}]", :delayed
#    end
#    retries 5 # sometimes there's a bit of lag
#    retry_delay 6
#    not_if (node['platform_version'].to_i == 6 ? "tune2fs -l #{real_devicepath(devicepath)} > /dev/null" : "xfs_admin -l #{real_devicepath(devicepath)} > /dev/null")
#  end

  if !new_resource.reboot_after_create
    directory "Ensure existence of #{path}" do
      recursive true
      path path
    end

    execute "/sbin/restorecon -R #{path}" do
      only_if { ::File.exist?("/sbin/restorecon") }
      action :nothing
    end

  end


end
