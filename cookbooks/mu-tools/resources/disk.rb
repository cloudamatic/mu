
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

  mu_tools_mommacat_request "create #{devicepath} for #{path}" do
    request "add_volume"
    passparams(
      :dev => devicename,
      :size => new_resource.size,
      :delete_on_termination => new_resource.delete_on_termination
    )
    not_if { ::File.exist?(real_devicepath(devicepath)) }
  end

  reboot "Rebooting after adding #{path}" do
    action :nothing
  end

  fstype = node['platform_version'].to_i == 6 ? "ext4" : "xfs"
  mkfs_cmd = fstype == "xfs" ? "mkfs.xfs -i size=512" : "mkfs.ext4 -F"
  have_fs_cmd = fstype == "xfs" ? "xfs_admin -l " : "tune2fs -l"

  ruby_block "format #{path} by its real device name" do
    block do
      guard_cmd = have_fs_cmd+" "+real_devicepath(devicepath)+" 2>&1 > /dev/null"
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
      dev_pattern = Regexp.quote(real_devicepath(devicepath))
      uuid_line = uuid_line(devicepath)
      uuid_line = nil if uuid_line.empty?
      if uuid_line
        dev_pattern = "("+dev_pattern+"|"+Regexp.quote(uuid_line)+")"
      end

      have_mtab = false
      ::File.read("/etc/mtab").each_line { |l|
        if l =~ /^#{dev_pattern}\s+#{path}\s+#{fstype}\s+/
          have_mtab = true
          break
        end
      }

      if !have_mtab and new_resource.preserve_data
        backupname = path.gsub(/[^a-z0-9]/i, "_")
        puts "\nPreserving data from #{path}"
        %x{mkdir -p /mnt#{backupname}}
        %x{mount #{real_devicepath(devicepath)} /mnt#{backupname}}
        %x{( cd #{path} && tar -cpf - . | su -c 'cd /mnt#{backupname}/ && tar -xpf -' ) && find #{path}/ -type f -exec rm -f {} \\;}
        %x{umount /mnt#{backupname}}
      end


      have_fstab = false
      fstab_lines = []
      ::File.read("/etc/fstab").each_line { |l|
        fstab_lines << l
        if l =~ /^#{dev_pattern}\s+#{path}\s+#{fstype}\s+/
          have_fstab = true
          break
        end
      }

      if !have_fstab
        fstabline = "#{uuid_line ? uuid_line : real_devicepath(devicepath)} #{path} #{fstype} nodev 0 2"
        ::File.open("/etc/fstab", "a") { |f|
          puts "\nAppending to /etc/fstab: #{fstabline}"
          f.puts fstabline
        }
      end

      if !new_resource.reboot_after_create
        %x{mkdir -p #{path}}
        %x{/bin/mount -a}
        %x{/sbin/restorecon -R #{path}}
      end
    end
    not_if "grep ' #{path} ' /etc/mtab && grep ' #{path} ' /etc/fstab"
    if new_resource.reboot_after_create
      notifies :request_reboot, "reboot[Rebooting after adding #{path}]", :delayed
    end
  end

  if !new_resource.reboot_after_create
    execute "/sbin/restorecon -R #{path}" do
      only_if { ::File.exist?("/sbin/restorecon") }
    end

  end


end
