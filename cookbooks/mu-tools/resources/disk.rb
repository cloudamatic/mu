
property :mountpoint, String, name_property: true
property :device, String, required: true
property :delete_on_termination, :kind_of => [TrueClass, FalseClass], default: true
property :preserve_data, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
property :reboot_after_create, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
property :swap, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
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

  fstype = if new_resource.swap
    "swap"
  else
    node['platform_version'].to_i == 6 ? "ext4" : "xfs"
  end
  path = "swap" if new_resource.swap

  mkfs_cmd = case fstype
  when "xfs"
    "mkfs.xfs -i size=512"
  when "ext4"
    "mkfs.ext4 -F"
  when "swap"
    "mkswap"
  end

  have_fs_cmd = case fstype
  when "xfs"
    "xfs_admin -l"
  when "ext4"
    "tune2fs -l"
  when "swap"
    "blkid"
  end

  ruby_block "format #{path} by its real device name" do
    block do
      guard_cmd = have_fs_cmd+" "+real_devicepath(devicepath)+" 2>&1 > /dev/null"
      format_cmd = mkfs_cmd+" "+real_devicepath(devicepath)

      shell_out(%Q{#{guard_cmd}})
      if $?.exitstatus != 0
        puts "\n"+format_cmd
        shell_out(%Q{#{format_cmd}})
      end
    end
    not_if "grep ' #{path} ' /etc/mtab"
  end


  ruby_block "mount #{path} by its real device name" do
    block do

      def sort_fstab(a, b)
        a_dev, a_path, a_fs, a_opts, a_dump, a_fsck = a.chomp.split(/[\t\s]+/)
        b_dev, b_path, b_fs, b_opts, b_dump, b_fsck = b.chomp.split(/[\t\s]+/)
        if a =~ /^\s*[#\n]/ or b =~ /^\s*[#\n]/ or !a_path or !b_path
          0
        elsif a_path =~ /^#{Regexp.quote(b_path)}\//
          1
        elsif b_path =~ /^#{Regexp.quote(a_path)}\//
          -1
        else
          0
        end
      end

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

      if !have_mtab and new_resource.preserve_data and path != "swap"
        backupname = path.gsub(/[^a-z0-9]/i, "_")
        puts "\nPreserving data from #{path}"
        shell_out(%Q{mkdir -p /mnt#{backupname}})
        shell_out(%Q{mount #{real_devicepath(devicepath)} /mnt#{backupname}})
        shell_out(%Q{( cd #{path} && tar -cpf - . | su -c 'cd /mnt#{backupname}/ && tar -xpf -' ) && find #{path}/ -type f -exec rm -f {} \\;})
        shell_out(%Q{umount /mnt#{backupname}})
      end


      have_fstab = false
      fstab_lines = []
      ::File.read("/etc/fstab").each_line { |l|
        fstab_lines << l.chomp
        if l =~ /^#{dev_pattern}\s+#{path}\s+#{fstype}\s+/
          have_fstab = true
          break
        end
      }

      if !have_fstab
        fstabline = "#{uuid_line ? uuid_line : real_devicepath(devicepath)} #{path} #{fstype} #{new_resource.swap ? "defaults" : "nodev" } 0 #{new_resource.swap ? "0" : "2"}"
        fstab_lines << fstabline
        puts "\nAppending to /etc/fstab: #{fstabline}"
        ::File.open("/etc/fstab", "w") { |f|
          fstab_lines.sort { |a, b| sort_fstab(a,b) }.uniq.each { |l|
            f.puts l
          }
        }
      end

      if !new_resource.reboot_after_create and !new_resource.swap
        shell_out(%Q{mkdir -p #{path}})
        shell_out(%Q{/bin/mount -a})
        shell_out(%Q{/sbin/restorecon -R #{path}})
      end
    end
    not_if "grep ' #{path} ' /etc/mtab && grep ' #{path} ' /etc/fstab"
    if new_resource.reboot_after_create
      notifies :request_reboot, "reboot[Rebooting after adding #{path}]", :delayed
    end
  end

  if new_resource.swap
    execute "/sbin/swapon -a"
  elsif !new_resource.reboot_after_create
    execute "/sbin/restorecon -R #{path}" do
      only_if { ::File.exist?("/sbin/restorecon") }
    end
  end


end
