
property :mountpoint, String, name_property: true
property :device, String, required: true
property :preserve_data, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
property :reboot_after_create, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
property :mount_only, :kind_of => [TrueClass, FalseClass], :required => false, :default => false
property :size, Integer, default: 8

actions :create
default_action :create

action :create do
  device = new_resource.device
  path = new_resource.mountpoint
  devicename = device

  if set_gcp_cfg_params
    devicename.gsub!(/.*?\//, "")
    device = "/dev/disk/by-id/google-"+devicename
  end

  if !new_resource.mount_only
    mu_tools_mommacat_request "create #{path}" do
      request "add_volume"
      params(
        :dev => devicename,
        :size => new_resource.size
      )
      not_if { ::File.exists?(device) }
    end

    reboot "Rebooting after adding #{path}" do
      action :nothing
    end

    if node.platform_version.to_i == 6
      execute "mkfs.ext4 #{device}" do
        if new_resource.reboot_after_create
          notifies :reboot_now, "reboot[Rebooting after adding #{path}]", :delayed
        end
        not_if "tune2fs -l #{device} > /dev/null"
      end
    elsif node.platform_version.to_i == 7
      execute "mkfs.xfs -i size=512 #{device}" do
        if new_resource.reboot_after_create
          notifies :reboot_now, "reboot[Rebooting after adding #{path}]", :delayed
        end
        not_if "xfs_admin -l #{device} > /dev/null"
      end
    end

    if !new_resource.reboot_after_create

      backupname = path.gsub(/[^a-z0-9]/i, "_")
      execute "back up #{backupname}" do
        command "tar czf /tmp/#{backupname}.tgz -C #{path} ."
        not_if "grep '^#{device} #{path}' /etc/mtab"
        only_if "test -d #{path}"
        action :nothing
      end

      execute "restore #{backupname}" do
        command "tar xzf /tmp/#{backupname}.tgz --preserve-permissions --same-owner --directory #{path}" 
        only_if "test -f /tmp/#{backupname}.tgz && test -d #{path}"
        action :nothing
      end

    end

    directory "Ensure existence of #{path} for #{device}" do
      recursive true
      path path
    end

    mount path do
      device device
      options "nodev"
      if new_resource.mount_only
        action :mount
      else
        action [:mount, :enable]
      end
      if new_resource.preserve_data
        notifies :run, "execute[back up #{backupname}]", :before
        notifies :run, "execute[restore #{backupname}]", :immediately
      end
    end
  end


end
