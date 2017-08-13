# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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
# limitations under the License.
# 
# This library deals with volume creation and mounting

module CAPVolume
  require 'pathname'
  require 'net/http'
  require 'json'

  def set_aws_cfg_params
    begin
      require 'aws-sdk-core'
      instance_identity = Net::HTTP.get(URI("http://169.254.169.254/latest/dynamic/instance-identity/document"))
      region = JSON.parse(instance_identity)["region"]
      ENV['AWS_DEFAULT_REGION'] = region

      if ENV['AWS_ACCESS_KEY_ID'] == nil or ENV['AWS_ACCESS_KEY_ID'].empty?
        ENV.delete('AWS_ACCESS_KEY_ID')
        ENV.delete('AWS_SECRET_ACCESS_KEY')
        Aws.config = {region: region}
      else
        Aws.config = {access_key_id: ENV['AWS_ACCESS_KEY_ID'], secret_access_key: ENV['AWS_SECRET_ACCESS_KEY'], region: region}
      end
    rescue LoadError
      Chef::Log.info("aws-sdk-gem hasn't been installed yet!")
    end
  end

  @ec2 = nil

  def ec2
    require 'aws-sdk-core'
    set_aws_cfg_params
    @ec2 = Aws::EC2::Client.new if @ec2.nil?
    return @ec2
  end

  def is_mounted?(target)
    pn = Pathname.new(target)
    Chef::Log.info("pn.mountpoint? is #{pn.mountpoint?}")
    pn.mountpoint?
  end

  def get_ec2_attribute(attribute_name)
    attribute_value =nil
    begin
      query="http://169.254.169.254/latest/meta-data/#{attribute_name}"
      uri = URI(query)
      Chef::Log.info("URI will be #{uri}")
      attribute_value = Net::HTTP.get(uri)
      Chef::Log.info("Retrieved dynamic ec2 value of #{attribute_value} for attribute #{attribute_name}")
    rescue Exception => e
      Chef::Log.info("Error response to dynamic ec2 value retrieve of #{attribute_name} is #{e}")
    end
    attribute_value
  end

  def make_temp_disk!(device='/dev/ram0', mount_directory='/tmp/ram0')
    #Creates a temporary ramdisk for holding credentials.  Destructive to existing device
    if is_mounted?(mount_directory)
      Chef::Log.fatal("#{mount_directory} is already mounted")
      raise
    end

    Dir.mkdir(mount_directory) unless Dir.exists?(mount_directory)
    `mount -t tmpfs -o size=50m #{device} #{mount_directory}`
  end

  def destroy_temp_disk(device='/dev/ram0')
    #destroys a ramdisk by overwriting with /dev/urandom
    `dd if=/dev/urandom of=#{device}` unless %w{redhat centos}.include?(node.platform) && node[:platform_version].to_i == 7
    `umount #{device}`
  end

  def mount_volume (mount_device, mount_directory, key_file=nil)
    if key_file.nil?
      if %w{redhat centos}.include?(node.platform) && node[:platform_version].to_i == 7
        `mkfs.xfs  "#{mount_device}"`
        # `echo -e "#{mount_device}\t#{mount_directory}\txfs\tdefaults\t0\t2"  >> /etc/fstab` unless File.open("/etc/fstab").read.match(/ #{mount_directory} /)
      else
        `mkfs.ext4 "#{mount_device}"`
      end

      command = "mount #{mount_device} #{mount_directory}"
      Chef::Log.info("Unencrypted mount of #{command}")
      `#{command}`
    else
      alias_device = mount_directory.gsub("/", "") #by convention
      `cryptsetup luksFormat #{mount_device} #{key_file} --batch-mode`
      `cryptsetup luksOpen #{mount_device} #{alias_device} --key-file #{key_file}`

      if %w{redhat centos}.include?(node.platform) && node[:platform_version].to_i == 7
        `mkfs.xfs  "/dev/mapper/#{alias_device}"`
        # `echo -e "/dev/mapper/#{alias_device}\t#{mount_directory}\txfs\tdefaults\t0\t2"  >> /etc/fstab` unless File.open("/etc/fstab").read.match(/ #{mount_directory} /)
      else
        `mkfs.ext4 "/dev/mapper/#{alias_device}"`
      end

      `mount "/dev/mapper/#{alias_device}" #{mount_directory}`
    end
  end

  def mount_node_volume(volume_label, key_file=nil)
    #helper method to discover node volume parms
    mount_device = node.application_attributes[volume_label].mount_device
    mount_directory = node.application_attributes[volume_label].mount_directory
    mount_volume(mount_device, mount_directory, key_file)
  end

  def mount_default_volume(key_file=nil)
    #helper method for apps volume
    mount_node_volume(:application_volume, key_file)
  end

  # Creation methods for volumes
  def create_default_volume()
    # Create a default application_volume using the volume attributes from the cookbook
    create_node_volume(:application_volume)
  end

  def create_node_volume (volume_label)
    # Helper method, create an arbitrary volume using an arbitrary label that must be preconfigured in nodes
    volume_size_gb = node.application_attributes[volume_label].volume_size_gb
    if volume_size_gb.nil?
      Chef::Log.fatal("Must supply a volume size")
      raise
    end
    create_volume(volume_label, volume_size_gb)
  end

  def get_cloudprovider
    cloudprovider = 'ec2'
    cloudprovider = node.cloudprovider if node.attribute?("cloudprovider")
    return cloudprovider
  end

  def tag_volume(device, tags)
    volume_id = find_volume_id(device)
    raise "No volume ID found. Not tagging" if volume_id.nil?
    ec2.create_tags(resources: [volume_id], tags: tags)
  end

  def create_volume(volume_label, volume_size_gb)
    #Helper method, create an arbitrary volume, configures itself in nodes
    Chef::Log.info("volume_label, volume_size_gb => #{volume_label} #{volume_size_gb}")

    if get_cloudprovider == 'ec2'
      instance_id = get_ec2_attribute("instance-id")
      az = get_ec2_attribute("placement/availability-zone")

      # EC2 stuff
      if az
        resp = ec2.create_volume(size: volume_size_gb, availability_zone: az, volume_type: "gp2")
        volume_id = resp.volume_id
        node.set.application_attributes[volume_label].volume_id = volume_id
        node.save

        if node.application_attributes[volume_label].label
          description = node.application_attributes[volume_label].label
        else
          description = "#{instance_id} #{node.application_attributes[volume_label].mount_directory}"
        end

        ec2.create_tags(resources: [volume_id], tags: [{key: "Name", value: description}])
        volume_id
      else
        Chef::Log.info("create_volume fail zone not found")
      end
    else
      Chef::Log.info("create_volume in the nonec2 branch with volume #{volume_label}")
    end
  end

  # Attachment methods for volumes
  def attach_node_volume (volume_label)
    # XXX should check whether this device name is already allocated,
    # and if so throw an exception
    # Helper method, attach an arbitrary volume using an arbitrary label that must be preconfigured in nodes
    Chef::Log.info("In attach_node_volume with volume_label #{volume_label}")
    mount_device = node.application_attributes[volume_label].mount_device
    volume_id = node.application_attributes[volume_label].volume_id

    if mount_device.nil?
      Chef::Log.fatal("No mount device for volume label #{volume_label}.	Must supply a volume label configured in nodes")
      raise
    end

    attach_volume(volume_label, volume_id, mount_device)
  end

  def find_volume_id(device_target)
    if get_cloudprovider == 'ec2'
      instance_id = get_ec2_attribute("instance-id")
      instance = ec2.describe_instance_attribute(instance_id: instance_id, attribute: "blockDeviceMapping")
      instance.block_device_mappings.each { |device|
        return device.ebs.volume_id if device.device_name == device_target
      }
    end
    return nil
  end

  def check_device_status(device_target)
    #Helper method to ascertain status of a device.
    if get_cloudprovider == 'ec2'
      instance_id = get_ec2_attribute("instance-id")
      instance = ec2.describe_instance_attribute(instance_id: instance_id, attribute: "blockDeviceMapping")
      device_status = "unattached"
      volume_id = nil

      instance.block_device_mappings.each { |device|
        device_name = device.device_name
        Chef::Log.info("Examining #{device_name}")

        if device_name == device_target
          Chef::Log.info("Got equals on #{device_name} equals #{device_target}")
          volume_id=device.ebs.volume_id
          device_status=device.ebs.status
          break
        end
      }
      Chef::Log.info("Attachment status of #{device_target} is #{device_status} for volume #{volume_id}")
      device_status
    else
      Chef::Log.info("attach_volume in the nonec2 branch with	 volume #{device_target}")
    end
  end

  def attach_volume(volume_label, volume_id, mount_device)
    #Helper method, attaches an arbitrary volume, configures itself in nodes
    Chef::Log.info("In attach_volume with volume_label #{volume_label}, volume_id #{volume_id} and mount device #{mount_device}")

    if get_cloudprovider == 'ec2'
      device_status = check_device_status(mount_device)

      unless device_status == "unattached"
        Chef::Log.error("Not attempting attachment, device #{mount_device} is in status #{device_status}")
        device_status
        return
      end

      volume_id = node.application_attributes[volume_label].volume_id
      instance_id = get_ec2_attribute("instance-id")

      if volume_id.nil?
        Chef::Log.fatal("No volume created for label #{volume_label}")
        raise
      else
        Chef::Log.info("Node indicates an existing mounted volume of #{volume_id}")
      end

      retries = 0
      begin
        response = ec2.attach_volume(volume_id: volume_id, instance_id: instance_id, device: mount_device)
      rescue Aws::EC2::Errors::IncorrectState => e
        retries += 1
        if retries < 10
          sleep 10
          retry
        else
          raise e
        end
      end

      if response.nil? || response.length == 0
        Chef::Log.fatal("Error in attach, former attach is in place but node reflects new volume")
        raise
      else
        node.set.application_attributes[volume_label].mount_device = mount_device
        node.save
      end

      begin
        sleep 5
        resp = ec2.describe_volumes(volume_ids: [volume_id])
        vol = resp.volumes.first
      end while vol.nil? or vol.attachments.first.nil? or vol.attachments.first.state != "attached"
      response
    else
      Chef::Log.info("attach_volume in the nonec2 branch with	 volume #{volume_label}")
    end
  end

  def volume_attached(device_target, n_tries=5, interval_sec = 10)
    # Try device_target until attached for n_tries with interval_sec between tries
    if get_cloudprovider == 'ec2'
      for try in (1..n_tries)
        sleep interval_sec
        device_status = check_device_status(device_target)
        return true if device_status == "attached"
      end
      false
    else
      Chef::Log.info("volume_attached in a non-ec2 branch with  device #{device_target}")
    end
  end
end
