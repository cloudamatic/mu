# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'net/ssh'
require 'net/ssh/multi'
require 'net/ssh/proxy/command'
autoload :OpenStruct, "ostruct"
autoload :Timeout, "timeout"
autoload :ERB, "erb"
autoload :Base64, "base64"
require 'open-uri'

module MU
  class Cloud
    class AWS

      # A server as configured in {MU::Config::BasketofKittens::servers}
      class Server < MU::Cloud::Server

        # A list of block device names to use if we get a storage block that
        # doesn't declare one explicitly.
        # This probably fails on some AMIs. It's crude.
        @disk_devices = [
            "/dev/sdf",
            "/dev/sdg",
            "/dev/sdh",
            "/dev/sdi",
            "/dev/sdj",
            "/dev/sdk",
            "/dev/sdl",
            "/dev/sdm",
            "/dev/sdn"
        ]
        # List of standard disk device names to present to instances.
        # @return [Array<String>]
        def self.disk_devices
          @disk_devices
        end
        
        # See that we get our ephemeral storage devices with AMIs that don't do it
        # for us
        @ephemeral_mappings = [
          {
            :device_name => "/dev/sdr",
            :virtual_name => "ephemeral0"
          },
          {
            :device_name => "/dev/sds",
            :virtual_name => "ephemeral1"
          },
          {
            :device_name => "/dev/sdt",
            :virtual_name => "ephemeral2"
          },
          {
            :device_name => "/dev/sdu",
            :virtual_name => "ephemeral3"
          }
        ]
        # Ephemeral storage device mappings. Useful for AMIs that don't do this
        # for us.
        # @return [Hash]
        def self.ephemeral_mappings
          @ephemeral_mappings
        end

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @userdata = if @config['userdata_script']
            @config['userdata_script']
          elsif @deploy and !@config['scrub_mu_isms']
            MU::Cloud.fetchUserdata(
              platform: @config["platform"],
              cloud: "AWS",
              credentials: @config['credentials'],
              template_variables: {
                "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                "deploySSHKey" => @deploy.ssh_public_key,
                "muID" => MU.deploy_id,
                "muUser" => MU.mu_user,
                "publicIP" => MU.mu_public_ip,
                "mommaCatPort" => MU.mommaCatPort,
                "adminBucketName" => MU::Cloud::AWS.adminBucketName(@credentials),
                "chefVersion" => MU.chefVersion,
                "skipApplyUpdates" => @config['skipinitialupdates'],
              "windowsAdminName" => @config['windows_admin_username'],
              "resourceName" => @config["name"],
              "resourceType" => "server",
              "platform" => @config["platform"]
            },
            custom_append: @config['userdata_script']
          )
        end

        @disk_devices = MU::Cloud::AWS::Server.disk_devices
        @ephemeral_mappings = MU::Cloud::AWS::Server.ephemeral_mappings

        if !@mu_name.nil?
          @config['mu_name'] = @mu_name
          @mu_windows_name = @deploydata['mu_windows_name'] if @mu_windows_name.nil? and @deploydata
        else
          if kitten_cfg.has_key?("basis")
            @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end
          @config['mu_name'] = @mu_name

        end

        @config['instance_secret'] ||= Password.random(50)

        @groomer = MU::Groomer.new(self) unless MU.inGem?
      end

      @@userdata_semaphore = Mutex.new

      # Fetch our baseline userdata argument (read: "script that runs on first
      # boot") for a given platform.
      # *XXX* both the eval() and the blind File.read() based on the platform
      # variable are dangerous without cleaning. Clean them.
      # @param platform [String]: The target OS.
      # @param template_variables [Hash]: A list of variable substitutions to pass as globals to the ERB parser when loading the userdata script.
      # @param custom_append [String]: Arbitrary extra code to append to our default userdata behavior.
      # @return [String]
      def self.fetchUserdata(platform: "linux", template_variables: {}, custom_append: nil, scrub_mu_isms: false)
        return nil if platform.nil? or platform.empty?
        @@userdata_semaphore.synchronize {
          script = ""
          if !scrub_mu_isms
            if template_variables.nil? or !template_variables.is_a?(Hash)
              raise MuError, "My second argument should be a hash of variables to pass into ERB templates"
            end
            $mu = OpenStruct.new(template_variables)
            userdata_dir = File.expand_path(MU.myRoot+"/modules/mu/clouds/aws/userdata")
            platform = "linux" if %w{centos centos6 centos7 ubuntu ubuntu14 rhel rhel7 rhel71 amazon}.include? platform
            platform = "windows" if %w{win2k12r2 win2k12 win2k8 win2k8r2 win2k16}.include? platform
            erbfile = "#{userdata_dir}/#{platform}.erb"
            if !File.exist?(erbfile)
              MU.log "No such userdata template '#{erbfile}'", MU::WARN, details: caller
              return ""
            end
            userdata = File.read(erbfile)
            begin
              erb = ERB.new(userdata, nil, "<>")
              script = erb.result
            rescue NameError => e
              raise MuError, "Error parsing userdata script #{erbfile} as an ERB template: #{e.inspect}"
            end
            MU.log "Parsed #{erbfile} as ERB", MU::DEBUG, details: script
          end

          if !custom_append.nil?
            if custom_append['path'].nil?
              raise MuError, "Got a custom userdata script argument, but no ['path'] component"
            end
            erbfile = File.read(custom_append['path'])
            MU.log "Loaded userdata script from #{custom_append['path']}"
            if custom_append['use_erb']
              begin
                erb = ERB.new(erbfile, 1, "<>")
                if custom_append['skip_std']
                  script = +erb.result
                else
                  script = script+"\n"+erb.result
                end
              rescue NameError => e
                raise MuError, "Error parsing userdata script #{erbfile} as an ERB template: #{e.inspect}"
              end
              MU.log "Parsed #{custom_append['path']} as ERB", MU::DEBUG, details: script
            else
              if custom_append['skip_std']
                script = erbfile
              else
                script = script+"\n"+erbfile
              end
              MU.log "Parsed #{custom_append['path']} as flat file", MU::DEBUG, details: script
            end
          end
          return script
        }
      end

      # Find volumes attached to a given instance id and tag them. If no arguments
      # besides the instance id are provided, it will add our special MU-ID
      # tag. Can also be used to do things like set the resource's name, if you
      # leverage the other arguments.
      # @param instance_id [String]: The cloud provider's identifier for the parent instance of this volume.
      # @param device [String]: The OS-level device name of the volume.
      # @param tag_name [String]: The name of the tag to attach.
      # @param tag_value [String]: The value of the tag to attach.
      # @param region [String]: The cloud provider region
      # @return [void]
      def self.tagVolumes(instance_id, device: nil, tag_name: "MU-ID", tag_value: MU.deploy_id, region: MU.curRegion, credentials: nil)
        MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_volumes(filters: [name: "attachment.instance-id", values: [instance_id]]).each { |vol|
          vol.volumes.each { |volume|
            volume.attachments.each { |attachment|
              vol_parent = attachment.instance_id
              vol_id = attachment.volume_id
              vol_dev = attachment.device
              if vol_parent == instance_id and (vol_dev == device or device.nil?)
                MU::Cloud::AWS.createTag(vol_id, tag_name, tag_value, region: region, credentials: credentials)
                break
              end
            }
          }
        }
      end

      # Called automatically by {MU::Deploy#createResources}
      def create
        begin
          done = false
          instance = createEc2Instance

          @cloud_id = instance.instance_id
          @deploy.saveNodeSecret(@cloud_id, @config['instance_secret'], "instance_secret")
          @config.delete("instance_secret")

          if !@config['async_groom']
            sleep 5
            MU::MommaCat.lock(instance.instance_id+"-create")
            if !postBoot
              MU.log "#{@config['name']} is already being groomed, skipping", MU::NOTICE
            else
              MU.log "Node creation complete for #{@config['name']}"
            end
            MU::MommaCat.unlock(instance.instance_id+"-create")
          else
            MU::Cloud::AWS.createStandardTags(instance.instance_id, region: @config['region'], credentials: @config['credentials'])
            MU::Cloud::AWS.createTag(instance.instance_id, "Name", @mu_name, region: @config['region'], credentials: @config['credentials'])
          end
          done = true
        rescue StandardError => e
          if !instance.nil? and !done
            MU.log "Aborted before I could finish setting up #{@config['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
            MU::MommaCat.unlockAll
            if !@deploy.nocleanup
              parent_thread_id = Thread.current.object_id
              Thread.new {
                MU.dupGlobals(parent_thread_id)
                MU::Cloud::AWS::Server.cleanup(noop: false, ignoremaster: false, region: @config['region'], credentials: @config['credentials'], flags: { "skipsnapshots" => true } )
              }
            end
          end
          raise e
        end

        return @config
      end



      # Create an Amazon EC2 instance.
      def createEc2Instance
        name = @config["name"]
        node = @config['mu_name']

        instance_descriptor = {
          :image_id => @config["ami_id"],
          :key_name => @deploy.ssh_key_name,
          :instance_type => @config["size"],
          :disable_api_termination => true,
          :min_count => 1,
          :max_count => 1
        }

        arn = nil
        if @config['generate_iam_role']
          role = @deploy.findLitterMate(name: @config['name'], type: "roles")
          s3_objs = ["#{@deploy.deploy_id}-secret", "#{role.mu_name}.pfx", "#{role.mu_name}.crt", "#{role.mu_name}.key", "#{role.mu_name}-winrm.crt", "#{role.mu_name}-winrm.key"].map { |file| 
            'arn:'+(MU::Cloud::AWS.isGovCloud?(@config['region']) ? "aws-us-gov" : "aws")+':s3:::'+MU::Cloud::AWS.adminBucketName(@credentials)+'/'+file
          }
          MU.log "Adding S3 read permissions to #{@mu_name}'s IAM profile", MU::NOTICE, details: s3_objs
          role.cloudobj.injectPolicyTargets("MuSecrets", s3_objs)

          @config['iam_role'] = role.mu_name
          arn = role.cloudobj.createInstanceProfile
#            @cfm_role_name, @cfm_prof_name

        elsif @config['iam_role'].nil?
          raise MuError, "#{@mu_name} has generate_iam_role set to false, but no iam_role assigned."
        end
        if !@config["iam_role"].nil?
          if arn
            instance_descriptor[:iam_instance_profile] = {arn: arn}
          else
            instance_descriptor[:iam_instance_profile] = {name: @config["iam_role"]}
          end
        end

        security_groups = []
        if @dependencies.has_key?("firewall_rule")
          @dependencies['firewall_rule'].values.each { |sg|
            security_groups << sg.cloud_id
          }
        end

        if security_groups.size > 0
          instance_descriptor[:security_group_ids] = security_groups
        else
          raise MuError, "Didn't get any security groups assigned to be in #{@mu_name}, that shouldn't happen"
        end

        if !@config['private_ip'].nil?
          instance_descriptor[:private_ip_address] = @config['private_ip']
        end

        vpc_id = subnet = nil
        if !@vpc.nil? and @config.has_key?("vpc")
          subnet_conf = @config['vpc']
          subnet_conf = @config['vpc']['subnets'].first if @config['vpc'].has_key?("subnets") and !@config['vpc']['subnets'].empty?
          tag_key, tag_value = subnet_conf['tag'].split(/=/, 2) if !subnet_conf['tag'].nil?

          subnet = @vpc.getSubnet(
            cloud_id: subnet_conf['subnet_id'],
            name: subnet_conf['subnet_name'],
            tag_key: tag_key,
            tag_value: tag_value
          )
          if subnet.nil?
            raise MuError, "Got null subnet id out of #{subnet_conf['vpc']}"
          end
          MU.log "Deploying #{node} into VPC #{@vpc.cloud_id} Subnet #{subnet.cloud_id}"
          punchAdminNAT
          instance_descriptor[:subnet_id] = subnet.cloud_id
        end

        if !@userdata.nil? and !@userdata.empty?
          instance_descriptor[:user_data] = Base64.encode64(@userdata)
        end

        MU::Cloud::AWS::Server.waitForAMI(@config["ami_id"], region: @config['region'], credentials: @config['credentials'])

        # Figure out which devices are embedded in the AMI already.
        image = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_images(image_ids: [@config["ami_id"]]).images.first
        ext_disks = {}
        if !image.block_device_mappings.nil?
          image.block_device_mappings.each { |disk|
            if !disk.device_name.nil? and !disk.device_name.empty? and !disk.ebs.nil? and !disk.ebs.empty?
              ext_disks[disk.device_name] = MU.structToHash(disk.ebs)
            end
          }
        end

        configured_storage = Array.new
        cfm_volume_map = {}
        if @config["storage"]
          @config["storage"].each { |vol|
            # Drop the "encrypted" flag if a snapshot for this device exists
            # in the AMI, even if they both agree about the value of said
            # flag. Apparently that's a thing now.
            if ext_disks.has_key?(vol["device"])
              if ext_disks[vol["device"]].has_key?(:snapshot_id)
                vol.delete("encrypted")
              end
            end
            mapping, cfm_mapping = MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
            configured_storage << mapping
          }
        end

        instance_descriptor[:block_device_mappings] = configured_storage
        instance_descriptor[:block_device_mappings].concat(@ephemeral_mappings)
        instance_descriptor[:monitoring] = {enabled: @config['monitoring']}

        if @tags and @tags.size > 0
          instance_descriptor[:tag_specifications] = [{
            :resource_type => "instance",
            :tags => @tags.keys.map { |k|
              { :key => k, :value => @tags[k] }
            }
          }]
        end

        MU.log "Creating EC2 instance #{node}"
        MU.log "Instance details for #{node}: #{instance_descriptor}", MU::DEBUG
#				if instance_descriptor[:block_device_mappings].empty?
#					instance_descriptor.delete(:block_device_mappings)
#				end

        retries = 0
        instance = begin
          response = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).run_instances(instance_descriptor)
          if response and response.instances and response.instances.size > 0
            instance = response.instances.first
          else
            MU.log "halp", MU::ERR, details: response
          end
        rescue Aws::EC2::Errors::InvalidRequest => e
          MU.log e.message, MU::ERR, details: instance_descriptor
          raise e
        rescue Aws::EC2::Errors::InvalidGroupNotFound, Aws::EC2::Errors::InvalidSubnetIDNotFound, Aws::EC2::Errors::InvalidParameterValue => e
          if retries < 10
            if retries > 7
              MU.log "Seeing #{e.inspect} while trying to launch #{node}, retrying a few more times...", MU::WARN, details: instance_descriptor
            end
            sleep 10
            retries = retries + 1
            retry
          else
            raise MuError, e.inspect
          end
        end

        MU.log "#{node} (#{instance.instance_id}) coming online"

        instance
      end

      # Ask the Amazon API to restart this node
      def reboot(hard = false)
        return if @cloud_id.nil?

        if hard
          groupname = nil
          if !@config['basis'].nil?
            resp = MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).describe_auto_scaling_instances(
              instance_ids: [@cloud_id]
            )
            groupname = resp.auto_scaling_instances.first.auto_scaling_group_name
            MU.log "Pausing Autoscale processes in #{groupname}", MU::NOTICE
            MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).suspend_processes(
              auto_scaling_group_name: groupname,
              scaling_processes: [
                "Terminate",
              ], 
            )
          end
          begin
            MU.log "Stopping #{@mu_name} (#{@cloud_id})", MU::NOTICE
            MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).stop_instances(
              instance_ids: [@cloud_id]
            )
            MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).wait_until(:instance_stopped, instance_ids: [@cloud_id]) do |waiter|
              waiter.before_attempt do |attempts|
                MU.log "Waiting for #{@mu_name} to stop for hard reboot"
              end
            end
            MU.log "Starting #{@mu_name} (#{@cloud_id})"
            MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).start_instances(
              instance_ids: [@cloud_id]
            )
          ensure
            if !groupname.nil?
              MU.log "Resuming Autoscale processes in #{groupname}", MU::NOTICE
              MU::Cloud::AWS.autoscale(region: @config['region'], credentials: @config['credentials']).resume_processes(
                auto_scaling_group_name: groupname,
                scaling_processes: [
                  "Terminate",
                ],
              )
            end
          end
        else
          MU.log "Rebooting #{@mu_name} (#{@cloud_id})"
          MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).reboot_instances(
            instance_ids: [@cloud_id]
          )
        end
      end

      # Figure out what's needed to SSH into this server.
      # @return [Array<String>]: nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name, alternate_names
      def getSSHConfig
        node, config, deploydata = describe(cloud_id: @cloud_id)
# XXX add some awesome alternate names from metadata and make sure they end
# up in MU::MommaCat's ssh config wangling
        ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
        return nil if @config.nil? or @deploy.nil?

        nat_ssh_key = nat_ssh_user = nat_ssh_host = nil
        if !@config["vpc"].nil? and !MU::Cloud::AWS::VPC.haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])
          if !@nat.nil?
            if @nat.is_a?(Struct) && @nat.nat_gateway_id && @nat.nat_gateway_id.start_with?("nat-")
              raise MuError, "Configured to use NAT Gateway, but I have no route to instance. Either use Bastion, or configure VPC peering"
            end

            if @nat.cloud_desc.nil?
              MU.log "NAT was missing cloud descriptor when called in #{@mu_name}'s getSSHConfig", MU::ERR
              return nil
            end
            # XXX Yanking these things from the cloud descriptor will only work in AWS!

            nat_ssh_key = @nat.cloud_desc.key_name
							nat_ssh_key = @config["vpc"]["nat_ssh_key"] if !@config["vpc"]["nat_ssh_key"].nil?
            nat_ssh_host = @nat.cloud_desc.public_ip_address
            nat_ssh_user = @config["vpc"]["nat_ssh_user"]
            if nat_ssh_user.nil? and !nat_ssh_host.nil?
              MU.log "#{@config["name"]} (#{MU.deploy_id}) is configured to use #{@config['vpc']} NAT #{nat_ssh_host}, but username isn't specified. Guessing root.", MU::ERR, details: caller
              nat_ssh_user = "root"
            end
          end
        end

        if @config['ssh_user'].nil?
          if windows?
            @config['ssh_user'] = "Administrator"
          else
            @config['ssh_user'] = "root"
          end
        end

        return [nat_ssh_key, nat_ssh_user, nat_ssh_host, canonicalIP, @config['ssh_user'], @deploy.ssh_key_name]

      end

      # Apply tags, bootstrap our configuration management, and other
      # administravia for a new instance.
      def postBoot(instance_id = nil)
        if !instance_id.nil?
          @cloud_id = instance_id
        end
        node, config, deploydata = describe(cloud_id: @cloud_id)
        instance = cloud_desc
        raise MuError, "Couldn't find instance #{@mu_name} (#{@cloud_id})" if !instance
        @cloud_id = instance.instance_id
        return false if !MU::MommaCat.lock(instance.instance_id+"-orchestrate", true)
        return false if !MU::MommaCat.lock(instance.instance_id+"-groom", true)

        MU::Cloud::AWS.createStandardTags(instance.instance_id, region: @config['region'], credentials: @config['credentials'])
        MU::Cloud::AWS.createTag(instance.instance_id, "Name", node, region: @config['region'], credentials: @config['credentials'])

        if @config['optional_tags']
          MU::MommaCat.listOptionalTags.each { |key, value|
            MU::Cloud::AWS.createTag(instance.instance_id, key, value, region: @config['region'], credentials: @config['credentials'])
          }
        end

        if !@config['tags'].nil?
          @config['tags'].each { |tag|
            MU::Cloud::AWS.createTag(instance.instance_id, tag['key'], tag['value'], region: @config['region'], credentials: @config['credentials'])
          }
        end
        MU.log "Tagged #{node} (#{instance.instance_id}) with MU-ID=#{MU.deploy_id}", MU::DEBUG

        # Make double sure we don't lose a cached mu_windows_name value.
        if windows? or !@config['active_directory'].nil?
          if @mu_windows_name.nil?
            @mu_windows_name = deploydata['mu_windows_name']
          end
        end

        retries = -1
        max_retries = 30
        begin
          if instance.nil? or instance.state.name != "running"
            retries = retries + 1
            if !instance.nil? and instance.state.name == "terminated"
              raise MuError, "#{@cloud_id} appears to have been terminated mid-bootstrap!"
            end
            if retries % 3 == 0
              MU.log "Waiting for EC2 instance #{node} (#{@cloud_id}) to be ready...", MU::NOTICE
            end
            sleep 40
            # Get a fresh AWS descriptor
            instance = MU::Cloud::Server.find(cloud_id: @cloud_id, region: @config['region'], credentials: @config['credentials']).values.first
            if instance and instance.state.name == "terminated"
              raise MuError, "EC2 instance #{node} (#{@cloud_id}) terminating during bootstrap!"
            end
          end
        rescue Aws::EC2::Errors::ServiceError => e
          if retries < max_retries
            MU.log "Got #{e.inspect} during initial instance creation of #{@cloud_id}, retrying...", MU::NOTICE, details: instance
            retries = retries + 1
            retry
          else
            raise MuError, "Too many retries creating #{node} (#{e.inspect})"
          end
        end while instance.nil? or (instance.state.name != "running" and retries < max_retries)

        punchAdminNAT


        # If we came up via AutoScale, the Alarm module won't have had our
        # instance ID to associate us with itself. So invoke that here.
        # XXX might be possible to do this with regular alarm resources and
        # dependencies now
        if !@config['basis'].nil? and @config["alarms"] and !@config["alarms"].empty?
          @config["alarms"].each { |alarm|
            alarm_obj = MU::MommaCat.findStray(
              "AWS",
              "alarms",
              region: @config["region"],
              deploy_id: @deploy.deploy_id,
              name: alarm['name']
            ).first
            alarm["dimensions"] = [{:name => "InstanceId", :value => @cloud_id}]

            if alarm["enable_notifications"]
              topic_arn = MU::Cloud::AWS::Notification.createTopic(alarm["notification_group"], region: @config["region"], credentials: @config['credentials'])
              MU::Cloud::AWS::Notification.subscribe(arn: topic_arn, protocol: alarm["notification_type"], endpoint: alarm["notification_endpoint"], region: @config["region"], credentials: @config["credentials"])
              alarm["alarm_actions"] = [topic_arn]
              alarm["ok_actions"]  = [topic_arn]
            end

            alarm_name = alarm_obj ? alarm_obj.cloud_id : "#{node}-#{alarm['name']}".upcase

            MU::Cloud::AWS::Alarm.setAlarm(
              name: alarm_name,
              ok_actions: alarm["ok_actions"],
              alarm_actions: alarm["alarm_actions"],
              insufficient_data_actions: alarm["no_data_actions"],
              metric_name: alarm["metric_name"],
              namespace: alarm["namespace"],
              statistic: alarm["statistic"],
              dimensions: alarm["dimensions"],
              period: alarm["period"],
              unit: alarm["unit"],
              evaluation_periods: alarm["evaluation_periods"],
              threshold: alarm["threshold"],
              comparison_operator: alarm["comparison_operator"],
              region: @config["region"],
              credentials: @config['credentials']
            )
          }
        end

        # We have issues sometimes where our dns_records are pointing at the wrong node name and IP address.
        # Make sure that doesn't happen. Happens with server pools only
        if @config['dns_records'] && !@config['dns_records'].empty?
          @config['dns_records'].each { |dnsrec|
            if dnsrec.has_key?("name")
              if dnsrec['name'].start_with?(MU.deploy_id.downcase) && !dnsrec['name'].start_with?(node.downcase)
                MU.log "DNS records for #{node} seem to be wrong, deleting from current config", MU::WARN, details: dnsrec
                dnsrec.delete('name')
                dnsrec.delete('target')
              end
            end
          }
        end

        # Unless we're planning on associating a different IP later, set up a
        # DNS entry for this thing and let it sync in the background. We'll come
        # back to it later.
        if @config['static_ip'].nil? && !@named
          MU::MommaCat.nameKitten(self)
          @named = true
        end

        if !@config['src_dst_check'] and !@config["vpc"].nil?
          MU.log "Disabling source_dest_check #{node} (making it NAT-worthy)"
          MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).modify_instance_attribute(
              instance_id: @cloud_id,
              source_dest_check: {:value => false}
          )
        end

        # Set console termination protection. Autoscale nodes won't set this
        # by default.
        MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).modify_instance_attribute(
            instance_id: @cloud_id,
            disable_api_termination: {:value => true}
        )

        has_elastic_ip = false
        if !instance.public_ip_address.nil?
          begin
            resp = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_addresses(public_ips: [instance.public_ip_address])
            if resp.addresses.size > 0 and resp.addresses.first.instance_id == @cloud_id
              has_elastic_ip = true
            end
          rescue Aws::EC2::Errors::InvalidAddressNotFound => e
            # XXX this is ok to ignore, it means the public IP isn't Elastic
          end
        end

        win_admin_password = nil
        ec2config_password = nil
        sshd_password = nil
        if windows?
          ssh_keydir = "#{Etc.getpwuid(Process.uid).dir}/.ssh"
          ssh_key_name = @deploy.ssh_key_name

          if @config['use_cloud_provider_windows_password']
            win_admin_password = getWindowsAdminPassword
          elsif @config['windows_auth_vault'] && !@config['windows_auth_vault'].empty?
            if @config["windows_auth_vault"].has_key?("password_field")
              win_admin_password = @groomer.getSecret(
                  vault: @config['windows_auth_vault']['vault'],
                  item: @config['windows_auth_vault']['item'],
                  field: @config["windows_auth_vault"]["password_field"]
              )
            else
              win_admin_password = getWindowsAdminPassword
            end

            if @config["windows_auth_vault"].has_key?("ec2config_password_field")
              ec2config_password = @groomer.getSecret(
                  vault: @config['windows_auth_vault']['vault'],
                  item: @config['windows_auth_vault']['item'],
                  field: @config["windows_auth_vault"]["ec2config_password_field"]
              )
            end

            if @config["windows_auth_vault"].has_key?("sshd_password_field")
              sshd_password = @groomer.getSecret(
                  vault: @config['windows_auth_vault']['vault'],
                  item: @config['windows_auth_vault']['item'],
                  field: @config["windows_auth_vault"]["sshd_password_field"]
              )
            end
          end

          win_admin_password = MU.generateWindowsPassword if win_admin_password.nil?
          ec2config_password = MU.generateWindowsPassword if ec2config_password.nil?
          sshd_password = MU.generateWindowsPassword if sshd_password.nil?

          # We're creating the vault here so when we run
          # MU::Cloud::Server.initialSSHTasks and we need to set the Windows
          # Admin password we can grab it from said vault.
          creds = {
              "username" => @config['windows_admin_username'],
              "password" => win_admin_password,
              "ec2config_username" => "ec2config",
              "ec2config_password" => ec2config_password,
              "sshd_username" => "sshd_service",
              "sshd_password" => sshd_password
          }
          @groomer.saveSecret(vault: @mu_name, item: "windows_credentials", data: creds, permissions: "name:#{@mu_name}")
        end

        subnet = nil
        if !@vpc.nil? and @config.has_key?("vpc") and !instance.subnet_id.nil?
          subnet = @vpc.getSubnet(
            cloud_id: instance.subnet_id
          )
          if subnet.nil?
            raise MuError, "Got null subnet id out of #{@config['vpc']} when asking for #{instance.subnet_id}"
          end
        end

        if !subnet.nil?
          if !subnet.private? or (!@config['static_ip'].nil? and !@config['static_ip']['assign_ip'].nil?)
            if !@config['static_ip'].nil?
              if !@config['static_ip']['ip'].nil?
                public_ip = MU::Cloud::AWS::Server.associateElasticIp(instance.instance_id, classic: false, ip: @config['static_ip']['ip'])
              elsif !has_elastic_ip
                public_ip = MU::Cloud::AWS::Server.associateElasticIp(instance.instance_id)
              end
            end
          end

          nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
          if subnet.private? and !nat_ssh_host and !MU::Cloud::AWS::VPC.haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])
            raise MuError, "#{node} is in a private subnet (#{subnet}), but has no bastion host configured, and I have no other route to it"
          end

          # If we've asked for additional subnets (and this @config is not a
          # member of a Server Pool, which has different semantics), create
          # extra interfaces to accomodate.
          if !@config['vpc']['subnets'].nil? and @config['basis'].nil?
            device_index = 1
            @vpc.subnets.each { |s|
              subnet_id = s.cloud_id
              MU.log "Adding network interface on subnet #{subnet_id} for #{node}"
              iface = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).create_network_interface(subnet_id: subnet_id).network_interface
              MU::Cloud::AWS.createStandardTags(iface.network_interface_id, region: @config['region'], credentials: @config['credentials'])
              MU::Cloud::AWS.createTag(iface.network_interface_id, "Name", node+"-ETH"+device_index.to_s, region: @config['region'], credentials: @config['credentials'])

              if @config['optional_tags']
                MU::MommaCat.listOptionalTags.each { |key, value|
                  MU::Cloud::AWS.createTag(iface.network_interface_id, key, value, region: @config['region'], credentials: @config['credentials'])
                }
              end

              if !@config['tags'].nil?
                @config['tags'].each { |tag|
                  MU::Cloud::AWS.createTag(iface.network_interface_id, tag['key'], tag['value'], region: @config['region'], credentials: @config['credentials'])
                }
              end

              MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).attach_network_interface(
                  network_interface_id: iface.network_interface_id,
                  instance_id: instance.instance_id,
                  device_index: device_index
              )
              device_index = device_index + 1
            }
          end
        elsif !@config['static_ip'].nil?
          if !@config['static_ip']['ip'].nil?
            public_ip = MU::Cloud::AWS::Server.associateElasticIp(instance.instance_id, classic: true, ip: @config['static_ip']['ip'])
          elsif !has_elastic_ip
            public_ip = MU::Cloud::AWS::Server.associateElasticIp(instance.instance_id, classic: true)
          end
        end


        if !@config['image_then_destroy']
          notify
        end

        MU.log "EC2 instance #{node} has id #{instance.instance_id}", MU::DEBUG

        @config["private_dns_name"] = instance.private_dns_name
        @config["public_dns_name"] = instance.public_dns_name
        @config["private_ip_address"] = instance.private_ip_address
        @config["public_ip_address"] = instance.public_ip_address

        ext_mappings = MU.structToHash(instance.block_device_mappings)

        # Root disk on standard CentOS AMI
        # tagVolumes(instance.instance_id, "/dev/sda", "Name", "ROOT-"+MU.deploy_id+"-"+@config["name"].upcase)
        # Root disk on standard Ubuntu AMI
        # tagVolumes(instance.instance_id, "/dev/sda1", "Name", "ROOT-"+MU.deploy_id+"-"+@config["name"].upcase)

        # Generic deploy ID tag
        # tagVolumes(instance.instance_id)

        # Tag volumes with all our standard tags.
        # Maybe replace tagVolumes with this? There is one more place tagVolumes is called from
        volumes = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_volumes(filters: [name: "attachment.instance-id", values: [instance.instance_id]])
        volumes.each { |vol|
          vol.volumes.each { |volume|
            volume.attachments.each { |attachment|
              MU::MommaCat.listStandardTags.each_pair { |key, value|
                MU::Cloud::AWS.createTag(attachment.volume_id, key, value, region: @config['region'], credentials: @config['credentials'])

                if attachment.device == "/dev/sda" or attachment.device == "/dev/sda1"
                  MU::Cloud::AWS.createTag(attachment.volume_id, "Name", "ROOT-#{MU.deploy_id}-#{@config["name"].upcase}", region: @config['region'], credentials: @config['credentials'])
                else
                  MU::Cloud::AWS.createTag(attachment.volume_id, "Name", "#{MU.deploy_id}-#{@config["name"].upcase}-#{attachment.device.upcase}", region: @config['region'], credentials: @config['credentials'])
                end
              }

              if @config['optional_tags']
                MU::MommaCat.listOptionalTags.each { |key, value|
                  MU::Cloud::AWS.createTag(attachment.volume_id, key, value, region: @config['region'], credentials: @config['credentials'])
                }
              end

              if @config['tags']
                @config['tags'].each { |tag|
                  MU::Cloud::AWS.createTag(attachment.volume_id, tag['key'], tag['value'], region: @config['region'], credentials: @config['credentials'])
                }
              end
            }
          }
        }

        canonical_name = instance.public_dns_name
        canonical_name = instance.private_dns_name if !canonical_name or nat_ssh_host != nil
        @config['canonical_name'] = canonical_name

        if !@config['add_private_ips'].nil?
          instance.network_interfaces.each { |int|
            if int.private_ip_address == instance.private_ip_address and int.private_ip_addresses.size < (@config['add_private_ips'] + 1)
              MU.log "Adding #{@config['add_private_ips']} extra private IP addresses to #{instance.instance_id}"
              MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).assign_private_ip_addresses(
                  network_interface_id: int.network_interface_id,
                  secondary_private_ip_address_count: @config['add_private_ips'],
                  allow_reassignment: false
              )
            end
          }
          notify
        end

        begin
          if @config['groom'].nil? or @config['groom']
            if windows?
              # kick off certificate generation early; WinRM will need it
              cert, key = @deploy.nodeSSLCerts(self)
              if @config.has_key?("basis")
                @deploy.nodeSSLCerts(self, true)
              end
              if !@groomer.haveBootstrapped?
                session = getWinRMSession(50, 60, reboot_on_problems: true)
                initialWinRMTasks(session)
                begin
                  session.close
                rescue StandardError
                  # this is allowed to fail- we're probably rebooting anyway
                end
              else # for an existing Windows node: WinRM, then SSH if it fails
                begin
                  session = getWinRMSession(1, 60)
                rescue StandardError # yeah, yeah
                  session = getSSHSession(1, 60)
                  # XXX maybe loop at least once if this also fails?
                end
              end
            else
              session = getSSHSession(40, 30)
              initialSSHTasks(session)
            end
          end
        rescue BootstrapTempFail
          sleep 45
          retry
        ensure
          session.close if !session.nil? and !windows?
        end

        if @config["existing_deploys"] && !@config["existing_deploys"].empty?
          @config["existing_deploys"].each { |ext_deploy|
            if ext_deploy["cloud_id"]
              found = MU::MommaCat.findStray(
                @config['cloud'],
                ext_deploy["cloud_type"],
                cloud_id: ext_deploy["cloud_id"],
                region: @config['region'],
                dummy_ok: false
              ).first

              MU.log "Couldn't find existing resource #{ext_deploy["cloud_id"]}, #{ext_deploy["cloud_type"]}", MU::ERR if found.nil?
              @deploy.notify(ext_deploy["cloud_type"], found.config["name"], found.deploydata, mu_name: found.mu_name, triggering_node: @mu_name)
            elsif ext_deploy["mu_name"] && ext_deploy["deploy_id"]
              MU.log "#{ext_deploy["mu_name"]} / #{ext_deploy["deploy_id"]}"
              found = MU::MommaCat.findStray(
                @config['cloud'],
                ext_deploy["cloud_type"],
                deploy_id: ext_deploy["deploy_id"],
                mu_name: ext_deploy["mu_name"],
                region: @config['region'],
                dummy_ok: false
              ).first

              MU.log "Couldn't find existing resource #{ext_deploy["mu_name"]}/#{ext_deploy["deploy_id"]}, #{ext_deploy["cloud_type"]}", MU::ERR if found.nil?
              @deploy.notify(ext_deploy["cloud_type"], found.config["name"], found.deploydata, mu_name: ext_deploy["mu_name"], triggering_node: @mu_name)
            else
              MU.log "Trying to find existing deploy, but either the cloud_id is not valid or no mu_name and deploy_id where provided", MU::ERR
            end
          }
        end

        # See if this node already exists in our config management. If it does,
        # we're done.
        if MU.inGem?
          MU.log "Deploying from a gem, not grooming"
          MU::MommaCat.unlock(instance.instance_id+"-orchestrate")
          MU::MommaCat.unlock(instance.instance_id+"-groom")

          return true
        elsif @groomer.haveBootstrapped?
          MU.log "Node #{node} has already been bootstrapped, skipping groomer setup.", MU::NOTICE

          if @config['groom'].nil? or @config['groom']
            @groomer.saveDeployData
          end

          MU::MommaCat.unlock(instance.instance_id+"-orchestrate")
          MU::MommaCat.unlock(instance.instance_id+"-groom")
          return true
        end

        begin
          @groomer.bootstrap if @config['groom'].nil? or @config['groom']
        rescue MU::Groomer::RunError
          MU::MommaCat.unlock(instance.instance_id+"-groom")
          MU::MommaCat.unlock(instance.instance_id+"-orchestrate")
          return false
        end

        # Make sure we got our name written everywhere applicable
        if !@named
          MU::MommaCat.nameKitten(self)
          @named = true
        end

        MU::MommaCat.unlock(instance.instance_id+"-groom")
        MU::MommaCat.unlock(instance.instance_id+"-orchestrate")
        return true
      end

      # postBoot

      # Locate an existing instance or instances and return an array containing matching AWS resource descriptors for those that match.
      # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching instances
      def self.find(**args)
        ip ||= args[:flags]['ip'] if args[:flags] and args[:flags]['ip']

        instance = nil
        if !args[:region].nil?
          regions = [args[:region]]
        else
          regions = MU::Cloud::AWS.listRegions
        end

        found = {}
        search_semaphore = Mutex.new
        search_threads = []

        if !ip and !args[:cloud_id] and !args[:tag_value]
          regions.each { |r|
            search_threads << Thread.new {
              MU::Cloud::AWS.ec2(region: r, credentials: args[:credentials]).describe_instances(
                filters: [
                  {
                    name: "instance-state-name",
                    values: ["running", "pending", "stopped"]
                  }
                ]
              ).reservations.each { |resp|
                if !resp.nil? and !resp.instances.nil?
                  resp.instances.each { |i|
                    search_semaphore.synchronize {
                      found[i.instance_id] = i
                    }
                  }
                end
              }
            }
          }

          search_threads.each { |t|
            t.join
          }

          return found
        end

        # If we got an instance id, go get it
        if args[:cloud_id]
          regions.each { |r|
            search_threads << Thread.new {
              MU.log "Hunting for instance with cloud id '#{args[:cloud_id]}' in #{r}", MU::DEBUG
              retries = 0
              begin
                MU::Cloud::AWS.ec2(region: r, credentials: args[:credentials]).describe_instances(
                  instance_ids: [args[:cloud_id]],
                  filters: [
                    {
                      name: "instance-state-name",
                      values: ["running", "pending", "stopped"]
                    }
                  ]
                ).reservations.each { |resp|
                  if !resp.nil? and !resp.instances.nil?
                    resp.instances.each { |i|
                      search_semaphore.synchronize {
                        found[i.instance_id] = i
                      }
                    }
                  end
                }
              rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
                if retries < 5
                  retries = retries + 1
                  sleep 5
                else
                  raise MuError, "#{e.inspect} in region #{r}"
                end
              end
            }
          }
          done_threads = []
          begin
            search_threads.each { |t|
              joined = t.join(2)
              done_threads << joined if !joined.nil?
            }
          end while found.size < 1 and done_threads.size != search_threads.size
        end

        return found if found.size > 0

        # Ok, well, let's try looking it up by IP then
        if !ip.nil?
          MU.log "Hunting for instance by IP '#{ip}'", MU::DEBUG
          ["ip-address", "private-ip-address"].each { |filter|
            regions.each { |r|
              response = MU::Cloud::AWS.ec2(region: r, credentials: args[:credentials]).describe_instances(
                filters: [
                  {name: filter, values: [ip]},
                  {name: "instance-state-name", values: ["running", "pending", "stopped"]}
                ]
              ).reservations.first
              response.instances.each { |i|
                found[i.instance_id] = i
              }
            }
          }
        end

        return found if found.size > 0

        # Fine, let's try it by tag.
        if args[:tag_value]
          MU.log "Searching for instance by tag '#{args[:tag_key]}=#{args[:tag_value]}'", MU::DEBUG
          regions.each { |r|
            MU::Cloud::AWS.ec2(region: r, credentials: args[:credentials]).describe_instances(
              filters: [
                {name: "tag:#{args[:tag_key]}", values: [args[:tag_value]]},
                {name: "instance-state-name", values: ["running", "pending", "stopped"]}
              ]
            ).reservations.each { |resp|
              if !resp.nil? and resp.instances.size > 0
                resp.instances.each { |i|
                  found[i.instance_id] = i
                }
              end
            }
          }
        end

        return found
      end

      # Reverse-map our cloud description into a runnable config hash.
      # We assume that any values we have in +@config+ are placeholders, and
      # calculate our own accordingly based on what's live in the cloud.
      def toKitten(**args)
        bok = {
          "cloud" => "AWS",
          "credentials" => @config['credentials'],
          "cloud_id" => @cloud_id,
          "region" => @config['region']
        }

        if !cloud_desc
          MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
          return nil
        end

        asgs = MU::Cloud::AWS::ServerPool.find(
          instance_id: @cloud_id,
          region: @config['region'],
          credentials: @credentials
        )
        if asgs.size > 0
          MU.log "#{@mu_name} is an Autoscale node, will be adopted under server_pools", MU::DEBUG, details: asgs
          return nil
        end

        bok['name'] = @cloud_id
        if cloud_desc.tags and !cloud_desc.tags.empty?
          bok['tags'] = MU.structToHash(cloud_desc.tags, stringify_keys: true)
          realname = MU::Adoption.tagsToName(bok['tags'])
          if realname
            bok['name'] = realname
            bok['name'].gsub!(/[^a-zA-Z0-9_\-]/, "_")
          end
        end

        bok['size'] = cloud_desc.instance_type

        if cloud_desc.vpc_id
          bok['vpc'] = MU::Config::Ref.get(
            id: cloud_desc.vpc_id,
            cloud: "AWS",
            credentials: @credentials,
            type: "vpcs",
          )
        end

        if !cloud_desc.source_dest_check
          bok['src_dst_check'] = false
        end

        bok['image_id'] = cloud_desc.image_id

        ami = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @credentials).describe_images(image_ids: [bok['image_id']]).images.first

        if ami.nil? or ami.empty?
          MU.log "#{@mu_name} source image #{bok['image_id']} no longer exists", MU::WARN
          bok.delete("image_id")
        end

        if cloud_desc.block_device_mappings and !cloud_desc.block_device_mappings.empty?
          vol_map = {}
          MU::Cloud::AWS.ec2(region: @config['region'], credentials: @credentials).describe_volumes(
            volume_ids: cloud_desc.block_device_mappings.map { |d| d.ebs.volume_id if d.ebs }
          ).volumes.each { |vol|
            vol_map[vol.volume_id] = vol
          }
          cloud_desc.block_device_mappings.each { |disk|
            if ami and ami.block_device_mappings
              is_ami_disk = false
              ami.block_device_mappings.each { |ami_dev|
                is_ami_disk = true if ami_dev.device_name == disk.device_name
              }
              next if is_ami_disk
            end
            disk_desc = { "device" => disk.device_name }
            if disk.ebs and disk.ebs.volume_id and vol_map[disk.ebs.volume_id]
              disk_desc["size"] = vol_map[disk.ebs.volume_id].size
              disk_desc["delete_on_termination"] = disk.ebs.delete_on_termination
              if vol_map[disk.ebs.volume_id].encrypted
                disk_desc['encrypted'] = true
              end
              if vol_map[disk.ebs.volume_id].iops
                disk_desc['iops'] = vol_map[disk.ebs.volume_id].iops
              end
              disk_desc["volume_type"] = vol_map[disk.ebs.volume_id].volume_type
            end
            bok['storage'] ||= []
            bok['storage'] << disk_desc
          }
        end

        cloud_desc.network_interfaces.each { |int|
          if !bok['vpc'] and int.vpc_id
            bok['vpc'] = MU::Config::Ref.get(
              id: int.vpc_id,
              cloud: "AWS",
              credentials: @credentials,
              region: @config['region'],
              subnet_id: int.subnet_id,
              habitat: MU::Config::Ref.get(
                id: int.owner_id,
                cloud: "AWS",
                credentials: @credentials
              )
            )
          end

          int.private_ip_addresses.each { |priv_ip|
            if !priv_ip.primary
              bok['add_private_ips'] ||= []
              bok['add_private_ips'] << priv_ip.private_ip_address
            end
            if priv_ip.association and priv_ip.association.public_ip 
              bok['associate_public_ip'] = true
              if priv_ip.association.ip_owner_id != "amazon"
                bok['static_ip'] = {
                  "assign_ip" => true,
                  "ip" => priv_ip.association.public_ip
                }
              end
            end
          }

          if int.groups.size > 0

            require 'mu/clouds/aws/firewall_rule'
            ifaces = MU::Cloud::AWS::FirewallRule.getAssociatedInterfaces(int.groups.map { |sg| sg.group_id }, credentials: @credentials, region: @config['region'])
            done_local_rules = false
            int.groups.each { |sg|
              if !done_local_rules and ifaces[sg.group_id].size == 1
                sg_desc = MU::Cloud::AWS::FirewallRule.find(cloud_id: sg.group_id, credentials: @credentials, region: @config['region']).values.first
                if sg_desc
                  bok["ingress_rules"] = MU::Cloud::AWS::FirewallRule.rulesToBoK(sg_desc.ip_permissions)
                  bok["ingress_rules"].concat(MU::Cloud::AWS::FirewallRule.rulesToBoK(sg_desc.ip_permissions_egress, egress: true))
                  done_local_rules = true
                  next
                end
              end
              bok['add_firewall_rules'] ||= []
              bok['add_firewall_rules'] << MU::Config::Ref.get(
                id: sg.group_id,
                cloud: "AWS",
                credentials: @credentials,
                type: "firewall_rules",
                region: @config['region']
              )
            }
          end
        }

# XXX go get the got-damned instance profile

        bok
      end

        # Return a description of this resource appropriate for deployment
        # metadata. Arguments reflect the return values of the MU::Cloud::[Resource].describe method
        def notify
          node, config, deploydata = describe(cloud_id: @cloud_id)
          deploydata = {} if deploydata.nil?

          if cloud_desc.nil?
            raise MuError, "Failed to load instance metadata for #{@mu_name}/#{@cloud_id}"
          end

          interfaces = []
          private_ips = []

          cloud_desc.network_interfaces.each { |iface|
            iface.private_ip_addresses.each { |priv_ip|
              private_ips << priv_ip.private_ip_address
            }
            interfaces << {
                "network_interface_id" => iface.network_interface_id,
                "subnet_id" => iface.subnet_id,
                "vpc_id" => iface.vpc_id
            }
          }

          deploydata = {
            "nodename" => @mu_name,
            "run_list" => @config['run_list'],
            "image_created" => @config['image_created'],
            "iam_role" => @config['iam_role'],
            "cloud_desc_id" => @cloud_id,
            "private_dns_name" => cloud_desc.private_dns_name,
            "public_dns_name" => cloud_desc.public_dns_name,
            "private_ip_address" => cloud_desc.private_ip_address,
            "public_ip_address" => cloud_desc.public_ip_address,
            "private_ip_list" => private_ips,
            "key_name" => cloud_desc.key_name,
            "subnet_id" => cloud_desc.subnet_id,
            "cloud_desc_type" => cloud_desc.instance_type #,
            #				"network_interfaces" => interfaces,
            #				"config" => server
          }

          if !@mu_windows_name.nil?
            deploydata["mu_windows_name"] = @mu_windows_name
          end
          if !@config['chef_data'].nil?
            deploydata.merge!(@config['chef_data'])
          end
          deploydata["region"] = @config['region'] if !@config['region'].nil?
          if !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          return deploydata
        end

        # If the specified server is in a VPC, and has a NAT, make sure we'll
        # be letting ssh traffic in from said NAT.
        def punchAdminNAT
          if @config['vpc'].nil? or 
            (
              !@config['vpc'].has_key?("nat_host_id") and
              !@config['vpc'].has_key?("nat_host_tag") and
              !@config['vpc'].has_key?("nat_host_ip") and
              !@config['vpc'].has_key?("nat_host_name")
            )
            return nil
          end

          return nil if @nat.is_a?(Struct) && @nat.nat_gateway_id && @nat.nat_gateway_id.start_with?("nat-")

          dependencies if @nat.nil?
          if @nat.nil? or @nat.cloud_desc.nil?
            raise MuError, "#{@mu_name} (#{MU.deploy_id}) is configured to use #{@config['vpc']} but I can't find the cloud descriptor for a matching NAT instance"
          end
          MU.log "Adding administrative holes for NAT host #{@nat.cloud_desc.private_ip_address} to #{@mu_name}"
          if !@deploy.kittens['firewall_rules'].nil?
            @deploy.kittens['firewall_rules'].each_pair { |name, acl|
              if acl.config["admin"]
                acl.addRule([@nat.cloud_desc.private_ip_address], proto: "tcp")
                acl.addRule([@nat.cloud_desc.private_ip_address], proto: "udp")
                acl.addRule([@nat.cloud_desc.private_ip_address], proto: "icmp")
              end
            }
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          MU::MommaCat.lock(@cloud_id+"-groom")
          node, config, deploydata = describe(cloud_id: @cloud_id)

          if node.nil? or node.empty?
            raise MuError, "MU::Cloud::AWS::Server.groom was called without a mu_name"
          end

          # Make double sure we don't lose a cached mu_windows_name value.
          if windows? or !@config['active_directory'].nil?
            if @mu_windows_name.nil?
              @mu_windows_name = deploydata['mu_windows_name']
            end
          end

          punchAdminNAT

          MU::Cloud::AWS::Server.tagVolumes(@cloud_id, credentials: @config['credentials'])

          # If we have a loadbalancer configured, attach us to it
          if !@config['loadbalancers'].nil?
            if @loadbalancers.nil?
              raise MuError, "#{@mu_name} is configured to use LoadBalancers, but none have been loaded by dependencies()"
            end
            @loadbalancers.each { |lb|
              lb.registerNode(@cloud_id)
            }
          end
          MU.log %Q{Server #{@config['name']} private IP is #{@deploydata["private_ip_address"]}#{@deploydata["public_ip_address"] ? ", public IP is "+@deploydata["public_ip_address"] : ""}}, MU::SUMMARY

          # Let us into any databases we depend on.
          # This is probelmtic with autscaling - old ips are not removed, and access to the database can easily be given at the BoK level
          # if @dependencies.has_key?("database")
            # @dependencies['database'].values.each { |db|
              # db.allowHost(@deploydata["private_ip_address"]+"/32")
              # if @deploydata["public_ip_address"]
                # db.allowHost(@deploydata["public_ip_address"]+"/32")
              # end
            # }
          # end

          if @config['groom'].nil? or @config['groom']
            @groomer.saveDeployData
          end

          begin
            if @config['groom'].nil? or @config['groom']
              @groomer.run(purpose: "Full Initial Run", max_retries: 15, reboot_first_fail: windows?, timeout: @config['groomer_timeout'])
            end
          rescue MU::Groomer::RunError => e
            MU.log "Proceeding after failed initial Groomer run, but #{node} may not behave as expected!", MU::WARN, details: e.message
          rescue StandardError => e
            MU.log "Caught #{e.inspect} on #{node} in an unexpected place (after @groomer.run on Full Initial Run)", MU::ERR
          end

          if !@config['create_image'].nil? and !@config['image_created']
            img_cfg = @config['create_image']
            # Scrub things that don't belong on an AMI
            session = getSSHSession
            sudo = purgecmd = ""
            sudo = "sudo" if @config['ssh_user'] != "root"
            if windows?
              purgecmd = "rm -rf /cygdrive/c/mu_installed_chef"
            else
              purgecmd = "rm -rf /opt/mu_installed_chef"
            end
            if img_cfg['image_then_destroy']
              if windows?
                purgecmd = "rm -rf /cygdrive/c/chef/ /home/#{@config['windows_admin_username']}/.ssh/authorized_keys /home/Administrator/.ssh/authorized_keys /cygdrive/c/mu-installer-ran-updates /cygdrive/c/mu_installed_chef"
                # session.exec!("powershell -Command \"& {(Get-WmiObject -Class Win32_Product -Filter \"Name='UniversalForwarder'\").Uninstall()}\"")
              else
                purgecmd = "#{sudo} rm -rf /var/lib/cloud/instances/i-* /root/.ssh/authorized_keys /etc/ssh/ssh_host_*key* /etc/chef /etc/opscode/* /.mu-installer-ran-updates /var/chef /opt/mu_installed_chef /opt/chef ; #{sudo} sed -i 's/^HOSTNAME=.*//' /etc/sysconfig/network"
              end
            end
            session.exec!(purgecmd)
            session.close
            ami_ids = MU::Cloud::AWS::Server.createImage(
                name: @mu_name,
                instance_id: @cloud_id,
                storage: @config['storage'],
                exclude_storage: img_cfg['image_exclude_storage'],
                copy_to_regions: img_cfg['copy_to_regions'],
                make_public: img_cfg['public'],
                region: @config['region'],
                tags: @config['tags'],
                credentials: @config['credentials']
            )
            @deploy.notify("images", @config['name'], ami_ids)
            @config['image_created'] = true
            if img_cfg['image_then_destroy']
              MU::Cloud::AWS::Server.waitForAMI(ami_ids[@config['region']], region: @config['region'], credentials: @config['credentials'])
              MU.log "AMI #{ami_ids[@config['region']]} ready, removing source node #{node}"
              MU::Cloud::AWS::Server.terminateInstance(id: @cloud_id, region: @config['region'], deploy_id: @deploy.deploy_id, mu_name: @mu_name, credentials: @config['credentials'])
              destroy
            end
          end

          MU::MommaCat.unlock(@cloud_id+"-groom")
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@config["region"]) ? "aws-us-gov" : "aws")+":ec2:"+@config['region']+":"+MU::Cloud::AWS.credToAcct(@config['credentials'])+":instance/"+@cloud_id
        end

        # Return the cloud provider's description for this instance
        # @return [Openstruct]
        def cloud_desc(use_cache: true)
          max_retries = 5
          retries = 0
          if !@cloud_id.nil?
            begin
              resp = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_instances(instance_ids: [@cloud_id])
              if resp and resp.reservations and resp.reservations.first and
                 resp.reservations.first.instances and
                 resp.reservations.first.instances.first
                return resp.reservations.first.instances.first
              end
            rescue Aws::EC2::Errors::InvalidInstanceIDNotFound
              return nil
            rescue NoMethodError => e
              if retries >= max_retries
                raise MuError, "Couldn't get a cloud descriptor for #{@mu_name} (#{@cloud_id})"
              else
                retries = retries + 1
                sleep 10
                retry
              end
            end
          end
          nil
        end

        # Return the IP address that we, the Mu server, should be using to access
        # this host via the network. Note that this does not factor in SSH
        # bastion hosts that may be in the path, see getSSHConfig if that's what
        # you need.
        def canonicalIP
          mu_name, config, deploydata = describe(cloud_id: @cloud_id)

          instance = cloud_desc

          if !instance
            raise MuError, "Couldn't retrieve cloud descriptor for server #{self}"
          end

          if deploydata.nil? or
              (!deploydata.has_key?("private_ip_address") and
                  !deploydata.has_key?("public_ip_address"))
            return nil if instance.nil?
            @deploydata = {} if @deploydata.nil?
            @deploydata["public_ip_address"] = instance.public_ip_address
            @deploydata["public_dns_name"] = instance.public_dns_name
            @deploydata["private_ip_address"] = instance.private_ip_address
            @deploydata["private_dns_name"] = instance.private_dns_name

            notify
          end

          # Our deploydata gets corrupted often with server pools, this will cause us to use the wrong IP to identify a node
          # which will cause us to create certificates, DNS records and other artifacts with incorrect information which will cause our deploy to fail.
          # The cloud_id is always correct so lets use 'cloud_desc' to get the correct IPs
          if MU::Cloud::AWS::VPC.haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials']) or @deploydata["public_ip_address"].nil?
            @config['canonical_ip'] = instance.private_ip_address
            @deploydata["private_ip_address"] = instance.private_ip_address
            return instance.private_ip_address
          else
            @config['canonical_ip'] = instance.public_ip_address
            @deploydata["public_ip_address"] = instance.public_ip_address
            return instance.public_ip_address
          end
        end

        # Create an AMI out of a running server. Requires either the name of a MU resource in the current deployment, or the cloud provider id of a running instance.
        # @param name [String]: The MU resource name of the server to use as the basis for this image.
        # @param instance_id [String]: The cloud provider resource identifier of the server to use as the basis for this image.
        # @param storage [Hash]: The storage devices to include in this image.
        # @param exclude_storage [Boolean]: Do not include the storage device profile of the running instance when creating this image.
        # @param region [String]: The cloud provider region
        # @param copy_to_regions [Array<String>]: Copy the resulting AMI into the listed regions.
        # @param tags [Array<String>]: Extra/override tags to apply to the image.
        # @return [String]: The cloud provider identifier of the new machine image.
        def self.createImage(name: nil, instance_id: nil, storage: {}, exclude_storage: false, make_public: false, region: MU.curRegion, copy_to_regions: [], tags: [], credentials: nil)
          ami_descriptor = {
            :instance_id => instance_id,
            :name => name,
            :description => "Image automatically generated by Mu from #{name}"
          }
          ami_ids = {}

          storage_list = Array.new
          if exclude_storage
            instance = MU::Cloud::Server.find(cloud_id: instance_id, region: region)
            instance.block_device_mappings.each { |vol|
              if vol.device_name != instance.root_device_name
                
                storage_list << MU::Cloud::AWS::Server.convertBlockDeviceMapping(
                    {
                        "device" => vol.device_name,
                        "no-device" => ""
                    }
                )[0]
              end
            }
          elsif !storage.nil?
            storage.each { |vol|
              storage_list << MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)[0]
            }
          end
          ami_descriptor[:block_device_mappings] = storage_list
          if !exclude_storage
            ami_descriptor[:block_device_mappings].concat(@ephemeral_mappings)
          end
          MU.log "Creating AMI from #{name}", details: ami_descriptor
          resp = nil
          begin
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).create_image(ami_descriptor)
          rescue Aws::EC2::Errors::InvalidAMINameDuplicate => e
            MU.log "AMI #{name} already exists, skipping", MU::WARN
            return nil
          end

          ami = resp.image_id

          ami_ids[region] = ami
          MU::Cloud::AWS.createStandardTags(ami, region: region, credentials: credentials)
          MU::Cloud::AWS.createTag(ami, "Name", name, region: region, credentials: credentials)
          MU.log "AMI of #{name} in region #{region}: #{ami}"
          if make_public
            MU::Cloud::AWS::Server.waitForAMI(ami, region: region, credentials: credentials)
            MU::Cloud::AWS.ec2(region: region, credentials: credentials).modify_image_attribute(
                image_id: ami,
                launch_permission: {add: [{group: "all"}]},
                attribute: "launchPermission"
            )
          end
          copythreads = []
          if !copy_to_regions.nil? and copy_to_regions.size > 0
            parent_thread_id = Thread.current.object_id
            MU::Cloud::AWS::Server.waitForAMI(ami, region: region, credentials: credentials) if !make_public
            copy_to_regions.each { |r|
              next if r == region
              copythreads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                copy = MU::Cloud::AWS.ec2(region: r, credentials: credentials).copy_image(
                    source_region: region,
                    source_image_id: ami,
                    name: name,
                    description: "Image automatically generated by Mu from #{name}"
                )
                MU.log "Initiated copy of #{ami} from #{region} to #{r}: #{copy.image_id}"
                ami_ids[r] = copy.image_id

                MU::Cloud::AWS.createStandardTags(copy.image_id, region: r, credentials: credentials)
                MU::Cloud::AWS.createTag(copy.image_id, "Name", name, region: r, credentials: credentials)
                if !tags.nil?
                  tags.each { |tag|
                    MU::Cloud::AWS.createTag(instance.instance_id, tag['key'], tag['value'], region: r, credentials: credentials)
                  }
                end
                MU::Cloud::AWS::Server.waitForAMI(copy.image_id, region: r, credentials: credentials)
                if make_public
                  MU::Cloud::AWS.ec2(region: r, credentials: credentials).modify_image_attribute(
                      image_id: copy.image_id,
                      launch_permission: {add: [{group: "all"}]},
                      attribute: "launchPermission"
                  )
                end
                MU.log "AMI of #{name} in region #{r}: #{copy.image_id}"
              } # Thread
            }
          end

          copythreads.each { |t|
            t.join
          }

          return ami_ids
        end

        # Given a cloud platform identifier for a machine image, wait until it's
        # flagged as ready.
        # @param image_id [String]: The machine image to wait for.
        # @param region [String]: The cloud provider region
        def self.waitForAMI(image_id, region: MU.curRegion, credentials: nil)
          MU.log "Checking to see if AMI #{image_id} is available", MU::DEBUG

          retries = 0
          begin
            images = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_images(image_ids: [image_id]).images
            if images.nil? or images.size == 0
              raise MuError, "No such AMI #{image_id} found"
            end
            state = images.first.state
            if state == "failed"
              raise MuError, "#{image_id} is marked as failed! I can't use this."
            end
            if state != "available"
              loglevel = MU::DEBUG
              loglevel = MU::NOTICE if retries % 3 == 0
              MU.log "Waiting for AMI #{image_id} in #{region} (#{state})", loglevel
              sleep 60
            end
          rescue Aws::EC2::Errors::InvalidAMIIDNotFound => e
            retries = retries + 1
            if retries >= 10
              raise e
            end
            sleep 5
            retry
          end while state != "available"
          MU.log "AMI #{image_id} is ready", MU::DEBUG
        end

        # Maps our configuration language's 'storage' primitive to an Amazon-style
        # block_device_mapping.
        # @param storage [Hash]: The {MU::Config}-style storage description.
        # @return [Hash]: The Amazon-style storage description.
        def self.convertBlockDeviceMapping(storage)
          vol_struct = {}
          cfm_mapping = {}
          if storage["no_device"]
            vol_struct[:no_device] = storage["no_device"]
            cfm_mapping["NoDevice"] = storage["no_device"]
          end

          if storage["device"]
            vol_struct[:device_name] = storage["device"]
            cfm_mapping["DeviceName"] = storage["device"]
          elsif storage["no_device"].nil?
            vol_struct[:device_name] = @disk_devices.shift
            cfm_mapping["DeviceName"] = @disk_devices.shift
          end

          vol_struct[:virtual_name] = storage["virtual_name"] if storage["virtual_name"]

          storage["volume_size"] = storage["size"]
          if storage["snapshot_id"] or storage["size"]
            vol_struct[:ebs] = {}
            cfm_mapping["Ebs"] = {}
            [:delete_on_termination, :snapshot_id, :volume_size, :volume_type, :encrypted].each { |arg|
              if storage.has_key?(arg.to_s) and !storage[arg.to_s].nil?
                vol_struct[:ebs][arg] = storage[arg.to_s]
                key = ""
                arg.to_s.split(/_/).each { |chunk| key = key + chunk.capitalize }
                cfm_mapping["Ebs"][key] = storage[arg.to_s]
              end
            }
            cfm_mapping["Ebs"].delete("Encrypted") if !cfm_mapping["Ebs"]["Encrypted"]

            if storage["iops"] and storage["volume_type"] == "io1"
              vol_struct[:ebs][:iops] = storage["iops"] 
              cfm_mapping["Ebs"]["Iops"] = storage["iops"]
            end
          end

          return [vol_struct, cfm_mapping]
        end

        # Retrieves the Cloud provider's randomly generated Windows password
        # Will only work on stock Amazon Windows AMIs or custom AMIs that where created with Administrator Password set to random in EC2Config
        # return [String]: A password string.
        def getWindowsAdminPassword
          if @cloud_id.nil?
            node, config, deploydata = describe
            @cloud_id = cloud_desc.instance_id
          end
          ssh_keydir = "#{Etc.getpwuid(Process.uid).dir}/.ssh"
          ssh_key_name = @deploy.ssh_key_name

          retries = 0
          MU.log "Waiting for Windows instance password to be set by Amazon and flagged as available from the API. Note- if you're using a source AMI that already has its password set, this may fail. You'll want to set use_cloud_provider_windows_password to false if this is the case.", MU::NOTICE
          begin
            MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).wait_until(:password_data_available, instance_id: @cloud_id) do |waiter|
              waiter.max_attempts = 60
              waiter.before_attempt do |attempts|
                MU.log "Waiting for Windows password data to be available for node #{@mu_name}", MU::NOTICE if attempts % 5 == 0
              end
              # waiter.before_wait do |attempts, resp|
              # throw :success if resp.data.password_data and !resp.data.password_data.empty?
              # end
            end
          rescue Aws::Waiters::Errors::TooManyAttemptsError => e
            if retries < 2
              retries = retries + 1
              MU.log "wait_until(:password_data_available, instance_id: #{@cloud_id}) in #{@config['region']} never got a good response, retrying (#{retries}/2)", MU::WARN, details: e.inspect
              retry
            else
              MU.log "wait_until(:password_data_available, instance_id: #{@cloud_id}) in #{@config['region']} never returned- this image may not be configured to have its password set by AWS.", MU::ERR
              return nil
            end
          end

          resp = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).get_password_data(instance_id: @cloud_id)
          encrypted_password = resp.password_data

          # Note: This is already implemented in the decrypt_windows_password API call
          decoded = Base64.decode64(encrypted_password)
          pem_bytes = File.open("#{ssh_keydir}/#{ssh_key_name}", 'rb') { |f| f.read }
          private_key = OpenSSL::PKey::RSA.new(pem_bytes)
          decrypted_password = private_key.private_decrypt(decoded)
          return decrypted_password
        end

        @eips_used = Array.new
        # Find a free AWS Elastic IP.
        # @param classic [Boolean]: Toggle whether to allocate an IP in EC2 Classic
        # instead of VPC.
        # @param ip [String]: Request a specific IP address.
        # @param region [String]: The cloud provider region
        def self.findFreeElasticIp(classic: false, ip: nil, region: MU.curRegion)
          filters = Array.new
          if !classic
            filters << {name: "domain", values: ["vpc"]}
          else
            filters << {name: "domain", values: ["standard"]}
          end
          filters << {name: "public-ip", values: [ip]} if ip != nil

          if filters.size > 0
            resp = MU::Cloud::AWS.ec2(region: region).describe_addresses(filters: filters)
          else
            resp = MU::Cloud::AWS.ec2(region: region).describe_addresses()
          end
          resp.addresses.each { |address|
            return address if (address.network_interface_id.nil? || address.network_interface_id.empty?) && !@eips_used.include?(address.public_ip)
          }
          if ip != nil
            if !classic
              raise MuError, "Requested EIP #{ip}, but no such IP exists or is avaulable in VPC"
            else
              raise MuError, "Requested EIP #{ip}, but no such IP exists or is available in EC2 Classic"
            end
          end
          if !classic
            resp = MU::Cloud::AWS.ec2(region: region).allocate_address(domain: "vpc")
            new_ip = resp.public_ip
          else
            new_ip = MU::Cloud::AWS.ec2(region: region).allocate_address().public_ip
          end
          filters = [{name: "public-ip", values: [new_ip]}]
          if resp.domain
            filters << {name: "domain", values: [resp.domain]}
          end rescue NoMethodError
          if new_ip.nil?
            MU.log "Unable to allocate new Elastic IP. Are we at quota?", MU::ERR
            raise MuError, "Unable to allocate new Elastic IP. Are we at quota?"
          end
          MU.log "Allocated new EIP #{new_ip}, fetching full description"


          begin
            begin
              sleep 5
              resp = MU::Cloud::AWS.ec2(region: region).describe_addresses(
                  filters: filters
              )
              addr = resp.addresses.first
            end while resp.addresses.size < 1 or addr.public_ip.nil?
          rescue NoMethodError
            MU.log "EIP descriptor came back without a public_ip attribute for #{new_ip}, retrying", MU::WARN
            sleep 5
            retry
          end

          return addr
        end

        # Add a volume to this instance
        # @param dev [String]: Device name to use when attaching to instance
        # @param size [String]: Size (in gb) of the new volume
        # @param type [String]: Cloud storage type of the volume, if applicable
        # @param delete_on_termination [Boolean]: Value of delete_on_termination flag to set
        def addVolume(dev, size, type: "gp2", delete_on_termination: false)
          if @cloud_id.nil? or @cloud_id.empty?
            MU.log "#{self} didn't have a cloud id, couldn't determine 'active?' status", MU::ERR
            return true
          end
          az = nil
          MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_instances(
            instance_ids: [@cloud_id]
          ).reservations.each { |resp|
            if !resp.nil? and !resp.instances.nil?
              resp.instances.each { |instance|
                az = instance.placement.availability_zone
                d_o_t_changed = true
                mappings = MU.structToHash(instance.block_device_mappings)
                mappings.each { |vol|
                  if vol[:ebs]
                    vol[:ebs].delete(:attach_time)
                    vol[:ebs].delete(:status)
                  end
                }
                mappings.each { |vol|
                  if vol[:device_name] == dev
                    MU.log "A volume #{dev} already attached to #{self}, skipping", MU::NOTICE
                    if vol[:ebs][:delete_on_termination] != delete_on_termination
                      vol[:ebs][:delete_on_termination] = delete_on_termination
                      MU.log "Setting delete_on_termination flag to #{delete_on_termination.to_s} on #{@mu_name}'s #{dev}"
                      MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).modify_instance_attribute(
                        instance_id: @cloud_id,
                        block_device_mappings: mappings
                      )
                    end
                    return
                  end
                }
              }
            end
          }
          MU.log "Creating #{size}GB #{type} volume on #{dev} for #{@cloud_id}"
          creation = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).create_volume(
            availability_zone: az,
            size: size,
            volume_type: type
          )
          begin
            sleep 3
            creation = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_volumes(volume_ids: [creation.volume_id]).volumes.first
            if !["creating", "available"].include?(creation.state)
              raise MuError, "Saw state '#{creation.state}' while creating #{size}GB #{type} volume on #{dev} for #{@cloud_id}"
            end
          end while creation.state != "available"

          if @deploy
            MU::MommaCat.listStandardTags.each_pair { |key, value|
              MU::Cloud::AWS.createTag(creation.volume_id, key, value, region: @config['region'], credentials: @config['credentials'])
            }
            MU::Cloud::AWS.createTag(creation.volume_id, "Name", "#{MU.deploy_id}-#{@config["name"].upcase}-#{dev.upcase}", region: @config['region'], credentials: @config['credentials'])
          end

          attachment = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).attach_volume(
            device: dev,
            instance_id: @cloud_id,
            volume_id: creation.volume_id
          )

          begin
            sleep 3
            attachment = MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_volumes(volume_ids: [attachment.volume_id]).volumes.first.attachments.first
            if !["attaching", "attached"].include?(attachment.state)
              raise MuError, "Saw state '#{creation.state}' while creating #{size}GB #{type} volume on #{dev} for #{@cloud_id}"
            end
          end while attachment.state != "attached"

          # Set delete_on_termination, which for some reason is an instance
          # attribute and not on the attachment
          mappings = MU.structToHash(cloud_desc.block_device_mappings)
          changed = false

          mappings.each { |mapping|
            if mapping[:ebs]
              mapping[:ebs].delete(:attach_time)
              mapping[:ebs].delete(:status)
            end
            if mapping[:device_name] == dev and 
               mapping[:ebs][:delete_on_termination] != delete_on_termination
              changed = true
              mapping[:ebs][:delete_on_termination] = delete_on_termination
            end
          }

          if changed
            MU.log "Setting delete_on_termination flag to #{delete_on_termination.to_s} on #{@mu_name}'s #{dev}"
            MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).modify_instance_attribute(
              instance_id: @cloud_id,
              block_device_mappings: mappings
            )
          end

        end

        # Determine whether the node in question exists at the Cloud provider
        # layer.
        # @return [Boolean]
        def active?
          if @cloud_id.nil? or @cloud_id.empty?
            MU.log "#{self} didn't have a #{@cloud_id}, couldn't determine 'active?' status", MU::ERR
            return true
          end
          begin
            MU::Cloud::AWS.ec2(region: @config['region'], credentials: @config['credentials']).describe_instances(
                instance_ids: [@cloud_id]
            ).reservations.each { |resp|
              if !resp.nil? and !resp.instances.nil?
                resp.instances.each { |instance|
                  if instance.state.name == "terminated" or
                      instance.state.name == "terminating"
                    return false
                  end
                  return true
                }
              end
            }
          rescue Aws::EC2::Errors::InvalidInstanceIDNotFound
            return false
          end
          return false
        end

        @eip_semaphore = Mutex.new
        # Associate an Amazon Elastic IP with an instance.
        # @param instance_id [String]: The cloud provider identifier of the instance.
        # @param classic [Boolean]: Whether to assume we're using an IP in EC2 Classic instead of VPC.
        # @param ip [String]: Request a specific IP address.
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.associateElasticIp(instance_id, classic: false, ip: nil, region: MU.curRegion)
          MU.log "associateElasticIp called: #{instance_id}, classic: #{classic}, ip: #{ip}, region: #{region}", MU::DEBUG
          elastic_ip = nil
          @eip_semaphore.synchronize {
            if !ip.nil?
              filters = [{name: "public-ip", values: [ip]}]
              resp = MU::Cloud::AWS.ec2(region: region).describe_addresses(filters: filters)
              if @eips_used.include?(ip)
                is_free = false
                resp.addresses.each { |address|
                  if address.public_ip == ip and (address.instance_id.nil? and address.network_interface_id.nil?) or address.instance_id == instance_id
                    @eips_used.delete(ip)
                    is_free = true
                  end
                }

                raise MuError, "Requested EIP #{ip}, but we've already assigned this IP to someone else" if !is_free
              else
                resp.addresses.each { |address|
                  if address.public_ip == ip and address.instance_id == instance_id
                    return ip
                  end
                }
              end
            end
            elastic_ip = findFreeElasticIp(classic: classic, ip: ip)
            if !ip.nil? and (elastic_ip.nil? or ip != elastic_ip.public_ip)
              raise MuError, "Requested EIP #{ip}, but this IP does not exist or is not available"
            end
            if elastic_ip.nil?
              raise MuError, "Couldn't find an Elastic IP to associate with #{instance_id}"
            end
            @eips_used << elastic_ip.public_ip
            MU.log "Associating Elastic IP #{elastic_ip.public_ip} with #{instance_id}", details: elastic_ip
          }
          attempts = 0
          begin
            if classic
              resp = MU::Cloud::AWS.ec2(region: region).associate_address(
                  instance_id: instance_id,
                  public_ip: elastic_ip.public_ip
              )
            else
              resp = MU::Cloud::AWS.ec2(region: region).associate_address(
                  instance_id: instance_id,
                  allocation_id: elastic_ip.allocation_id,
                  allow_reassociation: false
              )
            end
          rescue Aws::EC2::Errors::IncorrectInstanceState => e
            attempts = attempts + 1
            if attempts < 6
              MU.log "Got #{e.message} associating #{elastic_ip.allocation_id} with #{instance_id}, retrying", MU::WARN
              sleep 5
              retry
            end
            raise MuError "#{e.message} associating #{elastic_ip.allocation_id} with #{instance_id}"
          rescue Aws::EC2::Errors::ResourceAlreadyAssociated => e
            # A previous association attempt may have succeeded, albeit slowly.
            resp = MU::Cloud::AWS.ec2(region: region).describe_addresses(
                allocation_ids: [elastic_ip.allocation_id]
            )
            first_addr = resp.addresses.first
            if !first_addr.nil? and first_addr.instance_id == instance_id
              MU.log "#{elastic_ip.public_ip} already associated with #{instance_id}", MU::WARN
            else
              MU.log "#{elastic_ip.public_ip} shows as already associated!", MU::ERR, details: resp
              raise MuError, "#{elastic_ip.public_ip} shows as already associated with #{first_addr.instance_id}!"
            end
          end

          instance = MU::Cloud::AWS.ec2(region: region).describe_instances(instance_ids: [instance_id]).reservations.first.instances.first
          waited = false
          if instance.public_ip_address != elastic_ip.public_ip
            waited = true
            begin
              sleep 10
              MU.log "Waiting for Elastic IP association of #{elastic_ip.public_ip} to #{instance_id} to take effect", MU::NOTICE
              instance = MU::Cloud::AWS.ec2(region: region).describe_instances(instance_ids: [instance_id]).reservations.first.instances.first
            end while instance.public_ip_address != elastic_ip.public_ip
          end

          MU.log "Elastic IP #{elastic_ip.public_ip} now associated with #{instance_id}" if waited

          return elastic_ip.public_ip
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          false
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::RELEASE
        end

        # Remove all instances associated with the currently loaded deployment. Also cleans up associated volumes, droppings in the MU master's /etc/hosts and ~/.ssh, and in whatever Groomer was used.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          onlycloud = flags["onlycloud"]
          skipsnapshots = flags["skipsnapshots"]
          tagfilters = [
            {name: "tag:MU-ID", values: [MU.deploy_id]}
          ]
          if !ignoremaster
            tagfilters << {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]}
          end
          instances = Array.new
          unterminated = Array.new
          name_tags = Array.new

          # Build a list of instances we need to clean up. We guard against
          # accidental deletion here by requiring someone to have hand-terminated
          # these, by default.
          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_instances(
              filters: tagfilters
          )

          return if resp.data.reservations.nil?
          resp.data.reservations.each { |reservation|
            reservation.instances.each { |instance|
              if instance.state.name != "terminated"
                unterminated << instance
                instance.tags.each { |tag|
                  name_tags << tag.value if tag.key == "Name"
                }
              end
            }
          }

          parent_thread_id = Thread.current.object_id

          threads = []
          unterminated.each { |instance|
            threads << Thread.new(instance) { |myinstance|
              MU.dupGlobals(parent_thread_id)
              Thread.abort_on_exception = true
              MU::Cloud::AWS::Server.terminateInstance(id: myinstance.instance_id, noop: noop, onlycloud: onlycloud, region: region, deploy_id: MU.deploy_id, credentials: credentials)
            }
          }

          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_volumes(
              filters: tagfilters
          )
          resp.data.volumes.each { |volume|
            threads << Thread.new(volume) { |myvolume|
              MU.dupGlobals(parent_thread_id)
              Thread.abort_on_exception = true
              MU::Cloud::AWS::Server.delete_volume(myvolume, noop, skipsnapshots, credentials: credentials)
            }
          }

          # Wait for all of the instances to finish cleanup before proceeding
          threads.each { |t|
            t.join
          }
        end

        # Terminate an instance.
        # @param instance [OpenStruct]: The cloud provider's description of the instance.
        # @param id [String]: The cloud provider's identifier for the instance, to use if the full description is not available.
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.terminateInstance(instance: nil, noop: false, id: nil, onlycloud: false, region: MU.curRegion, deploy_id: MU.deploy_id, mu_name: nil, credentials: nil)
          ips = Array.new
          if !instance
            if id
              begin
                resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_instances(instance_ids: [id])
              rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
                MU.log "Instance #{id} no longer exists", MU::WARN
              end
              if !resp.nil? and !resp.reservations.nil? and !resp.reservations.first.nil?
                instance = resp.reservations.first.instances.first
                ips << instance.public_ip_address if !instance.public_ip_address.nil?
                ips << instance.private_ip_address if !instance.private_ip_address.nil?
              end
            else
              MU.log "You must supply an instance handle or id to terminateInstance", MU::ERR
            end
          else
            id = instance.instance_id
          end
          if !MU.deploy_id.empty?
            deploy_dir = File.expand_path("#{MU.dataDir}/deployments/"+MU.deploy_id)
            if Dir.exist?(deploy_dir) and !noop
              FileUtils.touch("#{deploy_dir}/.cleanup-"+id)
            end
          end

          server_obj = MU::MommaCat.findStray(
              "AWS",
              "servers",
              region: region,
              deploy_id: deploy_id,
              cloud_id: id,
              mu_name: mu_name
          ).first

          begin
            MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_instances(instance_ids: [id])
          rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
            MU.log "Instance #{id} no longer exists", MU::DEBUG
          end

          if !server_obj.nil? and MU::Cloud::AWS.hosted? and !MU::Cloud::AWS.isGovCloud?
            # DNS cleanup is now done in MU::Cloud::DNSZone. Keeping this for now
            cleaned_dns = false
            mu_name = server_obj.mu_name
            mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu", credentials: credentials).values.first
            if !mu_zone.nil?
              zone_rrsets = []
              rrsets = MU::Cloud::AWS.route53(credentials: credentials).list_resource_record_sets(hosted_zone_id: mu_zone.id)
              rrsets.resource_record_sets.each{ |record|
                zone_rrsets << record
              }

            # AWS API returns a maximum of 100 results. DNS zones are likely to have more than 100 records, lets page and make sure we grab all records in a given zone
              while rrsets.next_record_name && rrsets.next_record_type
                rrsets = MU::Cloud::AWS.route53(credentials: credentials).list_resource_record_sets(hosted_zone_id: mu_zone.id, start_record_name: rrsets.next_record_name, start_record_type: rrsets.next_record_type)
                rrsets.resource_record_sets.each{ |record|
                  zone_rrsets << record
                }
              end
            end
            if !onlycloud and !mu_name.nil?
              # DNS cleanup is now done in MU::Cloud::DNSZone. Keeping this for now
              if !zone_rrsets.nil? and !zone_rrsets.empty?
                zone_rrsets.each { |rrset|
                  if rrset.name.match(/^#{mu_name.downcase}\.server\.#{MU.myInstanceId}\.platform-mu/i)
                    rrset.resource_records.each { |record|
                      MU::Cloud::DNSZone.genericMuDNSEntry(name: mu_name, target: record.value, cloudclass: MU::Cloud::Server, delete: true)
                      cleaned_dns = true
                    }
                  end
                }
              end

							if !noop
                if !server_obj.nil? and !server_obj.config.nil?
			            MU.mommacat.notify(MU::Cloud::Server.cfg_plural, server_obj.config['name'], {}, mu_name: server_obj.mu_name, remove: true) if MU.mommacat
								end
							end

              # If we didn't manage to find this instance's Route53 entry by sifting
              # deployment metadata, see if we can get it with the Name tag.
              if !mu_zone.nil? and !cleaned_dns and !instance.nil?
                instance.tags.each { |tag|
                  if tag.key == "Name"
                    zone_rrsets.each { |rrset|
                      if rrset.name.match(/^#{tag.value.downcase}\.server\.#{MU.myInstanceId}\.platform-mu/i)
                        rrset.resource_records.each { |record|
                          MU::Cloud::DNSZone.genericMuDNSEntry(name: tag.value, target: record.value, cloudclass: MU::Cloud::Server, delete: true) if !noop
                        }
                      end
                    }
                  end
                }
              end
            end
          end

          if ips.size > 0 and !onlycloud
            known_hosts_files = [Etc.getpwuid(Process.uid).dir+"/.ssh/known_hosts"]
            if Etc.getpwuid(Process.uid).name == "root" and !MU.inGem?
              begin
                known_hosts_files << Etc.getpwnam("nagios").dir+"/.ssh/known_hosts"
              rescue ArgumentError
                # we're in a non-nagios environment and that's ok
              end
            end
            known_hosts_files.each { |known_hosts|
              next if !File.exist?(known_hosts)
              MU.log "Cleaning up #{ips} from #{known_hosts}"
              if !noop
                File.open(known_hosts, File::CREAT|File::RDWR, 0644) { |f|
                  f.flock(File::LOCK_EX)
                  newlines = Array.new
                  f.readlines.each { |line|
                    ip_match = false
                    ips.each { |ip|
                      if line.match(/(^|,| )#{ip}( |,)/)
                        MU.log "Expunging #{ip} from #{known_hosts}"
                        ip_match = true
                      end
                    }
                    newlines << line if !ip_match
                  }
                  f.rewind
                  f.truncate(0)
                  f.puts(newlines)
                  f.flush
                  f.flock(File::LOCK_UN)
                }
              end
            }
          end

          return if instance.nil?

          name = ""
          instance.tags.each { |tag|
            name = tag.value if tag.key == "Name"
          }

          if instance.state.name == "terminated"
            MU.log "#{instance.instance_id} (#{name}) has already been terminated, skipping"
          else
            if instance.state.name == "terminating"
              MU.log "#{instance.instance_id} (#{name}) already terminating, waiting"
            elsif instance.state.name != "running" and instance.state.name != "pending" and instance.state.name != "stopping" and instance.state.name != "stopped"
              MU.log "#{instance.instance_id} (#{name}) is in state #{instance.state.name}, waiting"
            else
              MU.log "Terminating #{instance.instance_id} (#{name}) #{noop}"
              if !noop
                begin
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).modify_instance_attribute(
                      instance_id: instance.instance_id,
                      disable_api_termination: {value: false}
                  )
                  MU::Cloud::AWS.ec2(credentials: credentials, region: region).terminate_instances(instance_ids: [instance.instance_id])
                    # Small race window here with the state changing from under us
                rescue Aws::EC2::Errors::IncorrectInstanceState => e
                  resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_instances(instance_ids: [id])
                  if !resp.nil? and !resp.reservations.nil? and !resp.reservations.first.nil?
                    instance = resp.reservations.first.instances.first
                    if !instance.nil? and instance.state.name != "terminated" and instance.state.name != "terminating"
                      sleep 5
                      retry
                    end
                  end
                rescue Aws::EC2::Errors::InternalError => e
                  MU.log "Error #{e.inspect} while Terminating instance #{instance.instance_id} (#{name}), retrying", MU::WARN, details: e.inspect
                  sleep 5
                  retry
                end
              end
            end
            while instance.state.name != "terminated" and !noop
              sleep 30
              instance_response = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_instances(instance_ids: [instance.instance_id])
              instance = instance_response.reservations.first.instances.first
            end
            MU.log "#{instance.instance_id} (#{name}) terminated" if !noop
          end
        end

        # Return a BoK-style config hash describing a NAT instance. We use this
        # to approximate NAT gateway functionality with a plain instance.
        # @return [Hash]
        def self.genericNAT
          return {
            "cloud" => "AWS",
            "bastion" => true,
            "size" => "t2.small",
            "run_list" => [ "mu-nat" ],
            "groomer" => "Ansible",
            "platform" => "centos7",
            "ssh_user" => "centos",
            "associate_public_ip" => true,
            "static_ip" => { "assign_ip" => true },
          }
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "ami_id" => {
              "type" => "string",
              "description" => "Alias for +image_id+"
            },
            "generate_iam_role" => {
              "type" => "boolean",
              "default" => true,
              "description" => "Generate a unique IAM profile for this Server or ServerPool.",
            },
            "iam_role" => {
              "type" => "string",
              "description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile. If generate_iam_role is false, will simple use this profile.",
            },
            "canned_iam_policies" => {
              "type" => "array",
              "items" => {
                "description" => "IAM policies to attach, pre-defined by Amazon (e.g. AmazonEKSWorkerNodePolicy)",
                "type" => "string"
              }
            },
            "iam_policies" => {
              "type" => "array",
              "items" => {
                "description" => "Amazon-compatible role policies which will be merged into this node's own instance profile.  Not valid with generate_iam_role set to false. Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
                "type" => "object"
              }
            },
            "ingress_rules" => {
              "items" => {
                "properties" => {
                  "sgs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "Other AWS Security Groups; resources that are associated with this group will have this rule applied to their traffic",
                      "type" => "string"
                    }
                  },
                  "lbs" => {
                    "type" => "array",
                    "items" => {
                      "description" => "AWS Load Balancers which will have this rule applied to their traffic",
                      "type" => "string"
                    }
                  }
                }
              }
            },
            "ssh_user" => {
              "type" => "string",
              "default" => "root",
              "default_if" => [
                {
                  "key_is" => "platform",
                  "value_is" => "windows",
                  "set" => "Administrator"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "win2k12",
                  "set" => "Administrator"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "win2k12r2",
                  "set" => "Administrator"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "win2k16",
                  "set" => "Administrator"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "rhel7",
                  "set" => "ec2-user"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "rhel71",
                  "set" => "ec2-user"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "amazon",
                  "set" => "ec2-user"
                }
              ]
            }
          }
          [toplevel_required, schema]
        end

        # Confirm that the given instance size is valid for the given region.
        # If someone accidentally specified an equivalent size from some other cloud provider, return something that makes sense. If nothing makes sense, return nil.
        # @param size [String]: Instance type to check
        # @param region [String]: Region to check against
        # @return [String,nil]
        def self.validateInstanceType(size, region)
          size = size.dup.to_s
          types = begin
            (MU::Cloud::AWS.listInstanceTypes(region))[region]
          rescue Aws::Pricing::Errors::Unrecognitypes.has_key?(size)
            MU.log "Saw authentication error communicating with Pricing API, going to assume our instance type is correct", MU::WARN
            return size
          end

          return size if types.has_key?(size)

          if size.nil? or !types.has_key?(size)
            # See if it's a type we can approximate from one of the other clouds
            foundmatch = false

            MU::Cloud.availableClouds.each { |cloud|
              next if cloud == "AWS"
              cloudbase = Object.const_get("MU").const_get("Cloud").const_get(cloud)
              foreign_types = (cloudbase.listInstanceTypes).values.first
              if foreign_types.size == 1
                foreign_types = foreign_types.values.first
              end
              if foreign_types and foreign_types.size > 0 and foreign_types.has_key?(size)
                vcpu = foreign_types[size]["vcpu"]
                mem = foreign_types[size]["memory"]
                ecu = foreign_types[size]["ecu"]
                types.keys.sort.reverse.each { |type|
                  features = types[type]
                  next if ecu == "Variable" and ecu != features["ecu"]
                  next if features["vcpu"] != vcpu
                  if (features["memory"] - mem.to_f).abs < 0.10*mem
                    foundmatch = true
                    MU.log "You specified #{cloud} instance type '#{size}.' Approximating with Amazon EC2 type '#{type}.'", MU::WARN
                    size = type
                    break
                  end
                }
              end
              break if foundmatch
            }

            if !foundmatch
              MU.log "Invalid size '#{size}' for AWS EC2 instance in #{region}. Supported types:", MU::ERR, details: types.keys.sort.join(", ")
              return nil
            end
          end
          size
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          ok = true

          server['size'] = validateInstanceType(server["size"], server["region"])
          ok = false if server['size'].nil?

          if !server['generate_iam_role']
            if !server['iam_role'] and server['cloud'] != "CloudFormation"
              MU.log "Must set iam_role if generate_iam_role set to false", MU::ERR
              ok = false
            end
            if !server['iam_policies'].nil? and server['iam_policies'].size > 0
              MU.log "Cannot mix iam_policies with generate_iam_role set to false", MU::ERR
              ok = false
            end
          else
            role = {
              "name" => server["name"],
              "credentials" => server["credentials"],
              "can_assume" => [
                {
                  "entity_id" => "ec2.amazonaws.com",
                  "entity_type" => "service"
                }
              ],
              "policies" => [
                {
                  "name" => "MuSecrets",
                  "permissions" => ["s3:GetObject"],
                  "targets" => [
                    {
                      "identifier" => 'arn:'+(MU::Cloud::AWS.isGovCloud?(server['region']) ? "aws-us-gov" : "aws")+':s3:::'+MU::Cloud::AWS.adminBucketName(server['credentials'])+'/Mu_CA.pem'
                    }
                  ]
                }
              ]
            }
            if server['iam_policies']
              role['iam_policies'] = server['iam_policies'].dup
            end
            if server['canned_iam_policies']
              role['import'] = server['canned_iam_policies'].dup
            end
            if server['iam_role']
# XXX maybe break this down into policies and add those?
            end

            configurator.insertKitten(role, "roles")
            server["dependencies"] ||= []
            server["dependencies"] << {
              "type" => "role",
              "name" => server["name"]
            }
          end
          if !server['create_image'].nil?
            if server['create_image'].has_key?('copy_to_regions') and
                (server['create_image']['copy_to_regions'].nil? or
                    server['create_image']['copy_to_regions'].include?("#ALL") or
                    server['create_image']['copy_to_regions'].size == 0
                )
              server['create_image']['copy_to_regions'] = MU::Cloud::AWS.listRegions(server['us_only'])
            end
          end

          server['ami_id'] ||= server['image_id']

          if server['ami_id'].nil?
            img_id = MU::Cloud.getStockImage("AWS", platform: server['platform'], region: server['region'])
            if img_id
              server['ami_id'] = configurator.getTail("server"+server['name']+"AMI", value: img_id, prettyname: "server"+server['name']+"AMI", cloudtype: "AWS::EC2::Image::Id")
            else
              MU.log "No AMI specified for #{server['name']} and no default available for platform #{server['platform']} in region #{server['region']}", MU::ERR, details: server
              ok = false
            end
          end

          if !server["loadbalancers"].nil?
            server["loadbalancers"].each { |lb|
              if lb["concurrent_load_balancer"] != nil
                server["dependencies"] << {
                    "type" => "loadbalancer",
                    "name" => lb["concurrent_load_balancer"]
                }
              end
            }
          end

          if !server["vpc"].nil?
            if server["vpc"]["subnet_name"].nil? and server["vpc"]["subnet_id"].nil? and server["vpc"]["subnet_pref"].nil?
              MU.log "A server VPC block must specify a target subnet", MU::ERR
              ok = false
            end
          end

          ok
        end

        # Return the date/time a machine image was created.
        # @param ami_id [String]: AMI identifier of an Amazon Machine Image
        # @param credentials [String]
        # @return [DateTime]
        def self.imageTimeStamp(ami_id, credentials: nil, region: nil)
          begin
            img = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_images(image_ids: [ami_id]).images.first
            return DateTime.new if img.nil?
            return DateTime.parse(img.creation_date)
          rescue Aws::EC2::Errors::InvalidAMIIDNotFound => e
          end

          return DateTime.new
        end

        private

        # Destroy a volume.
        # @param volume [OpenStruct]: The cloud provider's description of the volume.
        # @param id [String]: The cloud provider's identifier for the volume, to use if the full description is not available.
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.delete_volume(volume, noop, skipsnapshots, id: nil, region: MU.curRegion, credentials: nil)
          if !volume.nil?
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_volumes(volume_ids: [volume.volume_id])
            volume = resp.data.volumes.first
          end
          name = ""
          volume.tags.each { |tag|
            name = tag.value if tag.key == "Name"
          }

          MU.log("Deleting volume #{volume.volume_id} (#{name})")
          if !noop
            if !skipsnapshots
              if !name.nil? and !name.empty?
                desc = "#{MU.deploy_id}-MUfinal (#{name})"
              else
                desc = "#{MU.deploy_id}-MUfinal"
              end

              begin
                MU::Cloud::AWS.ec2(region: region, credentials: credentials).create_snapshot(
                  volume_id: volume.volume_id,
                  description: desc
                )
              rescue Aws::EC2::Errors::IncorrectState => e
                if e.message.match(/'deleting'/)
                  MU.log "Cannot snapshot volume '#{name}', is already being deleted", MU::WARN
                end
              end
            end

            retries = 0
            begin
              MU::Cloud::AWS.ec2(region: region, credentials: credentials).delete_volume(volume_id: volume.volume_id)
            rescue Aws::EC2::Errors::IncorrectState => e
              MU.log "Volume #{volume.volume_id} (#{name}) in incorrect state (#{e.message}), will retry", MU::WARN
              sleep 30
              retry
            rescue Aws::EC2::Errors::InvalidVolumeNotFound
              MU.log "Volume #{volume.volume_id} (#{name}) disappeared before I could remove it!", MU::WARN
            rescue Aws::EC2::Errors::VolumeInUse
              if retries < 10
                volume.attachments.each { |attachment|
                  MU.log "#{volume.volume_id} is attached to #{attachment.instance_id} as #{attachment.device}", MU::NOTICE
                }
                MU.log "Volume '#{name}' is still attached, waiting...", MU::NOTICE
                sleep 30
                retries = retries + 1
                retry
              else
                MU.log "Failed to delete #{name}", MU::ERR
              end
            end
          end
        end


      end #class
    end #class
  end
end #module
