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
              credentials: @credentials,
              template_variables: {
                "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                "deploySSHKey" => @deploy.ssh_public_key,
                "muID" => @deploy.deploy_id,
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
            userdata_dir = File.expand_path(MU.myRoot+"/modules/mu/providers/aws/userdata")
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
            MU::Cloud::AWS.createStandardTags(
              instance.instance_id,
              region: @region,
              credentials: @credentials,
              optional: @config['optional_tags'],
              nametag: @mu_name,
              othertags: @config['tags']
            )
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
                MU::Cloud::AWS::Server.cleanup(noop: false, ignoremaster: false, region: @region, credentials: @credentials, flags: { "skipsnapshots" => true } )
              }
            end
          end
          raise e
        end

        return @config
      end

      # Create an Amazon EC2 instance.
      def createEc2Instance

        instance_descriptor = {
          :image_id => @config["image_id"],
          :key_name => @deploy.ssh_key_name,
          :instance_type => @config["size"],
          :disable_api_termination => true,
          :metadata_options => {
            :http_tokens => "optional",
            :http_endpoint => "enabled",
            :instance_metadata_tags => "enabled"
          },
          :min_count => 1,
          :max_count => 1
        }

        instance_descriptor[:iam_instance_profile] = getIAMProfile

        security_groups = myFirewallRules.map { |fw| fw.cloud_id }
        if security_groups.size > 0
          instance_descriptor[:security_group_ids] = security_groups
        else
          raise MuError, "Didn't get any security groups assigned to be in #{@mu_name}, that shouldn't happen"
        end

        if @config['private_ip']
          instance_descriptor[:private_ip_address] = @config['private_ip']
        end

        if !@vpc.nil? and @config.has_key?("vpc")
          subnet = mySubnets.sample
          if subnet.nil?
            raise MuError, "Got null subnet id out of #{@config['vpc']}"
          end
          MU.log "Deploying #{@mu_name} into VPC #{@vpc.cloud_id} Subnet #{subnet.cloud_id}"
          allowBastionAccess
          instance_descriptor[:subnet_id] = subnet.cloud_id
        end

        if !@userdata.nil? and !@userdata.empty?
          instance_descriptor[:user_data] = Base64.encode64(@userdata)
        end

        MU::Cloud::AWS::Server.waitForAMI(@config["image_id"], region: @region, credentials: @credentials)

        instance_descriptor[:block_device_mappings] = MU::Cloud::AWS::Server.configureBlockDevices(image_id: @config["image_id"], storage: @config['storage'], region: @region, credentials: @credentials)

        instance_descriptor[:monitoring] = {enabled: @config['monitoring']}

        if @tags and @tags.size > 0
          instance_descriptor[:tag_specifications] = [{
            :resource_type => "instance",
            :tags => @tags.keys.map { |k|
              { :key => k, :value => @tags[k] }
            }
          }]
        end

        MU.log "Creating EC2 instance #{@mu_name}", details: instance_descriptor

        instance = resp = nil
        loop_if = Proc.new {
          instance = resp.instances.first if resp and resp.instances
          resp.nil? or resp.instances.nil? or instance.nil?
        }

        bad_subnets = []
        mysubnet_ids = if mySubnets
          mySubnets.map { |s| s.cloud_id }
        end
        begin
          MU.retrier([Aws::EC2::Errors::InvalidGroupNotFound, Aws::EC2::Errors::InvalidSubnetIDNotFound, Aws::EC2::Errors::InvalidParameterValue], loop_if: loop_if, loop_msg: "Waiting for run_instances to return #{@mu_name}") {
            resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).run_instances(instance_descriptor)
          }
        rescue Aws::EC2::Errors::Unsupported => e
          bad_subnets << instance_descriptor[:subnet_id]
          better_subnet = (mysubnet_ids - bad_subnets).sample
          if e.message !~ /is not supported in your requested Availability Zone/ and
             (mysubnet_ids.nil? or mysubnet_ids.empty? or
              mysubnet_ids.size == bad_subnets.size or
              better_subnet.nil? or better_subnet == "")
            raise MuError.new e.message, details: mysubnet_ids
          end
          instance_descriptor[:subnet_id] = (mysubnet_ids - bad_subnets).sample
          if instance_descriptor[:subnet_id].nil?
            raise MuError.new "Specified subnet#{bad_subnets.size > 1 ? "s do" : " does"} not support instance type #{instance_descriptor[:instance_type]}", details: bad_subnets
          end
          MU.log "One or more subnets does not support instance type #{instance_descriptor[:instance_type]}, attempting with #{instance_descriptor[:subnet_id]} instead", MU::WARN, details: bad_subnets
          retry
        rescue Aws::EC2::Errors::InvalidRequest => e
          MU.log e.message, MU::ERR, details: instance_descriptor
          raise e
        end

        MU.log "#{@mu_name} (#{instance.instance_id}) coming online"

        instance
      end

      # Ask the Amazon API to restart this node
      def reboot(hard = false)
        return if @cloud_id.nil?

        if hard
          groupname = nil
          if !@config['basis'].nil?
            resp = MU::Cloud::AWS.autoscale(region: @region, credentials: @credentials).describe_auto_scaling_instances(
              instance_ids: [@cloud_id]
            )
            groupname = resp.auto_scaling_instances.first.auto_scaling_group_name
            MU.log "Pausing Autoscale processes in #{groupname}", MU::NOTICE
            MU::Cloud::AWS.autoscale(region: @region, credentials: @credentials).suspend_processes(
              auto_scaling_group_name: groupname,
              scaling_processes: [
                "Terminate",
              ], 
            )
          end
          begin
            MU.log "Stopping #{@mu_name} (#{@cloud_id})", MU::NOTICE
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).stop_instances(
              instance_ids: [@cloud_id]
            )
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).wait_until(:instance_stopped, instance_ids: [@cloud_id]) do |waiter|
              waiter.before_attempt do
                MU.log "Waiting for #{@mu_name} to stop for hard reboot"
              end
            end
            MU.log "Starting #{@mu_name} (#{@cloud_id})"
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).start_instances(
              instance_ids: [@cloud_id]
            )
          ensure
            if !groupname.nil?
              MU.log "Resuming Autoscale processes in #{groupname}", MU::NOTICE
              MU::Cloud::AWS.autoscale(region: @region, credentials: @credentials).resume_processes(
                auto_scaling_group_name: groupname,
                scaling_processes: [
                  "Terminate",
                ],
              )
            end
          end
        else
          MU.log "Rebooting #{@mu_name} (#{@cloud_id})"
          MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).reboot_instances(
            instance_ids: [@cloud_id]
          )
        end
      end

      # Figure out what's needed to SSH into this server.
      # @return [Array<String>]: nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name, alternate_names
      def getSSHConfig
        cloud_desc(use_cache: false) # make sure we're current
# XXX add some awesome alternate names from metadata and make sure they end
# up in MU::MommaCat's ssh config wangling
        return nil if @config.nil? or @deploy.nil?

        nat_ssh_key = nat_ssh_user = nat_ssh_host = nil
        if !@config["vpc"].nil? and !MU::Cloud.resourceClass("AWS", "VPC").haveRouteToInstance?(cloud_desc, region: @region, credentials: @credentials)
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
        @cloud_id ||= instance_id
        _node, _config, deploydata = describe(cloud_id: @cloud_id)

        raise MuError, "Couldn't find instance #{@mu_name} (#{@cloud_id})" if !cloud_desc
        return false if !MU::MommaCat.lock(@cloud_id+"-orchestrate", true)
        return false if !MU::MommaCat.lock(@cloud_id+"-groom", true)

        getIAMProfile

        finish = Proc.new { |status|
          MU::MommaCat.unlock(@cloud_id+"-orchestrate")
          MU::MommaCat.unlock(@cloud_id+"-groom")
          return status
        }

        MU::Cloud::AWS.createStandardTags(
          @cloud_id,
          region: @region,
          credentials: @credentials,
          optional: @config['optional_tags'],
          nametag: @mu_name,
          othertags: @config['tags']
        )

        # Make double sure we don't lose a cached mu_windows_name value.
        if (windows? or !@config['active_directory'].nil?)
          @mu_windows_name ||= deploydata['mu_windows_name']
        end

        loop_if = Proc.new {
          !cloud_desc(use_cache: false) or cloud_desc.state.name != "running"
        }
        MU.retrier([Aws::EC2::Errors::ServiceError], max: 30, wait: 40, loop_if: loop_if) { |retries, _wait|
          if cloud_desc and cloud_desc.state.name == "terminated"
            logs = if !@config['basis'].nil?
              pool = @deploy.findLitterMate(type: "server_pools", name: @config["name"])
              if pool
                MU::Cloud::AWS.autoscale(region: @region, credentials: @credentials).describe_scaling_activities(auto_scaling_group_name: pool.cloud_id).activities
              else
                nil
              end
            end
            raise MuError.new, "#{@cloud_id} appears to have been terminated mid-bootstrap!", details: logs
          end
          if retries % 3 == 0
            MU.log "Waiting for EC2 instance #{@mu_name} (#{@cloud_id}) to be ready...", MU::NOTICE
          end
        }

        allowBastionAccess

        setAlarms

        # Unless we're planning on associating a different IP later, set up a
        # DNS entry for this thing and let it sync in the background. We'll come
        # back to it later.
        if @config['static_ip'].nil? and !@named
          MU::MommaCat.nameKitten(self)
          @named = true
        end

        if !@config['src_dst_check'] and !@config["vpc"].nil?
          MU.log "Disabling source_dest_check #{@mu_name} (making it NAT-worthy)"
          MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).modify_instance_attribute(
            instance_id: @cloud_id,
            source_dest_check: { value: false }
          )
        end

        # Set console termination protection. Autoscale nodes won't set this
        # by default.
        MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).modify_instance_attribute(
          instance_id: @cloud_id,
          disable_api_termination: { value: true}
        )

        tagVolumes
        configureNetworking
        saveCredentials

        if !@config['image_then_destroy']
          notify
        end

        finish.call(false) if !bootstrapGroomer

        # Make sure we got our name written everywhere applicable
        if !@named
          MU::MommaCat.nameKitten(self)
          @named = true
        end

        finish.call(true)
      end #postboot 

      # Locate an existing instance or instances and return an array containing matching AWS resource descriptors for those that match.
      # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching instances
      def self.find(**args)
        ip ||= args[:flags]['ip'] if args[:flags] and args[:flags]['ip']

        regions = args[:region].nil? ? MU::Cloud::AWS.listRegions : [args[:region]]

        found = {}
        search_semaphore = Mutex.new
        search_threads = []

        base_filter = { name: "instance-state-name", values: ["running", "pending", "stopped"] }
        searches = []

        if args[:cloud_id]
          searches << {
            :instance_ids => [args[:cloud_id]],
            :filters => [base_filter]
          }
        end

        if ip
          ["ip-address", "private-ip-address"].each { |ip_type|
            searches << {
              filters: [base_filter,  {name: ip_type, values: [ip]} ],
            }
          }
        end

        if args[:tag_value] and args[:tag_key]
          searches << {
            filters: [
              base_filter,
              {name: "tag:#{args[:tag_key]}", values: [args[:tag_value]]},
            ]
          }
        end

        if searches.empty?
          searches << { filters: [base_filter] }
        end

        regions.each { |r|
          searches.each { |search|
            search_threads << Thread.new(search) { |params|
              MU.retrier([], wait: 5, max: 5, ignoreme: [Aws::EC2::Errors::InvalidInstanceIDNotFound]) {
                MU::Cloud::AWS.ec2(region: r, credentials: args[:credentials]).describe_instances(params).reservations.each { |resp|
                  next if resp.nil? or resp.instances.nil?
                  resp.instances.each { |i|
                    search_semaphore.synchronize {
                      found[i.instance_id] = i
                    }
                  }
                }
              }
            }
          }
        }
        done_threads = []
        begin
          search_threads.each { |t|
            joined = t.join(2)
            done_threads << joined if !joined.nil?
          }
        end while found.size < 1 and done_threads.size != search_threads.size

        return found
      end

      # Reverse-map our cloud description into a runnable config hash.
      # We assume that any values we have in +@config+ are placeholders, and
      # calculate our own accordingly based on what's live in the cloud.
      def toKitten(**_args)
        bok = {
          "cloud" => "AWS",
          "credentials" => @credentials,
          "cloud_id" => @cloud_id,
          "region" => @region
        }

        if !cloud_desc
          MU.log "toKitten failed to load a cloud_desc from #{@cloud_id}", MU::ERR, details: @config
          return nil
        end

        asgs = MU::Cloud.resourceClass("AWS", "ServerPool").find(
          instance_id: @cloud_id,
          region: @region,
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

        ami = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_images(image_ids: [bok['image_id']]).images.first

        if ami.nil? or ami.empty?
          MU.log "#{@mu_name} source image #{bok['image_id']} no longer exists", MU::WARN
          bok.delete("image_id")
        end

        if cloud_desc.block_device_mappings and !cloud_desc.block_device_mappings.empty?
          vol_map = {}
          MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_volumes(
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
              region: @region,
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
              bok['add_private_ips'] ||= 0
              bok['add_private_ips'] += 1
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

            require 'mu/providers/aws/firewall_rule'
            ifaces = MU::Cloud.resourceClass("AWS", "FirewallRule").getAssociatedInterfaces(int.groups.map { |sg| sg.group_id }, credentials: @credentials, region: @region)
            done_local_rules = false
            int.groups.each { |sg|
              if !done_local_rules and ifaces[sg.group_id].size == 1
                sg_desc = MU::Cloud.resourceClass("AWS", "FirewallRule").find(cloud_id: sg.group_id, credentials: @credentials, region: @region).values.first
                if sg_desc
                  bok["ingress_rules"] = MU::Cloud.resourceClass("AWS", "FirewallRule").rulesToBoK(sg_desc.ip_permissions)
                  bok["ingress_rules"].concat(MU::Cloud.resourceClass("AWS", "FirewallRule").rulesToBoK(sg_desc.ip_permissions_egress, egress: true))
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
                region: @region
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
          deploydata["region"] = @region if !@region.nil?
          if !@named
            MU::MommaCat.nameKitten(self, no_dns: true)
            @named = true
          end

          return deploydata
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          MU::MommaCat.lock(@cloud_id+"-groom")

          # Make double sure we don't lose a cached mu_windows_name value.
          if windows? or !@config['active_directory'].nil?
            if @mu_windows_name.nil?
              @mu_windows_name = deploydata['mu_windows_name']
            end
          end

          allowBastionAccess

          tagVolumes

          # If we have a loadbalancer configured, attach us to it
          if !@config['loadbalancers'].nil?
            if @loadbalancers.nil?
              raise MuError, "#{@mu_name} is configured to use LoadBalancers, but none have been loaded by dependencies()"
            end
            @loadbalancers.each { |lb|
              lb.registerTarget(@cloud_id)
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
            getIAMProfile

            dbs = @deploy.findLitterMate(type: "database", return_all: true)
            if dbs
              dbs.each_pair { |sib_name, sib|
                @groomer.groomer_class.grantSecretAccess(@mu_name, sib_name, "database_credentials")
                if sib.config and sib.config['auth_vault']
                  @groomer.groomer_class.grantSecretAccess(@mu_name, sib.config['auth_vault']['vault'], sib.config['auth_vault']['item'])
                end
              }
            end

            if @config['groom'].nil? or @config['groom']
              @groomer.run(purpose: "Full Initial Run", max_retries: 15, reboot_first_fail: (windows? and @config['groomer'] != "Ansible"), timeout: @config['groomer_timeout'])
            end
          rescue MU::Groomer::RunError => e
            raise e if !@config['create_image'].nil? and !@config['image_created']
            MU.log "Proceeding after failed initial Groomer run, but #{@mu_name} may not behave as expected!", MU::WARN, details: e.inspect
            pp e.backtrace
          rescue StandardError => e
            raise e if !@config['create_image'].nil? and !@config['image_created']
            MU.log "Caught #{e.inspect} on #{@mu_name} in an unexpected place (after @groomer.run on Full Initial Run)", MU::ERR
          end

          if !@config['create_image'].nil? and !@config['image_created']
            createImage
          end

          MU::MommaCat.unlock(@cloud_id+"-groom")
        end

        # Canonical Amazon Resource Number for this resource
        # @return [String]
        def arn
          "arn:"+(MU::Cloud::AWS.isGovCloud?(@region) ? "aws-us-gov" : "aws")+":ec2:"+@region+":"+MU::Cloud::AWS.credToAcct(@credentials)+":instance/"+@cloud_id
        end

        @cloud_desc_cache = nil
        # Return the cloud provider's description for this instance
        # @return [Openstruct]
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          return nil if !@cloud_id
          max_retries = 5
          retries = 0
          if !@cloud_id.nil?
            begin
              resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_instances(instance_ids: [@cloud_id])
              if resp and resp.reservations and resp.reservations.first and
                 resp.reservations.first.instances and
                 resp.reservations.first.instances.first
                @cloud_desc_cache = resp.reservations.first.instances.first
                return @cloud_desc_cache
              end
            rescue Aws::EC2::Errors::InvalidInstanceIDNotFound
              return nil
            rescue NoMethodError
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
          if !cloud_desc
            raise MuError, "Couldn't retrieve cloud descriptor for server #{self}"
          end

          if deploydata.nil? or
              (!deploydata.has_key?("private_ip_address") and
                  !deploydata.has_key?("public_ip_address"))
            return nil if cloud_desc.nil?
            @deploydata = {} if @deploydata.nil?
            @deploydata["public_ip_address"] = cloud_desc.public_ip_address
            @deploydata["public_dns_name"] = cloud_desc.public_dns_name
            @deploydata["private_ip_address"] = cloud_desc.private_ip_address
            @deploydata["private_dns_name"] = cloud_desc.private_dns_name

            notify
          end

          # Our deploydata gets corrupted often with server pools, this will cause us to use the wrong IP to identify a node
          # which will cause us to create certificates, DNS records and other artifacts with incorrect information which will cause our deploy to fail.
          # The cloud_id is always correct so lets use 'cloud_desc' to get the correct IPs
          if MU::Cloud.resourceClass("AWS", "VPC").haveRouteToInstance?(cloud_desc, region: @region, credentials: @credentials) or @deploydata["public_ip_address"].nil?
            @config['canonical_ip'] = cloud_desc.private_ip_address
            @deploydata["private_ip_address"] = cloud_desc.private_ip_address
            return cloud_desc.private_ip_address
          else
            @config['canonical_ip'] = cloud_desc.public_ip_address
            @deploydata["public_ip_address"] = cloud_desc.public_ip_address
            return cloud_desc.public_ip_address
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
          rescue Aws::EC2::Errors::InvalidAMINameDuplicate
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
        def getWindowsAdminPassword(use_cache: true)
          @config['windows_auth_vault'] ||= {
            "vault" => @mu_name,
            "item" => "windows_credentials",
            "password_field" => "password"
          }

          if use_cache
            begin
              win_admin_password = @groomer.getSecret(
                vault: @config['windows_auth_vault']['vault'],
                item: @config['windows_auth_vault']['item'],
                field: @config["windows_auth_vault"]["password_field"]
              )

              return win_admin_password if win_admin_password
            rescue MU::Groomer::MuNoSuchSecret, MU::Groomer::RunError
            end
          end

          @cloud_id ||= cloud_desc(use_cache: false).instance_id
          ssh_keydir = "#{Etc.getpwuid(Process.uid).dir}/.ssh"
          ssh_key_name = @deploy.ssh_key_name

          retries = 0
          MU.log "Waiting for Windows instance password to be set by Amazon and flagged as available from the API. Note- if you're using a source AMI that already has its password set, this may fail. You'll want to set use_cloud_provider_windows_password to false if this is the case.", MU::NOTICE
          begin
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).wait_until(:password_data_available, instance_id: @cloud_id) do |waiter|
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
              MU.log "wait_until(:password_data_available, instance_id: #{@cloud_id}) in #{@region} never got a good response, retrying (#{retries}/2)", MU::WARN, details: e.inspect
              retry
            else
              MU.log "wait_until(:password_data_available, instance_id: #{@cloud_id}) in #{@region} never returned- this image may not be configured to have its password set by AWS.", MU::ERR
              return nil
            end
          end

          resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).get_password_data(instance_id: @cloud_id)
          encrypted_password = resp.password_data

          # Note: This is already implemented in the decrypt_windows_password API call
          decoded = Base64.decode64(encrypted_password)
          pem_bytes = File.open("#{ssh_keydir}/#{ssh_key_name}", 'rb') { |f| f.read }
          private_key = OpenSSL::PKey::RSA.new(pem_bytes)
          decrypted_password = private_key.private_decrypt(decoded)
          saveCredentials(decrypted_password)

          return decrypted_password
        end

        @eips_used = Array.new
        # Find a free AWS Elastic IP.
        # @param classic [Boolean]: Toggle whether to allocate an IP in EC2 Classic
        # instead of VPC.
        # @param ip [String]: Request a specific IP address.
        # @param region [String]: The cloud provider region
        def self.findFreeElasticIp(classic: false, ip: nil, region: MU.curRegion, credentials: nil)
          filters = Array.new
          if !classic
            filters << {name: "domain", values: ["vpc"]}
          else
            filters << {name: "domain", values: ["standard"]}
          end
          filters << {name: "public-ip", values: [ip]} if ip != nil

          if filters.size > 0
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_addresses(filters: filters)
          else
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_addresses
          end
          resp.addresses.each { |address|
            return address if (address.network_interface_id.nil? or address.network_interface_id.empty?) and !@eips_used.include?(address.public_ip)
          }
          if !ip.nil?
            mode = classic ? "EC2 Classic" : "VPC"
            raise MuError.new "Requested EIP #{ip}, but no such IP exists or is available in #{mode} mode#{credentials ? " with credentials #{credentials}" : ""}", details: { "describe_address filters" => filters, "describe_address response" => resp }
          end
          if !classic
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).allocate_address(domain: "vpc")
            new_ip = resp.public_ip
          else
            new_ip = MU::Cloud::AWS.ec2(region: region, credentials: credentials).allocate_address().public_ip
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
              resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_addresses(
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
        def addVolume(dev: nil, size: 0, type: "gp3", delete_on_termination: false)
          if dev.nil? or size == 0
            raise MuError, "Must specify a device name and a size for addVolume"
          end

          if setDeleteOntermination(dev, delete_on_termination)
            MU.log "A volume #{dev} already attached to #{self}, skipping", MU::NOTICE
            return
          end

          MU.log "Creating #{size}GB #{type} volume on #{dev} for #{@cloud_id}"
          creation = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_volume(
            availability_zone: cloud_desc.placement.availability_zone,
            size: size,
            volume_type: type
          )

          MU.retrier(wait: 3, loop_if: Proc.new {
            creation = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_volumes(volume_ids: [creation.volume_id]).volumes.first
            if !["creating", "available"].include?(creation.state)
              raise MuError, "Saw state '#{creation.state}' while creating #{size}GB #{type} volume on #{dev} for #{@cloud_id}"
            end
            creation.state != "available"
          })


          if @deploy
            MU::Cloud::AWS.createStandardTags(
              creation.volume_id,
              region: @region,
              credentials: @credentials,
              optional: @config['optional_tags'],
              nametag: @mu_name+"-"+dev.upcase,
              othertags: @config['tags']
            )
          end

          MU.log "Attaching #{creation.volume_id} as #{dev} to #{@cloud_id} in #{@region} (credentials #{@credentials})"
          attachment = nil
          MU.retrier([Aws::EC2::Errors::IncorrectState], wait: 15, max: 4) {
            attachment = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).attach_volume(
              device: dev,
              instance_id: @cloud_id,
              volume_id: creation.volume_id
            )
          }

          begin
            att_resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_volumes(volume_ids: [attachment.volume_id])
            if att_resp and att_resp.volumes and !att_resp.volumes.empty? and
               att_resp.volumes.first.attachments and
               !att_resp.volumes.first.attachments.empty?
              attachment = att_resp.volumes.first.attachments.first
              if !attachment.nil? and !["attaching", "attached"].include?(attachment.state)
                raise MuError, "Saw state '#{creation.state}' while creating #{size}GB #{type} volume on #{dev} for #{@cloud_id}"
              end
            end
          end while attachment.nil? or attachment.state != "attached"

          # Set delete_on_termination, which for some reason is an instance
          # attribute and not on the attachment
          setDeleteOntermination(dev, delete_on_termination)
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
            MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_instances(
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
        def self.associateElasticIp(instance_id, classic: false, ip: nil, region: MU.curRegion, credentials: nil)
          MU.log "associateElasticIp called: #{instance_id}, classic: #{classic}, ip: #{ip}, region: #{region}", MU::DEBUG
          elastic_ip = nil
          @eip_semaphore.synchronize {
            if !ip.nil?
              filters = [{name: "public-ip", values: [ip]}]
              resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_addresses(filters: filters)
              if @eips_used.include?(ip)
                is_free = false
                resp.addresses.each { |address|
                  if address.public_ip == ip and (address.instance_id.nil? and address.association.nil?) or address.instance_id == instance_id
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
            elastic_ip = findFreeElasticIp(classic: classic, ip: ip, credentials: credentials)
            if !ip.nil? and (elastic_ip.nil? or ip != elastic_ip.public_ip)
              raise MuError, "Requested EIP #{ip}, but this IP does not exist or is not available"
            end
            if elastic_ip.nil?
              raise MuError, "Couldn't find an Elastic IP to associate with #{instance_id}"
            end
            @eips_used << elastic_ip.public_ip
            MU.log "Associating Elastic IP #{elastic_ip.public_ip} with #{instance_id}", details: elastic_ip
          }

          on_retry = Proc.new { |e|
            if e.class == Aws::EC2::Errors::ResourceAlreadyAssociated
              # A previous association attempt may have succeeded, albeit slowly.
              resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_addresses(
                allocation_ids: [elastic_ip.allocation_id]
              )
              first_addr = resp.addresses.first
              if first_addr and !first_addr.association_id.nil? and first_addr.instance_id != instance_id
                ifaces = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_network_interfaces(
                  filters: [{name: "association.allocation-id", values: [elastic_ip.allocation_id]}]
                ).data.network_interfaces
                raise MuError.new "Tried to associate #{elastic_ip.public_ip} with #{instance_id}, but it's already associated with #{first_addr.instance_id}!", details: ifaces
              end
            end
          }

          MU.retrier([Aws::EC2::Errors::IncorrectInstanceState, Aws::EC2::Errors::ResourceAlreadyAssociated], wait: 5, max: 6, on_retry: on_retry) {
            if classic
              MU::Cloud::AWS.ec2(region: region, credentials: credentials).associate_address(
                instance_id: instance_id,
                public_ip: elastic_ip.public_ip
              )
            else
              MU::Cloud::AWS.ec2(region: region, credentials: credentials).associate_address(
                instance_id: instance_id,
                allocation_id: elastic_ip.allocation_id,
                allow_reassociation: false
              )
            end
          }

          loop_if = Proc.new {
            instance = find(cloud_id: instance_id, region: region, credentials: credentials).values.first
            instance.public_ip_address != elastic_ip.public_ip
          }
          MU.retrier(loop_if: loop_if, wait: 10, max: 3) {
            MU.log "Waiting for Elastic IP association of #{elastic_ip.public_ip} to #{instance_id} to take effect", MU::NOTICE
          }

          MU.log "Elastic IP #{elastic_ip.public_ip} now associated with #{instance_id}"

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
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          onlycloud = flags["onlycloud"]
          skipsnapshots = flags["skipsnapshots"]
          tagfilters = [
            {name: "tag:MU-ID", values: [deploy_id]}
          ]
          if !ignoremaster
            tagfilters << {name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip]}
          end
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
              MU::Cloud::AWS::Server.terminateInstance(id: myinstance.instance_id, noop: noop, onlycloud: onlycloud, region: region, deploy_id: deploy_id, credentials: credentials)
            }
          }

          resp = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_volumes(
              filters: tagfilters
          )
          resp.data.volumes.each { |volume|
            threads << Thread.new(volume) { |myvolume|
              MU.dupGlobals(parent_thread_id)
              Thread.abort_on_exception = true
              delete_volume(myvolume, noop, skipsnapshots, credentials: credentials, deploy_id: deploy_id)
            }
          }

          # Wait for all of the instances to finish cleanup before proceeding
          threads.each { |t|
            t.join
          }
        end

        # Return an instance's AWS-assigned IP addresses and hostnames.
        # @param instance [OpenStruct]
        # @param id [String]
        # @param region [String]
        # @param credentials [@String]
        # @return [Array<Array>]
        def self.getAddresses(instance = nil, id: nil, region: MU.curRegion, credentials: nil)
          return nil if !instance and !id

          instance ||= find(cloud_id: id, region: region, credentials: credentials).values.first
          return if !instance

          ips = []
          names = []
          instance.network_interfaces.each { |iface|
            iface.private_ip_addresses.each { |ip|
              ips << ip.private_ip_address
              names << ip.private_dns_name
              if ip.association
                ips << ip.association.public_ip
                names << ip.association.public_dns_name
              end
            }
          }

          [ips, names]
        end

        # Terminate an instance.
        # @param instance [OpenStruct]: The cloud provider's description of the instance.
        # @param id [String]: The cloud provider's identifier for the instance, to use if the full description is not available.
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.terminateInstance(instance: nil, noop: false, id: nil, onlycloud: false, region: MU.curRegion, deploy_id: MU.deploy_id, mu_name: nil, credentials: nil)
          if !id and !instance
            MU.log "You must supply an instance handle or id to terminateInstance", MU::ERR
            return
          end
          instance ||= find(cloud_id: id, region: region, credentials: credentials).values.first
          return if !instance

          id ||= instance.instance_id
          begin
            MU::MommaCat.lock(".cleanup-"+id)
          rescue Errno::ENOENT => e
            MU.log "No lock for terminating instance #{id} due to missing metadata", MU::DEBUG
          end

          ips, names = getAddresses(instance, region: region, credentials: credentials)
          targets = ips +names

          server_obj = MU::MommaCat.findStray(
            "AWS",
            "servers",
            region: region,
            deploy_id: deploy_id,
            cloud_id: id,
            mu_name: mu_name,
            dummy_ok: true
          ).first

          if MU::Cloud::AWS.hosted? and !MU::Cloud::AWS.isGovCloud? and server_obj
            targets.each { |target|
              MU::Cloud::DNSZone.genericMuDNSEntry(name: server_obj.mu_name, target: target, cloudclass: MU::Cloud::Server, delete: true, noop: noop)
            }
          end

          if targets.size > 0 and !onlycloud
            MU::Master.removeInstanceFromEtcHosts(server_obj.mu_name) if !noop and server_obj
            targets.each { |target|
              next if !target.match(/^\d+\.\d+\.\d+\.\d+$/)
              MU::Master.removeIPFromSSHKnownHosts(target, noop: noop)
            }
          end

          on_retry = Proc.new {
            instance = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_instances(instance_ids: [instance.instance_id]).reservations.first.instances.first
            if instance.state.name == "terminated"
              MU.log "#{instance.instance_id}#{server_obj ? " ("+server_obj.mu_name+")" : ""} has already been terminated, skipping"
              MU::MommaCat.unlock(".cleanup-"+id)
              return
            end
          }

          loop_if = Proc.new {
            instance = MU::Cloud::AWS.ec2(credentials: credentials, region: region).describe_instances(instance_ids: [instance.instance_id]).reservations.first.instances.first
            instance.state.name != "terminated"
          }

          MU.log "Terminating #{instance.instance_id}#{server_obj ? " ("+server_obj.mu_name+")" : ""}"
          if !noop
            MU.retrier([Aws::EC2::Errors::IncorrectInstanceState, Aws::EC2::Errors::InternalError], wait: 30, max: 60, loop_if: loop_if, on_retry: on_retry) {
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).modify_instance_attribute(
                instance_id: instance.instance_id,
                disable_api_termination: {value: false}
              )
              MU::Cloud::AWS.ec2(credentials: credentials, region: region).terminate_instances(instance_ids: [instance.instance_id])
            }
          end

          MU.log "#{instance.instance_id}#{server_obj ? " ("+server_obj.mu_name+")" : ""} terminated" if !noop
          begin
            MU::MommaCat.unlock(".cleanup-"+id)
          rescue Errno::ENOENT => e
            MU.log "No lock for terminating instance #{id} due to missing metadata", MU::DEBUG
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
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "ami_id" => {
              "type" => "string",
              "description" => "Alias for +image_id+"
            },
            "windows_admin_username" => {
              "type" => "string",
              "default" => "Administrator"
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
            "ingress_rules" => MU::Cloud.resourceClass("AWS", "FirewallRule").ingressRuleAddtlSchema,
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
                },
                {
                  "key_is" => "platform",
                  "value_is" => "amazon2",
                  "set" => "ec2-user"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "amazon2023",
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
              foreign_types = (MU::Cloud.cloudClass(cloud).listInstanceTypes).values.first
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

        # Boilerplate generation of an instance role
        # @param server [Hash]: The BoK-style config hash for a +Server+ or +ServerPool+
        # @param configurator [MU::Config]
        def self.generateStandardRole(server, configurator)
          role = {
            "name" => server["name"],
            "bare_policies" => !server['generate_iam_role'],
            "strip_path" => server["role_strip_path"],
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
          role["credentials"] = server["credentials"] if server["credentials"]
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
          MU::Config.addDependency(server, server["name"], "role")
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
          end

          generateStandardRole(server, configurator)

          if !server['create_image'].nil?
            if server['create_image'].has_key?('copy_to_regions') and
                (server['create_image']['copy_to_regions'].nil? or
                    server['create_image']['copy_to_regions'].include?("#ALL") or
                    server['create_image']['copy_to_regions'].size == 0
                )
              server['create_image']['copy_to_regions'] = MU::Cloud::AWS.listRegions(server['us_only'])
            end
          end

          server['image_id'] ||= server['ami_id']

          if server['image_id'].nil?
            img_id = MU::Cloud.getStockImage("AWS", platform: server['platform'], region: server['region'])
            if img_id
              server['image_id'] = configurator.getTail("server"+server['name']+"AMI", value: img_id, prettyname: "server"+server['name']+"AMI", cloudtype: "AWS::EC2::Image::Id")
            else
              MU.log "No AMI specified for #{server['name']} and no default available for platform #{server['platform']} in region #{server['region']}", MU::ERR, details: server
              ok = false
            end
          end

          if !server["loadbalancers"].nil?
            server["loadbalancers"].each { |lb|
              lb["name"] ||= lb["concurrent_load_balancer"]
              if lb["name"]
                MU::Config.addDependency(server, lb["name"], "loadbalancer")
              end
            }
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
          rescue Aws::EC2::Errors::InvalidAMIIDNotFound
          end

          return DateTime.new
        end

        # Destroy a volume.
        # @param volume [OpenStruct]: The cloud provider's description of the volume.
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.delete_volume(volume, noop, skipsnapshots, region: MU.curRegion, credentials: nil, deploy_id: MU.deploy_id)
          if !volume.nil?
            resp = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_volumes(volume_ids: [volume.volume_id])
            volume = resp.data.volumes.first
          end
          name = nil
          volume.tags.each { |tag|
            name = tag.value if tag.key == "Name"
          }
          name ||= volume.volume_id

          MU.log("Deleting volume #{volume.volume_id} (#{name})")
          if !noop
            if !skipsnapshots
              if !name.nil? and !name.empty?
                desc = "#{deploy_id}-MUfinal (#{name})"
              else
                desc = "#{deploy_id}-MUfinal"
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

            begin
              MU.retrier([Aws::EC2::Errors::IncorrectState, Aws::EC2::Errors::VolumeInUse], ignoreme: [Aws::EC2::Errors::InvalidVolumeNotFound], wait: 30, max: 10){
                MU::Cloud::AWS.ec2(region: region, credentials: credentials).delete_volume(volume_id: volume.volume_id)
              }
            rescue Aws::EC2::Errors::VolumeInUse
              MU.log "Failed to delete #{name}", MU::ERR
            end

          end
        end
        private_class_method :delete_volume

        # Given some combination of a base image, BoK-configured storage, and
        # ephemeral devices, return the structure passed to EC2 to declare
        # block devicde mappings.
        # @param image_id [String]
        # @param storage [Array]
        # @param add_ephemeral [Boolean]
        # @param region [String]
        # @param credentials [String]
        def self.configureBlockDevices(image_id: nil, storage: nil, add_ephemeral: true, region: MU.myRegion, credentials: nil)
          ext_disks = {}
  
          # Figure out which devices are embedded in the AMI already.
          if image_id
            image = MU::Cloud::AWS.ec2(region: region, credentials: credentials).describe_images(image_ids: [image_id]).images.first
            if !image.block_device_mappings.nil?
              image.block_device_mappings.each { |disk|
                if !disk.device_name.nil? and !disk.device_name.empty? and !disk.ebs.nil? and !disk.ebs.empty?
                  ext_disks[disk.device_name] = MU.structToHash(disk.ebs)
                end
              }
            end
          end
  
          configured_storage = []
          if storage
            storage.each { |vol|
              # Drop the "encrypted" flag if a snapshot for this device exists
              # in the AMI, even if they both agree about the value of said
              # flag. Apparently that's a thing now.
              if ext_disks.has_key?(vol["device"])
                if ext_disks[vol["device"]].has_key?(:snapshot_id)
                  vol.delete("encrypted")
                end
              end
              mapping, _cfm_mapping = MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
              configured_storage << mapping
            }
          end
  
          configured_storage.concat(@ephemeral_mappings) if add_ephemeral
  
          configured_storage
        end

        # Return all of the IP addresses, public and private, from all of our
        # network interfaces.
        # @return [Array<String>]
        def listIPs
          MU::Cloud::AWS::Server.getAddresses(cloud_desc).first
        end

        private

        def bootstrapGroomer
          if (@config['groom'].nil? or @config['groom']) and !@groomer.haveBootstrapped?
            MU.retrier([BootstrapTempFail], wait: 45) {
              if windows? 
                # kick off certificate generation early; WinRM will need it
                @deploy.nodeSSLCerts(self)
                @deploy.nodeSSLCerts(self, true) if @config.has_key?("basis")
                session = getWinRMSession(50, 60, reboot_on_problems: true)
                initialWinRMTasks(session)
                begin
                  session.close
                rescue StandardError
                  # session.close is allowed to fail- we're probably rebooting
                end
              else
                session = getSSHSession(40, 30)
                initialSSHTasks(session)
              end
            }
          end

          # See if this node already exists in our config management. If it
          # does, we're done.

          if MU.inGem?
            MU.log "Deploying from a gem, not grooming"
          elsif @config['groom'].nil? or @config['groom']
            if @groomer.haveBootstrapped?
              MU.log "Node #{@mu_name} has already been bootstrapped, skipping groomer setup.", MU::NOTICE
            else
              begin
                @groomer.bootstrap
              rescue MU::Groomer::RunError
                return false
              end
            end
            @groomer.saveDeployData
          end

          true
        end

        def saveCredentials(win_admin_password = nil)
          ec2config_password = nil
          sshd_password = nil
          if windows?
            if @config['use_cloud_provider_windows_password']
              win_admin_password ||= getWindowsAdminPassword
            elsif @config['windows_auth_vault'] and !@config['windows_auth_vault'].empty?
              if @config["windows_auth_vault"].has_key?("password_field")
                win_admin_password ||= @groomer.getSecret(
                  vault: @config['windows_auth_vault']['vault'],
                  item: @config['windows_auth_vault']['item'],
                  field: @config["windows_auth_vault"]["password_field"]
                )
              else
                win_admin_password ||= getWindowsAdminPassword
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

            win_admin_password ||= MU.generatePassword
            ec2config_password ||= MU.generatePassword
            sshd_password ||= MU.generatePassword

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
        end

        def haveElasticIP?
          if !cloud_desc.public_ip_address.nil?
            begin
              resp = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_addresses(public_ips: [cloud_desc.public_ip_address])
              if resp.addresses.size > 0 and resp.addresses.first.instance_id == @cloud_id
                return true
              end
            rescue Aws::EC2::Errors::InvalidAddressNotFound
              # XXX this is ok to ignore, it means the public IP isn't Elastic
            end
          end

          false
        end

        def configureNetworking
          if !@config['static_ip'].nil?
            if !@config['static_ip']['ip'].nil?
              MU::Cloud::AWS::Server.associateElasticIp(@cloud_id, classic: @vpc.nil?, ip: @config['static_ip']['ip'], credentials: @credentials)
            elsif !haveElasticIP?
              MU::Cloud::AWS::Server.associateElasticIp(@cloud_id, classic: @vpc.nil?, credentials: @credentials)
            end
          end

          if !@vpc.nil? and @config.has_key?("vpc")
            subnet = @vpc.getSubnet(cloud_id: cloud_desc.subnet_id)

            _nat_ssh_key, _nat_ssh_user, nat_ssh_host, _canonical_ip, _ssh_user, _ssh_key_name = getSSHConfig
            if subnet.private? and !nat_ssh_host and !MU::Cloud.resourceClass("AWS", "VPC").haveRouteToInstance?(cloud_desc, region: @region, credentials: @credentials)
              raise MuError, "#{@mu_name} is in a private subnet (#{subnet}), but has no bastion host configured, and I have no other route to it"
            end

            # If we've asked for additional subnets (and this @config is not a
            # member of a Server Pool, which has different semantics), create
            # extra interfaces to accomodate.
            if !@config['vpc']['subnets'].nil? and @config['basis'].nil?
              device_index = 1
              mySubnets.each { |s|
                next if s.cloud_id == cloud_desc.subnet_id

                if cloud_desc.placement.availability_zone != s.az
                  MU.log "Cannot create interface in subnet #{s.to_s} for #{@mu_name} due to AZ mismatch", MU::WARN
                  next
                end
                MU.log "Adding network interface on subnet #{s.cloud_id} for #{@mu_name}"
                iface = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).create_network_interface(subnet_id: s.cloud_id).network_interface
                MU::Cloud::AWS.createStandardTags(
                  iface.network_interface_id,
                  region: @region,
                  credentials: @credentials,
                  optional: @config['optional_tags'],
                  nametag: @mu_name+"-ETH"+device_index.to_s,
                  othertags: @config['tags']
                )

                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).attach_network_interface(
                  network_interface_id: iface.network_interface_id,
                  instance_id: cloud_desc.instance_id,
                  device_index: device_index
                )
                device_index = device_index + 1
              }
              cloud_desc(use_cache: false)
            end
          end

          [:private_dns_name, :public_dns_name, :private_ip_address, :public_ip_address].each { |field|
            @config[field.to_s] = cloud_desc.send(field)
          }

          if !@config['add_private_ips'].nil?
            cloud_desc.network_interfaces.each { |int|
              if int.private_ip_address == cloud_desc.private_ip_address and int.private_ip_addresses.size < (@config['add_private_ips'] + 1)
                MU.log "Adding #{@config['add_private_ips']} extra private IP addresses to #{cloud_desc.instance_id}"
                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).assign_private_ip_addresses(
                  network_interface_id: int.network_interface_id,
                  secondary_private_ip_address_count: @config['add_private_ips'],
                  allow_reassignment: false
                )
              end
            }
          end
        end

        def tagVolumes
          volumes = MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).describe_volumes(filters: [name: "attachment.instance-id", values: [@cloud_id]])
          volumes.each { |vol|
            vol.volumes.each { |volume|
              volume.attachments.each { |attachment|
                MU::Cloud::AWS.createStandardTags(
                  attachment.volume_id,
                  region: @region,
                  credentials: @credentials,
                  optional: @config['optional_tags'],
                  nametag: ["/dev/sda", "/dev/sda1"].include?(attachment.device) ? "ROOT-"+@mu_name : @mu_name+"-"+attachment.device.upcase,
                  othertags: @config['tags']
                )
  
              }
            }
          }
        end

        # If we came up via AutoScale, the Alarm module won't have had our
        # instance ID to associate us with itself. So invoke that here.
        # XXX might be possible to do this with regular alarm resources and
        # dependencies now
        def setAlarms
          if !@config['basis'].nil? and @config["alarms"] and !@config["alarms"].empty?
            @config["alarms"].each { |alarm|
              alarm_obj = MU::MommaCat.findStray(
                "AWS",
                "alarms",
                region: @region,
                deploy_id: @deploy.deploy_id,
                name: alarm['name']
              ).first
              alarm["dimensions"] = [{:name => "InstanceId", :value => @cloud_id}]

              if alarm["enable_notifications"]
                # XXX vile, this should be a sibling resource generated by the
                # parser
                topic_arn = MU::Cloud.resourceClass("AWS", "Notification").createTopic(alarm["notification_group"], region: @region, credentials: @credentials)
                MU::Cloud.resourceClass("AWS", "Notification").subscribe(topic_arn, alarm["notification_endpoint"], alarm["notification_type"], region: @region, credentials: @credentials)
                alarm["alarm_actions"] = [topic_arn]
                alarm["ok_actions"]  = [topic_arn]
              end

              alarm_name = alarm_obj ? alarm_obj.cloud_id : "#{@mu_name}-#{alarm['name']}".upcase

              MU::Cloud.resourceClass("AWS", "Alarm").setAlarm(
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
                region: @region,
                credentials: @credentials
              )
            }
          end
        end

        def getIAMProfile
          self.class.getIAMProfile(
            @config['name'],
            @deploy,
            generated: @config['generate_iam_role'],
            role_name: @config['iam_role'],
            region: @region,
            credentials: @credentials,
            want_arn: true
          )
        end

# XXX move to public section
        def self.getIAMProfile(myname, deploy, generated: true, role_name: nil, region: nil, credentials: nil, want_arn: false)

          arn = if generated
            role = deploy.findLitterMate(name: myname, type: "roles", debug: true)
            if !role
              raise MuError, "Failed to find a role matching #{myname}"
            end
            s3_objs = ["#{deploy.deploy_id}-secret", "#{role.mu_name}.pfx", "#{role.mu_name}.crt", "#{role.mu_name}.key", "#{role.mu_name}-winrm.crt", "#{role.mu_name}-winrm.key"].map { |file| 
              'arn:'+(MU::Cloud::AWS.isGovCloud?(region) ? "aws-us-gov" : "aws")+':s3:::'+MU::Cloud::AWS.adminBucketName(credentials)+'/'+file
            }
            MU.log "Adding S3 read permissions to #{myname}'s IAM profile", MU::NOTICE, details: s3_objs
            role.cloudobj.injectPolicyTargets("MuSecrets", s3_objs)
  
            role_name = role.mu_name
            role.cloudobj.createInstanceProfile
  
          elsif role_name.nil?
            raise MuError, "#{myname} has generate_iam_role set to false, but no iam_role assigned."
          else
            begin
              ext_prof = MU::Cloud::AWS.iam(credentials: credentials).get_instance_profile(instance_profile_name: role_name)
              role_name = ext_prof.instance_profile.instance_profile_name
              ext_prof.instance_profile.arn
            rescue Aws::IAM::Errors::NoSuchEntity
              role = MU::MommaCat.findStray("AWS", "role", cloud_id: role_name, dummy_ok: true, credentials: credentials).first
              if !role
                raise MuError, "#{myname} specified iam_role '#{role_name}', but I can't find a role with that name to use when creating an instance profile"
              end
              role.cloudobj.createInstanceProfile
            end
          end

          role_or_policy = deploy.findLitterMate(name: myname, type: "roles")

          # Make sure our permissions to read our identity secrets are set
          s3_objs = [
            "#{deploy.deploy_id}-secret",
            "#{role_or_policy.mu_name}.pfx",
            "#{role_or_policy.mu_name}.crt",
            "#{role_or_policy.mu_name}.key",
            "#{role_or_policy.mu_name}-winrm.crt",
            "#{role_or_policy.mu_name}-winrm.key"].map { |file| 
              'arn:'+(MU::Cloud::AWS.isGovCloud?(region) ? "aws-us-gov" : "aws")+':s3:::'+MU::Cloud::AWS.adminBucketName(credentials)+'/'+file
            }
          if generated
            role_or_policy.injectPolicyTargets("MuSecrets", s3_objs)
          elsif role_name
            realrole = MU::MommaCat.findStray("AWS", "role", cloud_id: role_name, dummy_ok: true, credentials: credentials).first
            if !role_or_policy
              raise MuError, "I should have a bare policy littermate named #{name} but I can't find it"
            end
            if realrole
              role_or_policy.bindTo("role", realrole.cloud_id)
              realrole.injectPolicyTargets(role_or_policy.mu_name+"-MUSECRETS", s3_objs)
            end
          end

          if !role_name.nil?
            if arn and want_arn
              return {arn: arn}
            else
              return {name: role_name}
            end
          end

          nil
        end

        def setDeleteOntermination(device, delete_on_termination = false)
          mappings = MU.structToHash(cloud_desc.block_device_mappings)
          mappings.each { |vol|
            if vol[:ebs]
              vol[:ebs].delete(:attach_time)
              vol[:ebs].delete(:status)
            end
            if vol[:device_name] == device
              if vol[:ebs][:delete_on_termination] != delete_on_termination
                vol[:ebs][:delete_on_termination] = delete_on_termination
                MU.log "Setting delete_on_termination flag to #{delete_on_termination.to_s} on #{@mu_name}'s #{device}"
                MU::Cloud::AWS.ec2(region: @region, credentials: @credentials).modify_instance_attribute(
                  instance_id: @cloud_id,
                  block_device_mappings: mappings
                )
              end
              return true
            end
          }

          false
        end

        def createImage
          img_cfg = @config['create_image']
          # Scrub things that don't belong on an AMI
          session = windows? ? getWinRMSession : getSSHSession
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
          if windows?
            session.run(purgecmd)
          else
            session.exec!(purgecmd)
          end
          session.close
          ami_ids = MU::Cloud::AWS::Server.createImage(
              name: @mu_name,
              instance_id: @cloud_id,
              storage: @config['storage'],
              exclude_storage: img_cfg['image_exclude_storage'],
              copy_to_regions: img_cfg['copy_to_regions'],
              make_public: img_cfg['public'],
              region: @region,
              tags: @config['tags'],
              credentials: @credentials
          )

          @deploy.notify("images", @config['name'], ami_ids)
          @config['image_created'] = true
          if img_cfg['image_then_destroy']
            MU::Cloud::AWS::Server.waitForAMI(ami_ids[@region], region: @region, credentials: @credentials)
            MU.log "AMI #{ami_ids[@region]} ready, removing source node #{@mu_name}"
            MU::Cloud::AWS::Server.terminateInstance(id: @cloud_id, region: @region, deploy_id: @deploy.deploy_id, mu_name: @mu_name, credentials: @credentials)
            destroy
          end
        end

      end #class
    end #class
  end
end #module
