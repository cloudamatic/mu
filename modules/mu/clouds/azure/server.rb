# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
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
    class Azure
      # A server as configured in {MU::Config::BasketofKittens::servers}.
      class Server < MU::Cloud::Server

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          if @deploy
            @userdata = MU::Cloud.fetchUserdata(
              platform: @config["platform"],
              cloud: "Azure",
              credentials: @config['credentials'],
              template_variables: {
                "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                "deploySSHKey" => @deploy.ssh_public_key,
                "muID" => MU.deploy_id,
                "muUser" => MU.mu_user,
                "publicIP" => MU.mu_public_ip,
                "skipApplyUpdates" => @config['skipinitialupdates'],
                "windowsAdminName" => @config['windows_admin_username'],
                "mommaCatPort" => MU.mommaCatPort,
                "resourceName" => @config["name"],
                "resourceType" => "server",
                "platform" => @config["platform"]
              },
              custom_append: @config['userdata_script']
            )
          end

          if !@mu_name
            if kitten_cfg.has_key?("basis")
              @mu_name = @deploy.getResourceName(@config['name'], need_unique_string: true)
            else
              @mu_name = @deploy.getResourceName(@config['name'])
            end
            @config['mu_name'] = @mu_name

          end
          @config['instance_secret'] ||= Password.random(50)

        end

        # Return the date/time a machine image was created.
        # @param image_id [String]: URL to a Azure disk image
        # @param credentials [String]
        # @return [DateTime]
        def self.imageTimeStamp(image_id, credentials: nil)
          begin
            img = fetchImage(image_id, credentials: credentials)
            return DateTime.new if img.nil?
            return DateTime.parse(img.creation_timestamp)
          rescue ::Azure::Apis::ClientError => e
          end

          return DateTime.new
        end

        # Retrieve the cloud descriptor for this machine image, which can be
        # a whole or partial URL. Will follow deprecation notices and retrieve
        # the latest version, if applicable.
        # @param image_id [String]: URL to a Azure disk image
        # @param credentials [String]
        # @return [Azure::Apis::ComputeBeta::Image]
        def self.fetchImage(image_id, credentials: nil)
        end

        # Generator for disk configuration parameters for a Compute instance
        # @param config [Hash]: The MU::Cloud::Server config hash for whom we're configuring disks
        # @param create [Boolean]: Actually create extra (non-root) disks, or just the one declared as the root disk of the image
        # @param disk_as_url [Boolean]: Whether to declare the disk type as a short string or full URL, which can vary depending on the calling resource
        # @return [Array]: The Compute :AttachedDisk objects describing disks that've been created
        def self.diskConfig(config, create = true, disk_as_url = true, credentials: nil)
          disks = []

          disks
        end

        # Generator for disk configuration parameters for a Compute instance
        # @param config [Hash]: The MU::Cloud::Server config hash for whom we're configuring network interfaces
        # @param vpc [MU::Cloud::Azure::VPC]: The VPC in which this interface should reside
        # @return [Array]: Configuration objects for network interfaces, suitable for passing to the Compute API
        def self.interfaceConfig(config, vpc)
          []
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          create_update
        end

        # Return a BoK-style config hash describing a NAT instance. We use this
        # to approximate Amazon's NAT gateway functionality with a plain
        # instance.
        # @return [Hash]
        def self.genericNAT
          return {
            "cloud" => "Azure",
            "size" => "g1-small",
            "run_list" => [ "mu-utility::nat" ],
            "platform" => "centos7",
            "ssh_user" => "centos",
            "associate_public_ip" => true,
            "static_ip" => { "assign_ip" => true },
            "routes" => [ {
              "gateway" => "#INTERNET",
              "priority" => 50,
              "destination_network" => "0.0.0.0/0"
            } ]
          }
        end

        # Ask the Azure API to stop this node
        def stop
          MU.log "XXX Stopping #{@cloud_id}"
        end

        # Ask the Azure API to start this node
        def start
          MU.log "XXX Starting #{@cloud_id}"
        end

        # Ask the Azure API to restart this node
        # XXX unimplemented
        def reboot(hard = false)
          return if @cloud_id.nil?

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
          if !@config["vpc"].nil? and !MU::Cloud::Azure::VPC.haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])

            if !@nat.nil?
              if @nat.cloud_desc.nil?
                MU.log "NAT was missing cloud descriptor when called in #{@mu_name}'s getSSHConfig", MU::ERR
                return nil
              end
              foo, bar, baz, nat_ssh_host, nat_ssh_user, nat_ssh_key  = @nat.getSSHConfig
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

          # Unless we're planning on associating a different IP later, set up a
          # DNS entry for this thing and let it sync in the background. We'll
          # come back to it later.
          if @config['static_ip'].nil? && !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
          if !nat_ssh_host and !MU::Cloud::Azure::VPC.haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])
# XXX check if canonical_ip is in the private ranges
#            raise MuError, "#{node} has no NAT host configured, and I have no other route to it"
          end

          # See if this node already exists in our config management. If it does,
          # we're done.
          if @groomer.haveBootstrapped?
            MU.log "Node #{node} has already been bootstrapped, skipping groomer setup.", MU::NOTICE
            @groomer.saveDeployData
            MU::MommaCat.unlock(@cloud_id+"-orchestrate")
            MU::MommaCat.unlock(@cloud_id+"-groom")
            return true
          end

          @groomer.bootstrap

          # Make sure we got our name written everywhere applicable
          if !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          MU::MommaCat.unlock(@cloud_id+"-groom")
          MU::MommaCat.unlock(@cloud_id+"-orchestrate")
          return true
        end #postBoot

        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching instances
        def self.find(**args)
          found = {}

          # Azure resources are namedspaced by resource group. If we weren't
          # told one, we may have to search all the ones we can see.
          resource_groups = if args[:resource_group]
            [args[:resource_group]]
          elsif args[:cloud_id] and args[:cloud_id].is_a?(MU::Cloud::Azure::Id)
            [args[:cloud_id].resource_group]
          else
            MU::Cloud::Azure.resources(credentials: args[:credentials]).resource_groups.list.map { |rg| rg.name }
          end

          if args[:cloud_id]
            id_str = args[:cloud_id].is_a?(MU::Cloud::Azure::Id) ? args[:cloud_id].name : args[:cloud_id]
            resource_groups.each { |rg|
              begin
                resp = MU::Cloud::Azure.compute(credentials: args[:credentials]).virtual_machines.get(rg, id_str)
                next if resp.nil?
                found[Id.new(resp.id)] = resp
              rescue MU::Cloud::Azure::APIError => e
                # this is fine, we're doing a blind search after all
              end
            }
          else
            if args[:resource_group]
              MU::Cloud::Azure.compute(credentials: args[:credentials]).virtual_machines.list(args[:resource_group]).each { |vm|
                found[Id.new(vm.id)] = vm
              }
            else
              MU::Cloud::Azure.compute(credentials: args[:credentials]).virtual_machines.list_all.each { |vm|
                found[Id.new(vm.id)] = vm
              }
            end
          end

          found
        end

        # Return a description of this resource appropriate for deployment
        # metadata. Arguments reflect the return values of the MU::Cloud::[Resource].describe method
        def notify
          MU.structToHash(cloud_desc)
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          create_update

          MU::MommaCat.lock(@cloud_id+"-groom")
          
          node, config, deploydata = describe(cloud_id: @cloud_id)

          if node.nil? or node.empty?
            raise MuError, "MU::Cloud::Azure::Server.groom was called without a mu_name"
          end

          # Make double sure we don't lose a cached mu_windows_name value.
          if windows? or !@config['active_directory'].nil?
            if @mu_windows_name.nil?
              @mu_windows_name = deploydata['mu_windows_name']
            end
          end

          @groomer.saveDeployData

          begin
            @groomer.run(purpose: "Full Initial Run", max_retries: 15)
          rescue MU::Groomer::RunError
            MU.log "Proceeding after failed initial Groomer run, but #{node} may not behave as expected!", MU::WARN
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
                purgecmd = "#{sudo} rm -rf /root/.ssh/authorized_keys /etc/ssh/ssh_host_*key* /etc/chef /etc/opscode/* /.mu-installer-ran-updates /var/chef /opt/mu_installed_chef /opt/chef ; #{sudo} sed -i 's/^HOSTNAME=.*//' /etc/sysconfig/network"
              end
            end
            session.exec!(purgecmd)
            session.close
            stop
            image_id = MU::Cloud::Azure::Server.createImage(
                name: MU::Cloud::Azure.nameStr(@mu_name),
                instance_id: @cloud_id,
                region: @config['region'],
                storage: @config['storage'],
                family: ("mu-"+@config['platform']+"-"+MU.environment).downcase,
                project: @project_id,
                exclude_storage: img_cfg['image_exclude_storage'],
                make_public: img_cfg['public'],
                tags: @config['tags'],
                zone: @config['availability_zone'],
                credentials: @config['credentials']
            )
            @deploy.notify("images", @config['name'], {"image_id" => image_id})
            @config['image_created'] = true
            if img_cfg['image_then_destroy']
              MU.log "Image #{image_id} ready, removing source node #{node}"
              MU::Cloud::Azure.compute(credentials: @config['credentials']).delete_instance(
                @project_id,
                @config['availability_zone'],
                @cloud_id
              )
              destroy
            else
              start
            end
          end

          MU::MommaCat.unlock(@cloud_id+"-groom")
        end

        # Create an image out of a running server. Requires either the name of a MU resource in the current deployment, or the cloud provider id of a running instance.
        # @param name [String]: The MU resource name of the server to use as the basis for this image.
        # @param instance_id [String]: The cloud provider resource identifier of the server to use as the basis for this image.
        # @param storage [Hash]: The storage devices to include in this image.
        # @param exclude_storage [Boolean]: Do not include the storage device profile of the running instance when creating this image.
        # @param region [String]: The cloud provider region
        # @param tags [Array<String>]: Extra/override tags to apply to the image.
        # @return [String]: The cloud provider identifier of the new machine image.
        def self.createImage(name: nil, instance_id: nil, storage: {}, exclude_storage: false, project: nil, make_public: false, tags: [], region: nil, family: "mu", zone: MU::Cloud::Azure.listAZs.sample, credentials: nil)
        end

        # Return the IP address that we, the Mu server, should be using to access
        # this host via the network. Note that this does not factor in SSH
        # bastion hosts that may be in the path, see getSSHConfig if that's what
        # you need.
        def canonicalIP
          mu_name, config, deploydata = describe(cloud_id: @cloud_id)

          if !cloud_desc
            raise MuError, "Couldn't retrieve cloud descriptor for server #{self}"
          end

          private_ips = []
          public_ips = []

          cloud_desc.network_interfaces.each { |iface|
            private_ips << iface.network_ip
            if iface.access_configs
              iface.access_configs.each { |acfg|
                public_ips << acfg.nat_ip if acfg.nat_ip
              }
            end
          }

          # Our deploydata gets corrupted often with server pools, this will cause us to use the wrong IP to identify a node
          # which will cause us to create certificates, DNS records and other artifacts with incorrect information which will cause our deploy to fail.
          # The cloud_id is always correct so lets use 'cloud_desc' to get the correct IPs
          if MU::Cloud::Azure::VPC.haveRouteToInstance?(cloud_desc, credentials: @config['credentials']) or public_ips.size == 0
            @config['canonical_ip'] = private_ips.first
            return private_ips.first
          else
            @config['canonical_ip'] = public_ips.first
            return public_ips.first
          end
        end

        # return [String]: A password string.
        def getWindowsAdminPassword
        end

        # Add a volume to this instance
        # @param dev [String]: Device name to use when attaching to instance
        # @param size [String]: Size (in gb) of the new volume
        # @param type [String]: Cloud storage type of the volume, if applicable
        # @param delete_on_termination [Boolean]: Value of delete_on_termination flag to set
        def addVolume(dev, size, type: "pd-standard", delete_on_termination: false)
        end

        # Determine whether the node in question exists at the Cloud provider
        # layer.
        # @return [Boolean]
        def active?
          !cloud_desc.nil?
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
          MU::Cloud::ALPHA
        end

        # Remove all instances associated with the currently loaded deployment. Also cleans up associated volumes, droppings in the MU master's /etc/hosts and ~/.ssh, and in whatever Groomer was used.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
          }
          [toplevel_required, schema]
        end

        # Confirm that the given instance size is valid for the given region.
        # If someone accidentally specified an equivalent size from some other cloud provider, return something that makes sense. If nothing makes sense, return nil.
        # @param size [String]: Instance type to check
        # @param region [String]: Region to check against
        # @return [String,nil]
        def self.validateInstanceType(size, region)
          types = (MU::Cloud::Azure.listInstanceTypes(region))[region]
          if types and (size.nil? or !types.has_key?(size))
            # See if it's a type we can approximate from one of the other clouds
            foundmatch = false
            MU::Cloud.availableClouds.each { |cloud|
              next if cloud == "Azure"
              cloudbase = Object.const_get("MU").const_get("Cloud").const_get(cloud)
              foreign_types = (cloudbase.listInstanceTypes)[cloudbase.myRegion]
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
                    MU.log "You specified #{cloud} instance type '#{size}.' Approximating with Azure Compute type '#{type}.'", MU::WARN
                    size = type
                    break
                  end
                }
              end
              break if foundmatch
            }

            if !foundmatch
              MU.log "Invalid size '#{size}' for Azure Compute instance in #{region}. Supported types:", MU::ERR, details: types.keys.sort.join(", ")
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

          server['region'] ||= MU::Cloud::Azure.myRegion
          server['ssh_user'] ||= "muadmin"

          server['size'] = validateInstanceType(server["size"], server["region"])

          # Azure doesn't have default VPCs, so our fallback approach will be
          # to generate one on the fly.
          if server['vpc'].nil?
            vpc = {
              "name" => server['name']+"vpc",
              "cloud" => "Azure",
              "region" => server['region'],
              "credentials" => server['credentials'],
              "route_tables" => [
                {
                  "name" => "internet",
                  "routes" => [
                    {
                      "destination_network" => "0.0.0.0/0",
                      "gateway" => "#INTERNET"
                    }
                  ]
                },
                {
                  "name" => "private",
                  "routes" => [
                    {
                      "gateway" => "#NAT"
                    }
                  ]
                }
              ]
            }
            if !configurator.insertKitten(vpc, "vpcs")
              ok = false
            end
            server['dependencies'] ||= []
            server['dependencies'] << {
              "type" => "vpcs",
              "name" => server['name']+"vpc"
            }
            server['vpc'] = {
              "name" => server['name']+"vpc",
              "subnet_pref" => "private"
            }
          end

          ok
        end

        private

        def create_update
          ipcfg = MU::Cloud::Azure.network(:NetworkInterfaceIPConfiguration).new
          ipcfg.name = @mu_name
          ipcfg.private_ipallocation_method = MU::Cloud::Azure.network(:IPAllocationMethod)::Dynamic
          if @config['associate_public_ip'] # TODO or inherit subnet setting

          end
          private_nets = @vpc.subnets.reject { |s| !s.private? }
          public_nets = @vpc.subnets.reject { |s| s.private? }

          stubnet = if @config['vpc']['subnets'] and @config['vpc']['subnets'].size > 0
# XXX test with a pre-existing vpc
          elsif @config['vpc']['subnet_pref'] == "private"
            if private_nets.size == 0
              raise MuError, "Server #{@mu_name} wanted a private subnet, but there are none in #{@vpc.to_s}"
            end
            private_nets.sample
          elsif @config['vpc']['subnet_pref'] == "public"
            if public_nets.size == 0
              raise MuError, "Server #{@mu_name} wanted a public subnet, but there are none in #{@vpc.to_s}"
            end
            public_nets.sample
          end
          ipcfg.subnet = MU::Cloud::Azure.network(:Subnet).new
          ipcfg.subnet.id = stubnet.cloud_desc.id

          iface_obj = MU::Cloud::Azure.network(:NetworkInterface).new
          iface_obj.location = @config['region']
          iface_obj.primary = true
          iface_obj.tags = @tags
          iface_obj.enable_ipforwarding = !@config['src_dest_check']
          iface_obj.ip_configurations = [ipcfg]
          MU.log "Creating network interface #{@mu_name}", MU::DEBUG, details: iface_obj
          iface = MU::Cloud::Azure.network(credentials: @credentials).network_interfaces.create_or_update(@resource_group, @mu_name, iface_obj)

          img_obj = MU::Cloud::Azure.compute(:ImageReference).new
          img_obj.publisher = "RedHat"
          img_obj.offer = "RHEL"
          img_obj.sku = "7.7"
          img_obj.version = "7.7.2019090316"

          hw_obj = MU::Cloud::Azure.compute(:HardwareProfile).new
          hw_obj.vm_size = @config['size']

          os_obj = MU::Cloud::Azure.compute(:OSProfile).new
          os_obj.admin_username = @config['ssh_user']
          os_obj.computer_name = @mu_name
          if windows?
            win_obj = MU::Cloud::Azure.compute(:WindowsConfiguration).new
            os_obj.windows_configuration = win_obj
          else
            key_obj = MU::Cloud::Azure.compute(:SshPublicKey).new
            key_obj.key_data = @deploy.ssh_public_key
            key_obj.path = "/home/#{@config['ssh_user']}/.ssh/authorized_keys"

            ssh_obj = MU::Cloud::Azure.compute(:SshConfiguration).new
            ssh_obj.public_keys = [key_obj]

            lnx_obj = MU::Cloud::Azure.compute(:LinuxConfiguration).new
            lnx_obj.disable_password_authentication = true
            lnx_obj.ssh = ssh_obj

            os_obj.linux_configuration = lnx_obj
          end

          vm_obj = MU::Cloud::Azure.compute(:VirtualMachine).new
          vm_obj.location = @config['region']
          vm_obj.tags = @tags
          vm_obj.network_profile = MU::Cloud::Azure.compute(:NetworkProfile).new
          vm_obj.network_profile.network_interfaces = [iface]
          vm_obj.hardware_profile = hw_obj
          vm_obj.os_profile = os_obj
          vm_obj.storage_profile = MU::Cloud::Azure.compute(:StorageProfile).new
          vm_obj.storage_profile.image_reference = img_obj

          MU.log "Creating VM #{@mu_name}", MU::NOTICE, details: vm_obj
          vm = MU::Cloud::Azure.compute(credentials: @credentials).virtual_machines.create_or_update(@resource_group, @mu_name, vm_obj)
pp vm
        end


      end #class
    end #class
  end
end #module
