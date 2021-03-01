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

          @userdata = if @config['userdata_script']
            @config['userdata_script']
          elsif @deploy and !@scrub_mu_isms
            MU::Cloud.fetchUserdata(
              platform: @config["platform"],
              cloud: "Azure",
              credentials: @config['credentials'],
              template_variables: {
                "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                "deploySSHKey" => @deploy.ssh_public_key,
                "muID" => MU.deploy_id,
                "muUser" => MU.mu_user,
                "publicIP" => MU.mu_public_ip,
                "adminBucketName" => MU::Cloud::Azure.adminBucketName(@credentials),
                "chefVersion" => MU.chefVersion,
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
          end
          @config['instance_secret'] ||= Password.random(50)

        end

        # Return the date/time a machine image was created.
        # @param image_id [String]: URL to a Azure disk image
        # @param credentials [String]
        # @return [DateTime]
        def self.imageTimeStamp(image_id, credentials: nil)
          return DateTime.new(0) # Azure doesn't seem to keep this anywhere, boo
#          begin
#            img = fetchImage(image_id, credentials: credentials)
#            return DateTime.new if img.nil?
#            return DateTime.parse(img.creation_timestamp)
#          rescue ::Azure::Apis::ClientError => e
#          end
#
#          return DateTime.new
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          create_update

          if !@config['async_groom']
            sleep 5
            MU::MommaCat.lock(@cloud_id.to_s+"-create")
            if !postBoot
              MU.log "#{@config['name']} is already being groomed, skipping", MU::NOTICE
            else
              MU.log "Node creation complete for #{@config['name']}"
            end
            MU::MommaCat.unlock(@cloud_id.to_s+"-create")
          end

        end

        # Return a BoK-style config hash describing a NAT instance. We use this
        # to approximate NAT gateway functionality with a plain instance.
        # @return [Hash]
        def self.genericNAT
          return {
            "cloud" => "Azure",
            "src_dst_check" => false,
            "bastion" => true,
            "size" => "Standard_B2s",
            "run_list" => [ "mu-nat" ],
            "groomer" => "Ansible",
            "platform" => "centos7",
            "associate_public_ip" => true,
            "static_ip" => { "assign_ip" => true },
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
          describe(cloud_id: @cloud_id)
# XXX add some awesome alternate names from metadata and make sure they end
# up in MU::MommaCat's ssh config wangling
          ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
          return nil if @config.nil? or @deploy.nil?

          nat_ssh_key = nat_ssh_user = nat_ssh_host = nil
          if !@config["vpc"].nil? and !MU::Cloud.resourceClass("Azure", "VPC").haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])

            if !@nat.nil? and @nat.mu_name != @mu_name
              if @nat.cloud_desc.nil?
                MU.log "NAT #{@nat} was missing cloud descriptor when called in #{@mu_name}'s getSSHConfig", MU::ERR
                return nil
              end
              _foo, _bar, _baz, nat_ssh_host, nat_ssh_user, nat_ssh_key  = @nat.getSSHConfig
              if nat_ssh_user.nil? and !nat_ssh_host.nil?
                MU.log "#{@config["name"]} (#{MU.deploy_id}) is configured to use #{@config['vpc']} NAT #{nat_ssh_host}, but username isn't specified. Guessing root.", MU::ERR, details: caller
                nat_ssh_user = "root"
              end
            end
          end

          if @config['ssh_user'].nil?
            if windows?
              @config['ssh_user'] = "muadmin"
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
            @cloud_id ||= instance_id
          end

          # Unless we're planning on associating a different IP later, set up a
          # DNS entry for this thing and let it sync in the background. We'll
          # come back to it later.
          if @config['static_ip'].nil? && !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          _nat_ssh_key, _nat_ssh_user, nat_ssh_host, _canonical_ip, _ssh_user, _ssh_key_name = getSSHConfig
          if !nat_ssh_host and !MU::Cloud.resourceClass("Azure", "VPC").haveRouteToInstance?(cloud_desc, region: @config['region'], credentials: @config['credentials'])
# XXX check if canonical_ip is in the private ranges
#            raise MuError, "#{node} has no NAT host configured, and I have no other route to it"
          end

          # See if this node already exists in our config management. If it does,
          # we're done.
          if @groomer.haveBootstrapped?
            MU.log "Node #{@mu_name} has already been bootstrapped, skipping groomer setup.", MU::NOTICE
            @groomer.saveDeployData
            MU::MommaCat.unlock(@cloud_id.to_s+"-orchestrate")
            MU::MommaCat.unlock(@cloud_id.to_s+"-groom")
            return true
          end

          @groomer.bootstrap

          # Make sure we got our name written everywhere applicable
          if !@named
            MU::MommaCat.nameKitten(self)
            @named = true
          end

          MU::MommaCat.unlock(@cloud_id.to_s+"-groom")
          MU::MommaCat.unlock(@cloud_id.to_s+"-orchestrate")
          return true
        end #postBoot

        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching instances
        def self.find(**args)
          found = {}

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
              rescue MU::Cloud::Azure::APIError
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

          MU::MommaCat.lock(@cloud_id.to_s+"-groom")
          
          node, _config, deploydata = describe(cloud_id: @cloud_id)

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

          MU::MommaCat.unlock(@cloud_id.to_s+"-groom")
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
          describe(cloud_id: @cloud_id)

          if !cloud_desc
            raise MuError, "Couldn't retrieve cloud descriptor for server #{self}"
          end

          private_ips = []
          public_ips = []

          cloud_desc.network_profile.network_interfaces.each { |iface|
            iface_id = Id.new(iface.is_a?(Hash) ? iface['id'] : iface.id)
            iface_desc = MU::Cloud::Azure.network(credentials: @credentials).network_interfaces.get(@resource_group, iface_id.to_s)
            iface_desc.ip_configurations.each { |ipcfg|
              private_ips << ipcfg.private_ipaddress
              if ipcfg.respond_to?(:public_ipaddress) and ipcfg.public_ipaddress
                ip_id = Id.new(ipcfg.public_ipaddress.id)
                ip_desc = MU::Cloud::Azure.network(credentials: @credentials).public_ipaddresses.get(@resource_group, ip_id.to_s)
                if ip_desc
                  public_ips << ip_desc.ip_address
                end
              end
            }
          }

          # Our deploydata gets corrupted often with server pools, this will cause us to use the wrong IP to identify a node
          # which will cause us to create certificates, DNS records and other artifacts with incorrect information which will cause our deploy to fail.
          # The cloud_id is always correct so lets use 'cloud_desc' to get the correct IPs
          if MU::Cloud.resourceClass("Azure", "VPC").haveRouteToInstance?(cloud_desc, credentials: @config['credentials']) or public_ips.size == 0
            @config['canonical_ip'] = private_ips.first
            return private_ips.first
          else
            @config['canonical_ip'] = public_ips.first
            return public_ips.first
          end
        end

        # Return all of the IP addresses, public and private, from all of our
        # network interfaces.
        # @return [Array<String>]
        def listIPs
          ips = []
          cloud_desc.network_profile.network_interfaces.each { |iface|
            iface_id = Id.new(iface.is_a?(Hash) ? iface['id'] : iface.id)
            iface_desc = MU::Cloud::Azure.network(credentials: @credentials).network_interfaces.get(@resource_group, iface_id.to_s)
            iface_desc.ip_configurations.each { |ipcfg|
              ips << ipcfg.private_ipaddress
              if ipcfg.respond_to?(:public_ipaddress) and ipcfg.public_ipaddress
                ip_id = Id.new(ipcfg.public_ipaddress.id)
                ip_desc = MU::Cloud::Azure.network(credentials: @credentials).public_ipaddresses.get(@resource_group, ip_id.to_s)
                if ip_desc
                  ips << ip_desc.ip_address
                end
              end
            }
          }
          ips
        end

        # return [String]: A password string.
        def getWindowsAdminPassword
          @deploy.fetchSecret(@mu_name, "windows_admin_password")
        end

        # Add a volume to this instance and return the descriptor for the attachment
        # @param dev [String]: Device name to use when attaching to instance
        # @param size [String]: Size (in gb) of the new volume
        # @param type [String]: Cloud storage type of the volume, if applicable
        # @return [Azure::Compute::Mgmt::V2020_06_01::Models::DataDisk]
        def addVolume(dev, size, type: "Standard_LRS")
          disk_desc = nil

          find_disk = Proc.new {
            ext_disks = MU::Cloud::Azure.compute(credentials: @credentials).disks.list
            ext_disks.each { |d|
              if d.location == @region and d.name == dev
                disk_desc = d
                break
              end
            }
          }

          attachment = nil
          find_attachment = Proc.new {
            cloud_desc.storage_profile.data_disks.each { |a|
              if a.managed_disk and a.name == dev
                attachment = a
                break
              end
            }
          }

          find_disk.call()
          if !disk_desc
            MU.log "Creating #{size.to_s}gb disk #{dev}"
            disk_sku_obj = MU::Cloud::Azure.compute(:DiskSku).new
            disk_sku_obj.name = type
            disk_createdata_obj = MU::Cloud::Azure.compute(:CreationData).new
            disk_createdata_obj.create_option = "Empty"
            disk_obj = MU::Cloud::Azure.compute(:Disk).new
            disk_obj.sku = disk_sku_obj
            disk_obj.creation_data = disk_createdata_obj
            disk_obj.disk_size_gb = size
            disk_obj.location = @region
            disk_obj.managed_by = cloud_desc.id
            disk_obj.os_type = windows? ? "Windows" : "Linux"
            disk_desc = MU::Cloud::Azure.compute(credentials: @credentials).disks.create_or_update(@resource_group, dev, disk_obj)
          end

          find_attachment.call()
          if !attachment
            MU.log "Attaching disk #{dev} to #{@cloud_id}"
            vm_obj = cloud_desc(use_cache: false).dup
            attached = vm_obj.storage_profile.data_disks
            mgd_disk = MU::Cloud::Azure.compute(:ManagedDiskParameters).new
            mgd_disk.storage_account_type = type
            mgd_disk.id = disk_desc.id
            new_attach = MU::Cloud::Azure.compute(:DataDisk).new
            new_attach.name = dev
            new_attach.lun = next_lun(vm_obj.storage_profile.data_disks)
            new_attach.create_option = "Attach"
            new_attach.managed_disk = mgd_disk
            vm_obj.storage_profile.data_disks << new_attach
            MU::Cloud::Azure.compute(credentials: @credentials).virtual_machines.create_or_update(@resource_group, @cloud_id, vm_obj)
            find_attachment.call()
          end

          [attachment, cloud_desc.storage_profile.data_disks.size]
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
          MU::Cloud::BETA
        end

        # Remove all instances associated with the currently loaded deployment. Also cleans up associated volumes, droppings in the MU master's /etc/hosts and ~/.ssh, and in whatever Groomer was used.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          hosts_schema = MU::Config::CIDR_PRIMITIVE
          hosts_schema["pattern"] = "^(\\d+\\.\\d+\\.\\d+\\.\\d+\/[0-9]{1,2}|\\*)$"
          schema = {
            "roles" => MU::Cloud.resourceClass("Azure", "User").schema(config)[1]["roles"],
            "ingress_rules" => {
              "items" => {
                "properties" => {
                  "hosts" => {
                    "type" => "array",
                    "items" => hosts_schema
                  }
                }
              }
            },
            "windows_admin_username" => {
              "type" => "string",
              "default" => "muadmin",
            },
            "ssh_user" => {
              "default_if" => [
                {
                  "key_is" => "platform",
                  "value_is" => "windows",
                  "set" => "muadmin"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "win2k12",
                  "set" => "muadmin"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "win2k12r2",
                  "set" => "muadmin"
                },
                {
                  "key_is" => "platform",
                  "value_is" => "win2k16",
                  "set" => "muadmin"
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
          types = (MU::Cloud::Azure.listInstanceTypes(region))[region]
          if types and (size.nil? or !types.has_key?(size))
            # See if it's a type we can approximate from one of the other clouds
            foundmatch = false
            MU::Cloud.availableClouds.each { |cloud|
              next if cloud == "Azure"
              foreign_types = (MU::Cloud.cloudClass(cloud).listInstanceTypes).values.first
              if foreign_types.size == 1
                foreign_types = foreign_types.values.first
              end
              if foreign_types and foreign_types.size > 0 and foreign_types.has_key?(size)
                vcpu = foreign_types[size]["vcpu"]
                mem = foreign_types[size]["memory"]
                ecu = foreign_types[size]["ecu"]
                types.keys.sort.reverse.each { |type|
                  next if type.match(/_Promo$/i)
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

          server['region'] ||= MU::Cloud::Azure.myRegion(server['credentials'])
          server['ssh_user'] ||= "muadmin"
          if server['windows_admin_username'] == "Administrator"
            MU.log "Azure does not permit admin user to be 'Administrator'", MU::ERR
            ok = false
          end

          server['size'] = validateInstanceType(server["size"], server["region"])
          ok = false if server['size'].nil?

          if server['image_id'].nil?
            img_id = MU::Cloud.getStockImage("Azure", platform: server['platform'])
            if img_id
              server['image_id'] = configurator.getTail("server"+server['name']+"Image", value: img_id, prettyname: "server"+server['name']+"Image")
            else
              MU.log "No image specified for #{server['name']} and no default available for platform #{server['platform']}", MU::ERR, details: server
              ok = false
            end
          end

          image_desc = MU::Cloud::Azure::Server.fetchImage(server['image_id'].to_s, credentials: server['credentials'], region: server['region'])

          if !image_desc
            MU.log "Failed to locate an Azure VM image for #{server['name']} from #{server['image_id']} in #{server['region']}", MU::ERR
            ok = false
          else
            if image_desc.plan
              terms = MU::Cloud::Azure.marketplace(credentials: @credentials).marketplace_agreements.get(image_desc.plan.publisher, image_desc.plan.product, image_desc.plan.name)
              if !terms.accepted
                MU.log "Deploying #{server['name']} will automatically agree to the licensing terms for #{terms.product}", MU::NOTICE, details: terms.license_text_link
              end
            end
            server['image_id'] = image_desc.id
          end

          if server['add_firewall_rules'] and server['add_firewall_rules'].size == 0
            MU.log "Azure resources can only have one security group per network interface; use ingress_rules instead of add_firewall_rules.", MU::ERR
            ok = false
          end

          # Azure doesn't have default VPCs, so our fallback approach will be
          # to generate one on the fly.
          if server['vpc'].nil?
            vpc = {
              "name" => server['name']+"vpc",
              "cloud" => "Azure",
              "region" => server['region'],
              "credentials" => server['credentials']
            }
            if !configurator.insertKitten(vpc, "vpcs", true)
              ok = false
            end
            MU::Config.addDependency(server, server['name']+"vpc", "vpc")
            MU::Config.addDependency(server, server['name']+"vpc-natstion", "server", their_phase: "groom")
            server['vpc'] = {
              "name" => server['name']+"vpc",
              "subnet_pref" => "private"
            }
          end
          server['vpc']['subnet_pref'] ||= "private"

          svcacct_desc = {
            "name" => server["name"]+"user",
            "region" => server["region"],
            "type" => "service",
            "cloud" => "Azure",
            "create_api_key" => true,
            "credentials" => server["credentials"],
            "roles" => server["roles"]
          }
          MU::Config.addDependency(server, server['name']+"user", "user")

          ok = false if !configurator.insertKitten(svcacct_desc, "users")

          ok
        end

        # stub
        def self.diskConfig(config, create = true, disk_as_url = true, credentials: nil)
        end

        # Retrieve the cloud descriptor for an Azure machine image
        # @param image_id [String]: A full Azure resource id, or a shorthand string like <tt>OpenLogic/CentOS/7.6/7.6.20190808</tt>. The third and fourth fields (major version numbers and release numbers, by convention) can be partial, and the release number can be omitted entirely. We default to the most recent matching release when applicable.
        # @param credentials [String]
        # @return [Azure::Compute::Mgmt::V2019_03_01::Models::VirtualMachineImage]
        def self.fetchImage(image_id, credentials: nil, region: MU::Cloud::Azure.myRegion)

          publisher = offer = sku = version = nil
          if image_id.match(/\/Subscriptions\/[^\/]+\/Providers\/Microsoft.Compute\/Locations\/([^\/]+)\/Publishers\/([^\/]+)\/ArtifactTypes\/VMImage\/Offers\/([^\/]+)\/Skus\/([^\/]+)\/Versions\/([^\/]+)$/)
            region = Regexp.last_match[1]
            publisher = Regexp.last_match[2]
            offer = Regexp.last_match[3]
            sku = Regexp.last_match[4]
            version = Regexp.last_match[5]
            return MU::Cloud::Azure.compute(credentials: credentials).virtual_machine_images.get(region, publisher, offer, sku, version)
          else
            publisher, offer, sku, version = image_id.split(/\//)
          end
          if !publisher or !offer or !sku
            raise MuError, "Azure image_id #{image_id} was invalid"
          end

          skus = MU::Cloud::Azure.compute(credentials: credentials).virtual_machine_images.list_skus(region, publisher, offer).map { |s| s.name }

          if !skus.include?(sku)
            skus.reject! { |s| !s.match(/^#{Regexp.quote(sku)}/) }
            skus.sort! { |a, b| MU.version_sort(a, b) }.reverse!
            sku = skus.first
          end

          version = nil
          begin
            versions = MU::Cloud::Azure.compute(credentials: credentials).virtual_machine_images.list(region, publisher, offer, sku).map { |v| v.name }
            if versions.nil? or versions.empty?
              skus.delete(sku)
              sku = skus.first
            end
          end while skus.size > 0 and (versions.nil? or versions.empty?)

          if versions.nil? or versions.empty?
            MU.log "Azure API returned empty machine image version list for publisher #{publisher} offer #{offer} sku #{sku}", MU::ERR, details: skus
            return nil
          end

          if version.nil?
            version = versions.sort { |a, b| MU.version_sort(a, b) }.reverse.first
          elsif !versions.include?(version)
            versions.sort { |a, b| MU.version_sort(a, b) }.reverse.each { |v|
              if v.match(/^#{Regexp.quote(version)}/)
                version = v
                break
              end
            }
          end

          MU::Cloud::Azure.compute(credentials: credentials).virtual_machine_images.get(region, publisher, offer, sku, version)
        end

        private

        def next_lun(ext_disks = cloud_desc(use_cache: false).storage_profile.data_disks)
          ext_disks ||= []
          used_luns = ext_disks.map { |d| d.lun } # XXX ...probably
          lun = 0
          if used_luns.include?(0)
            begin
              lun += 1
            end while used_luns.include?(lun)
          end
          lun
        end

        def create_update
          ipcfg = MU::Cloud::Azure.network(:NetworkInterfaceIPConfiguration).new
          ipcfg.name = @mu_name
          ipcfg.private_ipallocation_method = MU::Cloud::Azure.network(:IPAllocationMethod)::Dynamic

          private_nets = @vpc.subnets.reject { |s| !s.private? }
          public_nets = @vpc.subnets.reject { |s| s.private? }

          stubnet = if @config['vpc']['subnet_id']
            useme = nil
            @vpc.subnets.each { |s|
              if s.cloud_id.to_s == @config['vpc']['subnet_id']
                useme = s
                break
              end
            }
            if !useme
              raise MuError, "Failed to locate subnet #{@config['vpc']['subnet_id']} in VPC #{@vpc.to_s}"
            end
            useme
          elsif @config['vpc']['subnet_pref'] == "private" or
                @config['vpc']['subnet_pref'] == "all_private"
            if private_nets.size == 0
              raise MuError, "Server #{@mu_name} wanted a private subnet, but there are none in #{@vpc.to_s}"
            end
            private_nets.sample
          elsif @config['vpc']['subnet_pref'] == "public" or
                @config['vpc']['subnet_pref'] == "all_public"
            if public_nets.size == 0
              raise MuError, "Server #{@mu_name} wanted a public subnet, but there are none in #{@vpc.to_s}"
            end
            public_nets.sample
          end

          # Allocate a public IP if we asked for one
          if @config['associate_public_ip'] or !stubnet.private?
            pubip_obj = MU::Cloud::Azure.network(:PublicIPAddress).new
            pubip_obj.public_ipallocation_method =  MU::Cloud::Azure.network(:IPAllocationMethod)::Dynamic
            pubip_obj.location = @config['region']
            pubip_obj.tags = @tags
            resp = MU::Cloud::Azure.network(credentials: @credentials).public_ipaddresses.create_or_update(@resource_group, @mu_name, pubip_obj)
            ipcfg.public_ipaddress = resp
          end

          ipcfg.subnet = MU::Cloud::Azure.network(:Subnet).new
          ipcfg.subnet.id = stubnet.cloud_desc.id

          sg = @deploy.findLitterMate(type: "firewall_rule", name: "server"+@config['name'])

          iface_obj = MU::Cloud::Azure.network(:NetworkInterface).new
          iface_obj.location = @config['region']
          iface_obj.tags = @tags
          iface_obj.primary = true
          iface_obj.network_security_group = sg.cloud_desc if sg
          iface_obj.enable_ipforwarding = !@config['src_dst_check']
          iface_obj.ip_configurations = [ipcfg]
          MU.log "Creating network interface #{@mu_name}", MU::DEBUG, details: iface_obj
          iface = MU::Cloud::Azure.network(credentials: @credentials).network_interfaces.create_or_update(@resource_group, @mu_name, iface_obj)

          img_obj = MU::Cloud::Azure.compute(:ImageReference).new
          @config['image_id'].match(/\/Subscriptions\/[^\/]+\/Providers\/Microsoft.Compute\/Locations\/[^\/]+\/Publishers\/([^\/]+)\/ArtifactTypes\/VMImage\/Offers\/([^\/]+)\/Skus\/([^\/]+)\/Versions\/([^\/]+)$/)
          img_obj.publisher = Regexp.last_match[1]
          img_obj.offer = Regexp.last_match[2]
          img_obj.sku = Regexp.last_match[3]
          img_obj.version = Regexp.last_match[4]

          hw_obj = MU::Cloud::Azure.compute(:HardwareProfile).new
          hw_obj.vm_size = @config['size']

          os_obj = MU::Cloud::Azure.compute(:OSProfile).new
          if windows?
            winrm_listen = MU::Cloud::Azure.compute(:WinRMListener).new
            winrm_listen.certificate_url = "goddamn stupid ass thing"
            winrm_listen.protocol = "https"
            winrm = MU::Cloud::Azure.compute(:WinRMConfiguration).new
            winrm.listeners = [winrm_listen]

            win_obj = MU::Cloud::Azure.compute(:WindowsConfiguration).new
            win_obj.win_rmconfiguration = winrm
            os_obj.windows_configuration = win_obj
            os_obj.admin_username = @config['windows_admin_username']
            os_obj.admin_password = begin
              @deploy.fetchSecret(@mu_name, "windows_admin_password")
            rescue MU::MommaCat::SecretError
              pw = MU.generateWindowsPassword
              @deploy.saveNodeSecret(@mu_name, pw, "windows_admin_password")
              pw
            end
            os_obj.computer_name = @deploy.getResourceName(@config["name"], max_length: 15, disallowed_chars: /[~!@#$%^&*()=+_\[\]{}\\\|;:\.'",<>\/\?]/)
          else
            os_obj.admin_username = @config['ssh_user']
            os_obj.computer_name = @mu_name
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

          vm_id_obj = MU::Cloud::Azure.compute(:VirtualMachineIdentity).new
          vm_id_obj.type = "UserAssigned"
          svc_acct = @deploy.findLitterMate(type: "user", name: @config['name']+"user")
          raise MuError, "Failed to locate service account #{@config['name']}user" if !svc_acct
          vm_id_obj.user_assigned_identities  = {
            svc_acct.cloud_desc.id => svc_acct.cloud_desc
          }

          vm_obj = MU::Cloud::Azure.compute(:VirtualMachine).new
          vm_obj.location = @config['region']
          vm_obj.tags = @tags
          vm_obj.network_profile = MU::Cloud::Azure.compute(:NetworkProfile).new
          vm_obj.network_profile.network_interfaces = [iface]
          vm_obj.hardware_profile = hw_obj
          vm_obj.os_profile = os_obj
          vm_obj.identity = vm_id_obj
          vm_obj.storage_profile = MU::Cloud::Azure.compute(:StorageProfile).new
          vm_obj.storage_profile.image_reference = img_obj

          image_desc = MU::Cloud::Azure::Server.fetchImage(@config['image_id'].to_s, credentials: @config['credentials'], region: @config['region'])
# XXX do this as a catch around instance creation so we don't waste API calls
          if image_desc.plan
            terms = MU::Cloud::Azure.marketplace(credentials: @credentials).marketplace_agreements.get(image_desc.plan.publisher, image_desc.plan.product, image_desc.plan.name)
            if !terms.accepted
              MU.log "Agreeing to licensing terms of #{terms.product}", MU::NOTICE
              begin
# XXX this doesn't actually work as documented
                MU::Cloud::Azure.marketplace(credentials: @credentials).marketplace_agreements.sign(image_desc.plan.publisher, image_desc.plan.product, image_desc.plan.name)
              rescue StandardError => e
                MU.log e.message, MU::ERR
                vm_obj.plan = nil
              end
            end
            vm_obj.plan = image_desc.plan
          end
          if @config['storage']
            vm_obj.storage_profile.data_disks = []
            @config['storage'].each { |disk|
              lun = if disk['device'].is_a?(Integer) or
                       disk['device'].match(/^\d+$/)
                disk['device'].to_i
              else
                disk['device'].match(/([a-z])[^a-z]*$/i)
                # map the last letter of the requested device to a numeric lun
                # so that a => 1, b => 2, and so on
                Regexp.last_match[1].downcase.encode("ASCII-8BIT").ord - 96
              end
              disk_obj = MU::Cloud::Azure.compute(:DataDisk).new
              disk_obj.disk_size_gb = disk['size']
              disk_obj.lun = lun
              disk_obj.name = @mu_name+disk['device'].to_s.gsub(/[^\w\-._]/, '_').upcase
              disk_obj.create_option = MU::Cloud::Azure.compute(:DiskCreateOptionTypes)::Empty
              vm_obj.storage_profile.data_disks << disk_obj
            }
          end


if !@cloud_id
# XXX actually guard this correctly
          MU.log "Creating VM #{@mu_name}", details: vm_obj
          begin
            vm = MU::Cloud::Azure.compute(credentials: @credentials).virtual_machines.create_or_update(@resource_group, @mu_name, vm_obj)
          @cloud_id = Id.new(vm.id)
          rescue ::MU::Cloud::Azure::APIError => e
            if e.message.match(/InvalidParameter: /)
              MU.log e.message, MU::ERR, details: vm_obj
            end
            raise e
          end
end

        end


      end #class
    end #class
  end
end #module
