# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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
autoload :Timeout, "timeout"
autoload :Base64, "base64"

module MU
  class Cloud
    class VMWare
      # A server as configured in {MU::Config::BasketofKittens::servers}. In
      # VMWare Cloud, this amounts to a single Instance in an Unmanaged
      # Instance Group.
      class Server < MU::Cloud::Server

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          @userdata = if @config['userdata_script']
            @config['userdata_script']
          elsif @deploy and !@config['scrub_mu_isms']
            MU::Cloud.fetchUserdata(
              platform: @config["platform"],
              cloud: "VMWare",
              credentials: @config['credentials'],
              template_variables: {
                "deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
                "deploySSHKey" => @deploy.ssh_public_key,
                "muID" => MU.deploy_id,
                "muUser" => MU.mu_user,
                "publicIP" => MU.mu_public_ip,
                "skipApplyUpdates" => @config['skipinitialupdates'],
                "windowsAdminName" => @config['windows_admin_username'],
                "adminBucketName" => MU::Cloud::VMWare.adminBucketName(@credentials),
                "chefVersion" => MU.chefVersion,
                "mommaCatPort" => MU.mommaCatPort,
                "resourceName" => @config["name"],
                "resourceType" => "server",
                "platform" => @config["platform"]
              },
              custom_append: @config['userdata_script']
            )
          end
# XXX writing things into @config at runtime is a bad habit and we should stop
          if !@mu_name.nil?
            @config['mu_name'] = @mu_name # XXX whyyyy
            # describe
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
          @config['ssh_user'] ||= "muadmin"

        end

        # Called automatically by {MU::Deploy#createResources}
        def create
# https://vdc-repo.vmware.com/vmwb-repository/dcr-public/1cd28284-3b72-4885-9e31-d1c6d9e26686/71ef7304-a6c9-43b3-a3cd-868b2c236c81/doc/operations/com/vmware/vcenter/vm.create-operation.html

          folder = MU::Cloud::VMWare.folderToID(@config['folder'], @credentials)
          resource_pool = MU::Cloud::VMWare.resource_pool(credentials: @credentials, habitat: @sddc).list.value.select { |r| r.name == "Compute-ResourcePool" }.first.resource_pool # XXX it sure would be nice to create one of these for our deploy

          if @config['template']
            item_id, ovf_desc = MU::Cloud.resourceClass("VMWare", "Server").getImageFromLibrary(@config['template'])
            deployment_spec = {
              accept_all_EULA: true,
              annotation: @deploy.deploy_id,
              name: @mu_name
            }
            target = {
              resource_pool_id: resource_pool
            }

            resp = MU::Cloud::VMWare.ovf(credentials: credentials, habitat: habitat).deploy(
              item_id,
              ::VSphereAutomation::VCenter::VcenterOvfLibraryItemDeploy.new(
                deployment_spec: deployment_spec,
                target: target
              )
            ).value

            if !resp.respond_to?(:succeeded) or !resp.succeeded
              raise MuError.new "Failed to create VM #{@mu_name} from template #{@config['template']}", details: resp
            end
            @cloud_id = resp.resource_id.id
          else
            params = {
              "spec" => {
                "guest_OS" => @config["image_id"],
                "name" => @mu_name,
                "placement" => {
                  "folder" => folder,
                  "resource_pool" => resource_pool,
                  "host" => "host-16", # XXX expose/discover
                  "cluster" => "domain-c8", # XXX expose/discover
                  "datastore" => "datastore-48", # XXX expose/discover
                },
                "tags" => @tags.keys.map { |k| { "scope" => k, "tag" => @tags[k] } },
                "cdroms" => [
                  {
                    "allow_guest_control": true,
                    "start_connected": true,
                  }
                ],
              }
            }

            if config['iso']
              params["spec"]["cdroms"][0]["backing"] = {
                "iso_file" => "[#{config['iso']['datastore']}] #{config['iso']['path']}",
                "type" => "ISO_FILE"
              }
            end

            if @vpc
              params["spec"]["nics"] = [
                {
                  "start_connected" => true,
                  "allow_guest_control" => true,
                  "backing" => {
                    "type" => "OPAQUE_NETWORK", # STANDARD_PORTGROUP ?
                    "network" => @vpc.vSphereID
                  }
                }
              ]
            end

# spec.memory.size_MiB
            resp = MU::Cloud::VMWare.vm(credentials: @credentials).create(params)
            if resp and resp.is_a?(::VSphereAutomation::VCenter::VcenterVMCreateResp) and resp.respond_to?(:value) and resp.value
              @cloud_id = resp.value
            else
              pp params
              raise MuError.new "Failed to create VMWare VM #{@config['name']}", details: resp
            end
          end

          start
        end

        def self.getImageFromLibrary(url, credentials: nil, habitat: nil)
          habitat ||= MU::Cloud::VMWare.defaultSDDC(credentials)

          library, library_id, item, item_id = MU::Cloud::VMWare.parseLibraryUrl(url, credentials: credentials, habitat: habitat)

          list_available = Proc.new {
            if library_id
              MU::Cloud::VMWare.library_item(credentials: credentials, habitat: habitat).list(library_id).value.map { |i|
                { MU::Cloud::VMWare.library_item(credentials: credentials, habitat: habitat).get(i).value.name => MU::Cloud::VMWare.library_file(credentials: credentials, habitat: habitat).list(i).value.map { |f| f.name } }
              }
            end
          }

          if !library_id or !item_id
            have_items = list_available.call

            MU.log "Could not find a library and item matching #{url}", MU::ERR, details: {library => have_items}
            return nil
          end

          resp = MU::Cloud::VMWare.ovf(credentials: credentials, habitat: habitat).filter(
            item_id,
            ::VSphereAutomation::VCenter::VcenterOvfLibraryItemFilter.new(
              target: {
                resource_pool_id: MU::Cloud::VMWare.resource_pool(credentials: credentials, habitat: habitat).list.value.select { |r| r.name == "Compute-ResourcePool" }.first.resource_pool,
              }
            )
          )

          if !resp.is_a?(::VSphereAutomation::VCenter::VcenterOvfLibraryItemFilterResp) or !resp.value.is_a?(::VSphereAutomation::VCenter::VcenterOvfLibraryItemOvfSummary)
            have_items = list_available.call
            MU.log "Image at #{url} does not exist or is not a valid OVF library item", MU::ERR, details: resp
            pp have_items 
            return nil
          end

          [item_id, resp.value]
        end

        # Return a BoK-style config hash describing a NAT instance. We use this
        # to approximate Amazon's NAT gateway functionality with a plain
        # instance.
        # @return [Hash]
        def self.genericNAT
          return {
            "cloud" => "VMWare",
            "size" => "g1-small",
            "run_list" => [ "mu-nat" ],
            "groomer" => "Ansible",
            "platform" => "centos7",
            "src_dst_check" => false,
            "ssh_user" => "centos",
            "associate_public_ip" => true,
            "static_ip" => { "assign_ip" => true }
          }
        end

        # Return the date/time a machine image was created.
        # @param image_id [String]: URL to a Google disk image
        # @param credentials [String]
        # @return [DateTime]
        def self.imageTimeStamp(image_id, credentials: nil)
          nil
        end

        # Ask the VMWare API to stop this node
        def stop
          state = MU::Cloud::VMWare.power(credentials: @credentials, habitat: @sddc).get(@cloud_id).value.state
          if state != "POWERED_OFF"
            MU::Cloud::VMWare.power(credentials: @credentials).stop(@cloud_id)
          end

          MU.retrier([], loop_if: Proc.new { state != "POWERED_OFF" }) {
            state = MU::Cloud::VMWare.power(credentials: @credentials, habitat: @sddc).get(@cloud_id).value.state
          }
        end

        # Ask the VMWare API to start this node
        def start
          state = MU::Cloud::VMWare.power(credentials: @credentials, habitat: @sddc).get(@cloud_id).value.state
          if state != "POWERED_ON"
            MU::Cloud::VMWare.power(credentials: @credentials).start(@cloud_id)
          end

#          guest_info = MU::Cloud::VMWare.guest(credentials: @credentials, habitat: @sddc).get(@cloud_id).value
          MU.retrier([], loop_if: Proc.new { state != "POWERED_ON" }) {
            state = MU::Cloud::VMWare.power(credentials: @credentials, habitat: @sddc).get(@cloud_id).value.state
          }
          sleep 30 # XXX hackaround for guest tools not being responsive immediately, detect this better
        end

        # Ask the VMWare API to restart this node
        # @param _hard [Boolean]: [IGNORED] Force a stop/start. This is the only available way to restart an instance in VMWare, so this flag is ignored.
        def reboot(_hard = false)
          MU::Cloud::VMWare.power(credentials: @credentials).reset(@cloud_id)
        end

        # Figure out what's needed to SSH into this server.
        # @return [Array<String>]: nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name, alternate_names
        def getSSHConfig
          return nil if @config.nil? or @deploy.nil?

          nat_ssh_key = nat_ssh_user = nat_ssh_host = nil
          if !@config["vpc"].nil? and !MU::Cloud.resourceClass("Google", "VPC").haveRouteToInstance?(cloud_desc, credentials: @config['credentials'])

            if !@nat.nil?
              if @nat.cloud_desc.nil?
                MU.log "NAT was missing cloud descriptor when called in #{@mu_name}'s getSSHConfig", MU::ERR
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
              @config['ssh_user'] = @config['windows_admin_user']
              @config['ssh_user'] ||= "Administrator"
            else
              @config['ssh_user'] = "root"
            end
          end

          return [nat_ssh_key, nat_ssh_user, nat_ssh_host, canonicalIP, @config['ssh_user'], @deploy.ssh_key_name]
        end

        # Apply tags, bootstrap our configuration management, and other
        # administravia for a new instance.
        def postBoot(instance_id = nil)
          true
        end #postBoot

        # Locate an existing instance or instances and return an array containing matching VMWare resource descriptors for those that match.
        # @return [Array<Hash<String,OpenStruct>>]: The cloud provider's complete descriptions of matching instances
        def self.find(**args)
          found = {}

          if args[:cloud_id]
            resp = MU::Cloud::VMWare.vm(credentials: args[:credentials]).get(args[:cloud_id])
            if resp and resp.respond_to?(:value) and resp.value and resp.value.is_a?(::VSphereAutomation::VCenter::VcenterVMInfo)
              found[args[:cloud_id]] = resp.value
            end
          else
            resp = MU::Cloud::VMWare.vm(credentials: args[:credentials]).list()

            if !resp or !resp.is_a?(::VSphereAutomation::VCenter::VcenterVMListResp) or !resp.respond_to?(:value) or !resp.value
              MU.log "vm.list() returned #{resp.class.name}", MU::WARN, details: resp
              return found
            end

            resp.value.each { |v|
              found[v.vm] = MU::Cloud::VMWare.vm(credentials: args[:credentials]).get(v.vm).value
            }
          end

          return found
        end

        def notify
          deploydata = MU.structToHash(cloud_desc, stringify_keys: true)

          guest_info = MU::Cloud::VMWare.guest(credentials: @credentials, habitat: @sddc).get(@cloud_id).value
          if guest_info
            deploydata['guest_info'] = guest_info.to_hash
          end

          deploydata
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          puts @userdata
          metadata = Base64.strict_encode64(<<EOH
instance-id: #{@cloud_id}
local-hostname: #{@mu_name}
public-keys-data: #{@deploy.ssh_public_key.gsub(/\n/, ' ')}
EOH
).chomp

          userdata = Base64.strict_encode64(@userdata)

          resp = MU::Master.govc_run("vm.info", ["-e", "-g=false", @mu_name])

          if resp and resp["VirtualMachines"].size == 1
            extras = Hash[resp["VirtualMachines"].first["Config"]["ExtraConfig"].map { |v|
              [v["Key"], v["Value"]]
            }]
            if extras["guestinfo.metadata"] != metadata or
               extras["guestinfo.userdata"] != userdata
              stop
              puts MU::Master.govc_run(%Q{vm.change -vm=#{@mu_name} -e guestinfo.metadata="#{metadata}" -e guestinfo.metadata.encoding="base64" -e guestinfo.userdata="#{userdata}" -e guestinfo.userdata.encoding="base64"})
              start
            end
          else
            MU.log "govc vm.info on #{@mu_name} failed to return data I could use", MU::ERR, details: resp
          end

          start
          guest_info = MU::Cloud::VMWare.guest(credentials: @credentials, habitat: @sddc).get(@cloud_id).value

          if guest_info and guest_info.respond_to?(:ip_address)
            ip_desc = MU::Cloud::VMWare.nsx(credentials: @credentials, habitat: @habitat).allocatePublicIP(@mu_name)
            @private_ip = guest_info.ip_address

            @public_ip = @vpc.createRouteForIP(guest_info.ip_address, @config['associate_public_ip'])
          else
            MU.log "No guest OS info available for #{@mu_name}, will be unable to establish connectivity", MU::ERR
            return
          end

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

          MU::MommaCat.nameKitten(self)

          @groomer.saveDeployData

          begin
            @groomer.run(purpose: "Full Initial Run", max_retries: 15)
          rescue MU::Groomer::RunError
            MU.log "Proceeding after failed initial Groomer run, but #{node} may not behave as expected!", MU::WARN
          end

          if !@config['create_image'].nil? and !@config['image_created']
            MU::Cloud.resourceClass("VMWare", "Server").createImage(name: @mu_name, instance_id: @cloud_id, credentials: @credentials, habitat: @sddc)
          end

          MU::MommaCat.unlock(@cloud_id.to_s+"-groom")

        end

        # This functionality appears alluded to in the Ruby SDK, but does not
        # actually exist in the REST API. Cheers.
#        def runCmd(path, cwd: "/", arguments: "", env: {})
#          MU::Cloud::VMWare.guest_processes(credentials: @credentials, habitat: @sddc).create(
#            @cloud_id,
#            ::VSphereAutomation::VCenter::VcenterVmGuestProcessesCreate.new(
#              spec: ::VSphereAutomation::VCenter::VcenterVmGuestProcessesCreateSpec.new(
#                arguments: arguments,
#                environment_variables: env,
#                path: path,
#                working_directory: cwd
#              )
#            )
#          )
#        end

        # Create an image out of a running server. Requires either the name of a MU resource in the current deployment, or the cloud provider id of a running instance.
        # @param name [String]: The MU resource name of the server to use as the basis for this image.
        # @param instance_id [String]: The cloud provider resource identifier of the server to use as the basis for this image.
        # @param storage [Hash]: The storage devices to include in this image.
        # @param exclude_storage [Boolean]: Do not include the storage device profile of the running instance when creating this image.
        # @return [String]: The cloud provider identifier of the new machine image.
        def self.createImage(name: nil, instance_id: nil, library: "mu-images", credentials: nil, habitat: nil)
          library_desc = MU::Cloud.resourceClass("VMWare", "Bucket").find(cloud_id: library, credentials: credentials, habitat: habitat).values.first
          if !library_desc
            raise MuError, "Failed to find a library named #{library}"
          end

          # See if the item we're saving to already exists
          item_id = MU::Cloud::VMWare.library_item(credentials: credentials, habitat: habitat).find(::VSphereAutomation::Content::ContentLibraryItemFind.new(
            spec: ::VSphereAutomation::Content::ContentLibraryItemFindSpec.new(
              name: name,
              library_id: library_desc.id
          ))).value.first

          # create it, if not
          verb = if !item_id
            item_id = MU::Cloud.resourceClass("VMWare", "Bucket").createLibraryItem(library_desc.id, name, credentials: credentials, habitat: habitat, library_name: library)
            "Initializing"
          else
            "Updating"
          end

          MU.log "#{verb} OVF image #{item_id} in #{library} from VM #{instance_id}"
          resp = MU::Cloud::VMWare.ovf(credentials: credentials, habitat: habitat).create(
            ::VSphereAutomation::VCenter::VcenterOvfLibraryItemCreate.new(
              create_spec: ::VSphereAutomation::VCenter::VcenterOvfLibraryItemCreateSpec.new(
                name: name,
                description: "",
              ),
              source: {
                id: instance_id,
                type: "VirtualMachine"
              },
              target: {
                library_id: library_desc.id,
                library_item_id: item_id
              }
            )
          )

          resp.value.ovf_library_item_id
        end

        # Return the IP address that we, the Mu server, should be using to access
        # this host via the network. Note that this does not factor in SSH
        # bastion hosts that may be in the path, see getSSHConfig if that's what
        # you need.
        def canonicalIP
          @public_ip || @private_ip # XXX store these in a sensible place
        end

        # Return all of the IP addresses, public and private, from all of our
        # network interfaces.
        # @return [Array<String>]
        def listIPs
        end

        # return [String]: A password string.
        def getWindowsAdminPassword(use_cache: true)
          nil
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
          true
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
# XXX habitat is a flag; region probably isn't
          vms = find(credentials: credentials, region: region)

          vms.each_pair { |cloud_id, desc|
            if desc.name.match(/^#{Regexp.quote(MU.deploy_id)}/)
              MU.log "Deleting VM #{desc.name} (#{cloud_id})"
              if !noop
                MU::Cloud::VMWare.power(credentials: credentials).stop(cloud_id)
                pp MU::Cloud::VMWare.vm(credentials: credentials).delete(cloud_id)
              end
            end
          }
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "habitat" => MU::Config::Habitat.reference,
            "folder" => {
              "type" => "string",
              "default" => "Workloads"
            },
            "template" => {
              "type" => "string",
              "description" => "URL for OVF template or OVA archive which will serve as a base image for this virtual machine, typically a reference to an OVF library entry of the form +library-name:/item-name/foo+. If a remote (http/https) URL is specified, we will attempt to download the image and inject it into the VMWare environment's local OVF library.",
            },
            "iso" => {
              "type" => "object",
              "description" => "A +.iso+ file, which already exists in an accessible datastore, which we will mount on this virtual machine's CDROM device.",
              "required" => ["path"],
              "properties" => { 
                "datastore" => {
                  "type" => "string",
                  "description" => "The datastore in which the +.iso+ file resides",
                  "default" => "WorkloadDatastore"
                },
                "path" => {
                  "type" => "string",
                  "description" => "The path to the +.iso+ file"
                }
              }
            },
          }
          [toplevel_required, schema]
        end

        @@instance_type_cache = {}

        # Confirm that the given instance size is valid for the given region.
        # If someone accidentally specified an equivalent size from some other cloud provider, return something that makes sense. If nothing makes sense, return nil.
        # @param size [String]: Instance type to check
        # @param region [String]: Region to check against
        # @return [String,nil]
        def self.validateInstanceType(size, region, project: nil, credentials: nil)
          nil
        end


        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::servers}, bare and unvalidated.
        # @param server [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(server, configurator)
          ok = true
          server['habitat'] ||= MU::Config::Ref.get(
            id: MU::Cloud::VMWare.defaultSDDC(server['credentials']),
            cloud: "VMWare",
            type: "habitats"
          )

          if server['template']
            if !getImageFromLibrary(server['template'], credentials: server['credentials'], habitat: server['habitat'].id)
              ok = false
            end
          end

          if !server['vpc']
            MU.log "VMWare Server '#{server['name']}' did not declare a vpc block, and will be configured with no network interface", MU::WARN
          end

          ok
        end

      end #class
    end #class
  end
end #module
