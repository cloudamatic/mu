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

          params = {
            "spec" => {
              "guest_OS" => @config["image_id"],
              "name" => @mu_name,
              "placement" => {
                "folder" => MU::Cloud::VMWare.folderToID(@config['folder'], @credentials),
                "host" => "host-16",
                "cluster" => "domain-c8",
#              "resource_pool" => "", # in lieu of host+cluster
                "datastore" => "datastore-48"
              },
              "nics" => [
                {
                  "start_connected" => true,
                  "backing" => {
                    "type" => "OPAQUE_NETWORK",
                    "network" => "network-o32"
                  }
                }
              ]
            }
          }
# spec.memory.size_MiB
          resp = MU::Cloud::VMWare.vm(credentials: @credentials).create(params)
          if resp and resp.is_a?(::VSphereAutomation::VCenter::VcenterVMCreateResp) and resp.respond_to?(:value) and resp.value
            @cloud_id = resp.value
          else
            pp params
            raise MuError.new "Failed to create VMWare VM #{@config['name']}", details: resp
          end

          start
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
            "static_ip" => { "assign_ip" => true },
            "routes" => [ {
              "gateway" => "#INTERNET",
              "priority" => 50,
              "destination_network" => "0.0.0.0/0"
            } ]
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
          MU::Cloud::VMWare.power(credentials: @credentials).stop(@cloud_id)
        end

        # Ask the VMWare API to start this node
        def start
          MU::Cloud::VMWare.power(credentials: @credentials).start(@cloud_id)
        end

        # Ask the VMWare API to restart this node
        # @param _hard [Boolean]: [IGNORED] Force a stop/start. This is the only available way to restart an instance in VMWare, so this flag is ignored.
        def reboot(_hard = false)
          MU::Cloud::VMWare.power(credentials: @credentials).reset(@cloud_id)
        end

        # Figure out what's needed to SSH into this server.
        # @return [Array<String>]: nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name, alternate_names
        def getSSHConfig
        end

        # Apply tags, bootstrap our configuration management, and other
        # administravia for a new instance.
        def postBoot(instance_id = nil)
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

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        # Create an image out of a running server. Requires either the name of a MU resource in the current deployment, or the cloud provider id of a running instance.
        # @param name [String]: The MU resource name of the server to use as the basis for this image.
        # @param instance_id [String]: The cloud provider resource identifier of the server to use as the basis for this image.
        # @param storage [Hash]: The storage devices to include in this image.
        # @param exclude_storage [Boolean]: Do not include the storage device profile of the running instance when creating this image.
        # @param region [String]: The cloud provider region
        # @param tags [Array<String>]: Extra/override tags to apply to the image.
        # @return [String]: The cloud provider identifier of the new machine image.
        def self.createImage(name: nil, instance_id: nil, storage: {}, exclude_storage: false, project: nil, make_public: false, tags: [], region: nil, family: nil, zone: MU::Cloud::VMWare.listAZs.sample, credentials: nil)
        end

        # Return the IP address that we, the Mu server, should be using to access
        # this host via the network. Note that this does not factor in SSH
        # bastion hosts that may be in the path, see getSSHConfig if that's what
        # you need.
        def canonicalIP
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
                MU::Cloud::VMWare.vm(credentials: credentials).delete(cloud_id)
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
            "folder" => {
              "type" => "string",
              "default" => "Workloads"
            }
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

          ok
        end

      end #class
    end #class
  end
end #module
