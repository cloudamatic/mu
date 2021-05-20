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

module MU
  class Cloud
    class Azure
      # A load balancer as configured in {MU::Config::BasketofKittens::loadbalancers}
      class LoadBalancer < MU::Cloud::LoadBalancer

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          create_update
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          create_update

          if cloud_desc.tags != @tags
            tags_obj = MU::Cloud::Azure.network(:TagsObject).new
            tags_obj.tags = @tags
            MU.log "Updating tags on LoadBalancer #{@mu_name}", MU::NOTICE, details: @tags
            MU::Cloud::Azure.network(credentials: @config['credentials']).load_balancers.update_tags(@resource_group, @mu_name, tags_obj)
          end
        end

        # Return the metadata for this LoadBalancer
        # @return [Hash]
        def notify
        end

        # Register a Server node with an existing LoadBalancer.
        #
        # @param instance_id [String] A node to register.
        # @param targetgroups [Array<String>] The target group(s) of which this node should be made a member. Not applicable to classic LoadBalancers. If not supplied, the node will be registered to all available target groups on this LoadBalancer.
        def registerTarget(instance_id, backends: nil)
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

        # Stub method. Azure resources are cleaned up by removing the parent
        # resource group.
        # @return [void]
        def self.cleanup(**args)
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
#            "named_ports" => {
#              "type" => "array",
#              "items" => {
#                "type" => "object",
#                "required" => ["name", "port"],
#                "additionalProperties" => false,
#                "description" => "A named network port for a Azure instance group, used for health checks and forwarding targets.",
#                "properties" => {
#                  "name" => {
#                    "type" => "string"
#                  },
#                  "port" => {
#                    "type" => "integer"
#                  }
#                }
#              }
#            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::loadbalancers}, bare and unvalidated.
        # @param lb [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(lb, _configurator)
          ok = true
          lb['region'] ||= MU::Cloud::Azure.myRegion(lb['credentials'])

          ok
        end

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
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
              resp = MU::Cloud::Azure.network(credentials: args[:credentials]).load_balancers.get(rg, id_str)
              found[Id.new(resp.id)] = resp if resp
            }
          else
            if args[:resource_group]
              MU::Cloud::Azure.network(credentials: args[:credentials]).load_balancers.list(args[:resource_group]).each { |lb|
                found[Id.new(lb.id)] = lb
              }
            else
              MU::Cloud::Azure.network(credentials: args[:credentials]).load_balancers.list_all.each { |lb|
                found[Id.new(lb.id)] = lb
              }
            end
          end

          found
        end

        private

        def create_update
          @config['region'] ||= MU::Cloud::Azure.myRegion(@config['credentials'])

# XXX expose that second argument to BoK language to use a pre-existing resource
          ip_obj = MU::Cloud::Azure.fetchPublicIP(@resource_group, @mu_name, credentials: @config['credentials'], region: @config['region'], tags: @tags)

# XXX can have multiples of these
          front_obj = MU::Cloud::Azure.network(:FrontendIPConfiguration).new
          front_obj.name = @mu_name
          front_obj.public_ipaddress = ip_obj
          front_obj.private_ipallocation_method = "Dynamic"

          lb_obj = MU::Cloud::Azure.network(:LoadBalancer).new
          lb_obj.frontend_ipconfigurations = [front_obj]
          lb_obj.location = @config['region']
          lb_obj.tags = @tags


          need_apply = false
          ext_lb = MU::Cloud::Azure.network(credentials: @config['credentials']).load_balancers.get(
            @resource_group,
            @mu_name
          )
          if ext_lb
            pp ext_lb
            @cloud_id = MU::Cloud::Azure::Id.new(ext_lb.id)
          end
#MU.log "WHAT I GOT", MU::NOTICE, details: ext_lb
#MU.log "WHAT I NEED", MU::NOTICE, details: @config

          if !ext_lb
            MU.log "Creating Load Balancer #{@mu_name} in #{@config['region']}", details: lb_obj
            need_apply = true
          elsif ext_lb.frontend_ipconfigurations != lb_obj.frontend_ipconfigurations
            MU.log "Updating Network Security Group #{@mu_name} in #{@config['region']}", MU::NOTICE, details: lb_obj
            need_apply = true
          end

          if need_apply
            resp = MU::Cloud::Azure.network(credentials: @config['credentials']).load_balancers.create_or_update(@resource_group, @mu_name, lb_obj)
            @cloud_id = Id.new(resp.id)
          end
        end

      end
    end
  end
end
