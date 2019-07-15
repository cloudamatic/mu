# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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
      # A user as configured in {MU::Config::BasketofKittens::users}
      class User < MU::Cloud::User

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          if !mu_name.nil?
            @mu_name = mu_name
            @cloud_id = Id.new(cloud_desc.id)
          else
            @mu_name ||= @deploy.getResourceName(@config["name"], max_length: 31)
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          @config['region'] ||= MU::Cloud::Azure.myRegion(@config['credentials'])
          rgroup_name = @deploy.deploy_id+"-"+@config['region'].upcase

          tags = {}
          if !@config['scrub_mu_isms']
            tags = MU::MommaCat.listStandardTags
          end
          if @config['tags']
            @config['tags'].each { |tag|
              tags[tag['key']] = tag['value']
            }
          end

          if @config['type'] == "interactive"
            raise Mu::MuError, "I don't know how to make interactive users in Azure yet"
          else
            ident_obj = MU::Cloud::Azure.serviceaccts(:Identity).new
#            ident_obj.name = @mu_name
            ident_obj.location = @config['region']
            ident_obj.tags = tags
            begin
              MU.log "Creating service account #{@mu_name}"
              resp = MU::Cloud::Azure.serviceaccts(credentials: @config['credentials']).user_assigned_identities.create_or_update(rgroup_name, @mu_name, ident_obj)
              @cloud_id = Id.new(resp.id)
            rescue ::MsRestAzure::AzureOperationError => e
              MU::Cloud::Azure.handleError(e)
            end

          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          rgroup_name = @deploy.deploy_id+"-"+@config['region'].upcase
          if @config['roles']
            @config['roles'].each { |role|
              MU::Cloud::Azure::Role.assignTo(cloud_desc.principal_id, role_name: role, credentials: @config['credentials'])
            }
          end
        end

        # Return the metadata for this user configuration
        # @return [Hash]
        def notify
          description = MU.structToHash(cloud_desc)
          if description
            description.delete(:etag)
            return description
          end
          {
          }
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

# XXX Had to register Microsoft.ApiManagement at https://portal.azure.com/#@eglobaltechlabs.onmicrosoft.com/resource/subscriptions/3d20ddd8-4652-4074-adda-0d127ef1f0e0/resourceproviders
# ffs automate this process, it's just like API enabling in GCP


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
              resp = MU::Cloud::Azure.serviceaccts(credentials: args[:credentials]).user_assigned_identities.get(rg, id_str)
              found[Id.new(resp.id)] = resp if resp
            }
          else
            if args[:resource_group]
              MU::Cloud::Azure.serviceaccts(credentials: args[:credentials]).user_assigned_identities.list_by_resource_group.each { |ident|
                found[Id.new(ident.id)] = ident
              }
            else
              MU::Cloud::Azure.serviceaccts(credentials: args[:credentials]).user_assigned_identities.list_by_subscription.each { |ident|
                found[Id.new(ident.id)] = ident
              }
            end
          end

          found
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "region" => MU::Config.region_primitive,
            "name" => {
              "type" => "string",
              "description" => "The name of a account to create. Currently, +service+ is the only account type we support in Azure."
            },
            "type" => {
              "type" => "string",
              "description" => "'service' will create a service account (machine credentials) and generate API keys",
              "enum" => ["service"]
            },
            "roles" => {
              "type" => "array",
              "description" => "One or more Azure Authorization roles to associate with this user.",
              "default" => ["Reader"],
              "items" => {
                "type" => "string",
                "description" => "One or more Azure Authorization roles to associate with this user. If no roles are specified, we default to +Reader+, which permits read-only access subscription-wide."
              }
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::users}, bare and unvalidated.
        # @param user [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(user, configurator)
          ok = true
          user['region'] ||= MU::Cloud::Azure.myRegion(user['credentials'])

#          if user['groups'] and user['groups'].size > 0 and
#             !MU::Cloud::Azure.credConfig(user['credentials'])['masquerade_as']
#            MU.log "Cannot change Azure group memberships in non-GSuite environments.\nVisit https://groups.google.com to manage groups.", MU::ERR
#            ok = false
#          end

          if user['type'] != "service" and user["create_api_key"]
            MU.log "Only service accounts can have API keys in Azure", MU::ERR
            ok = false
          end

          if user['type'] != "service"
            MU.log "Human accounts not yet supported in Azure::User", MU::ERR
            ok = false
          end

          ok
        end

        private

        def bind_human_user
        end

      end
    end
  end
end
