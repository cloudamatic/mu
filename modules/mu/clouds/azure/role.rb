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
      # A user as configured in {MU::Config::BasketofKittens::roles}
      class Role < MU::Cloud::Role

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::roles}
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
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
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

        # Assign this role object to a given principal (create a RoleAssignment)
        # @param principal [MU::Cloud::Azure::Id]
        def assignTo(principal)
          MU::Cloud::Azure::Role.assignTo(principal_id, role_id: @cloud_id)
        end

        # Assign a role to a particular principal (create a RoleAssignment). We
        # support multiple ways of referring to a role
        # @param principal_id [MU::Cloud::Azure::Id]
        def self.assignTo(principal, role_name: nil, role_id: nil, credentials: nil)
# XXX subscription might need extraction
          if !role_name and !role_id
            raise MuError, "Role.assignTo requries one of role_name, role_id, or permissions in order to look up roles for association"

          end

          roles = MU::Cloud::Azure::Role.find(cloud_id: role_id, role_name: role_name, credentials: credentials)
          role = roles.values.first # XXX handle failures and multiples

#          assign_props = MU::Cloud::Azure.authorization(:RoleAssignmentPropertiesWithScope).new
          assign_props = MU::Cloud::Azure.authorization(:RoleAssignmentProperties).new
#          assign_props.scope = "/subscriptions/"+MU::Cloud::Azure.default_subscription(credentials)
          assign_props.principal_id = principal
          assign_props.role_definition_id = role.id


#          assign_obj = MU::Cloud::Azure.authorization(:RoleAssignmentCreateParameters, model_version: "V2015_07_01").new
          assign_obj = MU::Cloud::Azure.authorization(:RoleAssignmentCreateParameters).new
          assign_obj.properties = assign_props
#          assign_obj.principal_id = principal
#          assign_obj.role_definition_id = role.id
#          assign_obj.scope = "/subscriptions/"+MU::Cloud::Azure.default_subscription(credentials)
          role_name = begin
            role.role_name
          rescue NoMethodError
            role.properties.role_name
          end
          MU.log "Assigning role '#{role_name}' to principal #{principal}", MU::NOTICE, details: assign_obj
          MU::Cloud::Azure.authorization(credentials: credentials).role_assignments.create_by_id(
            role.id,
            assign_obj
          )

#MU::Cloud::Azure.authorization(credentials: @config['credentials']).role_assigments.list_for_resource_group(rgroup_name)
        end

        @@role_list_cache = {}
        @@role_list_semaphore = Mutex.new

        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching user group.
        def self.find(**args)
          found = {}

          sub_id = MU::Cloud::Azure.default_subscription(args[:credentials])
          scope = "/subscriptions/"+sub_id

          if args[:cloud_id]
            id_str = args[:cloud_id].is_a?(MU::Cloud::Azure::Id) ? args[:cloud_id].name : args[:cloud_id]
            begin
              resp = MU::Cloud::Azure.authorization(credentials: args[:credentials]).role_definitions.get(scope, id_str)
              found[Id.new(resp.id)] = resp
            rescue MsRestAzure::AzureOperationError => e
              # this is fine, we're doing a blind search after all
            end
          else
            @@role_list_semaphore.synchronize {
              if !@@role_list_cache[scope]
                @@role_list_cache[scope] = Hash[MU::Cloud::Azure.authorization(credentials: args[:credentials]).role_definitions.list(scope).map { |r| [Id.new(r.id), r] }]
              end
            }
            if args[:role_name]
              @@role_list_cache[scope].each_pair { |key, role|
              pp role
                begin
                  if role.role_name == args[:role_name]
                    found[Id.new(role.id)] = role
                    break
                  end
                rescue NoMethodError
                  if role.properties.role_name == args[:role_name]
                    found[Id.new(role.id)] = role
                    break
                  end
                end
              }
            else
              found = @@role_list_cache[scope].dup
            end
          end

          found
        end

        # Remove all users associated with the currently loaded deployment.
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

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::roles}, bare and unvalidated.
        # @param user [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(role, configurator)
          ok = true
          role['region'] ||= MU::Cloud::Azure.myRegion(role['credentials'])

          ok
        end

        private

      end
    end
  end
end
