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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          if !mu_name.nil?
            @mu_name = mu_name
            @cloud_id = Id.new(cloud_desc.id) if @cloud_id
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
        def assignTo(principal_id)
          MU::Cloud::Azure::Role.assignTo(principal_id, role_id: @cloud_id)
        end

        # Assign a role to a particular principal (create a RoleAssignment). We
        # support multiple ways of referring to a role
        # @param principal [MU::Cloud::Azure::Id]
        def self.assignTo(principal, role_name: nil, role_id: nil, credentials: nil)
# XXX subscription might need extraction
          if !role_name and !role_id
            raise MuError, "Role.assignTo requries one of role_name, role_id, or permissions in order to look up roles for association"

          end

          existing = MU::Cloud::Azure.authorization(credentials: credentials).role_assignments.list()

          roles = MU::Cloud::Azure::Role.find(cloud_id: role_id, role_name: role_name, credentials: credentials)
          role = roles.values.first # XXX handle failures and multiples

          assign_obj = MU::Cloud::Azure.authorization(:RoleAssignmentCreateParameters, model_version: "V2018_09_01_preview").new
          assign_obj.principal_id = principal
          assign_obj.principal_type = "ServicePrincipal"
          assign_obj.role_definition_id = role.id

          # TODO this should defintiely be configurable, and for most Mu
          # deploy resources will be scoped to the resource group level
          scope = "/subscriptions/"+MU::Cloud::Azure.default_subscription(credentials)

          role_name = begin
            role.role_name
          rescue NoMethodError
            role.properties.role_name
          end
          
          used_ids = []
          existing.each { |ext_assignment|
            used_ids << ext_assignment.name
            if ext_assignment.role_definition_id == role.id and
               ext_assignment.scope == scope and
               ext_assignment.principal_id == principal
              return
            end
          }

          guid = nil
          begin
            guid = MU::Cloud::Azure.genGUID
          end while used_ids.include?(guid)

          MU.log "Assigning role '#{role_name}' to principal #{principal}", details: assign_obj
          MU::Cloud::Azure.authorization(credentials: credentials).role_assignments.create(
            scope,
            guid,
            assign_obj
          )
        end

        @@role_list_cache = {}
        @@role_list_semaphore = Mutex.new

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

          sub_id = MU::Cloud::Azure.default_subscription(args[:credentials])
          scope = "/subscriptions/"+sub_id

          if args[:cloud_id]
            id_str = args[:cloud_id].is_a?(MU::Cloud::Azure::Id) ? args[:cloud_id].name : args[:cloud_id]
            begin
              resp = MU::Cloud::Azure.authorization(credentials: args[:credentials]).role_definitions.get(scope, id_str)
              found[Id.new(resp.id)] = resp
            rescue MsRestAzure::AzureOperationError
              # this is fine, we're doing a blind search after all
            end
          else
            @@role_list_semaphore.synchronize {
              if !@@role_list_cache[scope]
                @@role_list_cache[scope] = Hash[MU::Cloud::Azure.authorization(credentials: args[:credentials]).role_definitions.list(scope).map { |r| [Id.new(r.id), r] }]
              end
            }
            if args[:role_name]
              @@role_list_cache[scope].values.each { |role|
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
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::roles}, bare and unvalidated.
        # @param role [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(role, _configurator)
          ok = true
          role['region'] ||= MU::Cloud::Azure.myRegion(role['credentials'])

          ok
        end

      end
    end
  end
end
