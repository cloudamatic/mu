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
    class Google
      # A role as configured in {MU::Config::BasketofKittens::roles}
      class Role < MU::Cloud::Role

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::roles}
        def initialize(**args)
          super

          @mu_name ||= @deploy.getResourceName(@config["name"])

          # If we're being reverse-engineered from a cloud descriptor, use that
          # to determine what sort of account we are.
          if args[:from_cloud_desc]
            if args[:from_cloud_desc].class == ::Google::Apis::AdminDirectoryV1::Role
              @config['role_source'] = "directory"
#            elsif args[:from_cloud_desc].class == ::Google::Apis::IamV1::ServiceAccount
            elsif args[:from_cloud_desc].name.match(/^organizations\/\d+\/roles\/(.*)/)
              @config['role_source'] = "org"
              @config['name'] = Regexp.last_match[1]
            elsif args[:from_cloud_desc].name.match(/^projects\/([^\/]+?)\/roles\/(.*)/)
              @config['project'] = Regexp.last_match[1]
              @config['name'] = Regexp.last_match[2]
              @project_id = @config['project']
              @config['role_source'] = "project"
            else
              MU.log "I don't know what to do with this #{args[:from_cloud_desc].class.name}", MU::ERR, details: args[:from_cloud_desc]
              raise MuError, "I don't know what to do with this #{args[:from_cloud_desc].class.name}"
            end
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        def cloud_desc
          customer = MU::Cloud::Google.customerID(@config['credentials'])
          my_org = MU::Cloud::Google.getOrg(@config['credentials'])

          if @config['role_source'] == "directory"
            MU::Cloud::Google.admin_directory(credentials: @config['credentials']).get_role(customer, @cloud_id)
          elsif @config['role_source'] == "project"
            MU::Cloud::Google.iam(credentials: @config['credentials']).get_project_role(@cloud_id)
          elsif @config['role_source'] == "org"
            MU::Cloud::Google.iam(credentials: @config['credentials']).get_organization_role(@cloud_id)
          end

        end

        # Return the metadata for this group configuration
        # @return [Hash]
        def notify
          base = MU.structToHash(cloud_desc)
          base["cloud_id"] = @cloud_id

          base
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        def self.canLiveIn
          [nil, :Habitat, :Folder]
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::ALPHA
        end

        # Remove all roles associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        # Locate an existing group group.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching group group.
        def self.find(**args)
          credcfg = MU::Cloud::Google.credConfig(args[:credentials])
          customer = MU::Cloud::Google.customerID(args[:credentials])
          my_org = MU::Cloud::Google.getOrg(args[:credentials])

          found = {}

          if args[:project]
            if args[:cloud_id]
            else
              resp = MU::Cloud::Google.iam(credentials: args[:credentials]).list_project_roles("projects/"+args[:project])
              if resp and resp.roles
                resp.roles.each { |role|
                  found[role.name] = role
                }
              end
            end
          else
            if credcfg['masquerade_as']
              if args[:cloud_id]
                resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).get_role(customer, args[:cloud_id])
                if resp
                  found[args[:cloud_id]] = resp
                end
              else
                resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).list_roles(customer)
                if resp and resp.items
                  resp.items.each { |role|
                    found[role.role_id] = role
                  }
                end
              end
#              resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).list_role_assignments(MU::Cloud::Google.customerID(args[:credentials]))
            end
#            These are the canned roles
#            resp = MU::Cloud::Google.iam(credentials: args[:credentials]).list_roles
            resp = MU::Cloud::Google.iam(credentials: args[:credentials]).list_organization_roles(my_org.name)
            if resp and resp.roles
              resp.roles.each { |role|
                found[role.name] = role
              }
            end
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id,
            "role_source" => @config['type']
          }
          my_org = MU::Cloud::Google.getOrg(@config['credentials'])
 
          # GSuite or Cloud Identity role
          if cloud_desc.class == ::Google::Apis::AdminDirectoryV1::Role
            bok['role_source'] = "directory"
            bok["name"] = @config['name'].gsub(/[^a-z0-9]/i, '-').downcase
            bok["display_name"] = @config['name']
            if !cloud_desc.role_description.empty?
              bok["description"] = cloud_desc.role_description
            end
            if !cloud_desc.role_privileges.nil? and !cloud_desc.role_privileges.empty?
              bok['import'] = []
              cloud_desc.role_privileges.each { |priv|
                bok["import"] << priv.service_id+"/"+priv.privilege_name
              }
            end
          else # otherwise it's a GCP IAM role of some kind
            cloud_desc.name.match(/^([^\/]+?)\/([^\/]+?)\/roles\/(.*)/)
            junk, type, parent, name = Regexp.last_match.to_a
            bok['role_source'] = type == "organizations" ? "org" : "project"
            bok['name'] = name.gsub(/[^a-z0-9]/i, '-')
            if bok['role_source'] == "project"
              bok['project'] = parent
            end
            if !cloud_desc.description.nil? and !cloud_desc.description.empty?
              bok["description"] = cloud_desc.description
            end
            bok["display_name"] = cloud_desc.title
            if !cloud_desc.included_permissions.empty?
              bok['import'] = []
              cloud_desc.included_permissions.each { |priv|
                bok["import"] << priv
              }
            end

            bindings = MU::Cloud::Google::Role.getAllBindings(@config['credentials'])["by_entity"]

            if bindings and bindings["domain"]
              bindings["domain"].each_pair { |domain, roles|
                if roles[cloud_desc.name]
                  bok["bindings"] ||= []
                  newbinding = {
                    "entity" => { "id" => domain }
                  }
                  roles[cloud_desc.name].each_pair { |scopetype, places|
                    mu_type = scopetype == "projects" ? "habitats" : scopetype
                    newbinding[scopetype] = []
                    if scopetype == "organizations"
                      places.each { |org|
                        newbinding[scopetype] << ((org == my_org.name and @config['credentials']) ? @config['credentials'] : org)
                      }
                    else
                      places.each { |scope|
                        newbinding[scopetype] << MU::Config::Ref.new(
                          id: scope,
                          type: mu_type
                        )
                      }
                    end
                  }
                  bok["bindings"] << newbinding
                end
              }
            end
          end

          bok
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "display_name" => {
              "type" => "string",
              "description" => "A human readable name for this role. If not specified, will default to our long-form deploy-generated name."
            },
            "role_source" => {
              "type" => "string",
              "description" => "'interactive' will attempt to bind an existing user; 'service' will create a service account and generate API keys",
              "enum" => ["directory", "org", "project"]
            },
            "description" => {
              "type" => "string",
              "description" => "Detailed human-readable description of this role's purpose"
            },
            "bindings" => {
              "type" => "array",
              "items" => {
                "type" => "object",
                "description" => "One or more entities (+user+, +group+, etc) to associate with this role. IAM roles in Google can be associated at the project (+Habitat+), folder, or organization level, so we must specify not only the target entity, but each container in which it is granted to the entity in question.",
                "properties" => {
                  "entity" => MU::Config::Ref.schema,
                  "projects" => {
                    "type" => "array",
                    "items" => MU::Config::Ref.schema(type: "habitats")
                  },
                  "folders" => {
                    "type" => "array",
                    "items" => MU::Config::Ref.schema(type: "folders")
                  },
                  "organizations" => {
                    "type" => "array",
                    "items" => {
                      "description" => "Either an organization cloud identifier, like +organizations/123456789012+, or the name of set of Mu credentials, which can be used as an alias to the organization to which they authenticate."
                    }
                  }
                }
              }
            }
          }
          [toplevel_required, schema]
        end

        # Schema used by +user+ and +group+ entities to reference role
        # assignments and their scopes.
        # @return [<Hash>]
        def self.ref_schema
          {
            "type" => "object",
            "description" => "One or more Google IAM roles to associate with this entity. IAM roles in Google can be associated at the project (+Habitat+), folder, or organization level, so we must specify not only role, but each container in which it is granted to the entity in question.",
            "properties" => {
              "role" => MU::Config::Ref.schema(type: "roles"),
              "projects" => {
                "type" => "array",
                "items" => MU::Config::Ref.schema(type: "habitats")
              },
              "folders" => {
                "type" => "array",
                "items" => MU::Config::Ref.schema(type: "folders")
              },
              "organizations" => {
                "type" => "array",
                "items" => {
                  "description" => "Either an organization cloud identifier, like +organizations/123456789012+, or the name of set of Mu credentials, which can be used as an alias to the organization to which they authenticate."
                }
              }
            }
          }
        end

        @@binding_semaphore = Mutex.new
        @@bindings_by_role = {}
        @@bindings_by_entity = {}
        @@bindings_by_scope = {}

        # Retrieve IAM role bindings for all entities throughout our
        # organization, map them in useful ways, and cache the result.
        def self.getAllBindings(credentials = nil, refresh: false)
          my_org = MU::Cloud::Google.getOrg(credentials)
          @@binding_semaphore.synchronize {
            if @@bindings_by_role.size > 0 and !refresh
              return {
                "by_role" => @@bindings_by_role,
                "by_scope" => @@bindings_by_scope,
                "by_entity" => @@bindings_by_entity
              }
            end

            def self.insertBinding(scopetype, scope, binding)
              @@bindings_by_scope[scopetype] ||= {}
              @@bindings_by_scope[scopetype][scope] ||= {}
              @@bindings_by_scope[scopetype][scope][binding.role] ||= {}
              @@bindings_by_role[binding.role] ||= {}
              @@bindings_by_role[binding.role][scopetype] ||= {}
              @@bindings_by_role[binding.role][scopetype][scope] ||= {}
              binding.members.each { |member|
                member_type, member_id = member.split(/:/)

                @@bindings_by_role[binding.role][scopetype][scope][member_type] ||= []
                @@bindings_by_role[binding.role][scopetype][scope][member_type] << member_id
                @@bindings_by_scope[scopetype][scope][binding.role][member_type] ||= []
                @@bindings_by_scope[scopetype][scope][binding.role][member_type] << member_id
                @@bindings_by_entity[member_type] ||= {}
                @@bindings_by_entity[member_type][member_id] ||= {}
                @@bindings_by_entity[member_type][member_id][binding.role] ||= {}
                @@bindings_by_entity[member_type][member_id][binding.role][scopetype] ||= []
                @@bindings_by_entity[member_type][member_id][binding.role][scopetype] << scope
              }
            end

            resp = MU::Cloud::Google.resource_manager(credentials: credentials).get_organization_iam_policy(my_org.name)
            resp.bindings.each { |binding|
              insertBinding("organizations", my_org.name, binding)
            }

            MU::Cloud::Google::Folder.find(credentials: credentials).keys.each { |folder|
              MU::Cloud::Google::Folder.bindings(folder, credentials: credentials).each { |binding|
                insertBinding("folders", folder, binding)
              }
            }
            MU::Cloud::Google::Habitat.find(credentials: credentials).keys.each { |project|
              MU::Cloud::Google::Habitat.bindings(project, credentials: credentials).each { |binding|
                insertBinding("projects", project, binding)
              }
            }

            return {
              "by_role" => @@bindings_by_role,
              "by_scope" => @@bindings_by_scope,
              "by_entity" => @@bindings_by_entity
            }
          }
        end

        def self.entityBindingsToSchema(roles, credentials: nil)
          my_org = MU::Cloud::Google.getOrg(credentials)
          role_cfg = []
          roles.each_pair { |role, scopes|
            rolemap = { }
            rolemap["role"] = if role.match(/^roles\//)
              # generally referring to a canned GCP role
              { "id" => role }
            else
              # Possi-probably something we're declaring elsewhere in this
              # adopted Mu stack
              MU::Config::Ref.get(
                id: role,
                cloud: "Google",
                credentials: credentials,
                type: "roles"
              )
            end
            scopes.each_pair { |scopetype, places|
              if places.size > 0
                rolemap[scopetype] = []
                if scopetype == "organizations"
                  places.each { |org|
                    rolemap[scopetype] << ((org == my_org.name and credentials) ? credentials : org)
                  }
                else
                  places.each { |place|
                    mu_type = scopetype == "projects" ? "habitats" : scopetype
                    rolemap[scopetype] << MU::Config::Ref.get(
                      id: place,
                      cloud: "Google",
                      credentials: credentials,
                      type: mu_type
                    )
                  }
                end
              end
            }
            role_cfg << rolemap
          }

          role_cfg
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::roles}, bare and unvalidated.
        # @param group [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(role, configurator)
          ok = true

          credcfg = MU::Cloud::Google.credConfig(role['credentials'])

          ok
        end

        private

      end
    end
  end
end
