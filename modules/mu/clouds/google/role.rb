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

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          @mu_name ||= @deploy.getResourceName(@config["name"])

          # If we're being reverse-engineered from a cloud descriptor, use that
          # to determine what sort of account we are.
          if args[:from_cloud_desc]
            @cloud_desc_cache = args[:from_cloud_desc]
            if args[:from_cloud_desc].class == ::Google::Apis::AdminDirectoryV1::Role
              @config['role_source'] = "directory"
            elsif args[:from_cloud_desc].name.match(/^roles\/(.*)/)
              @config['role_source'] = "canned"
              @config['name'] = Regexp.last_match[1]
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
          @config['display_name'] ||= @mu_name
          if @config['role_source'] == "directory"
            role_obj = MU::Cloud::Google.admin_directory(:Role).new(
              role_name: @mu_name,
              role_description: @config['display_name'],
              privileges: map_directory_privileges
            )
            MU.log "Creating directory role #{@mu_name}", details: role_obj

            resp = MU::Cloud::Google.admin_directory(credentials: @credentials).insert_role(@customer, role_obj)
            @cloud_id = resp.role_id
puts @cloud_id
          elsif @config['role_source'] == "org"
          elsif @config['role_source'] == "project"
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['role_source'] == "directory"
#            MU.log "Updating directory role #{@mu_name}", MU::NOTICE, details: role_obj
#            MU::Cloud::Google.admin_directory(credentials: @credentials).patch_role(@customer, @cloud_id, role_obj)
          elsif @config['role_source'] == "org"
          elsif @config['role_source'] == "project"
          elsif @config['role_source'] == "canned"
# XXX I'm just here for the bindings ma'am
          end
        end

        # Return the cloud descriptor for the Role
        # @return [Google::Apis::Core::Hashable]
        def cloud_desc
          return @cloud_desc_cache if @cloud_desc_cache

          my_org = MU::Cloud::Google.getOrg(@config['credentials'])

          @cloud_desc_cache = if @config['role_source'] == "directory"
            MU::Cloud::Google.admin_directory(credentials: @config['credentials']).get_role(@customer, @cloud_id)
          elsif @config['role_source'] == "canned"
            MU::Cloud::Google.iam(credentials: @config['credentials']).get_role(@cloud_id)
          elsif @config['role_source'] == "project"
            MU::Cloud::Google.iam(credentials: @config['credentials']).get_project_role(@cloud_id)
          elsif @config['role_source'] == "org"
            MU::Cloud::Google.iam(credentials: @config['credentials']).get_organization_role(@cloud_id)
          end

          @cloud_desc_cache
        end

        # Return the metadata for this group configuration
        # @return [Hash]
        def notify
          base = MU.structToHash(cloud_desc)
          base["cloud_id"] = @cloud_id

          base
        end

        # Wrapper for #{MU::Cloud::Google::Role.bindTo}
        def bindTo(entity_type, entity_id, scope_type, scope_id)
          MU::Cloud::Google::Role.bindTo(@cloud_id, entity_type, entity_id, bindings, scope_type, scope_id, credentials: @config['credentials'])
        end

        @@role_bind_semaphore = Mutex.new
        @@role_bind_scope_semaphores = {}

        # Attach a role to an entity
        # @param role_id [String]: The cloud identifier of the role to which we're binding
        # @param entity_type [String]: The kind of entity to bind; typically user, group, or domain
        # @param entity_id [String]: The cloud identifier of the entity
        # @param scope_type [String]: The kind of scope in which this binding will be valid; typically project, folder, or organization
        # @param scope_id [String]: The cloud identifier of the scope in which this binding will be valid
        # @param credentials [String]:
        def self.bindTo(role_id, entity_type, entity_id, scope_type, scope_id, credentials: nil)
          @@role_bind_semaphore.synchronize {
            @@role_bind_scope_semaphores[scope_id] ||= Mutex.new
          }

          @@role_bind_scope_semaphores[scope_id].synchronize {
            entity = entity_type.sub(/s$/, "")+":"+entity_id
            policy = if scope_type == "organizations"
              MU::Cloud::Google.resource_manager(credentials: credentials).get_organization_iam_policy(scope_id)
            elsif scope_type == "folders"
              MU::Cloud::Google.resource_manager(credentials: credentials).get_folder_iam_policy(scope_id)
            elsif scope_type == "projects"
              MU::Cloud::Google.resource_manager(credentials: credentials).get_project_iam_policy(scope_id)
            end

            saw_role = false
            policy.bindings.each { |binding|
              if binding.role == role_id 
                saw_role = true
                if binding.members.include?(entity)
                  return # it's already bound, nothing needs doing
                else
                  binding.members << entity
                end
              end
            }
            if !saw_role
              policy.bindings <<  MU::Cloud::Google.resource_manager(:Binding).new(
                role: role_id,
                members: [entity]
              )
            end
            MU.log "Granting #{role_id} to #{entity} in #{scope_id}", MU::NOTICE
            req_obj = MU::Cloud::Google.resource_manager(:SetIamPolicyRequest).new(
              policy: policy
            )
            policy = if scope_type == "organizations"
              MU::Cloud::Google.resource_manager(credentials: credentials).set_organization_iam_policy(
                scope_id,
                req_obj
              )
            elsif scope_type == "folders"
              MU::Cloud::Google.resource_manager(credentials: credentials).set_folder_iam_policy(
                scope_id,
                req_obj
              )
            elsif scope_type == "projects"
              MU::Cloud::Google.resource_manager(credentials: credentials).set_project_iam_policy(
                scope_id,
                req_obj
              )
            end
          }
        end

        # Remove all bindings for the specified entity
        # @param entity_type [String]: The kind of entity to bind; typically user, group, or domain
        # @param entity_id [String]: The cloud identifier of the entity
        # @param credentials [String]:
        # @param noop [Boolean]: Just say what we'd do without doing it
        def self.removeBindings(entity_type, entity_id, credentials: nil, noop: false)

          scopes = {}

          my_org = MU::Cloud::Google.getOrg(credentials)
          if my_org
            scopes["organizations"] = [my_org.name]
            folders = MU::Cloud::Google::Folder.find(credentials: credentials)
            if folders and folders.size > 0
              scopes["folders"] = folders.keys
            end
          end

          projects = MU::Cloud::Google::Habitat.find(credentials: credentials)
          if projects and projects.size > 0
            scopes["projects"] = projects.keys
          end

          scopes.each_pair { |scope_type, scope_ids|
            scope_ids.each { |scope_id|
              @@role_bind_semaphore.synchronize {
                @@role_bind_scope_semaphores[scope_id] ||= Mutex.new
              }

              @@role_bind_scope_semaphores[scope_id].synchronize {
                entity = entity_type.sub(/s$/, "")+":"+entity_id
                policy = if scope_type == "organizations"
                  MU::Cloud::Google.resource_manager(credentials: credentials).get_organization_iam_policy(my_org.name)
                elsif scope_type == "folders"
                  MU::Cloud::Google.resource_manager(credentials: credentials).get_folder_iam_policy(scope_id)
                elsif scope_type == "projects"
                  MU::Cloud::Google.resource_manager(credentials: credentials).get_project_iam_policy(scope_id)
                end

                need_update = false
                policy.bindings.each { |binding|
                  if binding.members.include?(entity)
                    MU.log "Removing #{binding.role} from #{entity} in #{scope_id}"
                    need_update = true
                    binding.members.delete(entity)
                  end
                }
# XXX maybe drop bindings with 0 members?
                next if !need_update or noop
                req_obj = MU::Cloud::Google.resource_manager(:SetIamPolicyRequest).new(
                  policy: policy
                )

                policy = if scope_type == "organizations"
                  MU::Cloud::Google.resource_manager(credentials: credentials).set_organization_iam_policy(
                    scope_id,
                    req_obj
                  )
                elsif scope_type == "folders"
                  MU::Cloud::Google.resource_manager(credentials: credentials).set_folder_iam_policy(
                    scope_id,
                    req_obj
                  )
                elsif scope_type == "projects"
                  MU::Cloud::Google.resource_manager(credentials: credentials).set_project_iam_policy(
                    scope_id,
                    req_obj
                  )
                end
              }

            }
          }
        end

        # Add role bindings for a given entity from its BoK config
        # @param entity_type [String]: The kind of entity to bind; typically user, group, or domain
        # @param entity_id [String]: The cloud identifier of the entity
        # @param cfg [Hash]: A configuration block confirming to our own {MU::Cloud::Google::Role.ref_schema}
        # @param credentials [String]:
        def self.bindFromConfig(entity_type, entity_id, cfg, credentials: nil)
          bindings = []

          return if !cfg

          cfg.each { |binding|
            ["organizations", "projects", "folders"].each { |scopetype|
              next if !binding[scopetype]

              binding[scopetype].each { |scope|
# XXX resolution of Ref bits (roles, projects, and folders anyway; organizations and domains are direct)
#        def self.bindTo(role_id, entity_type, entity_id, scope_type, scope_id, credentials: nil)
                MU::Cloud::Google::Role.bindTo(
                  binding["role"]["id"],
                  entity_type,
                  entity_id,
                  scopetype,
                  scope,
                  credentials: credentials
                )
              }
            }
          }

# XXX whattabout GSuite-tier roles?
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        # Return the list of "container" resource types in which this resource
        # can reside. The list will include an explicit nil if this resource
        # can exist outside of any container.
        # @return [Array<Symbol,nil>]
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

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
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
            resp = MU::Cloud::Google.iam(credentials: args[:credentials]).list_roles
            resp.roles.each { |role|
              found[role.name] = role
            }

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
            "cloud_id" => @cloud_id
          }
          my_org = MU::Cloud::Google.getOrg(@config['credentials'])

          # GSuite or Cloud Identity role
          if cloud_desc.class == ::Google::Apis::AdminDirectoryV1::Role
            bok["name"] = @config['name'].gsub(/[^a-z0-9]/i, '-').downcase
            bok['role_source'] = "directory"
            bok["display_name"] = @config['name']
            if !cloud_desc.role_description.empty?
              bok["description"] = cloud_desc.role_description
            end
            if !cloud_desc.role_privileges.nil? and !cloud_desc.role_privileges.empty?
              bok['import'] = []
              ids, names, privs = MU::Cloud::Google::Role.privilege_service_to_name(@config['credentials'])
              cloud_desc.role_privileges.each { |priv|
                if !ids[priv.service_id]
                  MU.log "Role privilege defined for a service id with no name I can find, writing with raw id", MU::WARN, details: priv
                  bok["import"] << priv.service_id+"/"+priv.privilege_name
                else
                  bok["import"] << ids[priv.service_id]+"/"+priv.privilege_name
                end
              }
              bok['import'].sort! # at least be legible
            end
          else # otherwise it's a GCP IAM role of some kind

            if cloud_desc.name.match(/^roles\/([^\/]+)$/)
              name = Regexp.last_match[1]
              bok['name'] = name.gsub(/[^a-z0-9]/i, '-')
              bok['role_source'] = "canned"
            elsif cloud_desc.name.match(/^([^\/]+?)\/([^\/]+?)\/roles\/(.*)/)
              junk, type, parent, name = Regexp.last_match.to_a
              bok['name'] = name.gsub(/[^a-z0-9]/i, '-')
              bok['role_source'] = type == "organizations" ? "org" : "project"
              if bok['role_source'] == "project"
                bok['project'] = parent
              end
              pp cloud_desc
              raise "feck orf"
            else
              raise MuError, "I don't know how to parse GCP IAM role identifier #{cloud_desc.name}"
            end

            if !cloud_desc.description.nil? and !cloud_desc.description.empty?
              bok["description"] = cloud_desc.description
            end
            bok["display_name"] = cloud_desc.title
            if !cloud_desc.included_permissions.nil? and
               !cloud_desc.included_permissions.empty?
              bok['import'] = []
              cloud_desc.included_permissions.each { |priv|
                bok["import"] << priv
              }
            end

            bindings = MU::Cloud::Google::Role.getAllBindings(@config['credentials'])["by_entity"]


            if bindings 
              # XXX In theory, for non-canned roles, bindings are already
              # covered by our sibling user and group resources, but what if
              # we're not adopting those resource types today? Hm. We'd have to
              # somehow know whether a resource was being toKitten'd somewhere
              # else outside of this method's visibility.

              if bindings["domain"]
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
          end

          # Our only reason for declaring canned roles is so we can put their
          # domain bindings somewhere. If there aren't any, then we don't need
          # to bother with them.
          return nil if bok['role_source'] == "canned" and bok['bindings'].nil?

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
              "enum" => ["directory", "org", "project", "canned"]
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
                      "type" => "string",
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
                  "type" => "string",
                  "description" => "Either an organization cloud identifier, like +organizations/123456789012+, or the name of set of Mu credentials listed in +mu.yaml+, which can be used as an alias to the organization to which they authenticate."
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

        # Convert a list of bindings of the type returned by {MU::Cloud::Google::Role.getAllBindings} into valid configuration language.
        # @param roles [Hash]
        # @param credentials [String]
        # @return [Hash]
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
        # @param role [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(role, configurator)
          ok = true

          credcfg = MU::Cloud::Google.credConfig(role['credentials'])

          ok
        end

        private

        @@service_id_to_name = {}
        @@service_id_to_privs = {}
        @@service_name_to_id = {}
        @@service_name_map_semaphore = Mutex.new

        def self.privilege_service_to_name(credentials = nil)

          customer = MU::Cloud::Google.customerID(credentials)
          @@service_name_map_semaphore.synchronize {
            if !@@service_id_to_name[credentials] or
               !@@service_id_to_privs[credentials] or
               !@@service_name_to_id[credentials]
              @@service_id_to_name[credentials] ||= {}
              @@service_id_to_privs[credentials] ||= {}
              @@service_name_to_id[credentials] ||= {}
              resp = MU::Cloud::Google.admin_directory(credentials: credentials).list_privileges(customer)

              def self.id_map_recurse(items, parent_name = nil)
                id_to_name = {}
                name_to_id = {}
                id_to_privs = {}

                items.each { |p|
                  svcname = p.service_name || parent_name
                  if svcname
                    id_to_name[p.service_id] ||= svcname
                    name_to_id[svcname] ||= p.service_id
                  else
#                    MU.log "FREAKING #{p.service_id} HAS NO NAME", MU::WARN
                  end
                  id_to_privs[p.service_id] ||= []
                  id_to_privs[p.service_id] << p.privilege_name
                  if p.child_privileges
                    ids, names, privs = id_map_recurse(p.child_privileges, svcname)
                    id_to_name.merge!(ids)
                    name_to_id.merge!(names)
                    privs.each_pair { |id, childprivs|
                      id_to_privs[id] ||= []
                      id_to_privs[id].concat(childprivs)
                    }
                  end
                }

                [id_to_name, name_to_id, id_to_privs]
              end

              @@service_id_to_name[credentials], @@service_id_to_privs[credentials], @@service_name_to_id[credentials] = self.id_map_recurse(resp.items)
            end

            return [@@service_id_to_name[credentials], @@service_id_to_privs[credentials], @@service_name_to_id[credentials]]
          }
        end

        def map_directory_privileges
          rolepriv_objs = []
          notfound = []
          if @config['import']
            ids, names, privlist = MU::Cloud::Google::Role.privilege_service_to_name(@credentials)
            pp names
            pp ids
            @config['import'].each { |p|
              service, privilege = p.split(/\//)
              if !names[service] and !ids[service]
                notfound << service
              elsif !privlist[names[service]].include?(privilege)
                notfound << p
              elsif names[service]
                rolepriv_objs << MU::Cloud::Google.admin_directory(:Role)::RolePrivilege.new(
                  privilege_name: privilege,
                  service_id: names[service]
                )
              else
                rolepriv_objs << MU::Cloud::Google.admin_directory(:Role)::RolePrivilege.new(
                  privilege_name: privilege,
                  service_id: service
                )
              end
            }
            if notfound.size > 0
              MU.log "Role #{@config['name']} unable to map some declared services/privileges to available services/privileges in this account", MU::WARN, details: notfound.uniq.sort
            end
          end
          rolepriv_objs
        end

      end
    end
  end
end
