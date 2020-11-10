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

          @mu_name ||= if !@config['scrub_mu_isms']
            @deploy.getResourceName(@config["name"])
          else
            @config['name']
          end

          # If we're being reverse-engineered from a cloud descriptor, use that
          # to determine what sort of account we are.
          if args[:from_cloud_desc]
            require 'google/apis/admin_directory_v1'
            @cloud_desc_cache = args[:from_cloud_desc]
            if args[:from_cloud_desc].class == ::Google::Apis::AdminDirectoryV1::Role
              @config['role_source'] = "directory"
            elsif args[:from_cloud_desc].name.match(/^roles\/(.*)/) or
                  (@cloud_id and @cloud_id.match(/^roles\/(.*)/))
              @config['role_source'] = "canned"
              @config['name'] = Regexp.last_match[1]
            elsif args[:from_cloud_desc].name.match(/^organizations\/\d+\/roles\/(.*)/) or
                  (@cloud_id and @cloud_id.match(/^organizations\/\d+\/roles\/(.*)/))
              @config['role_source'] = "org"
              @config['name'] = Regexp.last_match[1]
            elsif args[:from_cloud_desc].name.match(/^projects\/([^\/]+?)\/roles\/(.*)/) or
                  (@cloud_id and @cloud_id.match(/^projects\/\d+\/roles\/(.*)/))
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
              role_privileges: MU::Cloud::Google::Role.map_directory_privileges(@config['import'], credentials: @credentials).first
            )
            MU.log "Creating directory role #{@mu_name}", details: role_obj

            resp = MU::Cloud::Google.admin_directory(credentials: @credentials).insert_role(@customer, role_obj)
            @cloud_id = resp.role_id.to_s

          elsif @config['role_source'] == "canned"
            @cloud_id = @config['name']
            if !@cloud_id.match(/^roles\//)
              @cloud_id = "roles/"+@cloud_id
            end
          else
            create_role_obj = MU::Cloud::Google.iam(:CreateRoleRequest).new(
              role: MU::Cloud::Google.iam(:Role).new(
                title: @config['display_name'],
                description: @config['description']
              ),
              role_id: MU::Cloud::Google.nameStr(@deploy.getResourceName(@config["name"], max_length: 64)).gsub(/[^a-zA-Z0-9_\.]/, "_")
            )

            resp = if @config['role_source'] == "org"
              my_org = MU::Cloud::Google.getOrg(@config['credentials'])
              MU.log "Creating IAM organization role #{@mu_name} in #{my_org.display_name}", details: create_role_obj
              MU::Cloud::Google.iam(credentials: @credentials).create_organization_role(my_org.name, create_role_obj)
            elsif @config['role_source'] == "project"
              if !@project_id
                raise MuError, "Role #{@mu_name} is supposed to be in project #{@config['project']}, but no such project was found"
              end
              MU.log "Creating IAM project role #{@mu_name} in #{@project_id}", details: create_role_obj
              MU::Cloud::Google.iam(credentials: @credentials).create_project_role("projects/"+@project_id, create_role_obj)
            end

            @cloud_id = resp.name

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
          end

          @config['bindings'].each { |binding|
            binding.keys.each { |scopetype|
              next if scopetype == "entity"
              binding[scopetype].each { |scope|
# XXX handle entity being a MU::Config::Ref
                entity_id = if binding["entity"]["name"]
                  sib = @deploy.findLitterMate(name: binding["entity"]["name"], type: binding["entity"]["type"])
                  raise MuError, "Failed to look up sibling #{binding["entity"]["type"]}:#{binding["entity"]["name"]}" if !sib
                  if binding["entity"]["type"] == "users" and sib.config["type"] == "service"
                    binding["entity"]["type"] = "serviceAccount"
                  end
                  sib.cloud_id
                else
                  binding["entity"]["id"]
                end
# XXX resolve scope as well, if it's named or a MU::Config::Ref
                bindToIAM(binding["entity"]["type"], entity_id.sub(/.*?\/([^\/]+)$/, '\1'), scopetype, scope["id"])
              }
            }
          }
        end

        @cloud_desc_cache = nil
        # Return the cloud descriptor for the Role
        # @return [Google::Apis::Core::Hashable]
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache

          MU::Cloud::Google.getOrg(@config['credentials'])

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
          base.delete(:etag)
          base["cloud_id"] = @cloud_id

          base
        end

        # Wrapper for #{MU::Cloud::Google::Role.bindToIAM}
        def bindToIAM(entity_type, entity_id, scope_type, scope_id)
          MU::Cloud::Google::Role.bindToIAM(@cloud_id, entity_type, entity_id, scope_type, scope_id, credentials: @config['credentials'])
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
        def self.bindToIAM(role_id, entity_type, entity_id, scope_type, scope_id, credentials: nil, debug: false)
          loglevel = debug ? MU::NOTICE : MU::DEBUG

          MU.log "Google::Role.bindToIAM(role_id: #{role_id}, entity_type: #{entity_type}, entity_id: #{entity_id}, scope_type: #{scope_type}, scope_id: #{scope_id}, credentials: #{credentials})", loglevel

          # scope_id might actually be the name of a credential set; if so, we
          # map it back to an actual organization on the fly
          if scope_type == "organizations"
            my_org = MU::Cloud::Google.getOrg(scope_id)
            if my_org
              scope_id = my_org.name
            end
          end

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
              if !scope_id
                raise MuError, "Google::Role.bindToIAM was called without a scope_id"
              elsif scope_id.is_a?(Hash)
                if scope_id["id"]
                  scope_id = scope_id["id"]
                else
                  raise MuError, "Google::Role.bindToIAM was called with a scope_id Ref hash that has no id field"
                end
              end
              MU::Cloud::Google.resource_manager(credentials: credentials).get_project_iam_policy(scope_id.sub(/^projects\//, ""))
            else
              puts "WTF DO WIT #{scope_type}"
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
            if scope_type == "organizations"
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
            folders = MU::Cloud.resourceClass("Google", "Folder").find(credentials: credentials)
            if folders and folders.size > 0
              scopes["folders"] = folders.keys
            end
          end

          projects = MU::Cloud.resourceClass("Google", "Habitat").find(credentials: credentials)
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
                    MU.log "Unbinding #{binding.role} from #{entity} in #{scope_id}"
                    need_update = true
                    binding.members.delete(entity)
                  end
                }
# XXX maybe drop bindings with 0 members?
                next if !need_update or noop
                req_obj = MU::Cloud::Google.resource_manager(:SetIamPolicyRequest).new(
                  policy: policy
                )

                if scope_type == "organizations"
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
        def self.bindFromConfig(entity_type, entity_id, cfg, credentials: nil, deploy: nil, debug: false)
          loglevel = debug ? MU::NOTICE : MU::DEBUG

          return if !cfg
          MU.log "Google::Role::bindFromConfig binding called for #{entity_type} #{entity_id}", loglevel, details: cfg

          cfg.each { |binding|
            if deploy and binding["role"]["name"] and !binding["role"]["id"]
              role_obj = deploy.findLitterMate(name: binding["role"]["name"], type: "roles")
              binding["role"]["id"] = role_obj.cloud_id if role_obj
            end
            ["organizations", "projects", "folders"].each { |scopetype|
              next if !binding[scopetype]

              binding[scopetype].each { |scope|
# XXX resolution of Ref bits (roles, projects, and folders anyway; organizations and domains are direct)
                MU::Cloud::Google::Role.bindToIAM(
                  binding["role"]["id"],
                  entity_type,
                  entity_id,
                  scopetype,
                  scope,
                  credentials: credentials
                )
              }
            }
            if binding["directories"]
              binding["directories"].each { |dir|
                # this is either an organization cloud_id, or the name of one
                # of our credential sets, which we must map to an organization
                # cloud id
                creds = MU::Cloud::Google.credConfig(dir)

                customer = if creds
                  my_org = MU::Cloud::Google.getOrg(dir)
                  if !my_org
                    raise MuError, "Google directory role binding specified directory #{dir}, which looks like one of our credential sets, but does not appear to map to an organization!"
                  end
                  my_org.owner.directory_customer_id
                elsif dir.match(/^organizations\//)
                  # Not sure if there's ever a case where we can do this with
                  # an org that's different from the one our credentials go with
                  my_org = MU::Cloud::Google.getOrg(credentials, with_id: dir)
                  if !my_org
                    raise MuError, "Failed to retrieve #{dir} with credentials #{credentials} in Google directory role binding for role #{binding["role"].to_s}"
                  end
                  my_org.owner.directory_customer_id
                else
                  # assume it's a raw customer id and hope for the best
                  dir
                end

                if !binding["role"]["id"].match(/^\d+$/)
                  resp = MU::Cloud::Google.admin_directory(credentials: credentials).list_roles(customer)
                  if resp and resp.items
                    resp.items.each { |role|
                      if role.role_name == binding["role"]["id"]
                        binding["role"]["id"] = role.role_id
                        break
                      end
                    }
                  end
                end

                # Ensure we're using the stupid internal id, instead of the
                # email field (which is the "real" id most of the time)
                real_id = nil
                if entity_type == "group"
                  found = MU::Cloud.resourceClass("Google", "Group").find(cloud_id: entity_id, credentials: credentials)
                  if found[entity_id]
                    real_id = found[entity_id].id
                  end
                elsif entity_type == "user"
                  found = MU::Cloud.resourceClass("Google", "User").find(cloud_id: entity_id, credentials: credentials)
                  if found[entity_id]
                    real_id = found[entity_id].id
                  end
                else
                  raise MuError, "I don't know how to identify entity type #{entity_type} with id #{entity_id} in directory role binding"
                end
                real_id ||= entity_id # fingers crossed

                assign_obj = MU::Cloud::Google.admin_directory(:RoleAssignment).new(
                  assigned_to: real_id,
                  role_id: binding["role"]["id"],
                  scope_type: "CUSTOMER"
                )
# XXX guard this mess
                MU.log "Binding directory role #{(binding["role"]["name"] || binding["role"]["id"])} to #{entity_type} #{entity_id} in #{dir}", details: assign_obj
                MU::Cloud::Google.admin_directory(credentials: credentials).insert_role_assignment(
                  customer,
                  assign_obj
                )

              }
            end
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
          MU::Cloud::RELEASE
        end

        # Remove all roles associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})
          customer = MU::Cloud::Google.customerID(credentials)
          my_org = MU::Cloud::Google.getOrg(credentials)

          filter = %Q{(labels.mu-id = "#{MU.deploy_id.downcase}")}
          if !ignoremaster and MU.mu_public_ip
            filter += %Q{ AND (labels.mu-master-ip = "#{MU.mu_public_ip.gsub(/\./, "_")}")}
          end
          MU.log "Placeholder: Google Role artifacts do not support labels, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: filter

          if flags['known']
            flags['known'].each { |id|
              next if id.nil?
              # GCP roles don't have a useful field for packing in our deploy
              # id, so if we have metadata to leverage for this, use it. For
              # directory roles, we try to make it into the name field, so
              # we'll check that later, but for org and project roles this is 
              # our only option.
              if my_org and id.is_a?(Integer) or id.match(/^\d+/)
                begin
                  resp = MU::Cloud::Google.admin_directory(credentials: credentials).get_role(customer, id)
                rescue ::Google::Apis::ClientError => e
                  next if e.message.match(/notFound/)
                  raise e
                end
                if resp
                  MU.log "Deleting directory role #{resp.role_name}"
                  if !noop
                    MU::Cloud::Google.admin_directory(credentials: credentials).delete_role(customer, id)
                  end
                end
              elsif id.match(/^projects\/.*?\/roles\//)
                begin
                  resp = MU::Cloud::Google.iam(credentials: credentials).get_project_role(id)
                rescue ::Google::Apis::ClientError => e
                  next if e.message.match(/notFound/)
                  raise e
                end
                if resp
                  MU.log "Deleting project role #{resp.name}"
                  if !noop
                    MU::Cloud::Google.iam(credentials: credentials).delete_project_role(id)
                  end
                end
              elsif id.match(/^organizations\//)
                begin
                  resp = MU::Cloud::Google.iam(credentials: credentials).get_organization_role(id)
                rescue ::Google::Apis::ClientError => e
#MU.log e.message, MU::ERR, details: id
#next
                  next if e.message.match(/notFound/)
                  raise e
                end
                if resp
                  MU.log "Deleting organization role #{resp.name}"
                  if !noop
                    MU::Cloud::Google.iam(credentials: credentials).delete_organization_role(id)
                  end
                end
              end
            }
          end

          if my_org and MU.deploy_id and !MU.deploy_id.empty?
            resp = MU::Cloud::Google.admin_directory(credentials: credentials).list_roles(customer)
            if resp and resp.items
              resp.items.each { |role|
                if role.role_name.match(/^#{Regexp.quote(MU.deploy_id)}/)
                  MU.log "Deleting directory role #{role.role_name}"
                  if !noop
                    MU::Cloud::Google.admin_directory(credentials: credentials).delete_role(customer, role.role_id)
                  end
                end
              }
            end
          end

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
          args[:project] ||= args[:habitat]

          if args[:project]
            canned = Hash[MU::Cloud::Google.iam(credentials: args[:credentials]).list_roles.roles.map { |r| [r.name, r] }]
            begin
              MU::Cloud.resourceClass("Google", "Habitat").bindings(args[:project], credentials: args[:credentials]).each { |binding|
                found[binding.role] = canned[binding.role]
              }
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden: /)
            end

            resp = begin
              MU::Cloud::Google.iam(credentials: args[:credentials]).list_project_roles("projects/"+args[:project])
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden: /)
            end
            if resp and resp.roles
              resp.roles.each { |role|
                found[role.name] = role
              }
            end
            if args[:cloud_id]
              found.reject! { |k, _v| k != args[:cloud_id] }
            end

            # Now go get everything that's bound here
            bindings = MU::Cloud::Google::Role.getAllBindings(args[:credentials])
            if bindings and bindings['by_scope'] and
               bindings['by_scope']['projects'] and
               bindings['by_scope']['projects'][args[:project]]
              bindings['by_scope']['projects'][args[:project]].keys.each { |r|
                if r.match(/^roles\//)
                  begin
                    role = MU::Cloud::Google.iam(credentials: args[:credentials]).get_role(r)
                    found[role.name] = role
                  rescue ::Google::Apis::ClientError => e
                    raise e if !e.message.match(/(?:forbidden|notFound): /)
                    MU.log "Failed  MU::Cloud::Google.iam(credentials: #{args[:credentials]}).get_role(#{r})", MU::WARN, details: e.message
                  end
                elsif !found[r]
#                  MU.log "NEED TO GET #{r}", MU::WARN
                end
              }
            end
          else
            if credcfg['masquerade_as']
              if args[:cloud_id]
                begin
                  resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).get_role(customer, args[:cloud_id].to_i)
                  if resp
                    found[args[:cloud_id].to_s] = resp
                  end
                rescue ::Google::Apis::ClientError => e
                  raise e if !e.message.match(/(?:forbidden|notFound): /)
                end
              else
                resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).list_roles(customer)
                if resp and resp.items
                  resp.items.each { |role|
                    found[role.role_id.to_s] = role
                  }
                end
              end

            end
#            These are the canned roles
            resp = begin
              MU::Cloud::Google.iam(credentials: args[:credentials]).list_roles
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden: /)
            end
            if resp
              resp.roles.each { |role|
                found[role.name] = role
              }
            end

            if my_org
              resp = begin
                MU::Cloud::Google.iam(credentials: args[:credentials]).list_organization_roles(my_org.name)
              rescue ::Google::Apis::ClientError => e
                raise e if !e.message.match(/forbidden: /)
              end
              if resp and resp.roles
                resp.roles.each { |role|
                  found[role.name] = role
                }
              end
            end
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**args)

          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials'],
            "cloud_id" => @cloud_id
          }

          my_org = MU::Cloud::Google.getOrg(@config['credentials'])

          # This can happen if the role_source isn't set correctly. This logic
          # maybe belongs inside cloud_desc. XXX
          if cloud_desc.nil?
            if @cloud_id and @cloud_id.match(/^roles\/(.*)/)
              @config['role_source'] = "canned"
            elsif @cloud_id and @cloud_id.match(/^organizations\/\d+\/roles\/(.*)/)
              @config['role_source'] = "org"
            elsif @cloud_id and @cloud_id.match(/^projects\/\d+\/roles\/(.*)/)
              @config['role_source'] = "project"
            end
          end

          # GSuite or Cloud Identity role
          if cloud_desc.class == ::Google::Apis::AdminDirectoryV1::Role
            return nil if cloud_desc.is_system_role

            bok["name"] = @config['name'].gsub(/[^a-z0-9]/i, '-').downcase
            bok['role_source'] = "directory"
            bok["display_name"] = @config['name']
            if !cloud_desc.role_description.empty?
              bok["description"] = cloud_desc.role_description
            end
            if !cloud_desc.role_privileges.nil? and !cloud_desc.role_privileges.empty?
              bok['import'] = []
              ids, _names, _privs = MU::Cloud::Google::Role.privilege_service_to_name(@config['credentials'])
              cloud_desc.role_privileges.each { |priv|
                if !ids[priv.service_id]
                  MU.log "Role privilege defined for a service id with no name I can find, writing with raw id", MU::DEBUG, details: priv
                  bok["import"] << priv.service_id+"/"+priv.privilege_name
                else
                  bok["import"] << ids[priv.service_id]+"/"+priv.privilege_name
                end
              }
              bok['import'].sort! # at least be legible
            end
          else # otherwise it's a GCP IAM role of some kind

            return nil if cloud_desc.stage == "DISABLED"
            if cloud_desc.name.match(/^roles\/([^\/]+)$/)
              name = Regexp.last_match[1]
              bok['name'] = name.gsub(/[^a-z0-9]/i, '-')
              bok['role_source'] = "canned"
            elsif cloud_desc.name.match(/^([^\/]+?)\/([^\/]+?)\/roles\/(.*)/)
              _junk, type, parent, name = Regexp.last_match.to_a
              bok['name'] = name.gsub(/[^a-z0-9]/i, '-')
              bok['role_source'] = type == "organizations" ? "org" : "project"
              if bok['role_source'] == "project"
                bok['project'] = parent
              end
              if cloud_desc.included_permissions and cloud_desc.included_permissions.size > 0
                bok['import'] = cloud_desc.included_permissions
              end

            else
              raise MuError, "I don't know how to parse GCP IAM role identifier #{cloud_desc.name}"
            end

            if !cloud_desc.description.nil? and !cloud_desc.description.empty?
              bok["description"] = cloud_desc.description
            end
            bok["display_name"] = cloud_desc.title

            bindings = MU::Cloud::Google::Role.getAllBindings(@config['credentials'])["by_role"][@cloud_id]

            if bindings
              refmap = {}
              bindings.keys.each { |scopetype|
                bindings[scopetype].each_pair { |scope_id, entity_types|
                  # If we've been given a habitat filter, skip over bindings
                  # that don't match it.
                  if scopetype == "projects"
                    if (args[:habitats] and !args[:habitats].empty? and
                       !args[:habitats].include?(scope_id)) or
                       !MU::Cloud::Google.listHabitats(@credentials).include?(scope_id)
                      next
                    end
                  end

                  entity_types.each_pair { |entity_type, entities|
                    next if entity_type == "deleted"
                    mu_entitytype = (entity_type == "serviceAccount" ? "user" : entity_type)+"s"
                    entities.each { |entity|
                      next if entity.nil?
                      foreign = if entity_type == "serviceAccount" and entity.match(/@(.*?)\.iam\.gserviceaccount\.com/)
                        !MU::Cloud::Google.listHabitats(@credentials).include?(Regexp.last_match[1])
                      end

                      entity_ref = if entity_type == "organizations"
                        { "id" => ((org == my_org.name and @config['credentials']) ? @config['credentials'] : org) }
                      elsif entity_type == "domain"
                        { "id" => entity }
                      else
                        shortclass, _cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(mu_entitytype)
                        if args[:types].include?(shortclass) and
                           !(entity_type == "serviceAccount" and
                             MU::Cloud::Google::User.cannedServiceAcctName?(entity))
                          MU.log "Role #{@cloud_id}: Skipping #{shortclass} binding for #{entity}; we are adopting that type and will set bindings from that resource", MU::DEBUG
                          next
                        end

                        MU::Config::Ref.get(
                          id: entity,
                          cloud: "Google",
                          type: mu_entitytype
                        )
                      end
                      if entity_ref.nil?
                        MU.log "I somehow ended up with a nil entity reference for #{entity_type} #{entity}", MU::ERR, details: [ bok, bindings ]
                        next
                      end
                      refmap ||= {}
                      refmap[entity_ref] ||= {}
                      refmap[entity_ref][scopetype] ||= []
                      mu_scopetype = scopetype == "projects" ? "habitats" : scopetype
                      if scopetype == "organizations" or scopetype == "domains" # XXX singular? plural? barf
                        refmap[entity_ref][scopetype] << ((scope_id == my_org.name and @config['credentials']) ? @config['credentials'] : scope_id)
                      else
                        refmap[entity_ref][scopetype] << MU::Config::Ref.get(
                          id: scope_id,
                          cloud: "Google",
                          type: mu_scopetype
                        )
                      end
                      refmap[entity_ref][scopetype].uniq!
                    }
                  }
                }
              }

              bok["bindings"] ||= []
              refmap.each_pair { |entity, scopes|
                newbinding = { "entity" => entity }
                scopes.keys.each { |scopetype|
                  newbinding[scopetype] = scopes[scopetype].sort
                }
                bok["bindings"] << newbinding
              }
            end
          end

          # Our only reason for declaring canned roles is so we can put their
          # bindings somewhere. If there aren't any, then we don't need
          # to bother with them.
          if bok['role_source'] == "canned" and
             (bok['bindings'].nil? or bok['bindings'].empty?)
            return nil
          end

          bok
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
                "by_role" => @@bindings_by_role.dup,
                "by_scope" => @@bindings_by_scope.dup,
                "by_entity" => @@bindings_by_entity.dup
              }
            end

            def self.insertBinding(scopetype, scope, binding = nil, member_type: nil, member_id: nil, role_id: nil)
              role_id = binding.role if binding
              @@bindings_by_scope[scopetype] ||= {}
              @@bindings_by_scope[scopetype][scope] ||= {}
              @@bindings_by_scope[scopetype][scope][role_id] ||= {}
              @@bindings_by_role[role_id] ||= {}
              @@bindings_by_role[role_id][scopetype] ||= {}
              @@bindings_by_role[role_id][scopetype][scope] ||= {}

              do_binding = Proc.new { |type, id|
                @@bindings_by_role[role_id][scopetype][scope][type] ||= []
                @@bindings_by_role[role_id][scopetype][scope][type] << id
                @@bindings_by_scope[scopetype][scope][role_id][type] ||= []
                @@bindings_by_scope[scopetype][scope][role_id][type] << id
                @@bindings_by_entity[type] ||= {}
                @@bindings_by_entity[type][id] ||= {}
                @@bindings_by_entity[type][id][role_id] ||= {}
                @@bindings_by_entity[type][id][role_id][scopetype] ||= []
                @@bindings_by_entity[type][id][role_id][scopetype] << scope
              }

              if binding
                binding.members.each { |member|
                  member_type, member_id = member.split(/:/)
                  do_binding.call(member_type, member_id)
                }
              elsif member_type and member_id
                do_binding.call(member_type, member_id)
              end

            end

            if my_org
              resp = MU::Cloud::Google.admin_directory(credentials: credentials).list_role_assignments(MU::Cloud::Google.customerID(credentials))

              resp.items.each { |binding|

                begin
                  user = MU::Cloud::Google.admin_directory(credentials: credentials).get_user(binding.assigned_to)
                  insertBinding("directories", my_org.name, member_id: user.primary_email, member_type: "user", role_id: binding.role_id.to_s)
                  next
                rescue ::Google::Apis::ClientError # notFound
                end

                begin
                  group = MU::Cloud::Google.admin_directory(credentials: credentials).get_group(binding.assigned_to)
                  MU.log "GROUP", MU::NOTICE, details: group
#                  insertBinding("directories", my_org.name, member_id: group.primary_email, member_type: "group", role_id: binding.role_id.to_s)
                  next
                rescue ::Google::Apis::ClientError # notFound
                end

                role = MU::Cloud::Google.admin_directory(credentials: credentials).get_role(MU::Cloud::Google.customerID(credentials), binding.role_id)
                MU.log "Failed to find entity #{binding.assigned_to} referenced in GSuite/Cloud Identity binding to role #{role.role_name}", MU::DEBUG, details: role
              }

              resp = MU::Cloud::Google.resource_manager(credentials: credentials).get_organization_iam_policy(my_org.name)
              resp.bindings.each { |binding|
                insertBinding("organizations", my_org.name, binding)
              }

              MU::Cloud.resourceClass("Google", "Folder").find(credentials: credentials).keys.each { |folder|
                folder_bindings = MU::Cloud.resourceClass("Google", "Folder").bindings(folder, credentials: credentials)
                next if !folder_bindings
                folder_bindings.each { |binding|
                  insertBinding("folders", folder, binding)
                }
              }
            end
            MU::Cloud::Google.listHabitats(credentials).each { |project|
              begin
                MU::Cloud.resourceClass("Google", "Habitat").bindings(project, credentials: credentials).each { |binding|
                  insertBinding("projects", project, binding)
                }
              rescue ::Google::Apis::ClientError => e
                if e.message.match(/forbidden: /)
                  MU.log "Do not have permissions to retrieve bindings in project #{project}, skipping", MU::WARN
                else
                  raise e
                end
              end

            }

            return {
              "by_role" => @@bindings_by_role.dup,
              "by_scope" => @@bindings_by_scope.dup,
              "by_entity" => @@bindings_by_entity.dup
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
            rolemap["role"] = if !role.is_a?(Integer) and role.match(/^roles\//)
              # generally referring to a canned GCP role
              { "id" => role.to_s }
            elsif role.is_a?(Integer) or role.match(/^\d+$/)
              # If this is a GSuite/Cloud Identity system role, reference it by
              # its human-readable name intead of its numeric id
              role_desc = MU::Cloud::Google::Role.find(cloud_id: role, credentials: credentials).values.first
              if role_desc.is_system_role
                { "id" => role_desc.role_name }
              else
                MU::Config::Ref.get(
                  id: role,
                  cloud: "Google",
                  credentials: credentials,
                  type: "roles"
                )
              end
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
                if scopetype == "organizations" or scopetype == "directories"
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

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "name" => {
              "pattern" => '^[a-zA-Z0-9\-\.\/]+$'
            },
            "display_name" => {
              "type" => "string",
              "description" => "A human readable name for this role. If not specified, will default to our long-form deploy-generated name."
            },
            "role_source" => {
              "type" => "string",
              "description" => "Google effectively has four types of roles:
              
+directory+: An admin role in GSuite or Cloud Identity

+org+: A custom organization-level IAM role. Note that these are only valid in GSuite or Cloud Identity environments

+project+: A custom project-level IAM role.

+canned+: A reference to one of the standard pre-defined IAM roles, usually only declared to apply {bindings} to other artifacts.

If this value is not specified, and the role name matches the name of an existing +canned+ role, we will assume it should be +canned+. If it does not, and we have credentials which map to a valid organization, we will assume +org+; if the credentials do not map to an organization, we will assume +project+.",
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

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::roles}, bare and unvalidated.
        # @param role [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(role, configurator)
          ok = true

          MU::Cloud::Google.credConfig(role['credentials'])

          my_org = MU::Cloud::Google.getOrg(role['credentials'])
          if !role['role_source']
            begin
              lookup_name = role['name'].dup
              if !lookup_name.match(/^roles\//)
                lookup_name = "roles/"+lookup_name
              end
              MU::Cloud::Google.iam(credentials: role['credentials']).get_role(lookup_name)
              MU.log "Role #{role['name']} appears to be a referenced to canned role #{role.name} (#{role.title})", MU::NOTICE
              role['role_source'] = "canned"
            rescue ::Google::Apis::ClientError
              role['role_source'] = my_org ? "org" : "project"
            end
          end

          if role['role_source'] == "canned"
            if role['bindings'].nil? or role['bindings'].empty?
              MU.log "Role #{role['name']} appears to refer to a canned role, but does not have any bindings declared- this will effectively do nothing.", MU::WARN
            end
          end

          if role['role_source'] == "directory" 

            if role['import'] and role['import'].size > 0
              mappings, missing = map_directory_privileges(role['import'], credentials: role['credentials'])
              if mappings.size == 0
                MU.log "None of the directory service privileges available to credentials #{role['credentials']} map to the ones declared for role #{role['name']}", MU::ERR, details: role['import'].sort
                ok = false
              elsif missing.size > 0
                MU.log "Some directory service privileges declared for role #{role['name']} aren't available to credentials #{role['credentials']}, will skip", MU::DEBUG, details: missing
              end
            end
          end

          if role['role_source'] == "directory" or role['role_source'] == "org"
            if !my_org
              MU.log "Role #{role['name']} requires an organization/directory, but credential set #{role['credentials']} doesn't appear to have access to one", MU::ERR
              ok = false
            end
          end

          if role['role_source'] == "project"
            role['project'] ||= MU::Cloud::Google.defaultProject(role['credentials'])
            if configurator.haveLitterMate?(role['project'], "habitats")
              MU::Config.addDependency(role, role['project'], "habitat")
            end
          end

          if role['bindings']
            role['bindings'].each { |binding|
              if binding['entity'] and binding['entity']['name'] and 
                 configurator.haveLitterMate?(binding['entity']['name'], binding['entity']['type'])
                MU::Config.addDependency(role, binding['entity']['name'], binding['entity']['type'])
              end
            }
            role['bindings'].uniq!
          end

          ok
        end

        @@service_id_to_name = {}
        @@service_id_to_privs = {}
        @@service_name_to_id = {}
        @@service_name_map_semaphore = Mutex.new

        # Generate lookup tables mapping between hex service role identifiers,
        # human-readable names of services, and the privileges associated with
        # those roles.
        # @param credentials [String]
        # @return [Array<Hash,Hash,Hash>]
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

        # Convert a list of shorthand GSuite/Cloud Identity privileges into
        # +RolePrivilege+ objects for consumption by other API calls
        # @param roles [Array<String>]:
        # @param credentials [String]:
        # @return [Array<Google::Apis::AdminDirectoryV1::DirectoryService::Role::RolePrivilege>]
        def self.map_directory_privileges(roles, credentials: nil)
          rolepriv_objs = []
          notfound = []
          if roles
            ids, names, privlist = MU::Cloud::Google::Role.privilege_service_to_name(credentials)
            roles.each { |p|
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
          end
          [rolepriv_objs, notfound.uniq.sort]
        end

      end
    end
  end
end
