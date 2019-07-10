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
              @config['type'] = "directory"
#            elsif args[:from_cloud_desc].class == ::Google::Apis::IamV1::ServiceAccount
            elsif args[:from_cloud_desc].name.match(/^organizations\/\d+\/roles\/(.*)/)
              @config['type'] = "org"
              @config['name'] = Regexp.last_match[1]
              puts @cloud_id
            elsif args[:from_cloud_desc].name.match(/^projects\/([^\/]+?)\/roles\/(.*)/)
              @config['project'] = Regexp.last_match[1]
              @config['name'] = Regexp.last_match[2]
              @project_id = @config['project']
              @config['type'] = "project"
              puts @cloud_id
            else
              pp args[:from_cloud_desc]
              puts args[:from_cloud_desc].class.name
              pp @config
              @config['type'] = "iam"
              exit
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

          if @config['type'] == "directory"
            MU::Cloud::Google.admin_directory(credentials: @config['credentials']).get_role(customer, @cloud_id)
          elsif @config['type'] == "project"
            MU::Cloud::Google.iam(credentials: @config['credentials']).get_project_role(@cloud_id)
          elsif @config['type'] == "org"
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
            "type" => @config['type']
          }
 
          # GSuite or Cloud Identity role
          if cloud_desc.class == ::Google::Apis::AdminDirectoryV1::Role
            bok['type'] = "directory"
            bok["name"] = @config['name'].gsub(/[^a-z0-9]/i, '-').downcase
            bok["display_name"] = @config['name']
            if !cloud_desc.role_description.empty?
              bok["description"] = cloud_desc.role_description
            end
            if !cloud_desc.role_privileges.nil? and !cloud_desc.role_privileges.empty?
              bok['import'] = []
              cloud_desc.role_privileges.each { |priv|
# XXX is priv.service_id (GSuite) needed to namespace these?
                bok["import"] << priv.privilege_name
              }
            end
          else # otherwise it's a GCP IAM role of some kind
            pp cloud_desc
            cloud_desc.name.match(/^([^\/]+?)\/([^\/]+?)\/roles\/(.*)/)
            junk, type, parent, name = Regexp.last_match.to_a
            bok['type'] = type == "organizations" ? "org" : "project"
            bok['name'] = name.gsub(/[^a-z0-9]/i, '-')
            if bok['type'] == "project"
              bok['project'] = parent
            end
            if !cloud_desc.description.nil? and !cloud_desc.description.empty?
              bok["description"] = cloud_desc.description
            end
            bok["display_name"] = cloud_desc.title
            if !cloud_desc.included_permissions.empty?
# XXX user query_grantable_roles and see if we can wildcard this mess
              bok['import'] = []
              cloud_desc.included_permissions.each { |priv|
                bok["import"] << priv
              }
            end
            if bok["project"] == "ncbi-research-dbas"
            MU.log "WHAT THE GODDAMN HELL", MU::NOTICE, details: bok
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
            "type" => {
              "type" => "string",
              "description" => "'interactive' will attempt to bind an existing user; 'service' will create a service account and generate API keys",
              "enum" => ["directory", "org", "project"]
            },
            "description" => {
              "type" => "string",
              "description" => "Detailed human-readable description of this role's purpose"
            }
# XXX probably need a flag to distinguish directory roles from project/org/folder ones
          }
          [toplevel_required, schema]
        end

        @@binding_semaphore = Mutex.new
        @@bindings_by_role = {}
        @@bindings_by_entity = {}

        # Retrieve IAM role bindings for all entities throughout our
        # organization, map them in useful ways, and cache the result.
        def self.getAllBindings(credentials = nil, refresh: false)
          my_org = MU::Cloud::Google.getOrg(credentials)
          @@binding_semaphore.synchronize {
            if @@bindings_by_role[my_org.name] and @@bindings_by_entity[my_org.name] and !refresh
              return {
                "by_role" => @@bindings_by_role[my_org.name],
                "by_entity" => @@bindings_by_entity[my_org.name]
              }
            end

            def self.insertBinding(scope, binding)
              @@bindings_by_role[scope] ||= {}
              @@bindings_by_entity[scope] ||= {}
              @@bindings_by_role[scope][binding.role] = {}
              binding.members.each { |member|
                member_type, member_id = member.split(/:/)
                @@bindings_by_role[scope][binding.role][member_type] ||= []
                @@bindings_by_role[scope][binding.role][member_type] << member_id
                @@bindings_by_entity[scope][member_type] ||= {}
                @@bindings_by_entity[scope][member_type][member_id] ||= []
                @@bindings_by_entity[scope][member_type][member_id] << binding.role
              }
            end

            resp = MU::Cloud::Google.resource_manager(credentials: credentials).get_organization_iam_policy(my_org.name)
            resp.bindings.each { |binding|
              insertBinding(my_org.name, binding)
            }

            MU::Cloud::Google::Folder.find(credentials: credentials).keys.each { |folder|
              MU::Cloud::Google::Folder.bindings(folder, credentials: credentials).each { |binding|
                insertBinding(folder, binding)
              }
            }
            MU::Cloud::Google::Habitat.find(credentials: credentials).keys.each { |project|
              MU::Cloud::Google::Habitat.bindings(project, credentials: credentials).each { |binding|
                insertBinding(project, binding)
              }
            }

            {
              "by_role" => @@bindings_by_role,
              "by_entity" => @@bindings_by_entity
            }
          }
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
