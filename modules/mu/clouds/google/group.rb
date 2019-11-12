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
    class Google
      # A group as configured in {MU::Config::BasketofKittens::groups}
      class Group < MU::Cloud::Group

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if !@config['external']
            if !@config['email']
              domains = MU::Cloud::Google.admin_directory(credentials: @credentials).list_domains(@customer)
              @config['email'] = @mu_name.downcase+"@"+domains.domains.first.domain_name
            end
            group_obj = MU::Cloud::Google.admin_directory(:Group).new(
              name: @mu_name,
              email: @config['email'],
              description: @deploy.deploy_id
            )

            MU.log "Creating group #{@mu_name}", details: group_obj

            resp = MU::Cloud::Google.admin_directory(credentials: @credentials).insert_group(group_obj)
            @cloud_id = resp.email

            MU::Cloud::Google::Role.bindFromConfig("group", @cloud_id, @config['roles'], credentials: @config['credentials'])
          else
            @cloud_id = @config['name'].sub(/@.*/, "")+"@"+@config['domain']
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          MU::Cloud::Google::Role.bindFromConfig("group", @cloud_id, @config['roles'], credentials: @config['credentials'], debug: true)

          if @config['members']
            resolved_desired = []
            @config['members'].each { |m|
              sibling_user = @deploy.findLitterMate(name: m, type: "users")
              usermail = if sibling_user
                sibling_user.cloud_id
              elsif !m.match(/@/)
                domains = MU::Cloud::Google.admin_directory(credentials: @credentials).list_domains(@customer)
                m+"@"+domains.domains.first.domain_name
              else
                m
              end
              resolved_desired << usermail
              next if members.include?(usermail)
              MU.log "Adding user #{usermail} to group #{@mu_name}"
              MU::Cloud::Google.admin_directory(credentials: @credentials).insert_member(
                @cloud_id,
                MU::Cloud::Google.admin_directory(:Member).new(
                  email: usermail
                )
              )
            }

            deletia = members - resolved_desired
            deletia.each { |m|
              MU.log "Removing user #{m} from group #{@mu_name}", MU::NOTICE
              MU::Cloud::Google.admin_directory(credentials: @credentials).delete_member(@cloud_id, m)
            }

            # Theoretically there can be a delay
            begin
              if members.sort != resolved_desired.sort
                sleep 3
              end
            end while members.sort != resolved_desired.sort
          end

        end

        # Retrieve a list of users (by cloud id) of this group
        def members
          resp = MU::Cloud::Google.admin_directory(credentials: @credentials).list_members(@cloud_id)
          members = []
          if resp and resp.members
            members = resp.members.map { |m| m.email }
# XXX reject status != "ACTIVE" ?
          end
          members
        end

        # Return the metadata for this group configuration
        # @return [Hash]
        def notify
          if !@config['external']
            base = MU.structToHash(cloud_desc)
          end
          base ||= {}

          base
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
          [nil]
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::BETA
        end

        # Remove all groups associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          my_domains = MU::Cloud::Google.getDomains(credentials)
          my_org = MU::Cloud::Google.getOrg(credentials)

          if my_org
            groups = MU::Cloud::Google.admin_directory(credentials: credentials).list_groups(customer: MU::Cloud::Google.customerID(credentials)).groups
            if groups
              groups.each { |group|
                if group.description == MU.deploy_id
                  MU.log "Deleting group #{group.name} from #{my_org.display_name}", details: group
                  if !noop
                    MU::Cloud::Google.admin_directory(credentials: credentials).delete_group(group.id)
                  end
                end
              }
            end
          end

          if flags['known']
            flags['known'].each { |group|
              MU::Cloud::Google::Role.removeBindings("group", group, credentials: credentials, noop: noop)
            }
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
          found = {}

          # The API treats the email address field as its main identifier, so
          # we'll go ahead and respect that.
          if args[:cloud_id]
            begin
              resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).get_group(args[:cloud_id])
              found[resp.email] = resp if resp
            rescue ::Google::Apis::ClientError => e
              raise e if !e.message.match(/forbidden: /)
            end
          else
            resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).list_groups(customer: MU::Cloud::Google.customerID(args[:credentials]))
            if resp and resp.groups
              found = Hash[resp.groups.map { |g| [g.email, g] }]
            end
          end
# XXX what about Google Groups groups and other external groups? Where do we fish for those? Do we even need to?
          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil, habitats: nil)

          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }

          bok['name'] = cloud_desc.name
          bok['cloud_id'] = cloud_desc.email
          bok['members'] = members
          bok['members'].each { |m|
            m = MU::Config::Ref.get(
              id: m,
              cloud: "Google",
              credentials: @config['credentials'],
              type: "users"
            )
          }
          group_roles = MU::Cloud::Google::Role.getAllBindings(@config['credentials'])["by_entity"]
          if group_roles["group"] and group_roles["group"][bok['cloud_id']] and
             group_roles["group"][bok['cloud_id']].size > 0
            bok['roles'] = MU::Cloud::Google::Role.entityBindingsToSchema(group_roles["group"][bok['cloud_id']], credentials: @config['credentials'])
          end

          bok
       end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "name" => {
              "type" => "string",
              "description" => "This can include an optional @domain component (<tt>foo@example.com</tt>).

If the domain portion is not specified, and we manage exactly one GSuite or Cloud Identity domain, we will attempt to create the group in that domain.

If we do not manage any domains, and none are specified, we will assume <tt>@googlegroups.com</tt> for the domain and attempt to bind an existing external Google Group to roles under our jurisdiction.

If the domain portion is specified, and our credentials can manage that domain via GSuite or Cloud Identity, we will attempt to create the group in that domain.

If it is a domain we do not manage, we will attempt to bind an existing external group from that domain to roles under our jurisdiction.

If we are binding (rather than creating) a group and no roles are specified, we will default to +roles/viewer+ at the organization scope. If our credentials do not manage an organization, we will grant this role in our default project.

"
            },
            "domain" => {
              "type" => "string",
              "description" => "The domain from which the group originates or in which it should be created. This can instead be embedded in the {name} field: +foo@example.com+."
            },
            "external" => {
              "type" => "boolean",
              "description" => "Explicitly flag this group as originating from an external domain. This should always autodetect correctly."
            },

            "roles" => {
              "type" => "array",
              "items" => MU::Cloud::Google::Role.ref_schema
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::groups}, bare and unvalidated.
        # @param group [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(group, configurator)
          ok = true

          my_domains = MU::Cloud::Google.getDomains(group['credentials'])
          my_org = MU::Cloud::Google.getOrg(group['credentials'])

          if group['name'].match(/@(.*+)$/)
            domain = Regexp.last_match[1].downcase
            if domain and group['domain'] and domain != group['domain'].downcase
              MU.log "Group #{group['name']} had a domain component, but the domain field was also specified (#{group['domain']}) and they don't match."
              ok = false
            end
            group['domain'] = domain

            if !my_domains or !my_domains.include?(domain)
              group['external'] = true

              if !["googlegroups.com", "google.com"].include?(domain)
                MU.log "#{group['name']} appears to be a member of a domain that our credentials (#{group['credentials']}) do not manage; attempts to grant access for this group may fail!", MU::WARN
              end

              if !group['roles'] or group['roles'].empty?
                group['roles'] = [
                  {
                    "role" => {
                      "id" => "roles/viewer"
                    }
                  }
                ]
                if my_org
                  group['roles'][0]["organizations"] = [my_org.name]
                else
                  group['roles'][0]["projects"] = {
                    "id" => group["project"]
                  }
                end
                MU.log "External Google group specified with no role binding, will grant 'viewer' in #{my_org ? "organization #{my_org.display_name}" : "project #{group['project']}"}", MU::WARN
              end
            end
          else
            if !group['domain']
              if my_domains.size == 1
                group['domain'] = my_domains.first
              elsif my_domains.size > 1
                MU.log "Google interactive User #{group['name']} did not specify a domain, and we have multiple defaults available. Must specify exactly one.", MU::ERR, details: my_domains
                ok = false
              else
                group['domain'] = "googlegroups.com"
              end
            end
          end


          credcfg = MU::Cloud::Google.credConfig(group['credentials'])

          if group['external'] and group['members']
            MU.log "Cannot manage memberships for external group #{group['name']}", MU::ERR
            if group['domain'] == "googlegroups.com"
              MU.log "Visit https://groups.google.com to manage Google Groups.", MU::ERR
            end
            ok = false
          end

          if group['members']
            group['members'].each { |m|
              if configurator.haveLitterMate?(m, "users")
                group['dependencies'] ||= []
                group['dependencies'] << {
                  "name" => m,
                  "type" => "user"
                }
              end
            }
          end

          if group['roles']
            group['roles'].each { |r|
              if r['role'] and r['role']['name'] and
                 (!r['role']['deploy_id'] and !r['role']['id'])
                group['dependencies'] ||= []
                group['dependencies'] << {
                  "type" => "role",
                  "name" => r['role']['name']
                }
              end
            }
          end

          ok
        end

        private

      end
    end
  end
end
