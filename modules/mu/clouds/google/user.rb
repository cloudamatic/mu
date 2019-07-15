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
      # A user as configured in {MU::Config::BasketofKittens::users}
      class User < MU::Cloud::User

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like +@vpc+, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super

          # If we're being reverse-engineered from a cloud descriptor, use that
          # to determine what sort of account we are.
          if args[:from_cloud_desc]
            if args[:from_cloud_desc].class == ::Google::Apis::AdminDirectoryV1::User
              @config['type'] = "interactive"
            elsif args[:from_cloud_desc].class == ::Google::Apis::IamV1::ServiceAccount
              @config['type'] = "service"
              @config['name'] = args[:from_cloud_desc].display_name
              if @config['name'].nil? or @config['name'].empty?
                @config['name'] = args[:from_cloud_desc].name.sub(/.*?\/([^\/@]+)(?:@[^\/]*)?$/, '\1')
              end
              @cloud_id = args[:from_cloud_desc].name
            else
              puts args[:from_cloud_desc].class.name
              pp @config
            end
          end

          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config['type'] == "interactive"
# XXX bind_external_user is really some logic that belongs in Role; what goes here
# is logic to create GSuite or CLoud Identity accounts, assuming adequate privileges.
#            bind_external_user
# XXX all of the below only applicable for masqueraded read-write credentials with GSuite or Cloud Identity
            if !@config['email']
              domains = MU::Cloud::Google.admin_directory(credentials: @credentials).list_domains(MU::Cloud::Google.customerID(@credentials))
              @config['email'] = @config['name'].gsub(/@.*/, "")+"@"+domains.domains.first.domain_name
            end

            username_obj = MU::Cloud::Google.admin_directory(:UserName).new(
              given_name: @config['name'],              
              family_name: @deploy.deploy_id,
              full_name: @mu_name
            )

            user_obj = MU::Cloud::Google.admin_directory(:User).new(
              name: username_obj,
              primary_email: @config['email'],
              change_password_at_next_login: true,
              password: MU.generateWindowsPassword
            )

            MU.log "Creating user #{@mu_name}", details: user_obj
pp user_obj
            resp = MU::Cloud::Google.admin_directory(credentials: @credentials).insert_user(user_obj)
            pp resp
            @cloud_id = resp.primary_email
          else
            req_obj = MU::Cloud::Google.iam(:CreateServiceAccountRequest).new(
              account_id: @deploy.getResourceName(@config["name"], max_length: 30).downcase,
              service_account: MU::Cloud::Google.iam(:ServiceAccount).new(
                display_name: @mu_name
              )
            )
            MU.log "Creating service account #{@mu_name}"
            MU::Cloud::Google.iam(credentials: @config['credentials']).create_service_account(
              "projects/"+@config['project'],
              req_obj
            )
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['type'] == "interactive"
#            bind_external_user
          else
            if @config['create_api_key']
              resp = MU::Cloud::Google.iam(credentials: @config['credentials']).list_project_service_account_keys(
                cloud_desc.name
              )
              if resp.keys.size == 0
                MU.log "Generating API keys for service account #{@mu_name}"
                resp = MU::Cloud::Google.iam(credentials: @config['credentials']).create_service_account_key(
                  cloud_desc.name
                )
                scratchitem = MU::Master.storeScratchPadSecret("Google Cloud Service Account credentials for #{@mu_name}:\n<pre style='text-align:left;'>#{resp.private_key_data}</pre>")
                MU.log "User #{@mu_name}'s Google Cloud Service Account credentials can be retrieved from: https://#{$MU_CFG['public_address']}/scratchpad/#{scratchitem}", MU::SUMMARY
              end
            end
          end
        end

        # Retrieve the cloud descriptor for this resource.
        # @return [Google::Apis::Core::Hashable]
        def cloud_desc
          if @config['type'] == "interactive" or
             !@config['type'] and !@project_id
            @config['type'] ||= "interactive"
            return MU::Cloud::Google.admin_directory(credentials: @config['credentials']).get_user(@cloud_id)
          else
            @config['type'] ||= "service"
            resp = MU::Cloud::Google.iam(credentials: @config['credentials']).list_project_service_accounts(
              "projects/"+@project_id
            )

            if resp and resp.accounts
              resp.accounts.each { |sa|
                if (sa.display_name and sa.display_name == @mu_name) or (sa.name and sa.name == @cloud_id)
                  return sa
                end
              }
            end
          end
          nil
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
          true
        end

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::ALPHA
        end

        # Remove all users associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
          resp = MU::Cloud::Google.iam(credentials: credentials).list_project_service_accounts(
            "projects/"+flags["project"]
          )

          if resp and resp.accounts and MU.deploy_id
            resp.accounts.each { |sa|
              if sa.display_name and sa.display_name.match(/^#{Regexp.quote(MU.deploy_id)}-/i)
                begin
                  MU.log "Deleting service account #{sa.name}", details: sa
                  if !noop
                    MU::Cloud::Google.iam(credentials: credentials).delete_project_service_account(sa.name)
                  end
                rescue ::Google::Apis::ClientError => e
                  raise e if !e.message.match(/^notFound: /)
                end
              end
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
          cred_cfg = MU::Cloud::Google.credConfig(args[:credentials])

          found = {}

          if args[:project]
            # project-local service accounts
            resp = MU::Cloud::Google.iam(credentials: args[:credentials]).list_project_service_accounts(
              "projects/"+args[:project]
            )

            if resp and resp.accounts
              resp.accounts.each { |sa|
                if !args[:cloud_id] or (sa.display_name and sa.display_name == args[:cloud_id]) or (sa.name and sa.name == args[:cloud_id])
                  found[sa.name] = sa
                end
              }
            end
          else
            if cred_cfg['masquerade_as']
              resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).list_users(customer: MU::Cloud::Google.customerID(args[:credentials]), show_deleted: false)
              if resp and resp.users
                resp.users.each { |u|
                  found[u.primary_email] = u
                }
              end
            end
          end

          found
        end

        # We can either refer to a service account, which is scoped to a project
        # (a +Habitat+ in Mu parlance), or a "real" user, which comes from
        # an external directory like GMail, GSuite, or Cloud Identity.
        def self.canLiveIn
          [:Habitat, nil]
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }

          # TODO fill in other stock service accounts which we should ignore
          if ["Compute Engine default service account",
              "App Engine default service account"].include?(@config['name'])
            return nil
          end

          user_roles = MU::Cloud::Google::Role.getAllBindings(@config['credentials'])["by_entity"]

          if cloud_desc.nil?
            MU.log "FAILED TO FIND CLOUD DESCRIPTOR FOR #{self}", MU::ERR, details: @config
            return nil
          end

          bok['name'] = @config['name']
          bok['cloud_id'] = @cloud_id
          bok['type'] = @config['type']
          bok['type'] ||= "service"
          if bok['type'] == "service"
            bok['project'] = @project_id
            keys = MU::Cloud::Google.iam(credentials: @config['credentials']).list_project_service_account_keys(@cloud_id)

            if keys and keys.keys and keys.keys.size > 0
              bok['create_api_key'] = true
            end
#            MU.log "service account #{@cloud_id}", MU::NOTICE, details: MU::Cloud::Google.iam(credentials: @config['credentials']).get_project_service_account_iam_policy(cloud_desc.name)
            if user_roles["serviceAccount"] and
               user_roles["serviceAccount"][bok['cloud_id']] and
               user_roles["serviceAccount"][bok['cloud_id']].size > 0
              bok['roles'] = MU::Cloud::Google::Role.entityBindingsToSchema(user_roles["serviceAccount"][bok['cloud_id']])
            end
          else
            if user_roles["user"] and
               user_roles["user"][bok['cloud_id']] and
               user_roles["user"][bok['cloud_id']].size > 0
              bok['roles'] = MU::Cloud::Google::Role.entityBindingsToSchema(user_roles["user"][bok['cloud_id']], credentials: @config['credentials'])
            end
          end

          bok['use_if_exists'] = true # don't try to step on existing accounts with the same names

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
              "description" => "If the +type+ of this account is not +service+, this can include an optional @domain component (<tt>foo@example.com</tt>). The following rules apply to +directory+ (non-<tt>service</tt>) accounts only:

If the domain portion is not specified, and we manage exactly one GSuite or Cloud Identity domain, we will attempt to create the user in that domain.

If we do not manage any domains, and none are specified, we will assume <tt>@gmail.com</tt> for the domain and attempt to bind an existing external GMail user to roles under our jurisdiction.

If the domain portion is specified, and our credentials can manage that domain via GSuite or Cloud Identity, we will attempt to create the user in that domain.

If it is a domain we do not manage, we will attempt to bind an existing external user from that domain to roles under our jurisdiction.

If we are binding (rather than creating) a user and no roles are specified, we will default to +roles/viewer+ at the organization scope. If our credentials do not manage an organization, we will grant this role in our default project.

"
            },
            "type" => {
              "type" => "string",
              "description" => "'interactive' will either attempt to bind an existing user to a role under our jurisdiction, or create a new directory user, depending on the domain of the user specified and whether we manage any directories; 'service' will create a service account and generate API keys.",
              "enum" => ["interactive", "service"]
            },
            "roles" => {
              "type" => "array",
              "description" => "One or more Google IAM roles to associate with this user.",
              "items" => MU::Cloud::Google::Role.ref_schema
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

          my_domains = MU::Cloud::Google.getDomains(user['credentials'])
          my_org = MU::Cloud::Google.getOrg(user['credentials'])

          if user['name'].match(/@(.*+)$/)
            domain = Regexp.last_match[1].downcase
            if user['type'] == "service"
              MU.log "Username #{user['name']} appears to be a directory or external username, cannot use with 'service'", MU::ERR
              ok = false
            else
              user['type'] = "interactive"
              if !my_domains or !my_domains.include?(domain)
                user['project'] ||= MU::Cloud::Google.defaultProject(user['credentials'])

                if !["gmail.com", "google.com"].include?(domain)
                  MU.log "#{user['name']} appears to be a member of a domain that our credentials (#{user['credentials']}) do not manage; attempts to grant access for this user may fail!", MU::WARN
                end

                if !user['roles'] or user['roles'].empty?
                  user['roles'] = [
                    {
                      "role" => {
                        "id" => "roles/viewer"
                      }
                    }
                  ]
                  if my_org
                    user['roles'][0]["organizations"] = [my_org.name]
                  else
                    user['roles'][0]["projects"] = {
                      "id" => user["project"]
                    }
                  end
                  MU.log "External Google user specified with no role binding, will grant 'viewer' in #{my_org ? "organization #{my_org.display_name}" : "project #{user['project']}"}", MU::WARN
                end
              else # this is actually targeting a domain we manage! yay!
              end
            end
          end

          if MU::Cloud::Google.credConfig(user['credentials'])['masquerade_as'] and user['type'] != "service"
            # XXX flesh this check out, need to test with a GSuite site
            # what exactly do we need to check though? write privs? existence?
          end

          if user['groups'] and user['groups'].size > 0 and my_org.nil?
            MU.log "Cannot change Google group memberships with credentials that do not manage GSuite or Cloud Identity.\nVisit https://groups.google.com to manage groups.", MU::ERR
            ok = false
          end

          if user['type'] != "service" and user["create_api_key"]
            MU.log "Only service accounts can have API keys in Google Cloud", MU::ERR
            ok = false
          end

          ok
        end

        private

        def bind_external_user
          bindings = []
          ext_policy = MU::Cloud::Google.resource_manager(credentials: @config['credentials']).get_project_iam_policy(
            @config['project']
          )

          change_needed = false
          @config['roles'].each { |role|
            seen = false
            ext_policy.bindings.each { |b|
              if b.role == role
                seen = true
                if !b.members.include?("user:"+@config['name'])
                  change_needed = true
                  b.members << "user:"+@config['name']
                end
              end
            }
            if !seen
              ext_policy.bindings << MU::Cloud::Google.resource_manager(:Binding).new(
                role: role,
                members: ["user:"+@config['name']]
              )
              change_needed = true
            end
          }

          if change_needed
            req_obj = MU::Cloud::Google.resource_manager(:SetIamPolicyRequest).new(
              policy: ext_policy
            )
            MU.log "Adding #{@config['name']} to Google Cloud project #{@config['project']}", details: @config['roles']

            begin
              MU::Cloud::Google.resource_manager(credentials: @config['credentials']).set_project_iam_policy(
                @config['project'],
                req_obj
              )
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/does not exist/i) and !MU::Cloud::Google.credConfig(@config['credentials'])['masquerade_as']
                raise MuError, "User #{@config['name']} does not exist, and we cannot create Google user in non-GSuite environments.\nVisit https://accounts.google.com to create new accounts."
              end
              raise e
            end
          end
        end

      end
    end
  end
end
