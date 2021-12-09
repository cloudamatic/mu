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
            @cloud_desc_cache = args[:from_cloud_desc]
            MU::Cloud::Google.admin_directory
            MU::Cloud::Google.iam
            if args[:from_cloud_desc].class == ::Google::Apis::AdminDirectoryV1::User
              @config['type'] = "interactive"
              @cloud_id = args[:from_cloud_desc].primary_email
            elsif args[:from_cloud_desc].class == ::Google::Apis::IamV1::ServiceAccount
              @config['type'] = "service"
              @config['name'] = args[:from_cloud_desc].display_name
              if @config['name'].nil? or @config['name'].empty?
                @config['name'] = args[:from_cloud_desc].name.sub(/.*?\/([^\/@]+)(?:@[^\/]*)?$/, '\1')
              end
              @cloud_id = args[:from_cloud_desc].name
            else
              raise MuError, "Google::User got from_cloud_desc arg of class #{args[:from_cloud_desc].class.name}, but doesn't know what to do with it"
            end
          end

          @mu_name ||= if (@config['unique_name'] or @config['type'] == "service") and !@config['scrub_mu_isms']
            @deploy.getResourceName(@config["name"])
          else
            @config['name']
          end

          if @config['type'] == "interactive" and @config['email']
            @cloud_id ||= @config['email']
          end

        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config['type'] == "service"
            acct_id = @config['scrub_mu_isms'] ? @config['name'] : @deploy.getResourceName(@config["name"], max_length: 30).downcase
            req_obj = MU::Cloud::Google.iam(:CreateServiceAccountRequest).new(
              account_id: acct_id,
              service_account: MU::Cloud::Google.iam(:ServiceAccount).new(
                display_name: @mu_name,
                description: @config['scrub_mu_isms'] ? @config['description'] : @deploy.deploy_id
              )
            )
            if @config['use_if_exists']
              # XXX maybe just set @cloud_id to projects/#{@project_id}/serviceAccounts/#{@mu_name}@#{@project_id}.iam.gserviceaccount.com and see if cloud_desc returns something
              found = MU::Cloud::Google::User.find(project: @project_id, cloud_id: @mu_name)
              if found.size == 1
                @cloud_id = found.keys.first
                MU.log "Service account #{@cloud_id} already existed, using it"
              end
            end

            if !@cloud_id
              MU.log "Creating service account #{@mu_name}"
              resp = MU::Cloud::Google.iam(credentials: @config['credentials']).create_service_account(
                "projects/"+@config['project'],
                req_obj
              )
              @cloud_id = resp.name
            end

            # make sure we've been created before moving on
            begin
              cloud_desc
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/notFound:/)
                sleep 3
                retry
              end
            end
          elsif @config['external']
            @cloud_id = @config['email']
            MU::Cloud.resourceClass("Google", "Role").bindFromConfig("user", @cloud_id, @config['roles'], credentials: @config['credentials'])
          else
            if !@config['email']
              domains = MU::Cloud::Google.admin_directory(credentials: @credentials).list_domains(@customer)
              @config['email'] = @mu_name.gsub(/@.*/, "")+"@"+domains.domains.first.domain_name
            end

            username_obj = MU::Cloud::Google.admin_directory(:UserName).new(
              given_name: (@config['given_name'] || @config['name']),
              family_name: (@config['family_name'] || @deploy.deploy_id),
              full_name: @mu_name
            )

            user_obj = MU::Cloud::Google.admin_directory(:User).new(
              name: username_obj,
              primary_email: @config['email'],
              suspended: @config['suspend'],
              is_admin: @config['admin'],
              password: MU.generatePassword,
              change_password_at_next_login: (@config.has_key?('force_password_change') ? @config['force_password_change'] : true)
            )

            MU.log "Creating user #{@mu_name}", details: user_obj
            resp = MU::Cloud::Google.admin_directory(credentials: @credentials).insert_user(user_obj)
            @cloud_id = resp.primary_email

          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['external']
            MU::Cloud.resourceClass("Google", "Role").bindFromConfig("user", @cloud_id, @config['roles'], credentials: @config['credentials'])
          elsif @config['type'] == "interactive"
            need_update = false
            MU::Cloud.resourceClass("Google", "Role").bindFromConfig("user", @cloud_id, @config['roles'], credentials: @config['credentials'])

            if @config['force_password_change'] and !cloud_desc.change_password_at_next_login
              MU.log "Forcing #{@mu_name} to change their password at next login", MU::NOTICE
              need_update = true
            elsif @config.has_key?("force_password_change") and
                  !@config['force_password_change'] and
                  cloud_desc.change_password_at_next_login
              MU.log "No longer forcing #{@mu_name} to change their password at next login", MU::NOTICE
              need_update = true
            end
            if @config['admin'] != cloud_desc.is_admin
              MU.log "Setting 'is_admin' flag to #{@config['admin'].to_s} for directory user #{@mu_name}", MU::NOTICE
              MU::Cloud::Google.admin_directory(credentials: @credentials).make_user_admin(@cloud_id, MU::Cloud::Google.admin_directory(:UserMakeAdmin).new(status: @config['admin']))
            end

            if @config['suspend'] != cloud_desc.suspended
              need_update = true
            end
            if cloud_desc.name.given_name != (@config['given_name'] || @config['name']) or
               cloud_desc.name.family_name != (@config['family_name'] || @deploy.deploy_id) or
               cloud_desc.primary_email != @config['email']
              need_update = true
            end

            if need_update
              username_obj = MU::Cloud::Google.admin_directory(:UserName).new(
                given_name: (@config['given_name'] || @config['name']),
                family_name: (@config['family_name'] || @deploy.deploy_id),
                full_name: @mu_name
              )
              user_obj = MU::Cloud::Google.admin_directory(:User).new(
                name: username_obj,
                primary_email: @config['email'],
                suspended: @config['suspend'],
                change_password_at_next_login: (@config.has_key?('force_password_change') ? @config['force_password_change'] : true)
              )

              MU.log "Updating directory user #{@mu_name}", MU::NOTICE, details: user_obj

              resp = MU::Cloud::Google.admin_directory(credentials: @credentials).update_user(@cloud_id, user_obj)
              @cloud_id = resp.primary_email
            end

          else
            MU::Cloud.resourceClass("Google", "Role").bindFromConfig("serviceAccount", @cloud_id.gsub(/.*?\/([^\/]+)$/, '\1'), @config['roles'], credentials: @config['credentials'])
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

        @cloud_desc_cache = nil
        # Retrieve the cloud descriptor for this resource.
        # @return [Google::Apis::Core::Hashable]
        def cloud_desc(use_cache: true)
          return @cloud_desc_cache if @cloud_desc_cache and use_cache
          if @config['type'] == "interactive" or !@config['type']
             @config['type'] ||= "interactive"
            if !@config['external']
              @cloud_id ||= @config['email']
              @cloud_desc_cache = MU::Cloud::Google.admin_directory(credentials: @config['credentials']).get_user(@cloud_id)
            else
              return nil
            end
          else
            @config['type'] ||= "service"
            # this often fails even when it succeeded earlier, so try to be
            # resilient on GCP's behalf
            retries = 0
            begin
              @cloud_desc_cache = MU::Cloud::Google.iam(credentials: @config['credentials']).get_project_service_account(@cloud_id)
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/notFound:/) and retries < 10
                sleep 3
                retries += 1
                retry
              end
            end
          end

          @cloud_desc_cache
        end

        # Return the metadata for this user configuration
        # @return [Hash]
        def notify
          description = if !@config['external']
            MU.structToHash(cloud_desc)
          else
            {}
          end
          description.delete(:etag) if description
          description
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
          MU::Cloud::RELEASE
        end

        # Remove all users associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})
          MU::Cloud::Google.getDomains(credentials)
          my_org = MU::Cloud::Google.getOrg(credentials)

          filter = %Q{(labels.mu-id = "#{MU.deploy_id.downcase}")}
          if !ignoremaster and MU.mu_public_ip
            filter += %Q{ AND (labels.mu-master-ip = "#{MU.mu_public_ip.gsub(/\./, "_")}")}
          end
          MU.log "Placeholder: Google User artifacts do not support labels, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: filter

          # We don't have a good way of tagging directory users, so we rely
          # on the known parameter, which is pulled from deployment metadata
          if flags['known'] and my_org
            dir_users = MU::Cloud::Google.admin_directory(credentials: credentials).list_users(customer: MU::Cloud::Google.customerID(credentials)).users
            if dir_users
              dir_users.each { |user|
                if flags['known'].include?(user.primary_email)
                  MU.log "Deleting user #{user.primary_email} from #{my_org.display_name}", details: user
                  if !noop
                    MU::Cloud::Google.admin_directory(credentials: credentials).delete_user(user.id)
                  end
                end
              }

              flags['known'].each { |user_email|
                next if user_email.nil?
                next if !user_email.match(/^[^\/]+@[^\/]+$/)

                MU::Cloud.resourceClass("Google", "Role").removeBindings("user", user_email, credentials: credentials, noop: noop)
              }

            end
          end

          flags["habitat"] ||= MU::Cloud::Google.defaultProject(credentials)
          resp = MU::Cloud::Google.iam(credentials: credentials).list_project_service_accounts(
            "projects/"+flags["habitat"]
          )

          if resp and resp.accounts and MU.deploy_id
            resp.accounts.each { |sa|
              if (sa.description and sa.description == MU.deploy_id) or
                 (sa.display_name and sa.display_name.match(/^#{Regexp.quote(MU.deploy_id)}-/i))
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
          args[:project] ||= args[:habitat]

          found = {}

          if args[:cloud_id] and args[:flags] and
             args[:flags]["skip_provider_owned"] and
             MU::Cloud::Google::User.cannedServiceAcctName?(args[:cloud_id])
            return found
          end

          # If the project id is embedded in the cloud_id, honor it
          if args[:cloud_id]
            if args[:cloud_id].match(/projects\/(.+?)\//)
              args[:project] = Regexp.last_match[1]
            elsif args[:cloud_id].match(/@([^\.]+)\.iam\.gserviceaccount\.com$/)
              args[:project] = Regexp.last_match[1]
            end
          end

          if args[:project]
            # project-local service accounts
            resp = begin
              MU::Cloud::Google.iam(credentials: args[:credentials]).list_project_service_accounts(
                "projects/"+args[:project]
              )
            rescue ::Google::Apis::ClientError
              MU.log "Do not have permissions to retrieve service accounts for project #{args[:project]}, org #{MU::Cloud::Google.getOrg(args[:credentials]).display_name}", MU::WARN
            end

            if resp and resp.accounts
              resp.accounts.each { |sa|
                if args[:flags] and args[:flags]["skip_provider_owned"] and
                   MU::Cloud::Google::User.cannedServiceAcctName?(sa.name)
                  next
                end
                if !args[:cloud_id] or (sa.display_name and sa.display_name == args[:cloud_id]) or (sa.name and sa.name == args[:cloud_id]) or (sa.email and sa.email == args[:cloud_id])
                  found[sa.name] = sa
                end
              }
            end
          else
            if cred_cfg['masquerade_as']
              resp = MU::Cloud::Google.admin_directory(credentials: args[:credentials]).list_users(customer: MU::Cloud::Google.customerID(args[:credentials]), show_deleted: false)
# XXX this ain't exactly performant, do some caching or something
              if resp and resp.users
                resp.users.each { |u|
                  next if args[:cloud_id] and !args[:cloud_id] != u.primary_email
                  found[u.primary_email] = u
                }
              end
            end
          end

          found
        end

        # Try to determine whether the given string looks like a pre-configured
        # GCP service account, as distinct from one we might create or manage
        def self.cannedServiceAcctName?(name)
          return false if !name
          name.match(/\b\d+\-compute@developer\.gserviceaccount\.com$/) or
          name.match(/\bproject-\d+@storage-transfer-service\.iam\.gserviceaccount\.com$/) or
          name.match(/\b\d+@cloudbuild\.gserviceaccount\.com$/) or
          name.match(/\b\d+@cloudservices\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@containerregistry\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@container-analysis\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@compute-system\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@container-engine-robot\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@gc[pf]-admin-robot\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@dataflow-service-producer-prod\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@dataproc-accounts\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@endpoints-portal\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@cloud-filer\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@cloud-redis\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@firebase-rules\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@cloud-tpu\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@sourcerepo-service-accounts\.iam\.gserviceaccount\.com$/) or
          name.match(/\bservice-\d+@gcp-sa-[^\.]+\.iam\.gserviceaccount\.com$/) or
          name.match(/\bp\d+\-\d+@gcp-sa-logging\.iam\.gserviceaccount\.com$/)
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
        def toKitten(**_args)
          if MU::Cloud::Google::User.cannedServiceAcctName?(@cloud_id)
            return nil
          end

          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }

          if cloud_desc.nil?
            MU.log @config['name']+" couldn't fetch its cloud descriptor", MU::WARN, details: @cloud_id
            return nil
          end

          user_roles = MU::Cloud.resourceClass("Google", "Role").getAllBindings(@config['credentials'])["by_entity"]

          if cloud_desc.nil?
            MU.log "FAILED TO FIND CLOUD DESCRIPTOR FOR #{self}", MU::ERR, details: @config
            return nil
          end
          bok['name'] = @config['name']
          bok['cloud_id'] = @cloud_id
          bok['type'] = @config['type']
          bok['type'] ||= "service"

          if bok['type'] == "service"
            bok['name'].gsub!(/@.*/, '')
            if cloud_desc.description and !cloud_desc.description.empty? and
               !cloud_desc.description.match(/^[A-Z0-9_-]+-[A-Z0-9_-]+-\d{10}-[A-Z]{2}$/)
              bok['description'] = cloud_desc.description
            end
            bok['project'] = @project_id
            keys = MU::Cloud::Google.iam(credentials: @config['credentials']).list_project_service_account_keys(@cloud_id)

            if keys and keys.keys and keys.keys.size > 0
              bok['create_api_key'] = true
            end
#            MU.log "service account #{@cloud_id}", MU::NOTICE, details: MU::Cloud::Google.iam(credentials: @config['credentials']).get_project_service_account_iam_policy(cloud_desc.name)
            if user_roles["serviceAccount"] and
               user_roles["serviceAccount"][bok['cloud_id']] and
               user_roles["serviceAccount"][bok['cloud_id']].size > 0
              bok['roles'] = MU::Cloud.resourceClass("Google", "Role").entityBindingsToSchema(user_roles["serviceAccount"][bok['cloud_id']])
            end
          else
            if user_roles["user"] and
               user_roles["user"][bok['cloud_id']] and
               user_roles["user"][bok['cloud_id']].size > 0
              bok['roles'] = MU::Cloud.resourceClass("Google", "Role").entityBindingsToSchema(user_roles["user"][bok['cloud_id']], credentials: @config['credentials'])
            end
            bok['given_name'] = cloud_desc.name.given_name if cloud_desc.name.given_name and !cloud_desc.name.given_name.empty?
            bok['family_name'] = cloud_desc.name.family_name if cloud_desc.name.family_name and !cloud_desc.name.family_name.empty?
            bok['email'] = cloud_desc.primary_email
            bok['suspend'] = cloud_desc.suspended
            bok['admin'] = cloud_desc.is_admin
          end

          bok['use_if_exists'] = true

          bok
       end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "name" => {
              "type" => "string",
              "description" => "If the +type+ of this account is not +service+, this can include an optional @domain component (<tt>foo@example.com</tt>), which is equivalent to the +domain+ configuration option. The following rules apply to +directory+ (non-<tt>service</tt>) accounts only:

If the domain portion is not specified, and we manage exactly one GSuite or Cloud Identity domain, we will attempt to create the user in that domain.

If we do not manage any domains, and none are specified, we will assume <tt>@gmail.com</tt> for the domain and attempt to bind an existing external GMail user to roles under our jurisdiction.

If the domain portion is specified, and our credentials can manage that domain via GSuite or Cloud Identity, we will attempt to create the user in that domain.

If it is a domain we do not manage, we will attempt to bind an existing external user from that domain to roles under our jurisdiction.

If we are binding (rather than creating) a user and no roles are specified, we will default to +roles/viewer+ at the organization scope. If our credentials do not manage an organization, we will grant this role in our default project.

"
            },
            "domain" => {
              "type" => "string",
              "description" => "If creating or binding an +interactive+ user, this is the domain of which the user should be a member. This can instead be embedded in the {name} field: +foo@example.com+."
            },
            "given_name" => {
              "type" => "string",
              "description" => "Optionally set the +given_name+ field of a +directory+ account. Ignored for +service+ accounts."
            },
            "first_name" => {
              "type" => "string",
              "description" => "Alias for +given_name+"
            },
            "family_name" => {
              "type" => "string",
              "description" => "Optionally set the +family_name+ field of a +directory+ account. Ignored for +service+ accounts."
            },
            "last_name" => {
              "type" => "string",
              "description" => "Alias for +family_name+"
            },
            "description" => {
              "type" => "string",
              "description" => "Comment field for service accounts, which we normally use to store the originating deploy's deploy id, since GCP service accounts do not have labels. This field is only honored if +scrub_mu_isms+ is set."
            },
            "email" => {
              "type" => "string",
              "description" => "Canonical email address for a +directory+ user. If not specified, will be set to +name@domain+."
            },
            "external" => {
              "type" => "boolean",
              "description" => "Explicitly flag this user as originating from an external domain. This should always autodetect correctly."
            },
            "admin" => {
              "type" => "boolean",
              "description" => "If the user is +interactive+ and resides in a domain we manage, set their +is_admin+ flag.",
              "default" => false
            },
            "suspend" => {
              "type" => "boolean",
              "description" => "If the user is +interactive+ and resides in a domain we manage, this can be used to lock their account.",
              "default" => false
            },
            "type" => {
              "type" => "string",
              "description" => "'interactive' will either attempt to bind an existing user to a role under our jurisdiction, or create a new directory user, depending on the domain of the user specified and whether we manage any directories; 'service' will create a service account and generate API keys.",
              "enum" => ["interactive", "service"],
              "default" => "interactive"
            },
            "roles" => {
              "type" => "array",
              "description" => "One or more Google IAM roles to associate with this user.",
              "items" => MU::Cloud.resourceClass("Google", "Role").ref_schema
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::users}, bare and unvalidated.
        # @param user [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(user, _configurator)
          ok = true

          my_domains = MU::Cloud::Google.getDomains(user['credentials'])
          my_org = MU::Cloud::Google.getOrg(user['credentials'])

          # Deal with these name alias fields, here for the convenience of your
          # easily confused english-centric type of person
          user['given_name'] ||= user['first_name'] if user['first_name']
          user['family_name'] ||= user['last_name'] if user['last_name']
          user.delete("first_name")
          user.delete("last_name")

          if user['name'].match(/@(.*+)$/)
            domain = Regexp.last_match[1].downcase
            if domain and user['domain'] and domain != user['domain'].downcase
              MU.log "User #{user['name']} had a domain component, but the domain field was also specified (#{user['domain']}) and they don't match."
              ok = false
            end
            user['domain'] = domain
            if user['type'] == "service"
              MU.log "Username #{user['name']} appears to be a directory or external username, cannot use with 'service'", MU::ERR
              ok = false
            else
              user['type'] = "interactive"
              if !my_domains or !my_domains.include?(domain)
                user['external'] = true

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
                  MU.log "External Google user specified with no role binding, will grant 'viewer' in #{my_org ? "organization #{my_org.display_name}" : "project #{user['project']}"}", MU::WARN
                end
              else # this is actually targeting a domain we manage! yay!
              end
            end
          elsif user['type'] != "service"
            if !user['domain']
              if my_domains.size == 1
                user['domain'] = my_domains.first
              elsif my_domains.size > 1
                MU.log "Google interactive User #{user['name']} did not specify a domain, and we have multiple defaults available. Must specify exactly one.", MU::ERR, details: my_domains
                ok = false
              else
                user['domain'] = "gmail.com"
              end
            end
          end

          if user['domain']
            user['email'] ||= user['name'].gsub(/@.*/, "")+"@"+user['domain']
          end

          if user['groups'] and user['groups'].size > 0 and my_org.nil?
            MU.log "Cannot change Google group memberships with credentials that do not manage GSuite or Cloud Identity.\nVisit https://groups.google.com to manage groups.", MU::ERR
            ok = false
          end

          if user['type'] == "service"
            user['project'] ||= MU::Cloud::Google.defaultProject(user['credentials'])
          end

          if user['type'] != "service" and user["create_api_key"]
            MU.log "Only service accounts can have API keys in Google Cloud", MU::ERR
            ok = false
          end

          if user['roles']
            user['roles'].each { |r|
              if r['role'] and r['role']['name'] and
                 (!r['role']['deploy_id'] and !r['role']['id'])
                MU::Config.addDependency(user, r['role']['name'], "role")
              end

              if !r["projects"] and !r["organizations"] and !r["folders"]
                if my_org
                  r["organizations"] = [my_org.name]
                else
                  r["projects"] = [
                    "id" => user["project"]
                  ]
                end
              end
            }
          end

          ok
        end

        # Create and inject a service account on behalf of the parent resource.
        # Return the modified parent configuration hash with references to the
        # new addition.
        # @param parent [Hash]
        # @param configurator [MU::Config]
        # @return [Hash]
        def self.genericServiceAccount(parent, configurator)
          user = {
            "name" => parent['name'],
            "cloud" => "Google",
            "project" => parent["project"],
            "credentials" => parent["credentials"],
            "type" => "service"
          }
          if user["name"].length < 6
            user["name"] += Password.pronounceable(6)
          end
          if parent['roles']
            user['roles'] = parent['roles'].dup
          end
          configurator.insertKitten(user, "users", true)
          parent['service_account'] = MU::Config::Ref.get(
            type: "users",
            cloud: "Google",
            name: user["name"],
            project: user["project"],
            credentials: user["credentials"]
          )
          MU::Config.addDependency(parent, user['name'], "user")

          parent
        end

      end
    end
  end
end
