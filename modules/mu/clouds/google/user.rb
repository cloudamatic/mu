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
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::users}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          if @config['type'] == "interactive"
            bind_human_user
          else
            req_obj = MU::Cloud::Google.iam(:CreateServiceAccountRequest).new(
              account_id: @deploy.getResourceName(@config["name"], max_length: 30).downcase,
              service_account: MU::Cloud::Google.iam(:ServiceAccount).new(
                display_name: @mu_name
              )
            )
            MU.log "Creating service account #{@mu_name}"
            MU::Cloud::Google.iam.create_service_account(
              "projects/"+@config['project'],
              req_obj
            )
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          if @config['type'] == "interactive"
            bind_human_user
          else
            if @config['create_api_key']
              resp = MU::Cloud::Google.iam.list_project_service_account_keys(
                cloud_desc.name
              )
              if resp.keys.size == 0
                MU.log "Generating API keys for service account #{@mu_name}"
                resp = MU::Cloud::Google.iam.create_service_account_key(
                  cloud_desc.name
                )
                scratchitem = MU::Master.storeScratchPadSecret("Google Cloud Service Account credentials for #{@mu_name}:\n<pre style='text-align:left;'>#{resp.private_key_data}</pre>")
                MU.log "User #{@mu_name}'s Google Cloud Service Account credentials can be retrieved from: https://#{$MU_CFG['public_address']}/scratchpad/#{scratchitem}", MU::SUMMARY
              end
            end
          end
        end

        # Retrieve the cloud descriptor for this resource.
        def cloud_desc
          if @config['type'] == "interactive"
            return nil
          else
            resp = MU::Cloud::Google.iam.list_project_service_accounts(
              "projects/"+@config["project"]
            )

            if resp and resp.accounts
              resp.accounts.each { |sa|
                if sa.display_name and sa.display_name == @mu_name
                  return sa
                end
              }
            end
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

        # Remove all users associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
          flags["project"] ||= MU::Cloud::Google.defaultProject
          resp = MU::Cloud::Google.iam.list_project_service_accounts(
            "projects/"+flags["project"]
          )

          if resp and resp.accounts and MU.deploy_id
            resp.accounts.each { |sa|
              if sa.display_name and sa.display_name.match(/^#{Regexp.quote(MU.deploy_id)}-/i)
                begin
                  MU.log "Deleting service account #{sa.name}", details: sa
                  if !noop
                    MU::Cloud::Google.iam.delete_project_service_account(sa.name)
                  end
                rescue ::Google::Apis::ClientError => e
                  raise e if !e.message.match(/^notFound: /)
                end
              end
            }
          end
        end

        # Locate an existing user.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching user group.
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {})
          found = nil
          resp = MU::Cloud::Google.iam.list_project_service_accounts(
            "projects/"+flags["project"]
          )

          if resp and resp.accounts
            resp.accounts.each { |sa|
              if sa.display_name and sa.display_name == cloud_id
                found ||= {}
                found[cloud_id] = sa
              end
            }
          end

          found
        end

        # Cloud-specific configuration properties.
        # @param config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(config)
          toplevel_required = []
          schema = {
            "name" => {
              "type" => "string",
              "description" => "This must be the email address of an existing Google user account (+foo@gmail.com+), or of a federated GSuite or Cloud Identity domain account from your organization."
            },
            "type" => {
              "type" => "string",
              "description" => "'interactive' will attempt to bind an existing user; 'service' will create a service account and generate API keys"
            },
            "roles" => {
              "type" => "array",
              "description" => "One or more Google IAM roles to associate with this user.",
              "default" => ["roles/viewer"],
              "items" => {
                "type" => "string",
                "description" => "One or more Google IAM roles to associate with this user. Google Cloud human user accounts (as distinct from service accounts) are not created directly; pre-existing Google accounts are associated with a project by being bound to one or more roles in that project. If no roles are specified, we default to +roles/viewer+, which permits read-only access project-wide."
              }
            },
            "project" => {
              "type" => "string",
              "description" => "The project into which to deploy resources"
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

          # admin_directory only works in a GSuite environment
          if !user['name'].match(/@/i) and $MU_CFG['google']['masquerade_as']
            # XXX flesh this check out, need to test with a GSuite site
            pp MU::Cloud::Google.admin_directory.get_user(user['name'])
          end

          if user['groups'] and user['groups'].size > 0 and
             !$MU_CFG['google']['masquerade_as']
            MU.log "Cannot change Google group memberships in non-GSuite environments.\nVisit https://groups.google.com to manage groups.", MU::ERR
            ok = false
          end

          if user['type'] != "service" and user["create_api_key"]
            MU.log "Only service accounts can have API keys in Google Cloud", MU::ERR
            ok = false
          end

          ok
        end

        private

        def bind_human_user
          bindings = []
          ext_policy = MU::Cloud::Google.resource_manager.get_project_iam_policy(
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
              MU::Cloud::Google.resource_manager.set_project_iam_policy(
                @config['project'],
                req_obj
              )
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/does not exist/i) and !$MU_CFG['google']['masquerade_as']
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
