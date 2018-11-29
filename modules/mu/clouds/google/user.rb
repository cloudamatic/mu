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
#          @mu_name ||= @deploy.getResourceName(@config["name"])
          @mu_name ||= @config["name"]
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          bind_user
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          bind_user
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          {
          }
        end

        # Remove all users associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
        end

        # Locate an existing user group.
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching user group.
        def self.find(cloud_id: nil, region: MU.curRegion, flags: {})
          found = nil
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
            "roles" => {
              "type" => "array",
              "description" => "One or more Google IAM roles to associate with this user.",
              "default" => ["roles/viewer"],
              "items" => {
                "type" => "string",
                "description" => "Name of a Google IAM role to associate. Google Cloud human user accounts (as distinct from service accounts) are not created directly; pre-existing Google accounts are associated with a project by being bound to one or more roles in that project. If no roles are specified, we default to +roles/viewer+, which permits read-only access project-wide."
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
          if !user['name'].match(/@gmail\.com$/i) and $MU_CFG['google']['masquerade_as']
# XXX flesh this check out
            pp MU::Cloud::Google.admin_directory.get_user(user['name'])
          end

# XXX create_api_keys only valid for machine accounts?
          ok
        end

        private

        def bind_user
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

            MU::Cloud::Google.resource_manager.set_project_iam_policy(
              @config['project'],
              req_obj
            )
          end
        end

      end
    end
  end
end
