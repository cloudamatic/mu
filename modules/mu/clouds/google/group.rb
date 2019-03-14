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
        @deploy = nil
        @config = nil
        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::groups}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          bind_group
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          bind_group
        end

        # Return the metadata for this group configuration
        # @return [Hash]
        def notify
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

        # Remove all groups associated with the currently loaded deployment.
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
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {}, tag_key: nil, tag_value: nil)
          flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
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
              "description" => "This must be the email address of an existing Google Group (+foo@googlegroups.com+), or of a federated GSuite or Cloud Identity domain group from your organization."
            },
            "roles" => {
              "type" => "array",
              "description" => "One or more Google IAM roles to associate with this group.",
              "default" => ["roles/viewer"],
              "items" => {
                "type" => "string",
                "description" => "One or more Google IAM roles to associate with this group. Google Cloud groups are not created directly; pre-existing Google Groups are associated with a project by being bound to one or more roles in that project. If no roles are specified, we default to +roles/viewer+, which permits read-only access project-wide."
              }
            },
            "project" => {
              "type" => "string",
              "description" => "The project into which to deploy resources"
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
          if group['members'] and group['members'].size > 0 and
             !$MU_CFG['google']['masquerade_as']
            MU.log "Cannot change Google group memberships in non-GSuite environments.\nVisit https://groups.google.com to manage groups.", MU::ERR
            ok = false
          end

          ok
        end

        private

        def bind_group
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
                  b.members << "group:"+@config['name']
                end
              end
            }
            if !seen
              ext_policy.bindings << MU::Cloud::Google.resource_manager(:Binding).new(
                role: role,
                members: ["group:"+@config['name']]
              )
              change_needed = true
            end
          }

          if change_needed
            req_obj = MU::Cloud::Google.resource_manager(:SetIamPolicyRequest).new(
              policy: ext_policy
            )
            MU.log "Adding group #{@config['name']} to Google Cloud project #{@config['project']}", details: @config['roles']

            begin
              MU::Cloud::Google.resource_manager(credentials: @config['credentials']).set_project_iam_policy(
                @config['project'],
                req_obj
              )
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/does not exist/i) and !MU::Cloud::Google.credConfig(@config['credentials'])['masquerade_as']
                raise MuError, "Group #{@config['name']} does not exist, and we cannot create Google groups in non-GSuite environments.\nVisit https://groups.google.com to manage groups."
              end
              raise e
            end
          end
        end

      end
    end
  end
end
