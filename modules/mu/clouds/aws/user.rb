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
    class AWS
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
          @mu_name ||= if @config['unique']
            @deploy.getResourceName(@config["name"])
          else
            @config['name']
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create

          begin
            resp = MU::Cloud::AWS.iam.get_user(user_name: @mu_name)
            if !@config['use_if_exists']
              raise MuError, "IAM user #{@mu_name} already exists and fail_if_exists is true"
            end

          rescue Aws::IAM::Errors::NoSuchEntity => e
            MU.log "Creating IAM user #{@mu_name}"
            MU::Cloud::AWS.iam.create_user(
              user_name: @mu_name,
              tags: get_tag_params
            )
          end


        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          resp = MU::Cloud::AWS.iam.list_user_tags(user_name: @mu_name)
pp resp
          tag_param = get_tag_params
          if @config['use_if_exists']
            tag_param.reject! { |t|
              resp.tags.map { |x| x.key }.include?(t[:key])
            }
          end

          if tag_param.size > 0
            MU.log "Updating tags on IAM user #{@mu_name}", MU::NOTICE, details: tag_param
            MU::Cloud::AWS.iam.tag_user(user_name: @mu_name, tags: tag_param)
          end
          raise "NAH"
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
          MU.log "IN User.find cloud_id: #{cloud_id}", MU::WARN, details: flags
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
              "description" => "A plain IAM user. If the user already exists, we will operate on that existing user. Otherwise, we will attempt to create a new user."
            },
            "tags" => MU::Config.tags_primitive,
            "optional_tags" => {
              "type" => "boolean",
              "default" => true,
              "description" => "Tag the resource with our optional tags (MU-HANDLE, MU-MASTER-NAME, MU-OWNER)."
            },
            "unique_name" => {
              "type" => "boolean",
              "default" => false,
              "description" => "Instead of creating/updating a user account with
 the exact name specified in the 'name' field, generate a unique-per-deploy Mu-
style long name, like +IAMTESTS-DEV-2018112815-IS-USER-FOO+"
            },
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::users}, bare and unvalidated.
        # @param user [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(user, configurator)
          ok = true

          ok
        end

        private

        def get_tag_params
          @config['tags'] ||= []
          MU::MommaCat.listStandardTags.each_pair { |key, value|
            @config['tags'] << { "key" => key, "value" => value }
          }

          if @config['optional_tags']
            MU::MommaCat.listOptionalTags.each { |key, value|
              @config['tags'] << { "key" => key, "value" => value }
            }
          end

          if @config['use_if_exists']
            @config['tags'] << { "key" => "MU-NO-DELETE", "value" => "true" }
          end

          @config['tags'].map { |t|
            { :key => t["key"], :value => t["value"] }
          }
        end

      end
    end
  end
end
