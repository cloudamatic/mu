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
#              @config['type'] = "iam"
            else
              puts args[:from_cloud_desc].class.name
              pp @config
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
#            resp = MU::Cloud::Google.iam(credentials: args[:credentials]).list_project_roles
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
            "cloud_id" => @cloud_id
          }

          if cloud_desc.is_system_role
            return nil
          end

          bok["display_name"] = @config['name']
          bok["descripion"] = cloud_desc.role_description if !cloud_desc.role_description.empty?
          bok["name"] = @config['name'].gsub(/[^a-z0-9]/i, '-').downcase

          if cloud_desc.role_privileges
            bok["import"] = []
            cloud_desc.role_privileges.each { |priv|
# XXX is priv.service_id needed to namespace these?
              bok["import"] << priv.privilege_name
            }
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
            "description" => {
              "type" => "string",
              "description" => "Detailed human-readable description of this role's purpose"
            }
# XXX probably need a flag to distinguish directory roles from project/org/folder ones
          }
          [toplevel_required, schema]
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
