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
      # Creates an Google project as configured in {MU::Config::BasketofKittens::habitats}
      class Habitat < MU::Cloud::Habitat
        @deploy = nil
        @config = nil

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::habitats}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          labels = {}

          name_string = @deploy.getResourceName(@config["name"], max_length: 30).downcase

          MU::MommaCat.listStandardTags.each_pair { |name, value|
            if !value.nil?
              labels[name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }

          desc = {
            name: name_string,
            project_id: name_string,
            labels: labels
          }
          if @config['folder'] and @config['folder']['id']
            desc["parent"] = @config['folder']['id']
          end

          project_obj = MU::Cloud::Google.resource_manager(:Project).new(desc)
pp project_obj
          MU.log "Creating project #{@mu_name}", details: project_obj
          resp = MU::Cloud::Google.resource_manager(credentials: @config['credentials']).create_project(project_obj)

          @cloud_id = name_string.downcase
        end

        # Return the cloud descriptor for the Habitat
        def cloud_desc
          MU::Cloud::Google::Habitat.find(cloud_id: @cloud_id).values.first
        end

        # Return the metadata for this project's configuration
        # @return [Hash]
        def notify
          desc = MU.structToHash(MU::Cloud::Google.resource_manager(credentials: credentials).list_projects(
              filter: "name:#{cloud_id}"
            ).projects.first)
          desc["mu_name"] = @mu_name
          desc["cloud_id"] = @cloud_id
          desc
        end

        # Does this resource type exist as a global (cloud-wide) artifact, or
        # is it localized to a region/zone?
        # @return [Boolean]
        def self.isGlobal?
          true
        end

        # Remove all Google projects associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @param region [String]: The cloud provider region
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, credentials: nil, flags: {})
        end

        # Locate an existing project
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param region [String]: The cloud provider region.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching project
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {})
          found = {}
          if cloud_id
            resp = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects(
              filter: "name:#{cloud_id}"
            ).projects.first
            found[resp.name] = resp
          else
            resp = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects().projects
            resp.each { |p|
              found[p.name] = p
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
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::habitats}, bare and unvalidated.
        # @param habitat [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(habitat, configurator)
          ok = true

          if habitat['folder'] and habitat['folder']['name'] and !habitat['folder']['deploy_id']
            habitat["dependencies"] ||= []
            habitat["dependencies"] << {
              "type" => "folder",
              "name" => habitat['folder']['name']
            }
          end

          ok
        end

      end
    end
  end
end
