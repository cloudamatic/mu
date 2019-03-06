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

          if !mu_name.nil?
            @mu_name = mu_name
          elsif @config['scrub_mu_isms']
            @mu_name = @config['name']
          else
            @mu_name = @deploy.getResourceName(@config['name'])
          end
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
          labels = {}

          name_string = if @config['scrub_mu_isms']
            @config["name"]
          else
            @deploy.getResourceName(@config["name"], max_length: 30).downcase
          end

          params = {
            name: name_string,
            project_id: name_string,
          }

          MU::MommaCat.listStandardTags.each_pair { |name, value|
            if !value.nil?
              labels[name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }
          
          if !@config['scrub_mu_isms']
            params[:labels] = labels
          end

# XXX sibling lookup of folders
# XXX default to root of org
          if @config['folder'] and @config['folder']['id']
            params[:parent] = MU::Cloud::Google.resource_manager(:ResourceId).new(
              id: @config['folder']['id'],
              type: "folder"
            )
          end

          project_obj = MU::Cloud::Google.resource_manager(:Project).new(params)

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
          MU.structToHash(MU::Cloud::Google.resource_manager(credentials: @config['credentials']).get_project(@cloud_id))
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
          resp = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects
          if resp and resp.projects
            resp.projects.each { |p|
              if p.labels and p.labels["mu-id"] == MU.deploy_id.downcase
                MU.log "Deleting project #{p.name}", details: p
                if !noop
                  MU::Cloud::Google.resource_manager(credentials: credentials).delete_project(p.name)
                end
              end
            }
          end
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
