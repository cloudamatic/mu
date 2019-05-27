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

          parent = MU::Cloud::Google::Folder.resolveParent(@config['parent'], credentials: @config['credentials'])
          if !parent
            MU.log "Unable to resolve parent resource of Google Project #{@config['name']}", MU::ERR, details: @config['parent']
            raise "Unable to resolve parent resource of Google Project #{@config['name']}"
          end

          type, parent_id = parent.split(/\//)
          params[:parent] = MU::Cloud::Google.resource_manager(:ResourceId).new(
            id: parent_id,
            type: type.sub(/s$/, "") # I wish these engineering teams would talk to each other
          )

          project_obj = MU::Cloud::Google.resource_manager(:Project).new(params)

          MU.log "Creating project #{name_string} under #{parent}", details: project_obj
          MU::Cloud::Google.resource_manager(credentials: @config['credentials']).create_project(project_obj)


          found = false
          retries = 0
          begin
            resp = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects
            if resp and resp.projects
              resp.projects.each { |p|
                if p.name == name_string.downcase
                  found = true
                end
              }
            end
            if !found
              if retries > 0 and (retries % 3) == 0
                MU.log "Waiting for Google Cloud project #{name_string} to appear in list_projects results...", MU::NOTICE
              end
              retries += 1
              sleep 15
            end
          end while !found


          @cloud_id = name_string.downcase
          setProjectBilling
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
          setProjectBilling
        end

        # Associate a billing account with this project. If none is specified in
        # our configuration, use the billing account tied the the default
        # project of our credential set.
        def setProjectBilling
          cur_billing = MU::Cloud::Google.billing(credentials: @config['credentials']).get_project_billing_info("projects/"+@cloud_id)

          if !cur_billing or
             cur_billing.billing_account_name != "billingAccounts/"+@config['billing_acct'] or
             !cur_billing.billing_enabled

            billing_obj = MU::Cloud::Google.billing(:ProjectBillingInfo).new(
              billing_account_name: "billingAccounts/"+@config['billing_acct'],
              billing_enabled: true,
              name: "projects/"+@cloud_id+"/billingInfo",
              project_id: @cloud_id
            )
            MU.log "Associating project #{@cloud_id} with billing account #{@config['billing_acct']}"
            MU::Cloud::Google.billing(credentials: credentials).update_project_billing_info(
              "projects/"+@cloud_id,
              billing_obj
            )

          end
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

        # Denote whether this resource implementation is experiment, ready for
        # testing, or ready for production use.
        def self.quality
          MU::Cloud::BETA
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
              if p.labels and p.labels["mu-id"] == MU.deploy_id.downcase and
                 p.lifecycle_state == "ACTIVE"
                MU.log "Deleting project #{p.name}", details: p
                if !noop
                  begin
                    MU::Cloud::Google.resource_manager(credentials: credentials).delete_project(p.name)
                  rescue ::Google::Apis::ClientError => e
                    if e.message.match(/Cannot delete an inactive project/)
                      # this is fine
                    else
                      raise e
                    end
                  end
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
        def self.find(cloud_id: nil, region: MU.curRegion, credentials: nil, flags: {}, tag_key: nil, tag_value: nil)
          found = {}
          if cloud_id
            resp = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects(
              filter: "name:#{cloud_id}"
            )
            found[resp.projects.first.name] = resp.projects.first if resp and resp.projects
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
            "billing_acct" => {
              "type" => "string",
              "description" => "Billing account ID to associate with a newly-created Google Project. If not specified, will attempt to locate a billing account associated with the default project for our credentials."
            }
          }
          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::habitats}, bare and unvalidated.
        # @param habitat [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(habitat, configurator)
          ok = true

          if !MU::Cloud::Google.getOrg(habitat['credentials'])
            MU.log "Cannot manage Google Cloud projects in environments without an organization. See also: https://cloud.google.com/resource-manager/docs/creating-managing-organization", MU::ERR
            ok = false
          end

          if !habitat['billing_acct']
            default_billing = MU::Cloud::Google.billing(credentials: habitat['credentials']).get_project_billing_info("projects/"+MU::Cloud::Google.defaultProject(habitat['credentials']))
            if !default_billing or !default_billing.billing_account_name
              MU.log "Google project #{habitat['name']} does not specify 'billing_acct' and I'm unable to locate a default", MU::ERR
              ok = false
            end
            habitat['billing_acct'] = default_billing.billing_account_name.sub(/^billingAccounts\//, "")
          end

          if habitat['parent'] and habitat['parent']['name'] and !habitat['parent']['deploy_id'] and configurator.haveLitterMate?(habitat['parent']['name'], "folders")
            habitat["dependencies"] ||= []
            habitat["dependencies"] << {
              "type" => "folder",
              "name" => habitat['parent']['name']
            }
          end

          ok
        end

      end
    end
  end
end
