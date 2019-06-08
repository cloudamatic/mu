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
        attr_reader :habitat_id # misnomer- it's really a parent folder, which may or may not exist
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :url

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::habitats}
        def initialize(mommacat: nil, kitten_cfg: nil, mu_name: nil, cloud_id: nil)
          @deploy = mommacat
          @config = MU::Config.manxify(kitten_cfg)
          @cloud_id ||= cloud_id
          cloud_desc if @cloud_id # XXX why don't I have this on regroom?
          if !@cloud_id and cloud_desc and cloud_desc.project_id
            @cloud_id = cloud_desc.project_id
          end

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
            @deploy.getResourceName(@config["name"], max_length: 30)
          end
          display_name = @config['display_name'] || name_string.gsub(/[^a-z0-9\-'"\s!]/i, "-")

          params = {
            name: display_name,
            project_id: name_string.downcase.gsub(/[^0-9a-z\-]/, "-")
          }

          MU::MommaCat.listStandardTags.each_pair { |name, value|
            if !value.nil?
              labels[name.downcase] = value.downcase.gsub(/[^a-z0-9\-\_]/i, "_")
            end
          }
          
          if !@config['scrub_mu_isms']
            params[:labels] = labels
          end

          if @config['parent']['name'] and !@config['parent']['id']
            @config['parent']['deploy_id'] = @deploy.deploy_id
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

          MU.log "Creating project #{params[:project_id]} (#{params[:name]}) under #{parent}", details: project_obj

          begin
            MU::Cloud::Google.resource_manager(credentials: @config['credentials']).create_project(project_obj)
          rescue ::Google::Apis::ClientError => e
            MU.log "Got #{e.message} attempting to create #{params[:project_id]}", MU::ERR, details: project_obj
          end


          found = false
          retries = 0
          begin
# can... can we filter this?
            resp = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects(filter: "id:#{name_string.downcase.gsub(/[^0-9a-z\-]/, "-")}")
            if resp and resp.projects
              resp.projects.each { |p|
                if p.project_id ==  name_string.downcase.gsub(/[^0-9a-z\-]/, "-")
                  found = true
                end
              }
            end
            if !found
              if retries > 30
                raise MuError, "Project #{name_string} never showed up in list_projects after I created it!"
              end
              if retries > 0 and (retries % 3) == 0
                MU.log "Waiting for Google Cloud project #{name_string} to appear in list_projects results...", MU::NOTICE
              end
              retries += 1
              sleep 15
            end
          end while !found


          @cloud_id = params[:project_id]
          @habitat_id = parent_id
          setProjectBilling
          MU.log "Project #{params[:project_id]} (#{params[:name]}) created"
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
            begin
              MU::Cloud::Google.billing(credentials: credentials).update_project_billing_info(
                "projects/"+@cloud_id,
                billing_obj
              )
            rescue ::Google::Apis::ClientError => e
              MU.log "Error setting billing for #{@cloud_id}: "+e.message, MU::ERR, details: billing_obj
            end

          end
        end

        # Return the cloud descriptor for the Habitat
        def cloud_desc
          @cached_cloud_desc ||= MU::Cloud::Google::Habitat.find(cloud_id: @cloud_id).values.first
          @habitat_id ||= @cached_cloud_desc.parent.id if @cached_cloud_desc
          @cached_cloud_desc
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

        # Check whether is in the +ACTIVE+ state and has billing enabled.
        # @param project_id [String]
        # @return [Boolean]
        def self.isLive?(project_id, credentials = nil)
          project = MU::Cloud::Google::Habitat.find(cloud_id: project_id).values.first
          return false if project.nil? or project.lifecycle_state != "ACTIVE"

          billing = MU::Cloud::Google.billing(credentials: credentials).get_project_billing_info("projects/"+project_id)
          if !billing or !billing.billing_account_name or
             billing.billing_account_name.empty?
            return false
          end

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
              if p.labels and p.labels["mu-id"] == MU.deploy_id.downcase and
                 p.lifecycle_state == "ACTIVE"
                MU.log "Deleting project #{p.project_id} (#{p.name})", details: p
                if !noop
                  begin
                    MU::Cloud::Google.resource_manager(credentials: credentials).delete_project(p.project_id)
                  rescue ::Google::Apis::ClientError => e
                    if e.message.match(/Cannot delete an inactive project/)
                      # this is fine
                    else
                      MU.log "Got #{e.message} trying to delete project #{p.project_id} (#{p.name})", MU::ERR
                      next
                    end
                  end
                end
              end
            }
          end
        end

        @@list_projects_cache = nil

        # Locate an existing project
        # @return [Hash<OpenStruct>]: The cloud provider's complete descriptions of matching project
        def self.find(**args)
#MU.log "habitat.find called by #{caller[0]}", MU::WARN, details: args
          found = {}

          args[:cloud_id] ||= args[:project]
# XXX we probably want to cache this
# XXX but why are we being called over and over?

          if args[:cloud_id]
            resp = MU::Cloud::Google.resource_manager(credentials: args[:credentials]).list_projects(
              filter: "id:#{args[:cloud_id]}"
            )
            if resp and resp.projects and resp.projects.size == 1
              found[args[:cloud_id]] = resp.projects.first if resp and resp.projects
            else
              # it's loony that there's no filter for project_number
              resp = MU::Cloud::Google.resource_manager(credentials: args[:credentials]).list_projects
              resp.projects.each { |p|
                if p.project_number.to_s == args[:cloud_id].to_s
                  found[args[:cloud_id]] = p
                  break
                end
              }
            end
          else
            return @@list_projects_cache if @@list_projects_cache # XXX decide on stale-ness after time or something
            resp = MU::Cloud::Google.resource_manager(credentials: args[:credentials]).list_projects#(page_token: page_token)
            resp.projects.each { |p|
              next if p.lifecycle_state == "DELETE_REQUESTED"
              found[p.project_id] = p
            }
            @@list_projects_cache = found
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(rootparent: nil, billing: nil)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }

          bok['name'] = cloud_desc.project_id
          bok['cloud_id'] = cloud_desc.project_id
#          if cloud_desc.name != cloud_desc.project_id
            bok['display_name'] = cloud_desc.name
#          end

          if cloud_desc.parent and cloud_desc.parent.id
            if cloud_desc.parent.type == "folder"
              bok['parent'] = MU::Config::Ref.get(
                id: cloud_desc.parent.id,
                cloud: "Google",
                credentials: @config['credentials'],
                type: "folders"
              )
            elsif rootparent
              bok['parent'] = {
                'id' => rootparent.is_a?(String) ? rootparent : rootparent.cloud_desc.name
              }
            else
              # org parent is *probably* safe to infer from credentials
            end
          end

          if billing
            bok['billing_acct'] = billing
          else
            cur_billing = MU::Cloud::Google.billing(credentials: @config['credentials']).get_project_billing_info("projects/"+@cloud_id)
            if cur_billing and cur_billing.billing_account_name
              bok['billing_acct'] = cur_billing.billing_account_name.sub(/^billingAccounts\//, '')
            end
          end

          bok
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
            },
            "display_name" => {
              "type" => "string",
              "description" => "A human readable name for this project. If not specified, will default to our long-form deploy-generated name."
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
            MU.log "Cannot manage Google Cloud folders in environments without an organization", MU::ERR
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
