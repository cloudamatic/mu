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
      # Creates an Google project as configured in {MU::Config::BasketofKittens::folders}
      class Folder < MU::Cloud::Folder
        @deploy = nil
        @config = nil
        @parent = nil

        attr_reader :mu_name
        attr_reader :config
        attr_reader :cloud_id
        attr_reader :url

        # @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
        # @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::folders}
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

          name_string = if @config['scrub_mu_isms']
            @config["name"]
          else
            @deploy.getResourceName(@config["name"], max_length: 30).downcase
          end

          params = {
            display_name: name_string
          }

          parent = MU::Cloud::Google::Folder.resolveParent(@config['parent'], credentials: @config['credentials'])

          folder_obj = MU::Cloud::Google.folder(:Folder).new(params)

          MU.log "Creating folder #{name_string} under #{parent}", details: folder_obj
          resp = MU::Cloud::Google.folder(credentials: @config['credentials']).create_folder(folder_obj, parent: parent)

          # Wait for list_folders output to be consistent (for the folder we
          # just created to show up)
          retries = 0
          begin
            found = MU::Cloud::Google::Folder.find(credentials: credentials, flags: { 'display_name' => name_string, 'parent_id' => parent })
            if found.size > 0
              @cloud_id = found.keys.first
              @parent = found.values.first.parent
              MU.log "Folder #{name_string} has identifier #{@cloud_id}"
            else
              if retries > 0 and (retries % 3) == 0
                MU.log "Waiting for Google Cloud folder #{name_string} to appear in list_folder results...", MU::NOTICE
              end
              retries += 1
              sleep 15
            end
          end while found.size == 0

        end

        # Given a {MU::Config::Folder.reference} configuration block, resolve
        # to a GCP resource id and type suitable for use in API calls to manage
        # projects and folders.
        # @param parentblock [Hash]
        # @return [String]
        def self.resolveParent(parentblock, credentials: nil)
          my_org = MU::Cloud::Google.getOrg(credentials)
          if !parentblock or parentblock['id'] == my_org.name or
             parentblock['name'] == my_org.display_name or (parentblock['id'] and
             "organizations/"+parentblock['id'] == my_org.name)
            return my_org.name
          end

          if parentblock['name']
            sib_folder = MU::MommaCat.findStray(
              "Google",
              "folders",
              deploy_id: parentblock['deploy_id'],
              credentials: credentials,
              name: parentblock['name']
            ).first
            if sib_folder
              return "folders/"+sib_folder.cloudobj.cloud_id
            end
          end

          begin
          found = MU::Cloud::Google::Folder.find(cloud_id: parentblock['id'], credentials: credentials, flags: { 'display_name' => parentblock['name'] })
          rescue ::Google::Apis::ClientError => e
            if !e.message.match(/Invalid request status_code: 404/)
              raise e
            end
          end

          if found and found.size > 0
            return found.values.first.name
          end

          nil
        end

        # Return the cloud descriptor for the Folder
        def cloud_desc
          MU::Cloud::Google::Folder.find(cloud_id: @cloud_id).values.first.to_h
        end

        # Return the metadata for this project's configuration
        # @return [Hash]
        def notify
          desc = MU.structToHash(MU::Cloud::Google.folder(credentials: @config['credentials']).get_folder("folders/"+@cloud_id))
          desc["mu_name"] = @mu_name
          desc["parent"] = @parent
          desc["cloud_id"] = @cloud_id
          desc
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
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, credentials: nil, flags: {}, region: MU.myRegion)
          # We can't label GCP folders, and their names are too short to encode
          # Mu deploy IDs, so all we can do is rely on flags['known'] passed in
          # from cleanup, which relies on our metadata to know what's ours.

          if flags and flags['known']
            flags['known'].each { |cloud_id|
              found = self.find(cloud_id: cloud_id, credentials: credentials)
              if found.size > 0 and found.values.first.lifecycle_state == "ACTIVE"
                MU.log "Deleting folder #{found.values.first.display_name} (#{found.keys.first})"
                if !noop
                  max_retries = 10
                  retries = 0
                  success = false
                  begin
                    MU::Cloud::Google.folder(credentials: credentials).delete_folder(
                      "folders/"+found.keys.first   
                    )
                    found = self.find(cloud_id: cloud_id, credentials: credentials)
                    if found and found.size > 0 and found.values.first.lifecycle_state != "DELETE_REQUESTED"
                      if retries < max_retries
                        sleep 30
                        retries += 1
                        puts retries
                      else
                        MU.log "Folder #{cloud_id} still exists after #{max_retries.to_s} attempts to delete", MU::ERR
                        break
                      end
                    else
                      success = true
                    end

                  rescue ::Google::Apis::ClientError => e
                    if e.message.match(/failedPrecondition/) and retries < max_retries
                      sleep 30
                      retries += 1
                      retry
                    else
                      raise e
                    end
                  end while !success
                end
              end
            }
          end
        end

        # Locate an existing project
        # @param cloud_id [String]: The cloud provider's identifier for this resource.
        # @param flags [Hash]: Optional flags
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching project
#        def self.find(cloud_id: nil, credentials: nil, flags: {}, tag_key: nil, tag_value: nil)
        def self.find(**args)
          found = {}
pp args
          # Recursively search a GCP folder hierarchy for a folder matching our
          # supplied name or identifier.
          def self.find_matching_folder(parent, name: nil, id: nil, credentials: nil)
            resp = MU::Cloud::Google.folder(credentials: credentials).list_folders(parent: parent)
            if resp and resp.folders
              resp.folders.each { |f|
                if name and name.downcase == f.display_name.downcase
                  return f
                elsif id and "folders/"+id== f.name
                  return f
                else
                  found = self.find_matching_folder(f.name, name: name, id: id, credentials: credentials)
                  return found if found
                end
              }
            end
            nil
          end

          parent = if args[:flags] and args[:flags]['parent_id']
            args[:flags]['parent_id']
          else
            my_org = MU::Cloud::Google.getOrg(args[:credentials])
            my_org.name
          end

          if args[:cloud_id]
            found[args[:cloud_id].sub(/^folders\//, "")] = MU::Cloud::Google.folder(credentials: args[:credentials]).get_folder("folders/"+args[:cloud_id].sub(/^folders\//, ""))
          elsif args[:flags]['display_name']

            if parent
              resp = self.find_matching_folder(parent, name: args[:flags]['display_name'], credentials: args[:credentials])
              if resp
                found[resp.name.sub(/^folders\//, "")] = resp
              end
            end
          else
            resp = MU::Cloud::Google.folder(credentials: args[:credentials]).list_folders(parent: parent)
            if resp and resp.folders
              resp.folders.each { |folder|
                found[folder.name.sub(/^folders\//, "")] = folder
              }
            end
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(strip_name: true)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }
          bok['name'] = cloud_desc[:display_name]

          bok
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

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::folders}, bare and unvalidated.
        # @param folder [Hash]: The resource to process and validate
        # @param configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(folder, configurator)
          ok = true

          if !MU::Cloud::Google.getOrg(folder['credentials'])
            MU.log "Cannot manage Google Cloud projects in environments without an organization. See also: https://cloud.google.com/resource-manager/docs/creating-managing-organization", MU::ERR
            ok = false
          end

          if folder['parent'] and folder['parent']['name'] and !folder['parent']['deploy_id'] and configurator.haveLitterMate?(folder['parent']['name'], "folders")
            folder["dependencies"] ||= []
            folder["dependencies"] << {
              "type" => "folder",
              "name" => folder['parent']['name']
            }
          end

          ok
        end

      end
    end
  end
end
