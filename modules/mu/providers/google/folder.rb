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
      # Creates a Google folder as configured in {MU::Config::BasketofKittens::folders}
      class Folder < MU::Cloud::Folder

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          cloud_desc if @cloud_id # XXX this maybe isn't my job

          @mu_name ||= @deploy.getResourceName(@config['name'])
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

          if @config['parent']['name'] and !@config['parent']['id']
            @config['parent']['deploy_id'] = @deploy.deploy_id
          end
          parent = MU::Cloud::Google::Folder.resolveParent(@config['parent'], credentials: @config['credentials'])

          folder_obj = MU::Cloud::Google.folder(:Folder).new(params)

          MU.log "Creating folder #{name_string} under #{parent}", details: folder_obj
          MU::Cloud::Google.folder(credentials: @config['credentials']).create_folder(folder_obj, parent: parent)

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

          @habitat = parent

        end

        # Retrieve the IAM bindings for this folder (associates between IAM roles and groups/users)
        def bindings
          MU::Cloud::Google::Folder.bindings(@cloud_id, credentials: @config['credentials'])
        end

        # Retrieve the IAM bindings for this folder (associates between IAM roles and groups/users)
        # @param folder [String]:
        # @param credentials [String]:
        def self.bindings(folder, credentials: nil)
          MU::Cloud::Google.folder(credentials: credentials).get_folder_iam_policy(folder).bindings
        end

        # Given a {MU::Config::Folder.reference} configuration block, resolve
        # to a GCP resource id and type suitable for use in API calls to manage
        # projects and folders.
        # @param parentblock [Hash]
        # @return [String]
        def self.resolveParent(parentblock, credentials: nil)
          my_org = MU::Cloud::Google.getOrg(credentials)
          if my_org and (!parentblock or parentblock['id'] == my_org.name or
             parentblock['name'] == my_org.display_name or (parentblock['id'] and
             "organizations/"+parentblock['id'] == my_org.name))
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
              return sib_folder.cloud_desc.name
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

        @cached_cloud_desc = nil
        # Return the cloud descriptor for the Folder
        # @return [Google::Apis::Core::Hashable]
        def cloud_desc(use_cache: true)
          return @cached_cloud_desc if @cached_cloud_desc and use_cache
          @cached_cloud_desc = MU::Cloud::Google::Folder.find(cloud_id: @cloud_id, credentials: @config['credentials']).values.first
          @habitat_id ||= @cached_cloud_desc.parent.sub(/^(folders|organizations)\//, "")
          @cached_cloud_desc
        end

        # Return the metadata for this folders's configuration
        # @return [Hash]
        def notify
          desc = MU.structToHash(cloud_desc)
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
          MU::Cloud::RELEASE
        end

        # Remove all Google projects associated with the currently loaded deployment. Try to, anyway.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, deploy_id: MU.deploy_id, ignoremaster: false, credentials: nil, flags: {})
          filter = %Q{(labels.mu-id = "#{MU.deploy_id.downcase}")}
          if !ignoremaster and MU.mu_public_ip
            filter += %Q{ AND (labels.mu-master-ip = "#{MU.mu_public_ip.gsub(/\./, "_")}")}
          end
          MU.log "Placeholder: Google Folder artifacts do not support labels, so ignoremaster cleanup flag has no effect", MU::DEBUG, details: filter
          # We can't label GCP folders, and their names are too short to encode
          # Mu deploy IDs, so all we can do is rely on flags['known'] passed in
          # from cleanup, which relies on our metadata to know what's ours.
#noop = true
          if flags and flags['known']
            threads = []
            flags['known'].each { |cloud_id|
              threads << Thread.new { 

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
# XXX maybe see if the folder has disappeared already?
# XXX look for child folders that haven't been deleted, that's what this tends
# to mean
                      if e.message.match(/failedPrecondition/) and retries < max_retries
                        sleep 30
                        retries += 1
                        retry
                      else
                        MU.log "Got 'failedPrecondition' a bunch while trying to delete #{found.values.first.display_name} (#{found.keys.first})", MU::ERR
                        break
                      end
                    end while !success
                  end
                end
              }
            }
            threads.each { |t|
              t.join
            }
          end
        end

        # Locate and return cloud provider descriptors of this resource type
        # which match the provided parameters, or all visible resources if no
        # filters are specified. At minimum, implementations of +find+ must
        # honor +credentials+ and +cloud_id+ arguments. We may optionally
        # support other search methods, such as +tag_key+ and +tag_value+, or
        # cloud-specific arguments like +project+. See also {MU::MommaCat.findStray}.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        # @return [Hash<String,OpenStruct>]: The cloud provider's complete descriptions of matching resources
        def self.find(**args)
          found = {}
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
# XXX re-raise with a clear permission error
            my_org.name if my_org
          end

          if args[:cloud_id]
            raw_id = args[:cloud_id].sub(/^folders\//, "")
            begin
              resp = MU::Cloud::Google.folder(credentials: args[:credentials]).get_folder("folders/"+raw_id)
              found[resp.name] = resp if resp
            rescue ::Google::Apis::ClientError => e
              raise e if e.message !~ /forbidden: /
            end

          elsif args[:flags] and args[:flags]['display_name']

            if parent
              resp = self.find_matching_folder(parent, name: args[:flags]['display_name'], credentials: args[:credentials])
              if resp
                found[resp.name] = resp
              end
            end
          else
            resp = MU::Cloud::Google.folder(credentials: args[:credentials]).list_folders(parent: parent)

            if resp and resp.folders
              resp.folders.each { |folder|
                next if folder.lifecycle_state == "DELETE_REQUESTED"
                found[folder.name] = folder
                # recurse so that we'll pick up child folders
                children = self.find(
                  credentials: args[:credentials],
                  flags: { 'parent_id' => folder.name }
                )
                if !children.nil? and !children.empty?
                  found.merge!(children)
                end
              }
            end
          end

          found
        end

        # Reverse-map our cloud description into a runnable config hash.
        # We assume that any values we have in +@config+ are placeholders, and
        # calculate our own accordingly based on what's live in the cloud.
        def toKitten(**args)
          bok = {
            "cloud" => "Google",
            "credentials" => @config['credentials']
          }

          bok['display_name'] = cloud_desc.display_name
          bok['cloud_id'] = cloud_desc.name
          bok['name'] = cloud_desc.display_name#+bok['cloud_id'] # only way to guarantee uniqueness
          if cloud_desc.parent.match(/^folders\/(.*)/)
            bok['parent'] = MU::Config::Ref.get(
              id: cloud_desc.parent,
              cloud: "Google",
              credentials: @config['credentials'],
              type: "folders"
            )
          elsif args[:rootparent]
            bok['parent'] = {
              'id' => args[:rootparent].is_a?(String) ? args[:rootparent] : args[:rootparent].cloud_desc.name
            }
          else
            bok['parent'] = { 'id' => cloud_desc.parent }
          end

          bok
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {
            "display_name" => {
              "type" => "string",
              "description" => "The +display_name+ field of this folder, specified only if we want it to be something other than the automatically-generated string derived from the +name+ field.",
            }
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
            MU.log "Cannot manage Google Cloud folders in environments without an organization", MU::ERR
            ok = false
          end

          if folder['parent'] and folder['parent']['name'] and !folder['parent']['deploy_id'] and configurator.haveLitterMate?(folder['parent']['name'], "folders")
            MU::Config.addDependency(folder, folder['parent']['name'], "folder")
          end

          ok
        end

      end
    end
  end
end
