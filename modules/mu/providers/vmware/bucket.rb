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
    class VMWare
      # Support for VMWare Cloud Storage
      class Bucket < MU::Cloud::Bucket

        # Initialize this cloud resource object. Calling +super+ will invoke the initializer defined under {MU::Cloud}, which should set the attribtues listed in {MU::Cloud::PUBLIC_ATTRS} as well as applicable dependency shortcuts, like <tt>@vpc</tt>, for us.
        # @param args [Hash]: Hash of named arguments passed via Ruby's double-splat
        def initialize(**args)
          super
          @mu_name ||= @deploy.getResourceName(@config["name"])
        end

        # Called automatically by {MU::Deploy#createResources}
        def create
        end

        # Called automatically by {MU::Deploy#createResources}
        def groom
        end

        def self.createLibraryItem(library_id, name, description = nil, credentials: nil, habitat: nil, library_name: nil)
          create_spec = {
            library_id: library_id,
            name: name
          }
          create_spec[:description] = description if description
          library_name ||= library_id

          params = ::VSphereAutomation::Content::ContentLibraryItemCreate.new(create_spec: create_spec)

          MU.log "Creating item #{name} in library #{library_name}"
          MU::Cloud::VMWare.library_item(credentials: credentials, habitat: habitat).create(params).value
        end

        # Upload a file to a bucket.
        # @param url [String]: Target URL, of the form library://item/file
        # @param acl [String]: Canned ACL permission to assign to the object we upload
        # @param file [String]: Path to a local file to write to our target location. One of +file+ or +data+ must be specified.
        # @param data [String]: Data to write to our target location. One of +file+ or +data+ must be specified.
        def self.upload(url, acl: "private", file: nil, data: nil, credentials: nil, habitat: nil, description: nil, source_url: nil)
          habitat ||= MU::Cloud::VMWare.defaultSDDC(credentials)
          if file and !File.readable?(file)
            raise MuError, "File #{file} must exist and be readable"
          end

          library, library_id, item, item_id = MU::Cloud::VMWare.parseLibraryUrl(url, credentials: credentials, habitat: habitat)

          if !item_id
            item_id = createLibraryItem(library_id, item, description, credentials: credentials, habitat: habitat, library_name: library)
          end

          session_id = nil
          loop_if = Proc.new { session_id.is_a?(::VSphereAutomation::Content::VapiStdErrorsResourceBusy) }

          MU.retrier([], loop_if: loop_if, max: 10, wait: 30) {
            session_id = MU::Cloud::VMWare.library_update(credentials: credentials, habitat: habitat).create(
              ::VSphereAutomation::Content::ContentLibraryItemUpdateSessionCreate.new(
                create_spec: {
                  library_item_id: item_id
                }
              )
            ).value
          }
          if !session_id or !session_id.is_a?(String)
            raise MuError, "Failed to create a session to modify #{library}://#{item}"
          end

          file_desc = MU::Cloud::VMWare.library_file(credentials: credentials, habitat: habitat).get(
            item_id,
            ::VSphereAutomation::Content::ContentLibraryItemFileGet.new(
             name: filename
            )
          ).value

          if file and file_desc and file_desc.respond_to?(:checksum_info) and
             file_desc.checksum_info.checksum and
             Digest::SHA1.file(file) == file_desc.checksum_info.checksum
            MU.log "#{file} already exists at #{library}://#{item}/#{filename} and has matching checksum", MU::NOTICE, details: file_desc.checksum_info.checksum
            return
          end

          file_spec = {
            name: filename,
          }
          if file
            file_spec[:source_type] = "PUSH"
          elsif source_url
            file_spec[:source_type] = "PULL"
            file_spec[:source_endpoint] = {
              uri: source_url
            }
          end
          add_arg = ::VSphereAutomation::Content::ContentLibraryItemUpdatesessionFileAdd.new(
              file_spec: file_spec
            )

          file_upload = MU::Cloud::VMWare.library_file_session(credentials: credentials, habitat: habitat).add(
            session_id,
            add_arg
          ).value

          begin
            if file
              MU.log "Uploading #{file} to #{library}://#{item}/#{filename}", MU::NOTICE, details: "PUT to #{file_upload.upload_endpoint.uri}"
              uri = URI file_upload.upload_endpoint.uri
              req = Net::HTTP::Put.new(uri)
              req['Content-Type'] = 'application/octet-stream'
              req['Accept'] = 'application/json'
              req['vmware-api-session-id'] = session_id
              req['Content-Length'] = File.size(file)
              req.body_stream = File.open(file)

              MU.log "Attempting to PUT #{file} to #{uri.to_s}", MU::NOTICE
              http = Net::HTTP.new(uri.host, uri.port)
              http.use_ssl = true
              http.set_debug_output($stdout)
              http.start
              http.finish
            end
          ensure
            MU::Cloud::VMWare.library_update(credentials: credentials, habitat: habitat).complete(session_id)
            MU::Cloud::VMWare.library_update(credentials: credentials, habitat: habitat).delete(session_id)
          end

        end

        def self.download(url, path: nil, credentials: nil, habitat: nil)
          library, library_id, item, item_id = MU::Cloud::VMWare.parseLibraryUrl(url, credentials: credentials, habitat: habitat)
          path ||= Dir.cwd

          session = MU::Cloud::VMWare.library_download.create(
            ::VSphereAutomation::Content::ContentLibraryItemDownloadSessionCreate.new(
              create_spec: {
                library_item_id: item_id
              }
            )
          ).value
          files = MU::Cloud::VMWare.library_file.list(item_id).value.map { |f| f.name }
          files.each { |file|
            prep = MU::Cloud::VMWare.library_file_download.prepare(
              session,
              ::VSphereAutomation::Content::ContentLibraryItemDownloadsessionFilePrepare.new(
                file_name: file
              )
            ).value
            MU.retrier([], loop_if: Proc.new {prep.status != "PREPARED"}) {
              prep = MU::Cloud::VMWare.library_file_download.get(
                session,
                ::VSphereAutomation::Content::ContentLibraryItemDownloadsessionFileGet.new(
                  file_name: file
                )
              ).value
            }
            uri = URI prep.download_endpoint.uri
            MU.log "Downloading #{library}://#{item}/#{file} to #{path}/#{file}"
        
            req = Net::HTTP::Get.new(uri)
            req['Accept'] = 'application/octet-stream'
            req['vmware-api-session-id'] = session
            f = File.open(path+"/"+file, "wb")
            Net::HTTP.start(uri.host,uri.port, :use_ssl => true){ |http|
              http.request(req) do |response|
                response.read_body do |segment|
                  f.write segment
                end
              end
            }
          }
          MU::Cloud::VMWare.library_download.delete(session)
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

        # Remove all buckets associated with the currently loaded deployment.
        # @param noop [Boolean]: If true, will only print what would be done
        # @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
        # @return [void]
        def self.cleanup(noop: false, ignoremaster: false, credentials: nil, flags: {})
        end

        # Return the metadata for this user cofiguration
        # @return [Hash]
        def notify
          desc = MU.structToHash(cloud_desc)
          desc
        end

        # Locate an existing bucket.
        # @return [OpenStruct]: The cloud provider's complete descriptions of matching bucket.
        def self.find(**args)
          found = {}

          MU::Cloud::VMWare.library(credentials: args[:credentials], habitat: args[:habitat]).list.value.each { |l|
            desc = MU::Cloud::VMWare.library(credentials: args[:credentials], habitat: args[:habitat]).get(l).value
            next if args[:cloud_id] and ![l, desc.name].include?(args[:cloud_id])
            found[l] = desc
          }

          found
        end

        # Cloud-specific configuration properties.
        # @param _config [MU::Config]: The calling MU::Config object
        # @return [Array<Array,Hash>]: List of required fields, and json-schema Hash of cloud-specific configuration parameters for this resource
        def self.schema(_config)
          toplevel_required = []
          schema = {}

          [toplevel_required, schema]
        end

        # Cloud-specific pre-processing of {MU::Config::BasketofKittens::bucket}, bare and unvalidated.

        # @param bucket [Hash]: The resource to process and validate
        # @param _configurator [MU::Config]: The overall deployment configurator of which this resource is a member
        # @return [Boolean]: True if validation succeeded, False otherwise
        def self.validateConfig(bucket, _configurator)
          ok = true

          ok
        end

        private

      end
    end
  end
end
