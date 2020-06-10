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
          library, path = url.split(/:/, 2)
          item, filename = path.sub(/^\/*/, '').split(/\//, 2)
          filename ||= item

          library_desc = find(cloud_id: library, credentials: credentials, habitat: habitat).values.first

          if !library_desc
            raise MuError, "Failed to find a datastore matching #{url}"
          end

          item_id = MU::Cloud::VMWare.library_item(credentials: credentials, habitat: habitat).find(::VSphereAutomation::Content::ContentLibraryItemFind.new(
            spec: ::VSphereAutomation::Content::ContentLibraryItemFindSpec.new(
              name: item,
              library_id: library_desc.id
          ))).value.first

          if !item_id
            create_spec = {
              library_id: library_desc.id,
              name: item
            }
            create_spec[:description] = description if description

            params = ::VSphereAutomation::Content::ContentLibraryItemCreate.new(create_spec: create_spec)

            MU.log "Creating item #{item} in library #{library}"
            resp = MU::Cloud::VMWare.library_item(credentials: credentials, habitat: habitat).create(params)
            item_id = resp.value
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
exit
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
            end
          ensure
            MU::Cloud::VMWare.library_update(credentials: credentials, habitat: habitat).complete(session_id)
            MU::Cloud::VMWare.library_update(credentials: credentials, habitat: habitat).delete(session_id)
          end

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
