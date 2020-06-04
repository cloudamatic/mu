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
        # @param url [String]: Target URL, of the form gs://bucket/folder/file
        # @param acl [String]: Canned ACL permission to assign to the object we upload
        # @param file [String]: Path to a local file to write to our target location. One of +file+ or +data+ must be specified.
        # @param data [String]: Data to write to our target location. One of +file+ or +data+ must be specified.
        def self.upload(url, acl: "private", file: nil, data: nil, credentials: nil, habitat: nil)
          habitat ||= MU::Cloud::VMWare.defaultSDDC(credentials)
          if file and !File.readable?(file)
            raise MuError, "File #{file} must exist and be readable"
          end
          datastore, path = url.split(/:/, 2)
          datastore_desc = MU::Cloud::VMWare.datastore(credentials: credentials, habitat: habitat).list.value.select { |d|
            [d.name, d.datastore].include?(datastore)
          }.first

          if !datastore_desc
            raise MuError, "Failed to find a datastore matching #{url}"
          end

          datacenters = MU::Cloud::VMWare.datacenter(credentials: credentials, habitat: habitat).list.value

          if datacenters and datacenters.size > 1
            raise MuError, "I see multiple datacenters and don't know how to identify the one I should use when uploading to #{url}", details: datacenters
          end
          params = {
            "dsName" => datastore_desc.name,
            "dcPath" => datacenters.first.name
          }
          pp params
          pp MU::Cloud::VMWare.datacenter(credentials: credentials, habitat: habitat).get(datacenters.first.datacenter)
          sddc_desc = MU::Cloud.resourceClass("VMWare", "Habitat").find(cloud_id: habitat).values.first
          uri = URI(sddc_desc["resource_config"]["vc_url"]+path.sub(/^\//, ''))
          uri.query = URI.encode_www_form(params)
          puts uri.to_s

          req = Net::HTTP::Put.new(uri)
          req['Content-Type'] = 'application/octet-stream'
#          req['Transfer-Encoding'] = 'chunked'
          req['Content-Length'] = File.size(file)
          req['Cookie'] = 'vmware_cgi_ticket='+MU::Cloud::VMWare.datastore(credentials: credentials, habitat: habitat).session_key
          req.body_stream = File.open(file)

          MU.log "Attempting to PUT #{file} to #{uri.to_s}", MU::NOTICE
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          http.set_debug_output($stdout)
          http.request(req)

          pp resp
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
