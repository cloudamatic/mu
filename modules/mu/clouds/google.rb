# Copyright:: Copyright (c) 2017 eGlobalTech, Inc., all rights reserved
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

require "google/cloud"
require 'googleauth'
require "net/http"
require 'net/https'

module MU
  class Cloud
    # Support for Google Cloud Platform as a provisioning layer.
    class Google
      @@client_id = nil

      # Pull our global Google Cloud Platform credentials out of their secure
      # vault and place them in ENV['GOOGLE_CLOUD_KEYFILE_JSON'], as expected
      # by the google-cloud-ruby gem family.
      # XXX supposedly this can be provided in-code. Would rather embed in all
      # calls instead of depending on a polluted environment.
      def self.loadCredentials(scopes = nil)
        if $MU_CFG.has_key?("google") and $MU_CFG["google"].has_key?("credentials") and @@client_id.nil?
          vault, item = $MU_CFG["google"]["credentials"].split(/:/)
          begin
            data = MU::Groomer::Chef.getSecret(vault: vault, item: item)
            ENV['GOOGLE_CLOUD_KEYFILE_JSON'] = JSON.generate(data)
            pp data
            @@client_id ||= ::Google::Auth::ClientId.from_hash(data.merge({"web" => data}))
          rescue MU::Groomer::Chef::MuNoSuchSecret
            raise MuError, "Google Cloud credentials not found in Vault #{vault}:#{item}"
          end
        else
          raise MuError, "Google Cloud credentials not configured"
        end
        if @@client_id and scopes
          # Boy does this seem awful and insecure
          token_store = ::Google::Auth::Stores::FileTokenStore.new(
            :file => MU.dataDir+'/tokens.yaml'
          )
          return ::Google::Auth::WebUserAuthorizer.new(
            @@client_id,
            scopes,
            token_store,
            '/oauth2callback'
          )
        end
        ENV['GOOGLE_CLOUD_KEYFILE_JSON']
      end

      # Fetch a URL
      def self.get(url)
        loadCredentials
        uri = URI url
        resp = nil

        Net::HTTP.start(uri.host, uri.port) do |http|
          resp = http.get(uri)
        end

        unless resp.code == "200"
          puts resp.code, resp.body
          exit
        end
        resp.body
      end

      # Our credentials map to a project, an organizational structure in Google
      # Cloud. This fetches the identifier of the project associated with our
      # default credentials.
      def self.defaultProject
        creds = loadCredentials
        creds["project_id"]
      end

      def self.listRegions
#        gcloud = Google::Cloud.new(MU::Cloud::Google.defaultProject)
#        MU::Cloud::Google.compute.authorization = ::Google::Auth.get_application_default(['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'])
        items = MU::Cloud::Google.compute.fetch_all do |token|
          MU::Cloud::Google.compute.list_regions(project, page_token: token)
        end
        pp items
      end
  
      # List the Availability Zones associated with a given Google Cloud
      # region. If no region is given, search the one in which this MU master
      # server resides (if it resides in this cloud provider's ecosystem).
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region = MU.curRegion)
      end

      # Google's Compute Service API
      def self.compute
        require 'google/apis/compute_v1'
        loadCredentials
# XXX this is probably a per-project kinda deal. Do regions matter? I munno.
#        region ||= MU.myRegion
#        @@compute_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "S3", region: region)
#        @@compute_api[region] ||= MU::Cloud::AWS::Endpoint.new(api: "S3", region: region)
        @@compute_api ||= MU::Cloud::Google::Endpoint.new(api: "Compute")
        @@compute_api.authorization = loadCredentials(['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'])
        @@compute_api
      end

      private

      # Wrapper class for Google APIs, so that we can catch some common
      # transient endpoint errors without having to spray rescues all over the
      # codebase.
      class Endpoint
        @api = nil
#        @region = nil

        # Create a Google Cloud Platform API client
        # @param api [String]: Which API are we wrapping?
        def initialize(api: "Compute")
#          @region = region
#          if region
#            @api = Object.const_get("Google::Apis::Compute::#{api}").new(region: region)
#          else
#            @api = Object.const_get("Google::Apis::ComputeV1::#{api}").new
            @api = Object.const_get("Google::Apis::#{api}").new
#          end
        end

        @instance_cache = {}
        # Catch-all for AWS client methods. Essentially a pass-through with some
        # rescues for known silly endpoint behavior.
        def method_missing(method_sym, *arguments)
          retries = 0
          begin
            MU.log "Calling #{method_sym}", MU::DEBUG, details: arguments
            retval = nil
            if !arguments.nil? and arguments.size == 1
              retval = @api.method(method_sym).call(arguments[0])
            elsif !arguments.nil? and arguments.size > 0
              retval = @api.method(method_sym).call(*arguments)
            else
              retval = @api.method(method_sym).call
            end
            return retval
          rescue Exception => e
            retries = retries + 1
#            debuglevel = MU::DEBUG
debuglevel = MU::NOTICE
            interval = 5 + Random.rand(4) - 2
            if retries < 10 and retries > 2
              debuglevel = MU::NOTICE
              interval = 20 + Random.rand(10) - 3
            # elsif retries >= 10 and retries <= 100
            elsif retries >= 10
              debuglevel = MU::WARN
              interval = 40 + Random.rand(15) - 5
            # elsif retries > 100
              # raise MuError, "Exhausted retries after #{retries} attempts while calling EC2's #{method_sym} in #{@region}.  Args were: #{arguments}"
            end
            MU.log "Got #{e.inspect} calling Google's #{method_sym}, waiting #{interval.to_s}s and retrying. Args were: #{arguments}", debuglevel, details: caller
            sleep interval
            retry
          end
        end
      end
      @@compute_api = {}
    end
  end
end
