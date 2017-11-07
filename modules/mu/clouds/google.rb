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
require 'multi_json'
require 'stringio'

module MU
  class Cloud
    # Support for Google Cloud Platform as a provisioning layer.
    class Google
      @@authtoken = nil
      @@default_project = nil
      @@authorizers = {}

      # Plant a Mu deploy secret into a storage bucket somewhere for so our kittens can consume it
      # @param deploy_id [String]: The deploy for which we're writing the secret
      # @param value [String]: The contents of the secret
      def self.writeDeploySecret(deploy_id, value)
        name = deploy_id+"-secret"
        begin
          MU.log "Writing #{name} to Cloud Storage bucket #{$MU_CFG['google']['log_bucket_name']}"
          f = Tempfile.new(name) # XXX this is insecure and stupid
          f.write value
          f.close
          objectobj = MU::Cloud::Google.storage(:Object).new(
            bucket: $MU_CFG['google']['log_bucket_name'],
            name: name
          )
          ebs_key = MU::Cloud::Google.storage.insert_object(
            $MU_CFG['google']['log_bucket_name'],
            objectobj,
            upload_source: f.path
          )
          f.unlink
        rescue ::Google::Apis::ClientError => e
        pp e.inspect
          raise MU::MommaCat::DeployInitializeError, "Got #{e.inspect} trying to write #{name} to #{$MU_CFG['google']['log_bucket_name']}"
        end
      end

      # Grant access to appropriate Cloud Storage objects in our log/secret bucket for a deploy member.
      # @param acct [String]: The service account (by email addr) to which we'll grant access
      # @param deploy_id [String]: The deploy for which we're granting the secret
      # XXX add equivalent for AWS and call agnostically
      def self.grantDeploySecretAccess(acct, deploy_id = MU.deploy_id)
        name = deploy_id+"-secret"
        begin
          MU.log "Granting #{acct} access to list Cloud Storage bucket #{$MU_CFG['google']['log_bucket_name']}"
          MU::Cloud::Google.storage.insert_bucket_access_control(
            $MU_CFG['google']['log_bucket_name'],
            MU::Cloud::Google.storage(:BucketAccessControl).new(
              bucket: $MU_CFG['google']['log_bucket_name'],
              role: "READER",
              entity: "user-"+acct
            )
          )

          aclobj = MU::Cloud::Google.storage(:ObjectAccessControl).new(
            bucket: $MU_CFG['google']['log_bucket_name'],
            role: "READER",
            entity: "user-"+acct
          )

          [name, "log_vol_ebs_key"].each { |obj|
            MU.log "Granting #{acct} access to #{obj} in Cloud Storage bucket #{$MU_CFG['google']['log_bucket_name']}"
            MU::Cloud::Google.storage.insert_object_access_control(
              $MU_CFG['google']['log_bucket_name'],
              obj,
              aclobj
            )
          }
        rescue ::Google::Apis::ClientError => e
          raise MuError, "Got #{e.inspect} trying to set ACLs for #{deploy_id} in #{$MU_CFG['google']['log_bucket_name']}"
        end
      end

      # Determine whether we (the Mu master, presumably) are hosted in this
      # cloud.
      # @return [Boolean]
      def self.hosted
        return true if self.getGoogleMetaData("instance/name")
        false
      end

      # Fetch a Google instance metadata parameter (example: instance/id).
      # @param param [String]: The parameter name to fetch
      # @return [String, nil]
      def self.getGoogleMetaData(param)
        base_url = "http://metadata.google.internal/computeMetadata/v1"
        begin
          Timeout.timeout(2) do
            response = open(
              "#{base_url}/#{param}",
              "Metadata-Flavor" => "Google"
            ).read
            return response
          end
        rescue Net::HTTPServerException, OpenURI::HTTPError, Timeout::Error, SocketError => e
          # This is fairly normal, just handle it gracefully
          logger = MU::Logger.new
          logger.log "Failed metadata request #{base_url}/#{param}: #{e.inspect}", MU::DEBUG
        end

        nil
      end

      # Pull our global Google Cloud Platform credentials out of their secure
      # vault, feed them to the googleauth gem, and stash the results on hand
      # for consumption by the various GCP APIs.
      # @param scopes [Array<String>]: One or more scopes for which to authorizer the caller. Will vary depending on the API you're calling.
      def self.loadCredentials(scopes = nil)
        return @@authorizers[scopes.to_s] if @@authorizers[scopes.to_s]

        if $MU_CFG.has_key?("google") and $MU_CFG["google"].has_key?("credentials")
          begin
            vault, item = $MU_CFG["google"]["credentials"].split(/:/)
            data = MU::Groomer::Chef.getSecret(vault: vault, item: item).to_h
            @@default_project ||= data["project_id"]
            creds = {
              :json_key_io => StringIO.new(MultiJson.dump(data)),
              :scope => scopes
            }
            @@authorizers[scopes.to_s] = ::Google::Auth::ServiceAccountCredentials.make_creds(creds)
            return @@authorizers[scopes.to_s]
          rescue MU::Groomer::Chef::MuNoSuchSecret
            raise MuError, "Google Cloud credentials not found in Vault #{vault}:#{item}"
          end
        elsif MU::Cloud::Google.hosted
          @@authorizers[scopes.to_s] = ::Google::Auth.get_application_default(scopes)
          @@default_project ||= MU::Cloud::Google.getGoogleMetaData("project/project-id")
        else
          raise MuError, "Google Cloud credentials not configured"
        end
        nil
      end

      # Fetch a URL
      def self.get(url)
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

      # If this Mu master resides in the Google Cloud Platform, return the
      # project id in which we reside. Nil if we're not in GCP.
      def self.myProject
        if MU::Cloud::Google.hosted
          return MU::Cloud::Google.getGoogleMetaData("project/project-id")
        end
        nil
      end

      # Our credentials map to a project, an organizational structure in Google
      # Cloud. This fetches the identifier of the project associated with our
      # default credentials.
      def self.defaultProject
        loadCredentials if !@@default_project
        @@default_project
      end

      @@regions = {}
      # List all known Google Cloud Platform regions
      # @param us_only [Boolean]: Restrict results to United States only
      def self.listRegions(us_only = false)
        if @@regions.size == 0
          result = MU::Cloud::Google.compute.list_regions(MU::Cloud::Google.defaultProject)
          regions = []
          result.items.each { |region|
            @@regions[region.name] = []
            region.zones.each { |az|
              @@regions[region.name] << az.sub(/^.*?\/([^\/]+)$/, '\1')
            }
          }
        end
        if us_only
          @@regions.keys.delete_if { |r| !r.match(/^us/) }
        else
          @@regions.keys
        end
      end

      # Google has fairly strict naming conventions (all lowercase, no
      # underscores, etc). Provide a wrapper to our standard names to handle it.
      def self.nameStr(name)
        name.downcase.gsub(/[^a-z0-9\-]/, "-")
      end
  
      # List the Availability Zones associated with a given Google Cloud
      # region. If no region is given, search the one in which this MU master
      # server resides (if it resides in this cloud provider's ecosystem).
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region = MU.curRegion)
        MU::Cloud::Google.listRegions if !@@regions.has_key?(region)
        raise MuError, "No such Google Cloud region '#{region}'" if !@@regions.has_key?(region)
        @@regions[region]
      end

      # Google's Compute Service API
      # @param subclass [<Google::Apis::ComputeBeta>]: If specified, will return the class ::Google::Apis::ComputeBeta::subclass instead of an API client instance
      def self.compute(subclass = nil)
        require 'google/apis/compute_beta'

        if subclass.nil?
          @@compute_api ||= MU::Cloud::Google::Endpoint.new(api: "ComputeBeta::ComputeService", scopes: ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'])
          return @@compute_api
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("ComputeBeta").const_get(subclass)
        end
      end

      # Google's Storage Service API
      # @param subclass [<Google::Apis::StorageV1>]: If specified, will return the class ::Google::Apis::StorageV1::subclass instead of an API client instance
      def self.storage(subclass = nil)
        require 'google/apis/storage_v1'

        if subclass.nil?
          @@storage_api ||= MU::Cloud::Google::Endpoint.new(api: "StorageV1::StorageService", scopes: ['https://www.googleapis.com/auth/cloud-platform'])
          return @@storage_api
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("StorageV1").const_get(subclass)
        end
      end

      # Google's Iam Service API
      # @param subclass [<Google::Apis::IamV1>]: If specified, will return the class ::Google::Apis::IamV1::subclass instead of an API client instance
      def self.iam(subclass = nil)
        require 'google/apis/iam_v1'

        if subclass.nil?
          @@iam_api ||= MU::Cloud::Google::Endpoint.new(api: "IamV1::IamService", scopes: ['https://www.googleapis.com/auth/cloud-platform'])
          return @@iam_api
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("IamV1").const_get(subclass)
        end
      end

      private

      # Wrapper class for Google APIs, so that we can catch some common
      # transient endpoint errors without having to spray rescues all over the
      # codebase.
      class Endpoint
        @api = nil

        # Create a Google Cloud Platform API client
        # @param api [String]: Which API are we wrapping?
        # @param scopes [Array<String>]: Google auth scopes applicable to this API
        def initialize(api: "ComputeBeta::ComputeService", scopes: ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'])
          @api = Object.const_get("Google::Apis::#{api}").new
          @api.authorization = MU::Cloud::Google.loadCredentials(scopes)
        end

        def delete(type, project, region = nil, noop = false, filter = "description eq #{MU.deploy_id}")
          list_sym = "list_#{type.sub(/y$/, "ie")}s".to_sym
          resp = nil
          begin
            if region
              resp = MU::Cloud::Google.compute.send(list_sym, project, region, filter: filter)
            else
              resp = MU::Cloud::Google.compute.send(list_sym, project, filter: filter)
            end
          rescue ::Google::Apis::ClientError => e
            return if e.message.match(/^notFound: /)
          end

          if !resp.nil? and !resp.items.nil?
            threads = []
            parent_thread_id = Thread.current.object_id
            resp.items.each { |obj|
              threads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                MU.log "Removing #{type.gsub(/_/, " ")} #{obj.name}"
                delete_sym = "delete_#{type}".to_sym
                if !noop
                  begin
                    if region
                      MU::Cloud::Google.compute.send(delete_sym, project, region, obj.name)
                    else
                      MU::Cloud::Google.compute.send(delete_sym, project, obj.name)
                    end
                  rescue ::Google::Apis::ClientError => e
                    raise e if !e.message.match(/^notFound: /)
                  end
                end
              }
            }
            threads.each do |t|
              t.join
            end

          end
        end

        @instance_cache = {}
        # Catch-all for AWS client methods. Essentially a pass-through with some
        # rescues for known silly endpoint behavior.
        def method_missing(method_sym, *arguments)
          retries = 0
          begin
            MU.log "Calling #{method_sym}", MU::DEBUG, details: arguments
            retval = nil
            retries = 0
            begin
              if !arguments.nil? and arguments.size == 1
                retval = @api.method(method_sym).call(arguments[0])
              elsif !arguments.nil? and arguments.size > 0
                retval = @api.method(method_sym).call(*arguments)
              else
                retval = @api.method(method_sym).call
              end
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/^invalidParameter:/)
                MU.log e.message, MU::ERR, details: arguments
                raise e
              end
              if retries <= 10 and
                 e.message.match(/^resourceNotReady:/) or
                 (e.message.match(/^resourceInUseByAnotherResource:/) and method_sym.to_s.match(/^delete_/))
                if retries > 0 and retries % 3 == 0
                  MU.log "Will retry #{method_sym} after #{e.message} (retry #{retries})", MU::NOTICE, details: arguments
                else
                  MU.log "Will retry #{method_sym} after #{e.message} (retry #{retries})", MU::DEBUG, details: arguments
                end
                retries = retries + 1
                sleep retries*10
                retry
              else
                raise e
              end
            end

            if retval.class == ::Google::Apis::ComputeBeta::Operation
              retries = 0
              begin
                if retries > 0 and retries % 3 == 0
                  MU.log "Waiting for #{method_sym} to be done (retry #{retries})", MU::NOTICE
                else
                  MU.log "Waiting for #{method_sym} to be done (retry #{retries})", MU::DEBUG, details: retval
                end
                if retval.status != "DONE"
                  sleep 7
                  begin
                    resp = MU::Cloud::Google.compute.get_global_operation(
                      arguments.first, # there's always a project id
                      retval.name
                    )
                    retval = resp
                  rescue ::Google::Apis::ClientError => e
                    # this is ok; just means the operation is done and went away
                    if e.message.match(/^notFound:/)
                      break
                    else
                      raise e
                    end
                  end
                  retries = retries + 1
                end
              end while retval.status != "DONE"

              # Most insert methods have a predictable get_* counterpart. Let's
              # take advantage.
              # XXX might want to do something similar for delete ops? just the
              # but where we wait for the operation to definitely be done
              had_been_found = false
              if method_sym.to_s.match(/^(insert|create)_/) and retval.target_link
#                service["#MU_CLOUDCLASS"].instance_methods(false).include?(:groom)
                get_method = method_sym.to_s.gsub(/^(insert|create_disk|create)_/, "get_").to_sym
                cloud_id = retval.target_link.sub(/^.*?\/([^\/]+)$/, '\1')
                faked_args = arguments.dup
                faked_args.pop
                if get_method == :get_snapshot
                  faked_args.pop
                  faked_args.pop
                end
                faked_args.push(cloud_id)
                actual_resource = @api.method(get_method).call(*faked_args)
                had_been_found = true
                if actual_resource.respond_to?(:status) and
                  ["PROVISIONING", "STAGING", "PENDING", "CREATING", "RESTORING"].include?(actual_resource.status)
                  retries = 0
                  begin 
                    if retries > 0 and retries % 3 == 0
                      MU.log "Waiting for #{cloud_id} to get past #{actual_resource.status} (retry #{retries})", MU::NOTICE
                    else
                      MU.log "Waiting for #{cloud_id} to get past #{actual_resource.status} (retry #{retries})", MU::DEBUG, details: actual_resource
                    end
                    sleep 10
                    actual_resource = @api.method(get_method).call(*faked_args)
                    retries = retries + 1
                  end while ["PROVISIONING", "STAGING", "PENDING", "CREATING", "RESTORING"].include?(actual_resource.status)
                end
                return actual_resource
              end
            end
            return retval
          rescue ::Google::Apis::ServerError, ::Google::Apis::ClientError => e
            if e.class.name == "Google::Apis::ClientError" and
               (!e.message.match(/^notFound: /) or
               !method_sym.to_s.match(/^insert_/) or
               (e.message.match(/^notFound: /) and had_been_found)) # disappeared
              raise e
            end
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
            MU.log "Got #{e.inspect} calling Google's #{method_sym}, waiting #{interval.to_s}s and retrying. Called from: #{caller[1]}", debuglevel, details: arguments
            sleep interval
            retry
          end
        end
      end
      @@compute_api = nil
      @@storage_api = nil
      @@iam_api = nil
    end
  end
end
