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
      @@myRegion_var = nil
      @@authorizers = {}

      # Any cloud-specific instance methods we require our resource
      # implementations to have, above and beyond the ones specified by
      # {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        []
      end

      # If we're running this cloud, return the $MU_CFG blob we'd use to
      # describe this environment as our target one.
      def self.hosted_config
        return nil if !hosted?
        getGoogleMetaData("instance/zone").match(/^projects\/[^\/]+\/zones\/([^\/]+)$/)
        zone = Regexp.last_match[1]
        {
          "project" => MU::Cloud::Google.getGoogleMetaData("project/project-id"),
          "region" => zone.sub(/-[a-z]$/, "")
        }
      end

      # A non-working example configuration
      def self.config_example
        sample = hosted_config
        sample ||= {
          "project" => "my-project",
          "region" => "us-east4"
        }
        sample["credentials_file"] = "#{Etc.getpwuid(Process.uid).dir}/gcp_serviceacct.json"
        sample["log_bucket_name"] = "my-mu-cloud-storage-bucket"
        sample
      end

      # Return the name strings of all known sets of credentials for this cloud
      # @return [Array<String>]
      def self.listCredentials
        if !$MU_CFG['google']
          return hosted? ? ["#default"] : nil
        end

        $MU_CFG['google'].keys
      end

      def self.adminBucketName(credentials = nil)
         #XXX find a default if this particular account doesn't have a log_bucket_name configured
        cfg = credConfig(credentials)
        cfg['log_bucket_name']
      end

      def self.adminBucketUrl(credentials = nil)
        "gs://"+adminBucketName(credentials)+"/"
      end

      # Return the $MU_CFG data associated with a particular profile/name/set of
      # credentials. If no account name is specified, will return one flagged as
      # default. Returns nil if GCP is not configured. Throws an exception if 
      # an account name is specified which does not exist.
      # @param name [String]: The name of the key under 'aws' in mu.yaml to return
      # @return [Hash,nil]
      def self.credConfig(name = nil, name_only: false)
        # If there's nothing in mu.yaml (which is wrong), but we're running
        # on a machine hosted in GCP, fake it with that machine's service
        # account and hope for the best.
        if !$MU_CFG['google'] or !$MU_CFG['google'].is_a?(Hash) or $MU_CFG['google'].size == 0
          return @@my_hosted_cfg if @@my_hosted_cfg

          if hosted?
            begin
#              iam_data = JSON.parse(getAWSMetaData("iam/info"))
#              if iam_data["InstanceProfileArn"] and !iam_data["InstanceProfileArn"].empty?
                @@my_hosted_cfg = hosted_config
                return name_only ? "#default" : @@my_hosted_cfg
#              end
            rescue JSON::ParserError => e
            end
          end

          return nil
        end

        if name.nil?
          $MU_CFG['google'].each_pair { |name, cfg|
            if cfg['default']
              return name_only ? name : cfg
            end
          }
        else
          if $MU_CFG['google'][name]
            return name_only ? name : $MU_CFG['google'][name]
          elsif @@acct_to_profile_map[name.to_s]
            return name_only ? name : @@acct_to_profile_map[name.to_s]
          end

          raise MuError, "Google credential set #{name} was requested, but I see no such working credentials in mu.yaml"
        end
      end

      # If we've configured Google as a provider, or are simply hosted in GCP, 
      # decide what our default region is.
      def self.myRegion(credentials = nil)
        cfg = credConfig(credentials)
        if cfg and cfg['region']
          @@myRegion_var = cfg['region']
        elsif MU::Cloud::Google.hosted?
          zone = MU::Cloud::Google.getGoogleMetaData("instance/zone")
          @@myRegion_var = zone.gsub(/^.*?\/|\-\d+$/, "")
        end
        @@myRegion_var
      end

      # Plant a Mu deploy secret into a storage bucket somewhere for so our kittens can consume it
      # @param deploy_id [String]: The deploy for which we're writing the secret
      # @param value [String]: The contents of the secret
      def self.writeDeploySecret(deploy_id, value, name = nil, credentials: nil)
        name ||= deploy_id+"-secret"
        begin
          MU.log "Writing #{name} to Cloud Storage bucket #{adminBucketName(credentials)}"
          f = Tempfile.new(name) # XXX this is insecure and stupid
          f.write value
          f.close
          objectobj = MU::Cloud::Google.storage(:Object).new(
            bucket: adminBucketName(credentials),
            name: name
          )
          ebs_key = MU::Cloud::Google.storage.insert_object(
            adminBucketName(credentials),
            objectobj,
            upload_source: f.path
          )
          f.unlink
        rescue ::Google::Apis::ClientError => e
# XXX comment for NCBI tests
#          raise MU::MommaCat::DeployInitializeError, "Got #{e.inspect} trying to write #{name} to #{adminBucketName(credentials)}"
        end
      end

      # Remove the service account and various deploy secrets associated with a deployment. Intended for invocation from MU::Cleanup.
      # @param deploy_id [String]: The deploy for which we're granting the secret
      # @param noop [Boolean]: If true, will only print what would be done
      def self.removeDeploySecretsAndRoles(deploy_id = MU.deploy_id, flags: {}, noop: false, credentials: nil)
        cfg = credConfig(credentials)
        return if !cfg or !cfg['project']
        flags["project"] ||= cfg['project']
        name = deploy_id+"-secret"
      end

      # Grant access to appropriate Cloud Storage objects in our log/secret bucket for a deploy member.
      # @param acct [String]: The service account (by email addr) to which we'll grant access
      # @param deploy_id [String]: The deploy for which we're granting the secret
      # XXX add equivalent for AWS and call agnostically
      def self.grantDeploySecretAccess(acct, deploy_id = MU.deploy_id, name = nil, credentials: nil)
        name ||= deploy_id+"-secret"
        begin
          MU.log "Granting #{acct} access to list Cloud Storage bucket #{adminBucketName(credentials)}"
          MU::Cloud::Google.storage.insert_bucket_access_control(
            adminBucketName(credentials),
            MU::Cloud::Google.storage(:BucketAccessControl).new(
              bucket: adminBucketName(credentials),
              role: "READER",
              entity: "user-"+acct
            )
          )

          aclobj = MU::Cloud::Google.storage(:ObjectAccessControl).new(
            bucket: adminBucketName(credentials),
            role: "READER",
            entity: "user-"+acct
          )

          [name, "log_vol_ebs_key"].each { |obj|
            MU.log "Granting #{acct} access to #{obj} in Cloud Storage bucket #{adminBucketName(credentials)}"
            MU::Cloud::Google.storage.insert_object_access_control(
              adminBucketName(credentials),
              obj,
              aclobj
            )
          }
        rescue ::Google::Apis::ClientError => e
          raise MuError, "Got #{e.inspect} trying to set ACLs for #{deploy_id} in #{adminBucketName(credentials)}"
        end
      end

      @@is_in_gcp = nil

      # Alias for #{MU::Cloud::Google.hosted?}
      def self.hosted
        MU::Cloud::Google.hosted?
      end

      # Determine whether we (the Mu master, presumably) are hosted in this
      # cloud.
      # @return [Boolean]
      def self.hosted?
        if !@@is_in_gcp.nil?
          return @@is_in_gcp
        end

        if getGoogleMetaData("instance/name")
          @@is_in_gcp = true
          return true
        end
        @@is_in_gcp = false
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
        rescue Net::HTTPServerException, OpenURI::HTTPError, Timeout::Error, SocketError, Errno::EHOSTUNREACH, Errno::ENETUNREACH => e
          # This is fairly normal, just handle it gracefully
          logger = MU::Logger.new
          logger.log "Failed metadata request #{base_url}/#{param}: #{e.inspect}", MU::DEBUG
        end

        nil
      end

      # Create an SSL Certificate resource from some local x509 cert files.
      # @param name [String]: A resource name for the certificate
      # @param cert [String,OpenSSL::X509::Certificate]: An x509 certificate
      # @param key [String,OpenSSL::PKey]: An x509 private key
      # @return [Google::Apis::ComputeBeta::SslCertificate]
      def self.createSSLCertificate(name, cert, key, flags = {}, credentials: nil)
        flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
        flags["description"] ||= MU.deploy_id
        certobj = ::Google::Apis::ComputeBeta::SslCertificate.new(
          name: name,
          certificate: cert.to_s,
          private_key: key.to_s,
          description: flags["description"]
        )
        MU::Cloud::Google.compute(credentials: credentials).insert_ssl_certificate(flags["project"], certobj)
      end

      @@svc_account_name = nil
      # Fetch the name of the service account we were using last time we loaded
      # GCP credentials.
      # @return [String]
      def self.svc_account_name
        @@svc_account_name
      end
      # Pull our global Google Cloud Platform credentials out of their secure
      # vault, feed them to the googleauth gem, and stash the results on hand
      # for consumption by the various GCP APIs.
      # @param scopes [Array<String>]: One or more scopes for which to authorizer the caller. Will vary depending on the API you're calling.
      def self.loadCredentials(scopes = nil, credentials: nil)
        return @@authorizers[scopes.to_s] if @@authorizers[scopes.to_s]

        cfg = credConfig(credentials)

        if cfg
          data = nil
  
          def self.get_machine_credentials(scopes)
            @@svc_account_name = MU::Cloud::Google.getGoogleMetaData("instance/service-accounts/default/email")
            MU.log "We are hosted in GCP, so I will attempt to use the service account #{@@svc_account_name} to make API requests.", MU::DEBUG

            @@authorizers[scopes.to_s] = ::Google::Auth.get_application_default(scopes)
            @@authorizers[scopes.to_s].fetch_access_token!
            @@default_project ||= MU::Cloud::Google.getGoogleMetaData("project/project-id")
            @@authorizers[scopes.to_s]
          end

          if cfg["credentials_file"]
            begin
              data = JSON.parse(File.read(cfg["credentials_file"]))
              @@default_project ||= data["project_id"]
              creds = {
                :json_key_io => StringIO.new(MultiJson.dump(data)),
                :scope => scopes
              }
              @@svc_account_name = data["client_email"]
              @@authorizers[scopes.to_s] = ::Google::Auth::ServiceAccountCredentials.make_creds(creds)
              return @@authorizers[scopes.to_s]
            rescue JSON::ParserError, Errno::ENOENT, Errno::EACCES => e
              if !MU::Cloud::Google.hosted?
                raise MuError, "Google Cloud credentials file #{cfg["credentials_file"]} is missing or invalid (#{e.message})"
              end
              MU.log "Google Cloud credentials file #{cfg["credentials_file"]} is missing or invalid", MU::WARN, details: e.message
              return get_machine_credentials(scopes)
            end
          elsif cfg["credentials"]
            begin
              vault, item = cfg["credentials"].split(/:/)
              data = MU::Groomer::Chef.getSecret(vault: vault, item: item).to_h
            rescue MU::Groomer::Chef::MuNoSuchSecret
              if !MU::Cloud::Google.hosted?
                raise MuError, "Google Cloud credentials not found in Vault #{vault}:#{item}"
              end
              MU.log "Google Cloud credentials not found in Vault #{vault}:#{item}", MU::WARN
              return get_machine_credentials(scopes)
            end

            @@default_project ||= data["project_id"]
            creds = {
              :json_key_io => StringIO.new(MultiJson.dump(data)),
              :scope => scopes
            }
            @@svc_account_name = data["client_email"]
            @@authorizers[scopes.to_s] = ::Google::Auth::ServiceAccountCredentials.make_creds(creds)
            return @@authorizers[scopes.to_s]
          elsif MU::Cloud::Google.hosted?
            return get_machine_credentials(scopes)
          else
            raise MuError, "Google Cloud credentials not configured"
          end

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
        if MU::Cloud::Google.hosted?
          return MU::Cloud::Google.getGoogleMetaData("project/project-id")
        end
        nil
      end

      # If this Mu master resides in the Google Cloud Platform, return the
      # default service account associated with its metadata.
      def self.myServiceAccount
        if MU::Cloud::Google.hosted?
          MU::Cloud::Google.getGoogleMetaData("instance/service-accounts/default/email")
        else
          nil
        end
      end

      # Our credentials map to a project, an organizational structure in Google
      # Cloud. This fetches the identifier of the project associated with our
      # default credentials.
      def self.defaultProject(credentials = nil)
        cfg = credConfig(credentials)
        return myProject if !cfg or !cfg['project']
        loadCredentials(credentials) if !@@default_project
        @@default_project
      end

      # List all Google Cloud Platform projects available to our credentials
      def self.listProjects(credentials = nil)
        cfg = credConfig(credentials)
        return [] if !cfg or !cfg['project']
        result = MU::Cloud::Google.resource_manager.list_projects
        result.projects.reject! { |p| p.lifecycle_state == "DELETE_REQUESTED" }
        result.projects.map { |p| p.project_id }
      end

      @@regions = {}
      # List all known Google Cloud Platform regions
      # @param us_only [Boolean]: Restrict results to United States only
      def self.listRegions(us_only = false, credentials: nil)
        if !MU::Cloud::Google.defaultProject(credentials)
          return []
        end
        if @@regions.size == 0
          begin
            result = MU::Cloud::Google.compute(credentials: credentials).list_regions(MU::Cloud::Google.defaultProject(credentials))
          rescue ::Google::Apis::ClientError => e
            if e.message.match(/forbidden/)
              raise MuError, "Insufficient permissions to list Google Cloud region. The service account #{myServiceAccount} should probably have the project owner role."
            end
            raise e
          end

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


      @@instance_types = nil
      # Query the GCP API for the list of valid Compute instance types and some of
      # their attributes. We can use this in config validation and to help
      # "translate" machine types across cloud providers.
      # @param region [String]: Supported machine types can vary from region to region, so we look for the set we're interested in specifically
      # @return [Hash]
      def self.listInstanceTypes(region = myRegion)
        return @@instance_types if @@instance_types and @@instance_types[region]
        if !MU::Cloud::Google.defaultProject
          return {}
        end

        @@instance_types ||= {}
        @@instance_types[region] ||= {}
        result = MU::Cloud::Google.compute.list_machine_types(MU::Cloud::Google.defaultProject, listAZs(region).first)
        result.items.each { |type|
          @@instance_types[region][type.name] ||= {}
          @@instance_types[region][type.name]["memory"] = sprintf("%.1f", type.memory_mb/1024.0).to_f
          @@instance_types[region][type.name]["vcpu"] = type.guest_cpus.to_f
          if type.is_shared_cpu
            @@instance_types[region][type.name]["ecu"] = "Variable"
          else
            @@instance_types[region][type.name]["ecu"] = type.guest_cpus
          end
        }
        @@instance_types
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
      def self.compute(subclass = nil, credentials: nil)
        require 'google/apis/compute_beta'

        if subclass.nil?
          @@compute_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "ComputeBeta::ComputeService", scopes: ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'], credentials: nil)
          return @@compute_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("ComputeBeta").const_get(subclass)
        end
      end

      # Google's Storage Service API
      # @param subclass [<Google::Apis::StorageV1>]: If specified, will return the class ::Google::Apis::StorageV1::subclass instead of an API client instance
      def self.storage(subclass = nil, credentials: nil)
        require 'google/apis/storage_v1'

        if subclass.nil?
          @@storage_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "StorageV1::StorageService", scopes: ['https://www.googleapis.com/auth/cloud-platform'], credentials: nil)
          return @@storage_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("StorageV1").const_get(subclass)
        end
      end

      # Google's IAM Service API
      # @param subclass [<Google::Apis::IamV1>]: If specified, will return the class ::Google::Apis::IamV1::subclass instead of an API client instance
      def self.iam(subclass = nil, credentials: nil)
        require 'google/apis/iam_v1'

        if subclass.nil?
          @@iam_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "IamV1::IamService", scopes: ['https://www.googleapis.com/auth/cloud-platform'], credentials: nil)
          return @@iam_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("IamV1").const_get(subclass)
        end
      end

      # GCP's AdminDirectory Service API
      # @param subclass [<Google::Apis::AdminDirectoryV1>]: If specified, will return the class ::Google::Apis::AdminDirectoryV1::subclass instead of an API client instance
      def self.admin_directory(subclass = nil, credentials: nil)
        require 'google/apis/admin_directory_v1'
    
        if subclass.nil?
          begin
            @@admin_directory_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "AdminDirectoryV1::DirectoryService", scopes: ['https://www.googleapis.com/auth/admin.directory.group.member.readonly', 'https://www.googleapis.com/auth/admin.directory.group.readonly', 'https://www.googleapis.com/auth/admin.directory.user.readonly', 'https://www.googleapis.com/auth/admin.directory.domain.readonly', 'https://www.googleapis.com/auth/admin.directory.orgunit.readonly', 'https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly', 'https://www.googleapis.com/auth/admin.directory.customer.readonly'], masquerade: $MU_CFG['google']['masquerade_as'], credentials: nil)
          rescue Signet::AuthorizationError => e
            MU.log "Cannot masquerade as #{$MU_CFG['google']['masquerade_as']}", MU::ERROR, details: "You can only use masquerade_as with GSuite. For more information on delegating GSuite authority to a service account, see:\nhttps://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority"
            raise e
          end
          return @@admin_directory_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("AdminDirectoryV1").const_get(subclass)
        end
      end

      # Google's Cloud Resource Manager API
      # @param subclass [<Google::Apis::CloudresourcemanagerV1>]: If specified, will return the class ::Google::Apis::CloudresourcemanagerV1::subclass instead of an API client instance
      def self.resource_manager(subclass = nil, credentials: nil)
        require 'google/apis/cloudresourcemanager_v1'

        if subclass.nil?
          @@resource_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "CloudresourcemanagerV1::CloudResourceManagerService", scopes: ['https://www.googleapis.com/auth/cloud-platform'], credentials: nil)
          return @@resource_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("CloudresourcemanagerV1").const_get(subclass)
        end
      end

      # Google's Container API
      # @param subclass [<Google::Apis::ContainerV1>]: If specified, will return the class ::Google::Apis::ContainerV1::subclass instead of an API client instance
      def self.container(subclass = nil, credentials: nil)
        require 'google/apis/container_v1'

        if subclass.nil?
          @@container_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "ContainerV1::ContainerService", scopes: ['https://www.googleapis.com/auth/cloud-platform'], credentials: nil)
          return @@container_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("ContainerV1").const_get(subclass)
        end
      end

      # Google's Service Manager API (the one you use to enable pre-project APIs)
      # @param subclass [<Google::Apis::ServicemanagementV1>]: If specified, will return the class ::Google::Apis::ServicemanagementV1::subclass instead of an API client instance
      def self.service_manager(subclass = nil, credentials: nil)
        require 'google/apis/servicemanagement_v1'

        if subclass.nil?
          @@service_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "ServicemanagementV1::ServiceManagementService", scopes: ['https://www.googleapis.com/auth/cloud-platform'], credentials: nil)
          return @@service_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("ServicemanagementV1").const_get(subclass)
        end
      end

      # Google's SQL Service API
      # @param subclass [<Google::Apis::SqladminV1beta4>]: If specified, will return the class ::Google::Apis::SqladminV1beta4::subclass instead of an API client instance
      def self.sql(subclass = nil, credentials: nil)
        require 'google/apis/sqladmin_v1beta4'

        if subclass.nil?
          @@sql_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "SqladminV1beta4::SQLAdminService", scopes: ['https://www.googleapis.com/auth/cloud-platform'], credentials: nil)
          return @@sql_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("SqladminV1beta4").const_get(subclass)
        end
      end

      # Google's StackDriver Logging Service API
      # @param subclass [<Google::Apis::LoggingV2>]: If specified, will return the class ::Google::Apis::LoggingV2::subclass instead of an API client instance
      def self.logging(subclass = nil, credentials: nil)
        require 'google/apis/logging_v2'

        if subclass.nil?
          @@logging_api[credentials] ||= MU::Cloud::Google::Endpoint.new(api: "LoggingV2::LoggingService", scopes: ['https://www.googleapis.com/auth/cloud-platform'], credentials: nil)
          return @@logging_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("LoggingV2").const_get(subclass)
        end
      end


      private

      # Wrapper class for Google APIs, so that we can catch some common
      # transient endpoint errors without having to spray rescues all over the
      # codebase.
      class Endpoint
        @api = nil
        @credentials = nil

        # Create a Google Cloud Platform API client
        # @param api [String]: Which API are we wrapping?
        # @param scopes [Array<String>]: Google auth scopes applicable to this API
        def initialize(api: "ComputeBeta::ComputeService", scopes: ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'], masquerade: nil, credentials: nil)
          @credentials = credentials
          @api = Object.const_get("Google::Apis::#{api}").new
          @api.authorization = MU::Cloud::Google.loadCredentials(scopes, credentials: credentials)
          if masquerade
            @api.authorization.sub = masquerade
            @api.authorization.fetch_access_token!
          end
        end

        # Generic wrapper for deleting Compute resources
        # @param type [String]: The type of resource, typically the string you'll find in all of the API calls referring to it
        # @param project [String]: The project in which we should look for the resources
        # @param region [String]: The region in which to loop for the resources
        # @param noop [Boolean]: If true, will only log messages about resources to be deleted, without actually deleting them
        # @param filter [String]: The Compute API filter string to use to isolate appropriate resources
        def delete(type, project, region = nil, noop = false, filter = "description eq #{MU.deploy_id}", credentials: nil)
          list_sym = "list_#{type.sub(/y$/, "ie")}s".to_sym
          resp = nil
          begin
            if region
              resp = MU::Cloud::Google.compute(credentials: credentials).send(list_sym, project, region, filter: filter)
            else
              resp = MU::Cloud::Google.compute(credentials: credentials).send(list_sym, project, filter: filter)
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
                  retries = 0
                  failed = false
                  begin
                    resp = nil
                    failed = false
                    if region
                      resp = MU::Cloud::Google.compute(credentials: credentials).send(delete_sym, project, region, obj.name)
                    else
                      resp = MU::Cloud::Google.compute(credentials: credentials).send(delete_sym, project, obj.name)
                    end
                    if resp.error and resp.error.errors and resp.error.errors.size > 0
                      failed = true
                      retries += 1
                      if resp.error.errors.first.code == "RESOURCE_IN_USE_BY_ANOTHER_RESOURCE" and retries < 3
                        sleep 10
                      else
                        MU.log "Error deleting #{type.gsub(/_/, " ")} #{obj.name}", MU::ERR, details: resp.error.errors
                        raise MuError, "Failed to delete #{type.gsub(/_/, " ")} #{obj.name}"
                      end
                    else
# TODO validate that the resource actually went away, because it seems not to do so very reliably
                    end
                    failed = false
                  rescue ::Google::Apis::ClientError => e
                    raise e if !e.message.match(/^notFound: /)
                  end while failed and retries < 3
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
          actual_resource = nil
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
            rescue ::Google::Apis::AuthorizationError => e
              if arguments.size > 0
                raise MU::MuError, "Service account #{MU::Cloud::Google.svc_account_name} has insufficient privileges to call #{method_sym} in project #{arguments.first}"
              else
                raise MU::MuError, "Service account #{MU::Cloud::Google.svc_account_name} has insufficient privileges to call #{method_sym}"
              end
            rescue ::Google::Apis::ClientError => e
              if e.message.match(/^invalidParameter:/)
                MU.log "#{method_sym.to_s}: "+e.message, MU::ERR, details: arguments
              end
              if retries <= 1 and e.message.match(/^accessNotConfigured/)
                enable_obj = nil
                project = arguments.size > 0 ? arguments.first.to_s : MU::Cloud::Google.defaultProject(@credentials)
                enable_obj = MU::Cloud::Google.service_manager(:EnableServiceRequest).new(
                  consumer_id: "project:"+project
                )
                # XXX dumbass way to get this string
                e.message.match(/Enable it by visiting https:\/\/console\.developers\.google\.com\/apis\/api\/(.+?)\//)
                svc_name = Regexp.last_match[1]
                save_verbosity = MU.verbosity
                if svc_name != "servicemanagement.googleapis.com"
                  MU.setLogging(MU::Logger::NORMAL)
                  MU.log "Attempting to enable #{svc_name} in project #{project}, then waiting for 30s", MU::WARN
                  MU.setLogging(save_verbosity)
                  MU::Cloud::Google.service_manager(credentials: @credentials).enable_service(svc_name, enable_obj)
                  sleep 30
                  retries += 1
                  retry
                else
                  MU.setLogging(MU::Logger::NORMAL)
                  MU.log "Google Cloud's Service Management API must be enabled manually by visiting #{e.message.gsub(/.*?(https?:\/\/[^\s]+)(?:$|\s).*/, '\1')}", MU::ERR
                  MU.setLogging(save_verbosity)
                  raise MU::MuError, "Service Management API not yet enabled for this account/project"
                end
              elsif retries <= 10 and
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
              orig_target = retval.name
              begin
                if retries > 0 and retries % 3 == 0
                  MU.log "Waiting for #{method_sym} to be done (retry #{retries})", MU::NOTICE
                else
                  MU.log "Waiting for #{method_sym} to be done (retry #{retries})", MU::DEBUG, details: retval
                end

                if retval.status != "DONE"
                  sleep 7
                  begin
                    resp = MU::Cloud::Google.compute(credentials: @credentials).get_global_operation(
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
#if method_sym == :insert_instance
#MU.log "actual_resource", MU::WARN, details: actual_resource
#end
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
               (!method_sym.to_s.match(/^insert_/) or !e.message.match(/^notFound: /) or
                (e.message.match(/^notFound: /) and method_sym.to_s.match(/^insert_/))
               )
              if e.message.match(/^notFound: /) and method_sym.to_s.match(/^insert_/)
                logreq = MU::Cloud::Google.logging(:ListLogEntriesRequest).new(
                  resource_names: ["projects/"+arguments.first],
                  filter: %Q{labels."compute.googleapis.com/resource_id"="#{retval.target_id}" OR labels."ssl_certificate_id"="#{retval.target_id}"} # XXX I guess we need to cover all of the possible keys, ugh
                )
                logs = MU::Cloud::Google.logging(credentials: @credentials).list_entry_log_entries(logreq)
                details = nil
                if logs.entries
                  details = logs.entries.map { |e| e.json_payload }
                  details.reject! { |e| e["error"].nil? or e["error"].size == 0 }
                end

                raise MuError, "#{method_sym.to_s} of #{retval.target_id} appeared to succeed, but then the resource disappeared! #{details.to_s}"
              end
              raise e
            end
            retries = retries + 1
            debuglevel = MU::DEBUG
            interval = 5 + Random.rand(4) - 2
            if retries < 10 and retries > 2
              debuglevel = MU::NOTICE
              interval = 20 + Random.rand(10) - 3
            # elsif retries >= 10 and retries <= 100
            elsif retries >= 10
              debuglevel = MU::WARN
              interval = 40 + Random.rand(15) - 5
            # elsif retries > 100
              # raise MuError, "Exhausted retries after #{retries} attempts while calling Compute's #{method_sym} in #{@region}.  Args were: #{arguments}"
            end

            MU.log "Got #{e.inspect} calling Google's #{method_sym}, waiting #{interval.to_s}s and retrying. Called from: #{caller[1]}", debuglevel, details: arguments
            sleep interval
            MU.log method_sym.to_s.bold+" "+e.inspect, MU::WARN, details: arguments
            retry
          end
        end
      end

      @@compute_api = {}
      @@container_api = {}
      @@storage_api = {}
      @@sql_api = {}
      @@iam_api = {}
      @@logging_api = {}
      @@resource_api = {}
      @@service_api = {}
      @@admin_directory_api = {}
    end
  end
end
