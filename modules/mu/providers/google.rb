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
      @@my_hosted_cfg = nil
      @@authorizers = {}
      @@acct_to_profile_map = {}
      @@enable_semaphores = {}
      @@readonly_semaphore = Mutex.new
      @@readonly = {}

      # Module used by {MU::Cloud} to insert additional instance methods into
      # instantiated resources in this cloud layer.
      module AdditionalResourceMethods
        # Google Cloud url attribute, found in some form on most GCP cloud
        # resources.
        # @return [String]
        def url
          desc = cloud_desc
          (desc and desc.self_link) ? desc.self_link : nil
        end
      end

      # Any cloud-specific instance methods we require our resource
      # implementations to have, above and beyond the ones specified by
      # {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        [:url]
      end

      # Is this a "real" cloud provider, or a stub like CloudFormation?
      def self.virtual?
        false
      end

      # Most of our resource implementation +find+ methods have to mangle their
      # args to make sure they've extracted a project or location argument from
      # other available information. This does it for them.
      # @return [Hash]
      def self.findLocationArgs(**args)
        args[:project] ||= args[:habitat]
        args[:project] ||= MU::Cloud::Google.defaultProject(args[:credentials])
        args[:location] ||= args[:region] || args[:availability_zone] || "-"
        args
      end

      # A hook that is always called just before any of the instance method of
      # our resource implementations gets invoked, so that we can ensure that
      # repetitive setup tasks (like resolving +:resource_group+ for Azure
      # resources) have always been done.
      # @param cloudobj [MU::Cloud]
      # @param deploy [MU::MommaCat]
      def self.resourceInitHook(cloudobj, deploy)
        class << self
          attr_reader :project_id
          attr_reader :customer
          # url is too complex for an attribute (we get it from the cloud API),
          # so it's up in AdditionalResourceMethods instead
        end
        return if !cloudobj

        cloudobj.instance_variable_set(:@customer, MU::Cloud::Google.customerID(cloudobj.config['credentials']))

# XXX ensure @cloud_id and @project_id if this is a habitat
# XXX skip project_id if this is a folder or group
        if deploy
# XXX this may be wrong for new deploys (but def right for regrooms)
          project = MU::Cloud::Google.projectLookup(cloudobj.config['project'], deploy, sibling_only: true, raise_on_fail: false)
          project_id = project.nil? ? cloudobj.config['project'] : project.cloudobj.cloud_id
          cloudobj.instance_variable_set(:@project_id, project_id)
        else
          cloudobj.instance_variable_set(:@project_id, cloudobj.config['project'])
        end

# XXX @url? Well we're not likely to have @cloud_desc at this point, so maybe
# that needs to be a generic-to-google wrapper like def url; cloud_desc.self_link;end

# XXX something like: vpc["habitat"] = MU::Cloud::Google.projectToRef(vpc["project"], config: configurator, credentials: vpc["credentials"])
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

      # If we reside in this cloud, return the VPC in which we, the Mu Master, reside.
      # @return [MU::Cloud::VPC]
      def self.myVPCObj
        return nil if !hosted?
        instance = MU.myCloudDescriptor
        return nil if !instance or !instance.network_interfaces or instance.network_interfaces.size == 0
        vpc = MU::MommaCat.findStray("Google", "vpc", cloud_id: instance.network_interfaces.first.network.gsub(/.*?\/([^\/]+)$/, '\1'), dummy_ok: true, habitats: [myProject])
        return nil if vpc.nil? or vpc.size == 0
        vpc.first
      end

      # Return the name strings of all known sets of credentials for this cloud
      # @return [Array<String>]
      def self.listCredentials
        if !$MU_CFG['google']
          return hosted? ? ["#default"] : nil
        end

        $MU_CFG['google'].keys
      end

      @@habmap = {}

      # Return what we think of as a cloud object's habitat. In GCP, this means
      # the +project_id+ in which is resident. If this is not applicable, such
      # as for a {Habitat} or {Folder}, returns nil.
      # @param cloudobj [MU::Cloud::Google]: The resource from which to extract the habitat id
      # @return [String,nil]
      def self.habitat(cloudobj, nolookup: false, deploy: nil)
        @@habmap ||= {}
# XXX whaddabout config['habitat'] HNNNGH
        return nil if !cloudobj.cloudclass.canLiveIn.include?(:Habitat)

# XXX these are assholes because they're valid two different ways ugh ugh
        return nil if [MU::Cloud::Google::Group, MU::Cloud::Google::Folder].include?(cloudobj.cloudclass)
        if cloudobj.config and cloudobj.config['project']
          if nolookup
            return cloudobj.config['project']
          end
          if @@habmap[cloudobj.config['project']]
            return @@habmap[cloudobj.config['project']]
          end
          deploy ||= cloudobj.deploy if cloudobj.respond_to?(:deploy)
          projectobj = projectLookup(cloudobj.config['project'], deploy, raise_on_fail: false)

          if projectobj
            @@habmap[cloudobj.config['project']] = projectobj.cloud_id
            return projectobj.cloud_id
          end
        end

        # blow up if this resource *has* to live in a project
        if cloudobj.cloudclass.canLiveIn == [:Habitat]
          MU.log "Failed to find project for cloudobj #{cloudobj.to_s}", MU::ERR, details: cloudobj
          raise MuError, "Failed to find project for cloudobj #{cloudobj.to_s}"
        end

        nil
      end

      # Take a plain string that might be a reference to sibling project
      # declared elsewhere in the active stack, or the project id of a live
      # cloud resource, and return a {MU::Config::Ref} object
      # @param project [String]: The name of a sibling project, or project id of an active project in GCP
      # @param config [MU::Config]: A {MU::Config} object containing sibling resources, typically what we'd pass if we're calling during configuration parsing
      # @param credentials [String]: 
      # @return [MU::Config::Ref]
      def self.projectToRef(project, config: nil, credentials: nil)
        return nil if !project

        if config and config.haveLitterMate?(project, "habitat")
          ref = MU::Config::Ref.new(
            name: project,
            cloud: "Google",
            credentials: credentials,
            type: "habitats"
          )
        end
        
        if !ref
          resp = MU::MommaCat.findStray(
            "Google",
            "habitats",
            cloud_id: project,
            credentials: credentials,
            dummy_ok: true
          )
          if resp and resp.size > 0
            project_obj = resp.first
            ref = MU::Config::Ref.new(
              id: project_obj.cloud_id,
              cloud: "Google",
              credentials: credentials,
              type: "habitats"
            )
          end
        end

        ref
      end

      # A shortcut for {MU::MommaCat.findStray} to resolve a shorthand project
      # name into a cloud object, whether it refers to a sibling by internal
      # name or by cloud identifier.
      # @param name [String]
      # @param deploy [String]
      # @param raise_on_fail [Boolean]
      # @param sibling_only [Boolean]
      # @return [MU::Config::Habitat,nil]
      def self.projectLookup(name, deploy = MU.mommacat, raise_on_fail: true, sibling_only: false)
        project_obj = deploy.findLitterMate(type: "habitats", name: name) if deploy and caller.grep(/`findLitterMate'/).empty? # XXX the dumbest

        if !project_obj and !sibling_only
          resp = MU::MommaCat.findStray(
            "Google",
            "habitats",
            deploy_id: deploy ? deploy.deploy_id : nil,
            cloud_id: name,
            name: name,
            dummy_ok: true
          )

          project_obj = resp.first if resp and resp.size > 0
        end

        if (!project_obj or !project_obj.cloud_id) and raise_on_fail
          raise MuError, "Failed to find project '#{name}' in deploy #{deploy.deploy_id}"
        end

        project_obj
      end

      # Resolve the administrative Cloud Storage bucket for a given credential
      # set, or return a default.
      # @param credentials [String]
      # @return [String]
      def self.adminBucketName(credentials = nil)
         #XXX find a default if this particular account doesn't have a log_bucket_name configured
        cfg = credConfig(credentials)
        if cfg.nil?
          raise MuError, "Failed to load Google credential set #{credentials}"
        end
        cfg['log_bucket_name']
      end

      # Resolve the administrative Cloud Storage bucket for a given credential
      # set, or return a default.
      # @param credentials [String]
      # @return [String]
      def self.adminBucketUrl(credentials = nil)
        "gs://"+adminBucketName(credentials)+"/"
      end

      # Return the $MU_CFG data associated with a particular profile/name/set of
      # credentials. If no account name is specified, will return one flagged as
      # default. Returns nil if GCP is not configured. Throws an exception if 
      # an account name is specified which does not exist.
      # @param name [String]: The name of the key under 'google' in mu.yaml to return
      # @return [Hash,nil]
      def self.credConfig(name = nil, name_only: false)
        # If there's nothing in mu.yaml (which is wrong), but we're running
        # on a machine hosted in GCP, fake it with that machine's service
        # account and hope for the best.
        if !$MU_CFG['google'] or !$MU_CFG['google'].is_a?(Hash) or $MU_CFG['google'].size == 0
          return @@my_hosted_cfg if @@my_hosted_cfg

          if hosted?
            @@my_hosted_cfg = hosted_config
            return name_only ? "#default" : @@my_hosted_cfg
          end

          return nil
        end

        if name.nil?
          $MU_CFG['google'].each_pair { |set, cfg|
            if cfg['default']
              return name_only ? set : cfg
            end
          }
        else
          if $MU_CFG['google'][name]
            return name_only ? name : $MU_CFG['google'][name]
          elsif @@acct_to_profile_map[name.to_s]
            return name_only ? name : @@acct_to_profile_map[name.to_s]
          end
# XXX whatever process might lead us to populate @@acct_to_profile_map with some mappings, like projectname -> account profile, goes here
          return nil
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
        else
          @@myRegion_var = "us-east4"
        end
        @@myRegion_var
      end

      # Do cloud-specific deploy instantiation tasks, such as copying SSH keys
      # around, sticking secrets in buckets, creating resource groups, etc
      # @param deploy [MU::MommaCat]
      def self.initDeploy(deploy)
      end

      # Purge cloud-specific deploy meta-artifacts (SSH keys, resource groups,
      # etc)
      # @param deploy_id [MU::MommaCat]
      def self.cleanDeploy(deploy_id, credentials: nil, noop: false)
        removeDeploySecretsAndRoles(deploy_id, noop: noop, credentials: credentials)
      end

      # Plant a Mu deploy secret into a storage bucket somewhere for so our kittens can consume it
      # @param deploy_id [String]: The deploy for which we're writing the secret
      # @param value [String]: The contents of the secret
      def self.writeDeploySecret(deploy, value, name = nil, credentials: nil)
        deploy_id = deploy.deploy_id
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
          MU::Cloud::Google.storage(credentials: credentials).insert_object(
            adminBucketName(credentials),
            objectobj,
            upload_source: f.path
          )
          f.unlink
        rescue ::Google::Apis::ClientError => e
          raise MU::MommaCat::DeployInitializeError, "Got #{e.inspect} trying to write #{name} to #{adminBucketName(credentials)}"
        end
      end

      # Remove the service account and various deploy secrets associated with a deployment. Intended for invocation from MU::Cleanup.
      # @param deploy_id [String]: The deploy for which we're granting the secret
      # @param noop [Boolean]: If true, will only print what would be done
      def self.removeDeploySecretsAndRoles(deploy_id = MU.deploy_id, flags: {}, noop: false, credentials: nil)
        cfg = credConfig(credentials)
        return if !cfg or !cfg['project']
        flags["project"] ||= cfg['project']

        resp = MU::Cloud::Google.storage(credentials: credentials).list_objects(
          adminBucketName(credentials),
          prefix: deploy_id
        )
        if resp and resp.items
          resp.items.each { |obj|
            MU.log "Deleting gs://#{adminBucketName(credentials)}/#{obj.name}"
            if !noop
              MU::Cloud::Google.storage(credentials: credentials).delete_object(
                adminBucketName(credentials),
                obj.name
              )
            end
          }
        end
      end

      # Grant access to appropriate Cloud Storage objects in our log/secret bucket for a deploy member.
      # @param acct [String]: The service account (by email addr) to which we'll grant access
      # @param deploy_id [String]: The deploy for which we're granting the secret
      # XXX add equivalent for AWS and call agnostically
      def self.grantDeploySecretAccess(acct, deploy_id = MU.deploy_id, name = nil, credentials: nil)
        name ||= deploy_id+"-secret"
        aclobj = nil

        retries = 0
        begin
          MU.log "Granting #{acct} access to list Cloud Storage bucket #{adminBucketName(credentials)}"
          MU::Cloud::Google.storage(credentials: credentials).insert_bucket_access_control(
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

          [name].each { |obj|
            MU.log "Granting #{acct} access to #{obj} in Cloud Storage bucket #{adminBucketName(credentials)}"

            MU::Cloud::Google.storage(credentials: credentials).insert_object_access_control(
              adminBucketName(credentials),
              obj,
              aclobj
            )
          }
        rescue ::Google::Apis::ClientError => e
MU.log e.message, MU::WARN, details: e.inspect
          if e.inspect.match(/body: "Not Found"/)
            raise MuError, "Google admin bucket #{adminBucketName(credentials)} or key #{name} does not appear to exist or is not visible with #{credentials ? credentials : "default"} credentials"
          elsif e.message.match(/notFound: |Unknown user:|conflict: /)
            if retries < 5
              sleep 5
              retries += 1
              retry
            else
              raise e
            end
          elsif e.inspect.match(/The metadata for object "null" was edited during the operation/)
            MU.log e.message+" - Google admin bucket #{adminBucketName(credentials)}/#{name} with #{credentials ? credentials : "default"} credentials", MU::DEBUG, details: aclobj
            sleep 10
            retry
          else
            raise MuError, "Got #{e.message} trying to set ACLs for #{deploy_id} in #{adminBucketName(credentials)}"
          end
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
        if $MU_CFG.has_key?("google_is_hosted")
          @@is_in_aws = $MU_CFG["google_is_hosted"]
          return $MU_CFG["google_is_hosted"]
        end
        if !@@is_in_gcp.nil?
          return @@is_in_gcp
        end

        if getGoogleMetaData("project/project-id")
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
      # @return [Google::Apis::ComputeV1::SslCertificate]
      def self.createSSLCertificate(name, cert, key, flags = {}, credentials: nil)
        flags["project"] ||= MU::Cloud::Google.defaultProject(credentials)
        flags["description"] ||= MU.deploy_id
        certobj = ::Google::Apis::ComputeV1::SslCertificate.new(
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
        if @@authorizers[credentials] and @@authorizers[credentials][scopes.to_s]
          return @@authorizers[credentials][scopes.to_s]
        end

        cfg = credConfig(credentials)

        if cfg
          if cfg['project']
            @@enable_semaphores[cfg['project']] ||= Mutex.new
          end
          data = nil
          @@authorizers[credentials] ||= {}
  
          def self.get_machine_credentials(scopes, credentials = nil)
            @@svc_account_name = MU::Cloud::Google.getGoogleMetaData("instance/service-accounts/default/email")
            MU.log "We are hosted in GCP, so I will attempt to use the service account #{@@svc_account_name} to make API requests.", MU::DEBUG

            @@authorizers[credentials][scopes.to_s] = ::Google::Auth.get_application_default(scopes)
            @@authorizers[credentials][scopes.to_s].fetch_access_token!
            @@default_project ||= MU::Cloud::Google.getGoogleMetaData("project/project-id")
            begin
              listRegions(credentials: credentials)
              listInstanceTypes(credentials: credentials)
              listHabitats(credentials)
            rescue ::Google::Apis::ClientError
              MU.log "Found machine credentials #{@@svc_account_name}, but these don't appear to have sufficient permissions or scopes", MU::WARN, details: scopes
              @@authorizers.delete(credentials)
              return nil
            end
            @@authorizers[credentials][scopes.to_s]
          end

          if cfg["credentials_file"] or cfg["credentials_encoded"]

            begin
              data = if cfg["credentials_encoded"]
                JSON.parse(Base64.decode64(cfg["credentials_encoded"]))
              else
                JSON.parse(File.read(cfg["credentials_file"]))
              end
              @@default_project ||= data["project_id"]
              creds = {
                :json_key_io => StringIO.new(MultiJson.dump(data)),
                :scope => scopes
              }
              @@svc_account_name = data["client_email"]
              @@authorizers[credentials][scopes.to_s] = ::Google::Auth::ServiceAccountCredentials.make_creds(creds)
              return @@authorizers[credentials][scopes.to_s]
            rescue JSON::ParserError, Errno::ENOENT, Errno::EACCES => e
              if !MU::Cloud::Google.hosted?
                raise MuError, "Google Cloud credentials file #{cfg["credentials_file"]} is missing or invalid (#{e.message})"
              end
              MU.log "Google Cloud credentials file #{cfg["credentials_file"]} is missing or invalid", MU::WARN, details: e.message
              return get_machine_credentials(scopes, credentials)
            end
          elsif cfg["credentials"]
            begin
              vault, item = cfg["credentials"].split(/:/)
              data = MU::Groomer::Chef.getSecret(vault: vault, item: item).to_h
            rescue MU::Groomer::MuNoSuchSecret
              if !MU::Cloud::Google.hosted?
                raise MuError, "Google Cloud credentials not found in Vault #{vault}:#{item}"
              end
              MU.log "Google Cloud credentials not found in Vault #{vault}:#{item}", MU::WARN
              found = get_machine_credentials(scopes, credentials)
              raise MuError, "No valid credentials available! Either grant admin privileges to machine service account, or manually add a different one with mu-configure" if found.nil?
              return found
            end

            @@default_project ||= data["project_id"]
            creds = {
              :json_key_io => StringIO.new(MultiJson.dump(data)),
              :scope => scopes
            }
            @@svc_account_name = data["client_email"]
            @@authorizers[credentials][scopes.to_s] = ::Google::Auth::ServiceAccountCredentials.make_creds(creds)
            return @@authorizers[credentials][scopes.to_s]
          elsif MU::Cloud::Google.hosted?
            found = get_machine_credentials(scopes, credentials)
            raise MuError, "No valid credentials available! Either grant admin privileges to machine service account, or manually add a different one with mu-configure" if found.nil?
            return found
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

      @@default_project_cache = {}

      # Our credentials map to a project, an organizational structure in Google
      # Cloud. This fetches the identifier of the project associated with our
      # default credentials.
      # @param credentials [String]
      # @return [String]
      def self.defaultProject(credentials = nil)
        if @@default_project_cache.has_key?(credentials)
          return @@default_project_cache[credentials]
        end
        cfg = credConfig(credentials)
        if !cfg or !cfg['project']
          if hosted?
            @@default_project_cache[credentials] = myProject
            return myProject 
          end
          if cfg
            begin
              result = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects
              result.projects.reject! { |p| p.lifecycle_state == "DELETE_REQUESTED" }
              available = result.projects.map { |p| p.project_id }
              if available.size == 1
                @@default_project_cache[credentials] = available[0]
                return available[0]
              end
            rescue # fine
            end
          end
        end
        return nil if !cfg
        loadCredentials(credentials) if !@@authorizers[credentials]
        @@default_project_cache[credentials] = cfg['project']
        cfg['project']
      end

      # We want a default place to put new projects for the Habitat resource,
      # so if we have a root folder, we can go ahead and use that.
      # @param credentials [String]
      # @return [String]
      def self.defaultFolder(credentials = nil)
        project = defaultProject(credentials)
        resp = MU::Cloud::Google.resource_manager(credentials: credentials).get_project_ancestry(project)
        resp.ancestor.each { |a|
          if a.resource_id.type == "folder"
            return a.resource_id.id
          end
        }
        nil
      end

      @allprojects = []

      # List all Google Cloud Platform projects available to our credentials
      def self.listHabitats(credentials = nil, use_cache: true)
        cfg = credConfig(credentials)
        return [] if !cfg
        if cfg['restrict_to_habitats'] and cfg['restrict_to_habitats'].is_a?(Array)
          cfg['restrict_to_habitats'] << cfg['project'] if cfg['project']
          return cfg['restrict_to_habitats'].uniq
        end
        if @allprojects and !@allprojects.empty? and use_cache
          return @allprojects
        end
        result = MU::Cloud::Google.resource_manager(credentials: credentials).list_projects
        result.projects.reject! { |p| p.lifecycle_state == "DELETE_REQUESTED" }
        @allprojects = result.projects.map { |p| p.project_id }
        if cfg['ignore_habitats'] and cfg['ignore_habitats'].is_a?(Array)
          @allprojects.reject! { |p| cfg['ignore_habitats'].include?(p) }
        end
        @allprojects
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
      def self.listInstanceTypes(region = self.myRegion, credentials: nil, project: MU::Cloud::Google.defaultProject)
        return {} if !credConfig(credentials)
        if @@instance_types and
           @@instance_types[project] and
           @@instance_types[project][region]
          return @@instance_types
        end

        return {} if !project

        @@instance_types ||= {}
        @@instance_types[project] ||= {}
        @@instance_types[project][region] ||= {}
        result = MU::Cloud::Google.compute(credentials: credentials).list_machine_types(project, listAZs(region).first)
        result.items.each { |type|
          @@instance_types[project][region][type.name] ||= {}
          @@instance_types[project][region][type.name]["memory"] = sprintf("%.1f", type.memory_mb/1024.0).to_f
          @@instance_types[project][region][type.name]["vcpu"] = type.guest_cpus.to_f
          if type.is_shared_cpu
            @@instance_types[project][region][type.name]["ecu"] = "Variable"
          else
            @@instance_types[project][region][type.name]["ecu"] = type.guest_cpus
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
      def self.listAZs(region = self.myRegion)
        return [] if !credConfig
        MU::Cloud::Google.listRegions if !@@regions.has_key?(region)
        if !@@regions.has_key?(region)
          MU.log "Failed to get GCP region #{region}", MU::ERR, details: @@regions
          raise MuError, "No such Google Cloud region '#{region}'" if !@@regions.has_key?(region)
        end
        @@regions[region]
      end

      # Google's Compute Service API
      # @param subclass [<Google::Apis::ComputeV1>]: If specified, will return the class ::Google::Apis::ComputeV1::subclass instead of an API client instance
      def self.compute(subclass = nil, credentials: nil)
        require 'google/apis/compute_v1'

        if subclass.nil?
          @@compute_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "ComputeV1::ComputeService", scopes: ['cloud-platform', 'compute.readonly'], credentials: credentials)
          return @@compute_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("ComputeV1").const_get(subclass)
        end
      end

      # Google's Storage Service API
      # @param subclass [<Google::Apis::StorageV1>]: If specified, will return the class ::Google::Apis::StorageV1::subclass instead of an API client instance
      def self.storage(subclass = nil, credentials: nil)
        require 'google/apis/storage_v1'

        if subclass.nil?
          @@storage_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "StorageV1::StorageService", scopes: ['cloud-platform'], credentials: credentials)
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
          @@iam_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "IamV1::IamService", scopes: ['cloud-platform', 'cloudplatformprojects', 'cloudplatformorganizations', 'cloudplatformfolders'], credentials: credentials)
          return @@iam_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("IamV1").const_get(subclass)
        end
      end

      # GCP's AdminDirectory Service API
      # @param subclass [<Google::Apis::AdminDirectoryV1>]: If specified, will return the class ::Google::Apis::AdminDirectoryV1::subclass instead of an API client instance
      def self.admin_directory(subclass = nil, credentials: nil)
        require 'google/apis/admin_directory_v1'

        # fill in the default credential set name so we don't generate
        # dopey extra warnings about falling back on scopes
        credentials ||= MU::Cloud::Google.credConfig(credentials, name_only: true)

        writescopes = ['admin.directory.group.member', 'admin.directory.group', 'admin.directory.user', 'admin.directory.domain', 'admin.directory.orgunit', 'admin.directory.rolemanagement', 'admin.directory.customer', 'admin.directory.user.alias', 'admin.directory.userschema']
        readscopes = ['admin.directory.group.member.readonly', 'admin.directory.group.readonly', 'admin.directory.user.readonly', 'admin.directory.domain.readonly', 'admin.directory.orgunit.readonly', 'admin.directory.rolemanagement.readonly', 'admin.directory.customer.readonly', 'admin.directory.user.alias.readonly', 'admin.directory.userschema.readonly']
        @@readonly_semaphore.synchronize {
          use_scopes = readscopes+writescopes
          if @@readonly[credentials] and @@readonly[credentials]["AdminDirectoryV1"]
            use_scopes = readscopes.dup
          end

          if subclass.nil?
            begin
              @@admin_directory_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "AdminDirectoryV1::DirectoryService", scopes: use_scopes, masquerade: MU::Cloud::Google.credConfig(credentials)['masquerade_as'], credentials: credentials, auth_error_quiet: true)
            rescue Signet::AuthorizationError
              MU.log "Falling back to read-only access to DirectoryService API for credential set '#{credentials}'", MU::WARN
              @@admin_directory_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "AdminDirectoryV1::DirectoryService", scopes: readscopes, masquerade: MU::Cloud::Google.credConfig(credentials)['masquerade_as'], credentials: credentials)
              @@readonly[credentials] ||= {}
              @@readonly[credentials]["AdminDirectoryV1"] = true
            end
            return @@admin_directory_api[credentials]
          elsif subclass.is_a?(Symbol)
            return Object.const_get("::Google").const_get("Apis").const_get("AdminDirectoryV1").const_get(subclass)
          end
        }
      end

      # Google's Cloud Resource Manager API
      # @param subclass [<Google::Apis::CloudresourcemanagerV1>]: If specified, will return the class ::Google::Apis::CloudresourcemanagerV1::subclass instead of an API client instance
      def self.resource_manager(subclass = nil, credentials: nil)
        require 'google/apis/cloudresourcemanager_v1'

        if subclass.nil?
          if !MU::Cloud::Google.credConfig(credentials)
            raise MuError, "No such credential set #{credentials} defined in mu.yaml!"
          end
          @@resource_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "CloudresourcemanagerV1::CloudResourceManagerService", scopes: ['cloud-platform', 'cloudplatformprojects', 'cloudplatformorganizations', 'cloudplatformfolders'], credentials: credentials, masquerade: MU::Cloud::Google.credConfig(credentials)['masquerade_as'])
          return @@resource_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("CloudresourcemanagerV1").const_get(subclass)
        end
      end

      # Google's Cloud Resource Manager API V2, which apparently has all the folder bits
      # @param subclass [<Google::Apis::CloudresourcemanagerV2>]: If specified, will return the class ::Google::Apis::CloudresourcemanagerV2::subclass instead of an API client instance
      def self.folder(subclass = nil, credentials: nil)
        require 'google/apis/cloudresourcemanager_v2'

        if subclass.nil?
          @@resource2_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "CloudresourcemanagerV2::CloudResourceManagerService", scopes: ['cloud-platform', 'cloudplatformfolders'], credentials: credentials,  masquerade: MU::Cloud::Google.credConfig(credentials)['masquerade_as'])
          return @@resource2_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("CloudresourcemanagerV2").const_get(subclass)
        end
      end

      # Google's Container API
      # @param subclass [<Google::Apis::ContainerV1>]: If specified, will return the class ::Google::Apis::ContainerV1::subclass instead of an API client instance
      def self.container(subclass = nil, credentials: nil)
        require 'google/apis/container_v1'

        if subclass.nil?
          @@container_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "ContainerV1::ContainerService", scopes: ['cloud-platform'], credentials: credentials)
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
          @@service_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "ServicemanagementV1::ServiceManagementService", scopes: ['cloud-platform'], credentials: credentials)
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
          @@sql_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "SqladminV1beta4::SQLAdminService", scopes: ['cloud-platform'], credentials: credentials)
          return @@sql_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("SqladminV1beta4").const_get(subclass)
        end
      end

      # Google's Firestore (NoSQL) Service API
      # @param subclass [<Google::Apis::FirestoreV1>]: If specified, will return the class ::Google::Apis::FirestoreV1::subclass instead of an API client instance
      def self.firestore(subclass = nil, credentials: nil)
        require 'google/apis/firestore_v1'

        if subclass.nil?
          @@firestore_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "FirestoreV1::FirestoreService", scopes: ['cloud-platform'], credentials: credentials)
          return @@firestore_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("FirestoreV1").const_get(subclass)
        end
      end

      # Google's StackDriver Logging Service API
      # @param subclass [<Google::Apis::LoggingV2>]: If specified, will return the class ::Google::Apis::LoggingV2::subclass instead of an API client instance
      def self.logging(subclass = nil, credentials: nil)
        require 'google/apis/logging_v2'

        if subclass.nil?
          @@logging_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "LoggingV2::LoggingService", scopes: ['cloud-platform'], credentials: credentials)
          return @@logging_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("LoggingV2").const_get(subclass)
        end
      end

      # Google's Cloud Billing Service API
      # @param subclass [<Google::Apis::CloudbillingV1>]: If specified, will return the class ::Google::Apis::CloudbillingV1::subclass instead of an API client instance
      def self.budgets(subclass = nil, credentials: nil)
        require 'google/apis/billingbudgets_v1'

        if subclass.nil?
          @@budgets_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "BillingbudgetsV1::CloudBillingBudgetService", scopes: ['cloud-platform', 'cloud-billing'], credentials: credentials, masquerade: MU::Cloud::Google.credConfig(credentials)['masquerade_as'])
          return @@budgets_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("BillingbudgetsV1").const_get(subclass)
        end
      end

      # Google's Cloud Billing Budget Service API
      # @param subclass [<Google::Apis::CloudbillingV1>]: If specified, will return the class ::Google::Apis::CloudbillingV1::subclass instead of an API client instance
      def self.billing(subclass = nil, credentials: nil)
        require 'google/apis/cloudbilling_v1'

        if subclass.nil?
          @@billing_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "CloudbillingV1::CloudbillingService", scopes: ['cloud-platform', 'cloud-billing'], credentials: credentials, masquerade: MU::Cloud::Google.credConfig(credentials)['masquerade_as'])
          return @@billing_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("CloudbillingV1").const_get(subclass)
        end
      end

      # Google's Cloud Function Service API
      # @param subclass [<Google::Apis::CloudfunctionsV1>]: If specified, will return the class ::Google::Apis::LoggingV2::subclass instead of an API client instance
      def self.function(subclass = nil, credentials: nil)
        require 'google/apis/cloudfunctions_v1'

        if subclass.nil?
          @@function_api[credentials] ||= MU::Cloud::Google::GoogleEndpoint.new(api: "CloudfunctionsV1::CloudFunctionsService", scopes: ['cloud-platform'], credentials: credentials, masquerade: MU::Cloud::Google.credConfig(credentials)['masquerade_as'])
          return @@function_api[credentials]
        elsif subclass.is_a?(Symbol)
          return Object.const_get("::Google").const_get("Apis").const_get("CloudfunctionsV1").const_get(subclass)
        end
      end

      # Retrieve the domains, if any, which these credentials can manage via
      # GSuite or Cloud Identity.
      # @param credentials [String]
      # @return [Array<String>],nil]
      def self.getDomains(credentials = nil)
        my_org = getOrg(credentials)
        return nil if !my_org

        resp = MU::Cloud::Google.admin_directory(credentials: credentials).list_domains(MU::Cloud::Google.customerID(credentials))
        resp.domains.map { |d| d.domain_name.downcase }
      end

      @@orgmap = {}
      # Retrieve the organization, if any, to which these credentials belong.
      # @param credentials [String]
      # @return [Array<OpenStruct>],nil]
      def self.getOrg(credentials = nil, with_id: nil)
        creds = MU::Cloud::Google.credConfig(credentials)
        return nil if !creds
        credname = if creds and creds['name']
          creds['name']
        else
          "default"
        end 

        with_id ||= creds['org'] if creds['org'] 
        return @@orgmap[credname] if @@orgmap.has_key?(credname)
        resp = MU::Cloud::Google.resource_manager(credentials: credname).search_organizations

        if resp and resp.organizations
          # XXX no idea if it's possible to be a member of multiple orgs
          if !with_id
            @@orgmap[credname] = resp.organizations.first
            return resp.organizations.first
          else
            resp.organizations.each { |org|
              if org.name == with_id or org.display_name == with_id or
                 org.name == "organizations/#{with_id}"
                @@orgmap[credname] = org
                return org
              end
            }
            return nil
          end
        end

        @@orgmap[credname] = nil

        
        MU.log "Unable to list_organizations with credentials #{credname}. If this account is part of a GSuite or Cloud Identity domain, verify that Oauth delegation is properly configured and that 'masquerade_as' is properly set for the #{credname} Google credential set in mu.yaml.", MU::ERR, details: ["https://cloud.google.com/resource-manager/docs/creating-managing-organization", "https://admin.google.com/AdminHome?chromeless=1#OGX:ManageOauthClients"]

        nil
      end

      @@customer_ids_cache = {}

      # Fetch the GSuite/Cloud Identity customer id for the domain associated
      # with the given credentials, if a domain is set via the +masquerade_as+
      # configuration option.
      def self.customerID(credentials = nil)
        cfg = credConfig(credentials)
        if !cfg or !cfg['masquerade_as']
          return nil
        end

        if @@customer_ids_cache[credentials]
          return @@customer_ids_cache[credentials]
        end

        user = MU::Cloud::Google.admin_directory(credentials: credentials).get_user(cfg['masquerade_as'])
        if user and user.customer_id
          @@customer_ids_cache[credentials] = user.customer_id
        end

        @@customer_ids_cache[credentials]
      end

      # Wrapper class for Google APIs, so that we can catch some common
      # transient endpoint errors without having to spray rescues all over the
      # codebase.
      class GoogleEndpoint
        @api = nil
        @credentials = nil
        @scopes = nil
        @masquerade = nil
        attr_reader :issuer

        # Create a Google Cloud Platform API client
        # @param api [String]: Which API are we wrapping?
        # @param scopes [Array<String>]: Google auth scopes applicable to this API
        def initialize(api: "ComputeV1::ComputeService", scopes: ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute.readonly'], masquerade: nil, credentials: nil, auth_error_quiet: false)
          @credentials = credentials
          @scopes = scopes.map { |s|
            if !s.match(/\//) # allow callers to use shorthand
              s = "https://www.googleapis.com/auth/"+s
            end
            s
          }
          @masquerade = masquerade
          @api = Object.const_get("Google::Apis::#{api}").new
          @api.authorization = MU::Cloud::Google.loadCredentials(@scopes, credentials: credentials)
          raise MuError, "No useable Google credentials found#{credentials ? " with set '#{credentials}'" : ""}" if @api.authorization.nil?
          if @masquerade
            begin
              @api.authorization.sub = @masquerade
              @api.authorization.fetch_access_token!
            rescue Signet::AuthorizationError => e
              if auth_error_quiet
                MU.log "Cannot masquerade as #{@masquerade} to API #{api}: #{e.message}", MU::DEBUG, details: @scopes
              else
                MU.log "Cannot masquerade as #{@masquerade} to API #{api}: #{e.message}", MU::ERROR, details: @scopes
                if e.message.match(/client not authorized for any of the scopes requested/)
# XXX it'd be helpful to list *all* scopes we like, as well as the API client's numeric id
                  MU.log "To grant access to API scopes for this service account, see:", MU::ERR, details: "https://admin.google.com/AdminHome?chromeless=1#OGX:ManageOauthClients"
                end
              end

              raise e
            end
          end
          @issuer = @api.authorization.issuer
        end

        # Generic wrapper for deleting Compute resources, which are consistent
        # enough that we can get away with this.
        # @param type [String]: The type of resource, typically the string you'll find in all of the API calls referring to it
        # @param project [String]: The project in which we should look for the resources
        # @param region [String]: The region in which to loop for the resources
        # @param noop [Boolean]: If true, will only log messages about resources to be deleted, without actually deleting them
        # @param filter [String]: The Compute API filter string to use to isolate appropriate resources
        def delete(type, project, region = nil, noop = false, filter = "description eq #{MU.deploy_id}", credentials: nil)
          list_sym = "list_#{type.sub(/y$/, "ie")}s".to_sym
          credentials ||= @credentials
          resp = nil
          begin
            if region
              resp = MU::Cloud::Google.compute(credentials: credentials).send(list_sym, project, region, filter: filter, mu_gcp_enable_apis: false)
            else
              resp = MU::Cloud::Google.compute(credentials: credentials).send(list_sym, project, filter: filter, mu_gcp_enable_apis: false)
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
                Thread.abort_on_exception = false
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
                      if resp.error.errors.first.code == "RESOURCE_IN_USE_BY_ANOTHER_RESOURCE" and retries < 6
                        sleep 10
                      else
                        MU.log "Error deleting #{type.gsub(/_/, " ")} #{obj.name}", MU::ERR, details: resp.error.errors
                        Thread.abort_on_exception = false
                        raise MuError, "Failed to delete #{type.gsub(/_/, " ")} #{obj.name}"
                      end
                    else
                      failed = false
                    end
# TODO validate that the resource actually went away, because it seems not to do so very reliably
                  rescue ::Google::Apis::ClientError => e
                    raise e if !e.message.match(/(^notFound: |operation in progress)/)
                  rescue MU::Cloud::MuDefunctHabitat => e
                    # this is ok- it's already deleted
                  end while failed and retries < 6
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

          enable_on_fail = true
          arguments.each { |arg|
            if arg.is_a?(Hash) and arg.has_key?(:mu_gcp_enable_apis)
              enable_on_fail = arg[:mu_gcp_enable_apis]
              arg.delete(:mu_gcp_enable_apis)
              
            end
          }
          arguments.delete({})
          next_page_token = nil
          overall_retval = nil

          begin
            MU.log "Calling #{method_sym}", MU::DEBUG, details: arguments
            retval = nil
            retries = 0
            wait_backoff = 5
            if next_page_token 
              if method_sym != :list_entry_log_entries
                if arguments.size == 1 and arguments.first.is_a?(Hash)
                  arguments[0][:page_token] = next_page_token
                else
                  arguments << { :page_token => next_page_token }
                end
              elsif arguments.first.class == ::Google::Apis::LoggingV2::ListLogEntriesRequest
                arguments[0] = ::Google::Apis::LoggingV2::ListLogEntriesRequest.new(
                  resource_names: arguments.first.resource_names,
                  filter: arguments.first.filter,
                  page_token: next_page_token
                )
              end
            end
            begin
              if !arguments.nil? and arguments.size == 1
                retval = @api.method(method_sym).call(arguments[0])
              elsif !arguments.nil? and arguments.size > 0
                retval = @api.method(method_sym).call(*arguments)
              else
                retval = @api.method(method_sym).call
              end
            rescue ArgumentError => e
              MU.log "#{e.class.name} calling #{@api.class.name}.#{method_sym.to_s}: #{e.message}", MU::ERR, details: arguments
              raise e
            rescue ::Google::Apis::AuthorizationError => e
              if arguments.size > 0
                raise MU::MuError, "Service account #{MU::Cloud::Google.svc_account_name} has insufficient privileges to call #{method_sym} in project #{arguments.first}"
              else
                raise MU::MuError, "Service account #{MU::Cloud::Google.svc_account_name} has insufficient privileges to call #{method_sym}"
              end
            rescue ::Google::Apis::RateLimitError, ::Google::Apis::TransmissionError, ::ThreadError, ::Google::Apis::ServerError => e
              if retries <= 10
                sleep wait_backoff
                retries += 1
                wait_backoff = wait_backoff * 2
                retry
              else
                raise e
              end
            rescue ::Google::Apis::ClientError, OpenSSL::SSL::SSLError => e
              if e.message.match(/^quotaExceeded: Request rate/)
                if retries <= 10
                  sleep wait_backoff
                  retries += 1
                  wait_backoff = wait_backoff * 2
                  retry
                else
                  raise e
                end
              elsif e.message.match(/^invalidParameter:|^badRequest:/)
                MU.log "#{e.class.name} calling #{@api.class.name}.#{method_sym.to_s}: "+e.message, MU::ERR, details: arguments
# uncomment for debugging stuff; this can occur in benign situations so we don't normally want it logging
              elsif e.message.match(/^forbidden:/)
                MU.log "#{e.class.name} calling #{@api.class.name}.#{method_sym.to_s} got \"#{e.message}\" using credentials #{@credentials}#{@masquerade ? " (OAuth'd as #{@masquerade})": ""}.#{@scopes ? "\nScopes:\n#{@scopes.join("\n")}" : "" }", MU::DEBUG, details: arguments
                raise e
              end
              @@enable_semaphores ||= {}
              max_retries = 3
              wait_time = 90
              if enable_on_fail and retries <= max_retries and e.message.match(/^accessNotConfigured/)
                enable_obj = nil

                project = if arguments.size > 0 and arguments.first.is_a?(String)
                  arguments.first
                else
                  MU::Cloud::Google.defaultProject(@credentials)
                end
# XXX validate that this actually looks like a project id, maybe
                if method_sym == :delete and !MU::Cloud::Google::Habitat.isLive?(project, @credentials)
                  MU.log "Got accessNotConfigured while attempting to delete a resource in #{project}", MU::WARN
                   
                  return
                end

                @@enable_semaphores[project] ||= Mutex.new
                enable_obj = MU::Cloud::Google.service_manager(:EnableServiceRequest).new(
                  consumer_id: "project:"+project.gsub(/^projects\/([^\/]+)\/.*/, '\1')
                )
                # XXX dumbass way to get this string
                if e.message.match(/by visiting https:\/\/console\.developers\.google\.com\/apis\/api\/(.+?)\//)

                  svc_name = Regexp.last_match[1]
                  save_verbosity = MU.verbosity
                  if !["servicemanagement.googleapis.com", "billingbudgets.googleapis.com"].include?(svc_name) and method_sym != :delete
                    retries += 1
                    @@enable_semaphores[project].synchronize {
                      MU.setLogging(MU::Logger::NORMAL)
                      MU.log "Attempting to enable #{svc_name} in project #{project.gsub(/^projects\/([^\/]+)\/.*/, '\1')}; will retry #{method_sym.to_s} in #{(wait_time/retries).to_s}s (#{retries.to_s}/#{max_retries.to_s})", MU::NOTICE
                      MU.setLogging(save_verbosity)
                      begin
                        MU::Cloud::Google.service_manager(credentials: @credentials).enable_service(svc_name, enable_obj)
                      rescue ::Google::Apis::ClientError => e
                        MU.log "Error enabling #{svc_name} in #{project.gsub(/^projects\/([^\/]+)\/.*/, '\1')} for #{method_sym.to_s}: "+ e.message, MU::ERR, details: enable_obj
                        raise e
                      end
                    }
                    sleep wait_time/retries
                    retry
                  else
                    MU.setLogging(MU::Logger::NORMAL)
                    MU.log "Google Cloud's Service Management API must be enabled manually by visiting #{e.message.gsub(/.*?(https?:\/\/[^\s]+)(?:$|\s).*/, '\1')}", MU::ERR
                    MU.setLogging(save_verbosity)
                    raise MU::MuError, "Service Management API not yet enabled for this account/project"
                  end
                elsif e.message.match(/scheduled for deletion and cannot be used for API calls/)
                  raise MuDefunctHabitat, e.message
                else
                  MU.log "Unfamiliar error calling #{method_sym.to_s} "+e.message, MU::ERR, details: arguments
                end
              elsif retries <= 10 and
                 e.message.match(/^resourceNotReady:/) or
                 (e.message.match(/^resourceInUseByAnotherResource:/) and method_sym.to_s.match(/^delete_/)) or
                 e.message.match(/SSL_connect/)
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

            if retval.class.name.match(/.*?::Operation$/)

              retries = 0

              # Check whether the various types of +Operation+ responses say
              # they're done, without knowing which specific API they're from
              def is_done?(retval)
                (retval.respond_to?(:status) and retval.status == "DONE") or (retval.respond_to?(:done) and retval.done)
              end

              begin
                if retries > 0 and retries % 3 == 0
                  MU.log "Waiting for #{method_sym} to be done (retry #{retries})", MU::NOTICE
                else
                  MU.log "Waiting for #{method_sym} to be done (retry #{retries})", MU::DEBUG, details: retval
                end

                if !is_done?(retval)
                  sleep 7
                  begin
                    if retval.class.name.match(/::Compute[^:]*::/)
                      resp = MU::Cloud::Google.compute(credentials: @credentials).get_global_operation(
                        arguments.first, # there's always a project id
                        retval.name
                      )
                      retval = resp
                    elsif retval.class.name.match(/::Servicemanagement[^:]*::/)
                      resp = MU::Cloud::Google.service_manager(credentials: @credentials).get_operation(
                        retval.name
                      )
                      retval = resp
                    elsif retval.class.name.match(/::Cloudresourcemanager[^:]*::/)
                      resp = MU::Cloud::Google.resource_manager(credentials: @credentials).get_operation(
                        retval.name
                      )
                      retval = resp
                      if retval.error
                        raise MuError, retval.error.message
                      end
                    elsif retval.class.name.match(/::Container[^:]*::/)
                      resp = MU::Cloud::Google.container(credentials: @credentials).get_project_location_operation(
                        retval.self_link.sub(/.*?\/projects\//, 'projects/')
                      )
                      retval = resp
                    elsif retval.class.name.match(/::Cloudfunctions[^:]*::/)
                      resp = MU::Cloud::Google.function(credentials: @credentials).get_operation(
                        retval.name
                      )
                      retval = resp
#MU.log method_sym.to_s, MU::WARN, details: retval
                      if retval.error
                        raise MuError, retval.error.message
                      end
                    else
                      pp retval
                      raise MuError, "I NEED TO IMPLEMENT AN OPERATION HANDLER FOR #{retval.class.name}"
                    end
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

              end while !is_done?(retval)

              # Most insert methods have a predictable get_* counterpart. Let's
              # take advantage.
              # XXX might want to do something similar for delete ops? just the
              # but where we wait for the operation to definitely be done
#              had_been_found = false
              if method_sym.to_s.match(/^(insert|create|patch)_/)
                get_method = method_sym.to_s.gsub(/^(insert|patch|create_disk|create)_/, "get_").to_sym
                cloud_id = if retval.respond_to?(:target_link)
                  retval.target_link.sub(/^.*?\/([^\/]+)$/, '\1')
                elsif retval.respond_to?(:metadata) and retval.metadata["target"]
                  retval.metadata["target"]
                else
                  arguments[0] # if we're lucky
                end
                faked_args = arguments.dup
                faked_args.pop
                if get_method == :get_snapshot
                  faked_args.pop
                  faked_args.pop
                end
                faked_args.push(cloud_id)
                if get_method == :get_project_location_cluster
                  faked_args[0] = faked_args[0]+"/clusters/"+faked_args[1]
                  faked_args.pop
                elsif get_method == :get_project_location_function
                  faked_args = [cloud_id]
                end
                actual_resource = @api.method(get_method).call(*faked_args)
#if method_sym == :insert_instance
#MU.log "actual_resource", MU::WARN, details: actual_resource
#end
#                had_been_found = true
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

            # This atrocity appends the pages of list_* results
            if overall_retval
              if method_sym.to_s.match(/^list_(.*)/)
                require 'google/apis/iam_v1'
                require 'google/apis/logging_v2'
                what = Regexp.last_match[1].to_sym
                whatassign = (Regexp.last_match[1]+"=").to_sym
                if overall_retval.class == ::Google::Apis::IamV1::ListServiceAccountsResponse
                  what = :accounts
                  whatassign = :accounts=
                end
                if retval.respond_to?(what) and retval.respond_to?(whatassign)
                  if !retval.public_send(what).nil?
                    newarray = retval.public_send(what) + overall_retval.public_send(what)
                    overall_retval.public_send(whatassign, newarray)
                  end
                elsif !retval.respond_to?(:next_page_token) or retval.next_page_token.nil? or retval.next_page_token.empty?
                  MU.log "Not sure how to append #{method_sym.to_s} results to #{overall_retval.class.name} (apparently #{what.to_s} and #{whatassign.to_s} aren't it), returning first page only", MU::WARN, details: retval
                  return retval
                end
              else
                MU.log "Not sure how to append #{method_sym.to_s} results, returning first page only", MU::WARN, details: retval
                return retval
              end
            else
              overall_retval = retval
            end

            arguments.delete({ :page_token => next_page_token })
            next_page_token = nil

            if retval.respond_to?(:next_page_token) and !retval.next_page_token.nil?
              next_page_token = retval.next_page_token
              MU.log "Getting another page of #{method_sym.to_s}", MU::DEBUG, details: next_page_token
            else
              return overall_retval
            end
          rescue ::Google::Apis::ServerError, ::Google::Apis::ClientError, ::Google::Apis::TransmissionError => e
            if e.class.name == "Google::Apis::ClientError" and
               (!method_sym.to_s.match(/^insert_/) or !e.message.match(/^notFound: /) or
                (e.message.match(/^notFound: /) and method_sym.to_s.match(/^insert_/))
               )
              if e.message.match(/^notFound: /) and method_sym.to_s.match(/^insert_/) and retval
                logreq = MU::Cloud::Google.logging(:ListLogEntriesRequest).new(
                  resource_names: ["projects/"+arguments.first],
                  filter: %Q{labels."compute.googleapis.com/resource_id"="#{retval.target_id}" OR labels."ssl_certificate_id"="#{retval.target_id}"} # XXX I guess we need to cover all of the possible keys, ugh
                )
                logs = MU::Cloud::Google.logging(credentials: @credentials).list_entry_log_entries(logreq)
                details = nil
                if logs.entries
                  details = logs.entries.map { |err| err.json_payload }
                  details.reject! { |err| err["error"].nil? or err["error"].size == 0 }
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
          end while !next_page_token.nil?
        end
      end

      @@compute_api = {}
      @@container_api = {}
      @@storage_api = {}
      @@sql_api = {}
      @@iam_api = {}
      @@logging_api = {}
      @@resource_api = {}
      @@resource2_api = {}
      @@service_api = {}
      @@firestore_api = {}
      @@admin_directory_api = {}
      @@billing_api = {}
      @@budgets_api = {}
      @@function_api = {}
    end
  end
end
