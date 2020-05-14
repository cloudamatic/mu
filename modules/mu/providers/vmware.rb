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

require "net/http"
require 'net/https'

module MU
  class Cloud
    # Support for VMWare as a provisioning layer.
    class VMWare
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
        # @return [String]
#        def url
#          desc = cloud_desc
#          (desc and desc.self_link) ? desc.self_link : nil
#        end
      end

      # Any cloud-specific instance methods we require our resource
      # implementations to have, above and beyond the ones specified by
      # {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        []
      end

      # Is this a "real" cloud provider, or a stub like CloudFormation?
      def self.virtual?
        false
      end


      class VMC
        AUTH_URI = URI "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"
        API_URL = "https://vmc.vmware.com/vmc/api"

        @@vmc_tokens = {}

        # Fetch a live authorization token from the VMC API, given a +vmc_token+ underneath our configured credentials
        # @param credentials [String]
        # @return [String]
        def self.getToken(credentials = nil)
          @@vmc_tokens ||= {}
          if @@vmc_tokens[credentials]
            return @@vmc_tokens[credentials]['access_token']
          end
          cfg = MU::Cloud::VMWare.credConfig(credentials)
          if !cfg or !cfg['vmc'] or !cfg['vmc']['token']
            raise MuError, "No VMWare credentials #{credentials ? credentials : "<default>"} found or no VMC token configured"
          end

          resp = nil

          req = Net::HTTP::Post.new(AUTH_URI)
          req['Content-type'] = "application/json"
          req.set_form_data('refresh_token' => cfg['vmc']['token'])

          resp = Net::HTTP.start(AUTH_URI.hostname, AUTH_URI.port, :use_ssl => true) {|http|
            http.request(req)
          }

          unless resp.code == "200"
            raise MuError.new "Failed to authenticate to VMC with auth token under credentials #{credentials ? credentials : "<default>"}", details: resp.body
          end
          @@vmc_tokens[credentials] = JSON.parse(resp.body)
          @@vmc_tokens[credentials]['last_fetched'] = Time.now
          @@vmc_tokens[credentials]['access_token']
        end

        # If the given set of credentials has VMC configured, return the default
        # organization.
        # @param credentials [String]
        # @return [Hash]
        def self.getOrg(credentials = nil)
          cfg =  MU::Cloud::VMWare.credConfig(credentials)
          orgs = callAPI("orgs", credentials: credentials)
          if orgs.size == 1
            return orgs.first
          elsif cfg and cfg['vmc'] and cfg['vmc']['org']
            orgs.each { |o|
              if [org['user_id'], org['user_name'], org['name'], org['display_name']].include?(cfg['vmc']['org'])
                return o
              end
            }
          elsif orgs.size > 1
            raise MuError.new, "I see multiple VMC orgs with credentials #{credentials ? credentials : "<default>"}, set vmc_org to specify one as default", details: orgs.map { |o| o['display_name'] }
          end

          nil
        end

        # Make an API request to VMC
        # @param path [String]
        # @param credentials [String]
        # @return [Array,Hash]
        def self.callAPI(path, method: nil, credentials: nil)
          uri = URI API_URL+"/"+path

          req = if method == "POST"
            Net::HTTP::Post.new(uri)
#        elsif method == "DELETE"
#          XXX
          else
            Net::HTTP::Get.new(uri)
          end

          req['Content-type'] = "application/json"
          req['csp-auth-token'] = getToken(credentials)

          MU.log "Calling #{uri.to_s}", MU::NOTICE
          resp = Net::HTTP.start(uri.host, uri.port, :use_ssl => true) do |http|
            http.request(req)
          end

          unless resp.code == "200"
            raise MuError.new "Bad response from VMC API (#{resp.code.to_s})", details: resp.body
          end

          JSON.parse(resp.body)
        end
      end

      # A hook that is always called just before any of the instance method of
      # our resource implementations gets invoked, so that we can ensure that
      # repetitive setup tasks (like resolving +:resource_group+ for Azure
      # resources) have always been done.
      # @param cloudobj [MU::Cloud]
      # @param deploy [MU::MommaCat]
      def self.resourceInitHook(cloudobj, deploy)
        class << self
        end
        return if !cloudobj
      end

      # If we're running this cloud, return the MU.muCfg blob we'd use to
      # describe this environment as our target one.
      def self.hosted_config
        nil
      end

      # A non-working example configuration
      def self.config_example
        sample = hosted_config
        sample ||= {
          "vmc_token" => "foobarbaz"
        }
        sample
      end

      # Return the name strings of all known sets of credentials for this cloud
      # @return [Array<String>]
      def self.listCredentials
        if !MU.muCfg['vmware']
          return hosted? ? ["#default"] : nil
        end

        MU.muCfg['vmware'].keys
      end

      @@habmap = {}

      # @param cloudobj [MU::Cloud::VMWare]: The resource from which to extract the habitat id
      # @return [String,nil]
      def self.habitat(cloudobj, nolookup: false, deploy: nil)
        @@habmap ||= {}

        nil
      end

      # Resolve the administrative Cloud Storage bucket for a given credential
      # set, or return a default.
      # @param credentials [String]
      # @return [String]
      def self.adminBucketName(credentials = nil)
         #XXX find a default if this particular account doesn't have a log_bucket_name configured
        cfg = credConfig(credentials)
        if cfg.nil?
          raise MuError, "Failed to load VMWare credential set #{credentials}"
        end
        cfg['log_bucket_name']
      end

      # Resolve the administrative Cloud Storage bucket for a given credential
      # set, or return a default.
      # @param credentials [String]
      # @return [String]
      def self.adminBucketUrl(credentials = nil)
        nil
      end

      # Return the MU.muCfg data associated with a particular profile/name/set of
      # credentials. If no account name is specified, will return one flagged as
      # default. Returns nil if GCP is not configured. Throws an exception if 
      # an account name is specified which does not exist.
      # @param name [String]: The name of the key under 'vmware' in mu.yaml to return
      # @return [Hash,nil]
      def self.credConfig(name = nil, name_only: false)
        # If there's nothing in mu.yaml (which is wrong), but we're running
        # on a machine hosted in GCP, fake it with that machine's service
        # account and hope for the best.
        if !MU.muCfg['vmware'] or !MU.muCfg['vmware'].is_a?(Hash) or MU.muCfg['vmware'].size == 0
          return @@my_hosted_cfg if @@my_hosted_cfg

          if hosted?
            @@my_hosted_cfg = hosted_config
            return name_only ? "#default" : @@my_hosted_cfg
          end

          return nil
        end

        if name.nil?
          MU.muCfg['vmware'].each_pair { |set, cfg|
            if cfg['default'] or MU.muCfg['vmware'].size == 1
              return name_only ? set : cfg
            end
          }
        else
          if MU.muCfg['vmware'][name]
            return name_only ? name : MU.muCfg['vmware'][name]
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
        elsif MU::Cloud::VMWare.hosted?
          zone = MU::Cloud::VMWare.getGoogleMetaData("instance/zone")
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
      def self.writeDeploySecret(deploy_id, value, name = nil, credentials: nil)
        name ||= deploy_id+"-secret"
      end

      # Remove the service account and various deploy secrets associated with a deployment. Intended for invocation from MU::Cleanup.
      # @param deploy_id [String]: The deploy for which we're granting the secret
      # @param noop [Boolean]: If true, will only print what would be done
      def self.removeDeploySecretsAndRoles(deploy_id = MU.deploy_id, flags: {}, noop: false, credentials: nil)
        cfg = credConfig(credentials)
      end

      # Grant access to appropriate Cloud Storage objects in our log/secret bucket for a deploy member.
      # @param acct [String]: The service account (by email addr) to which we'll grant access
      # @param deploy_id [String]: The deploy for which we're granting the secret
      # XXX add equivalent for AWS and call agnostically
      def self.grantDeploySecretAccess(acct, deploy_id = MU.deploy_id, name = nil, credentials: nil)
        name ||= deploy_id+"-secret"
      end

      @@is_in_gcp = nil

      # Alias for #{MU::Cloud::VMWare.hosted?}
      def self.hosted
        MU::Cloud::VMWare.hosted?
      end

      # Determine whether we (the Mu master, presumably) are hosted in this
      # cloud.
      # @return [Boolean]
      def self.hosted?
        false
      end

      def self.loadCredentials(scopes = nil, credentials: nil)
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

      # List all SDDCs available to our credentials
      def self.listHabitats(credentials = nil)
        habitats = []
        org = VMC.getOrg(credentials)
        if org and org['id']
          sddcs = VMC.call("orgs/"+org['id']+"/sddcs", credentials: credentials)
          habitats.concat(sddcs.map { |s| s['id'] })
          pp sddcs
        end
        habitats
      end

      @@regions = {}
      # List all known regions
      # @param us_only [Boolean]: Restrict results to United States only
      def self.listRegions(us_only = false, credentials: nil)
        @@regions
      end


      @@instance_types = nil
      # Query the GCP API for the list of valid Compute instance types and some of
      # their attributes. We can use this in config validation and to help
      # "translate" machine types across cloud providers.
      # @param region [String]: Supported machine types can vary from region to region, so we look for the set we're interested in specifically
      # @return [Hash]
      def self.listInstanceTypes(region = self.myRegion, credentials: nil, project: MU::Cloud::VMWare.defaultProject)
        {}
      end

      # List the Availability Zones associated with a given Google Cloud
      # region. If no region is given, search the one in which this MU master
      # server resides (if it resides in this cloud provider's ecosystem).
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region = self.myRegion)
        []
      end

      # Wrapper class for vSphere APIs, so that we can catch some common
      # transient endpoint errors without having to spray rescues all over the
      # codebase.
      class VSphereEndpoint
        @credentials = nil

        # Create a vSphere API client
        # @param api [String]: Which API are we wrapping?
        # @param scopes [Array<String>]: Google auth scopes applicable to this API
        def initialize(api: "", credentials: nil)
          @credentials = credentials
        end

        # Catch-all for AWS client methods. Essentially a pass-through with some
        # rescues for known silly endpoint behavior.
        def method_missing(method_sym, *arguments)
        end
      end

    end
  end
end
