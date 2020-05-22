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
require 'vsphere-automation-sdk'
require 'vsphere-automation-content'
require 'vsphere-automation-vcenter'
require 'vsphere-automation-cis'

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

        class APIError < MU::MuError
        end

        @@vmc_tokens = {}

        # Fetch a live authorization token from the VMC API, if there's a +token+ underneath the +vmc+ subsection configured credentials
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
          cfg = MU::Cloud::VMWare.credConfig(credentials)
          return if !cfg or !cfg['vmc']

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

        def self.setAWSIntegrations(credentials = nil)
          cfg = MU::Cloud::VMWare.credConfig(credentials)
          credname = credentials
          credname ||= "<default>"
          return if !cfg or !cfg['vmc'] or !cfg['vmc']['connections']
          org = getOrg(credentials)['id']

          aws = MU::Cloud.cloudClass("AWS")
          cfg['vmc']['connections'].each_pair { |awscreds, vpcs|
            credcfg= aws.credConfig(awscreds)
            if !credcfg
              MU.log "I have a VMWare VMC integration under #{credname} configured for an AWS account named '#{awscreds}', but no such AWS credential set exists", MU::ERR
              next
            end
            acctnum = aws.credToAcct(awscreds)

            resp = begin
              callAPI("orgs/"+org+"/account-link/connected-accounts")
            rescue APIError => e
              MU.log e.message, MU::WARN
            end
            aws_account = resp.select { |a| a["account_number"] == acctnum }.first if resp

            if !aws_account
              stackname = "vmware-vmc-#{credname.gsub(/[^a-z0-9\-]/i, '')}-to-aws-#{awscreds}"
              stack_cfg = callAPI("orgs/"+org+"/account-link")
              MU.log "Creating account link between VMWare VMC and AWS account #{awscreds}", details: stack_cfg
              begin
                aws.cloudformation(credentials: awscreds, region: region).create_stack(
                  stack_name: stackname,
                  capabilities: ["CAPABILITY_IAM"],
                  template_url: stack_cfg["template_url"]
                )
              rescue Aws::CloudFormation::Errors::AlreadyExistsException
                MU.log "Account link CloudFormation stack already exists", MU::NOTICE, details: stackname
              end

              desc = nil
              loop_if = Proc.new {
                desc = aws.cloudformation(credentials: awscreds, region: region).describe_stacks(
                  stack_name: stackname,
                ).stacks.first

                (!desc or desc.stack_status == "CREATE_IN_PROGRESS")
              }
              MU.retrier(loop_if: loop_if, wait: 60) {
                MU.log "Waiting for CloudFormation stack #{stackname} to complete" , MU::NOTICE, details: (desc.stack_status if desc)
              }
              if desc.stack_status != "CREATE_COMPLETE"
                MU.log "Failed to create VMC <=> AWS connective CloudFormation stack", MU::ERR, details: desc

              end
            end

            # XXX this is a dumb assumption
            my_sddc = callAPI("orgs/"+org+"/sddcs").first
            sddc_id = my_sddc["id"]

            connected = {}
            callAPI("orgs/"+org+"/account-link/sddc-connections", params: { "sddc" => sddc_id} ).each { |cnxn|

              connected[cnxn['vpc_id']] ||= []
              connected[cnxn['vpc_id']] << cnxn['subnet_id']
            }

            vpcs.each { |vpc_cfg|
              region = vpc_cfg['region'] || aws.myRegion(awscreds)

              if !vpc_cfg['auto']
# XXX create if does not exist
              end

              vpcs_confd = callAPI("orgs/"+org+"/account-link/compatible-subnets", params: { "linkedAccountId" => aws_account["id"], "region" => region, "forceRefresh" => true })["vpc_map"]
              vpcs_confd.each_pair { |vpc_id, vpc_desc|
                if [vpc_id, vpc_desc['description'], vpc_desc['cidr_block']].include?(vpc_cfg['vpc'])
# XXX honor subnet_prefs, etc, like just like an ordinary resource
                  vpc_desc["subnets"].reject { |s| !s["compatible"] }.each { |subnet|
                    next if connected[vpc_id] and connected[vpc_id].include?(subnet['subnet_id'])
                    subnet.reject! { |k, v|
                      v.nil? or !%w{connected_account_id region_name availability_zone subnet_id subnet_cidr_block is_compatible vpc_id vpc_cidr_block name}.include?(k)
                    }
                    callAPI(
                      "orgs/"+org+"/account-link/compatible-subnets",
                      method: "POST",
                      params: subnet
                    )
                    connected[vpc_id] ||= []
                    connected[vpc_id] << subnet['subnet_id']
                  }
                end
              }
            }

pp my_sddc
exit
            connected.each_pair { |vpc_id, subnet_ids|
MU.log "attempting to glue #{vpc_id}", MU::NOTICE, details: subnet_ids
              entangle = {
                "sddc_id" => sddc_id,
                "name" => my_sddc["name"],
                "account_link_sddc_config" => [{
                  "connected_account_id" => aws_account["id"],
                  "customer_subnet_ids" => subnet_ids
                }],
#                "account_link_config" => { "delay_account_link" => false }
              }
              pp callAPI("orgs/"+org+"/sddcs", method: "POST", params: entangle)
            }

#            callAPI("orgs/"+org+"/sddcs").each { |sddc|
#              sddc["resource_config"]["sddc_id"]
#MU.log "sddc", MU::NOTICE, details: sddc
#            }

          }
        end

        # Make an API request to VMC
        # @param path [String]
        # @param credentials [String]
        # @return [Array,Hash]
        def self.callAPI(path, method: "GET", credentials: nil, params: nil)
          uri = URI API_URL+"/"+path


          req = if method == "POST"
            Net::HTTP::Post.new(uri)
#        elsif method == "DELETE"
#          XXX
          else
            if params and !params.empty?
              uri.query = URI.encode_www_form(params)
            end
            Net::HTTP::Get.new(uri)
          end

          if method == "POST" and params and !params.empty?
            req.body = JSON.generate(params)
          end

          req['Content-type'] = "application/json"
          req['csp-auth-token'] = getToken(credentials)

          MU.log "#{method} #{uri.to_s}", MU::NOTICE, details: req.body
          resp = Net::HTTP.start(uri.host, uri.port, :use_ssl => true) do |http|
            http.request(req)
          end

          unless resp.code == "200"
            raise APIError.new "Bad response from VMC API (#{resp.code.to_s})", details: resp.body
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

      # Return the MU.muCfg data associated with a particular profile/name/set
      # of credentials. If no account name is specified, will return one
      # flagged as default. Returns nil if VMWare is not configured. Throws an
      # exception if an account name is specified which does not exist.
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
#        elsif MU::Cloud::VMWare.hosted?
        else
          @@myRegion_var = ""
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
          sddcs = VMC.callAPI("orgs/"+org['id']+"/sddcs", credentials: credentials)
          habitats.concat(sddcs.map { |s| s['id'] })
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

      def self.nsx(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "nsx", credentials: credentials, habitat: habitat)
      end

      def self.datastore(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "DatastoreApi", credentials: credentials, habitat: habitat)
      end

      def self.datacenter(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "DatacenterApi", credentials: credentials, habitat: habitat)
      end

      def self.folder(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "FolderApi", credentials: credentials, habitat: habitat)
      end
      @@vm_endpoints = {}

      def self.vm(credentials: nil, habitat: nil)
        @@vm_endpoints[credentials] ||= {}
#        habitat ||= some_default_magic
        @@vm_endpoints[credentials][habitat] ||= VSphereEndpoint.new(api: "VMApi", credentials: credentials, habitat: habitat)
        @@vm_endpoints[credentials][habitat]
      end

      def self.host(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "HostApi", credentials: credentials, habitat: habitat)
      end

      def self.identity(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "IdentityProvidersApi", credentials: credentials, habitat: habitat)
      end

      def self.cluster(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "ClusterApi", credentials: credentials, habitat: habitat)
      end

      def self.network(credentials: nil, habitat: nil)
        VSphereEndpoint.new(api: "NetworkApi", credentials: credentials, habitat: habitat)
      end

      # Wrapper class for vSphere APIs, so that we can catch some common
      # transient endpoint errors without having to spray rescues all over the
      # codebase.
      class VSphereEndpoint
        attr_reader :org
        attr_reader :api
        attr_reader :credentials

        @credentials = nil

        # Create a vSphere API client
        # @param api [String]: Which API are we wrapping?
        # @param scopes [Array<String>]: Google auth scopes applicable to this API
        def initialize(api: "esx", credentials: nil, habitat: nil)
          @credentials = credentials
          @org = VMC.getOrg(@credentials)['id']
          @api = api.to_sym

          @sddc = MU::Cloud.resourceClass("VMWare", "Habitat").find(credentials: @credentials).values.first # XXX again, a terrible assumption; we need a default habitat
          MU.log "public ips", MU::NOTICE, details: VMC.callAPI("orgs/#{@org}/sddcs/#{@sddc['id']}/publicips")

          url, cert = if api == "nsx"
            [@sddc["resource_config"]["nsx_mgr_url"], @sddc["resource_config"]["certificates"]["NSX_MANAGER"]]
          else
            [@sddc["resource_config"]["vc_url"], @sddc["resource_config"]["certificates"]["VCENTER"]]
          end
# ["resource_config"]["cloud_username"]
# ["resource_config"]["cloud_password"]
          configuration = VSphereAutomation::Configuration.new.tap do |c|
            c.host = url
            c.username = @sddc["resource_config"]["cloud_username"]
            c.password = @sddc["resource_config"]["cloud_password"]
            c.debugging = true
#            c.cert_file = StringIO.new(cert["certificate"])
            c.scheme = 'https'
          end

          @api_blob = VSphereAutomation::ApiClient.new(configuration)
          VSphereAutomation::CIS::SessionApi.new(@api_blob).create('')
          @api_client = VSphereAutomation::VCenter.const_get(@api).new(@api_blob)

        end

        # Catch-all for AWS client methods. Essentially a pass-through with some
        # rescues for known silly endpoint behavior.
        def method_missing(method_sym, *arguments)
          if arguments and !arguments.empty?
            @api_client.send(method_sym, arguments.first)
          else
            @api_client.send(method_sym)
          end
        end
      end

    end
  end
end
