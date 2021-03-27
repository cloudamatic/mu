# Copyright:: Copyright (c) 2018 eGlobalTech, Inc., all rights reserved
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

require 'open-uri'
require 'json'
require 'timeout'

module MU
  class Cloud
    # Support for Microsoft Azure as a provisioning layer.
    class Azure
      @@is_in_azure = nil
      @@metadata = nil
      @@acct_to_profile_map = nil #WHAT EVEN IS THIS? 
      @@myRegion_var = nil
      @@default_subscription = nil
      @@regions = []

      # Module used by {MU::Cloud} to insert additional instance methods into
      # instantiated resources in this cloud layer.
      module AdditionalResourceMethods
      end

      # Exception class for exclusive use by {MU::Cloud::Azure::SDKClient::ClientCallWrapper}
      class APIError < MU::MuError
      end

      # Exception class for exclusive use by {MU::Cloud::Azure.getVaultSecret}
      class MissingVaultSecret < MU::MuError
      end

      # Return a random Azure-valid GUID, because for some baffling reason some
      # API calls expect us to roll our own.
      def self.genGUID
        hexchars = Array("a".."f") + Array(0..9)
        guid_chunks = []
        [8, 4, 4, 4, 12].each { |count|
          guid_chunks << Array.new(count) { hexchars.sample }.join
        }
        guid_chunks.join("-")
      end

      # List all Azure subscriptions available to our credentials
      def self.listHabitats(credentials = nil, use_cache: true)
        []
      end

      # A hook that is always called just before any of the instance method of
      # our resource implementations gets invoked, so that we can ensure that
      # repetitive setup tasks (like resolving +:resource_group+ for Azure
      # resources) have always been done.
      # @param cloudobj [MU::Cloud]
      # @param deploy [MU::MommaCat]
      def self.resourceInitHook(cloudobj, deploy)
        class << self
          attr_reader :resource_group
          attr_reader :region
        end
        return if !cloudobj

        region = cloudobj.config['region'] || MU::Cloud::Azure.myRegion(cloudobj.config['credentials'])
        cloudobj.instance_variable_set(:@region, region)

        rg = if !deploy
          return if !hosted?
          MU.myInstanceId.resource_group
        else
          deploy.deploy_id+"-"+region.upcase
        end
        
        cloudobj.instance_variable_set(:@resource_group, rg)

      end

      # Any cloud-specific instance methods we require our resource implementations to have, above and beyond the ones specified by {MU::Cloud}
      # @return [Array<Symbol>]
      def self.required_instance_methods
        [:resource_group]
      end

      # Is this a "real" cloud provider, or a stub like CloudFormation?
      def self.virtual?
        false
      end

      # Stub class to represent Azure's resource identifiers, which look like:
      # /subscriptions/3d20ddd8-4652-4074-adda-0d127ef1f0e0/resourceGroups/mu/providers/Microsoft.Network/virtualNetworks/mu-vnet
      # Various API calls need chunks of this in different contexts, and this
      # full string is necessary to guarantee that a +cloud_id+ is a unique
      # identifier for a given resource. So we'll use this object of our own
      # devising to represent it.
      class Id
        attr_reader :subscription
        attr_reader :resource_group
        attr_reader :provider
        attr_reader :type
        attr_reader :name
        attr_reader :raw

        # The name of the attribute on a cloud object from this provider which
        # has the provider's long-form cloud identifier (Google Cloud URL,
        # Amazon ARN, etc).
        def self.idattr
          :id
        end

        def initialize(*args)
          if args.first.is_a?(String)
            @raw = args.first
            _junk, _junk2, @subscription, _junk3, @resource_group, _junk4, @provider, @resource_type, @name = @raw.split(/\//)
            if @subscription.nil? or @resource_group.nil? or @provider.nil? or @resource_type.nil? or @name.nil?
              # Not everything has a resource group
              if @raw.match(/^\/subscriptions\/#{Regexp.quote(@subscription)}\/providers/)
                _junk, _junk2, @subscription, _junk3, @provider, @resource_type, @name = @raw.split(/\//)
                if @subscription.nil? or @provider.nil? or @resource_type.nil? or @name.nil?
                  raise MuError, "Failed to parse Azure resource id string #{@raw} (got subscription: #{@subscription}, provider: #{@provider}, resource_type: #{@resource_type}, name: #{@name}"
                end

              else
                raise MuError, "Failed to parse Azure resource id string #{@raw} (got subscription: #{@subscription}, resource_group: #{@resource_group}, provider: #{@provider}, resource_type: #{@resource_type}, name: #{@name}"
              end
            end
          else
            args.each { |arg|
              if arg.is_a?(Hash)
                arg.each_pair { |k, v|
                  self.instance_variable_set(("@"+k.to_s).to_sym, v)
                }
              end
            }

            if @resource_group.nil? or @name.nil?
              raise MuError, "Failed to extract at least name and resource_group fields from #{args.flatten.join(", ").to_s}"
            end
          end
        end

        # Check for quality with another one of our kind
        # @param o [MU::Cloud::Azure::Id]
        def ==(o)
          return false if o.nil? or !o.is_a?(MU::Cloud::Azure::Id)
          (o.subscription == @subscription and o.resource_group == @resource_group and o.provider == @provider and o.type == @type and o.name == @name)
        end

        # Return a reasonable string representation of this {MU::Cloud::Azure::Id}
        def to_s
          @name
        end
      end

# UTILITY METHODS
      # Determine whether we (the Mu master, presumably) are hosted in Azure.
      # @return [Boolean]
      def self.hosted?
        if $MU_CFG and $MU_CFG.has_key?("azure_is_hosted")
          @@is_in_azure = $MU_CFG["azure_is_hosted"]
          return $MU_CFG["azure_is_hosted"]
        end

        if !@@is_in_azure.nil?
          return @@is_in_azure
        end

        begin
          metadata = get_metadata()
          if metadata['compute']['vmId']
            @@is_in_azure = true
            return true
          else
            return false
          end
        rescue
          # MU.log "Failed to get Azure MetaData. I assume I am not hosted in Azure", MU::DEBUG, details: resources
        end

        @@is_in_azure = false
        false
      end

      # If we reside in this cloud, return the VPC in which we, the Mu Master, reside.
      # @return [MU::Cloud::VPC]
      def self.myVPCObj
        return nil if !hosted?
        instance = MU.myCloudDescriptor
        return nil if !instance or !instance.network_profile or !instance.network_profile.network_interfaces or instance.network_profile.network_interfaces.empty?
        iface_id = Id.new(instance.network_profile.network_interfaces.first.id)
        iface_desc = MU::Cloud::Azure.network().network_interfaces.get(iface_id.resource_group, iface_id.name)
        subnet_id = Id.new(iface_desc.ip_configurations.first.subnet.id)
        vpc_id = subnet_id.raw.split(/\//)[8]
        vpc = MU::MommaCat.findStray("Azure", "vpc", cloud_id: vpc_id, dummy_ok: true)

        return nil if vpc.nil? or vpc.size == 0
        vpc.first
      end

      # If we reside in this cloud, return the VPC in which we, the Mu Master, reside.
      # @return [MU::Cloud::VPC]
      def self.myVPC
        return nil if !hosted?
# XXX do me
      end

      # Alias for #{MU::Cloud::Azure.hosted?}
      def self.hosted
        return MU::Cloud::Azure.hosted?
      end

      # If we're running this cloud, return the $MU_CFG blob we'd use to
      # describe this environment as our target one.
      def self.hosted_config
        return nil if !hosted?
        region = get_metadata()['compute']['location']
        subscription = get_metadata()['compute']['subscriptionId']
        {
          "region" => region,
          "subscriptionId" => subscription
        }
      end

      # Azure's API response objects don't implement +to_h+, so we'll wing it
      # ourselves
      # @param struct [MsRestAzure]
      # @return [Hash]
      def self.respToHash(struct)
        hash = {}
        struct.class.instance_methods(false).each { |m|
          next if m.to_s.match(/=$/)
          hash[m.to_s] = struct.send(m)
        }
        struct.instance_variables.each { |a|
          hash[a.to_s.sub(/^@/, "")] = struct.instance_variable_get(a)
        }
        hash
      end

      # Method that returns the default Azure region for this Mu Master
      # @return [string]
      def self.myRegion(credentials = nil)
        if @@myRegion_var
          return @@myRegion_var
        end

        cfg = credConfig(credentials)
        
        @@myRegion_var = if cfg['default_region']
          cfg['default_region']
        elsif MU::Cloud::Azure.hosted?
          # IF WE ARE HOSTED IN AZURE CHECK FOR THE REGION OF THE INSTANCE
          metadata = get_metadata()
          metadata['compute']['location'].downcase
        else
          "eastus" # XXX this only makes sense in commercial
        end

        return @@myRegion_var
      end

      # lookup the default subscription that will be used by methods
      def self.default_subscription(credentials = nil)
        cfg = credConfig(credentials)
        if @@default_subscription.nil?
          if cfg['subscription']
            # MU.log "Found default subscription in mu.yml. Using that..."
            @@default_subscription = cfg['subscription']

          elsif listSubscriptions().length == 1
            #MU.log "Found a single subscription on your account. Using that... (This may be incorrect)", MU::WARN, details: e.message
            @@default_subscription = listSubscriptions()[0]

          elsif MU::Cloud::Azure.hosted?
            #MU.log "Found a subscriptionID in my metadata. Using that... (This may be incorrect)", MU::WARN, details: e.message
            @@default_subscription = get_metadata()['compute']['subscriptionId']

          else
            raise MuError, "Default Subscription was not found. Please run mu-configure to setup a default subscription"
          end
        end

        return @@default_subscription
      end

      # List visible Azure regions
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # return [Array<String>]
      def self.listRegions(us_only = false, credentials: nil)
        cfg = credConfig(credentials)
        return nil if !cfg and !hosted?
        subscription = cfg['subscription']
        subscription ||= default_subscription()

        if @@regions.length() > 0 && subscription == default_subscription()
          return us_only ? @@regions.reject { |r| !r.match(/us\d?$/) } : @@regions
        end
        
        begin
          sdk_response = MU::Cloud::Azure.subs(credentials: credentials).subscriptions().list_locations(subscription)
        rescue StandardError => e
          MU.log e.inspect, MU::ERR, details: e.backtrace
          #pp "Error Getting the list of regions from Azure" #TODO: SWITCH THIS TO MU LOG
          if @@regions and @@regions.size > 0
            return us_only ? @@regions.reject { |r| !r.match(/us\d?$/) } : @@regions
          end
          raise e
        end
        if !sdk_response
          raise MuError, "Nil response from Azure API attempting list_locations(#{subscription})"
        end

        sdk_response.value.each { |region|
          begin
            listInstanceTypes(region.name) # use this to filter for broken regions
            @@regions.push(region.name)
          rescue APIError => e
            MU.log "Azure region "+region.name+" does not appear operational, skipping", MU::WARN
          end
        }

        return us_only ? @@regions.reject { |r| !r.match(/us\d?$/) } : @@regions
      end

      # List subscriptions visible to the given credentials
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # return [Array<String>]
      def self.listSubscriptions(credentials = nil)
        subscriptions = []

        sdk_response = MU::Cloud::Azure.subs(credentials: credentials).subscriptions().list
  return [] if !sdk_response

        sdk_response.each do |subscription|
          subscriptions.push(subscription.subscription_id)
        end

        return subscriptions
      end

      # List the Availability Zones associated with a given Azure region.
      # If no region is given, search the one in which this MU master
      # server resides (if it resides in this cloud provider's ecosystem).
      # @param region [String]: The region to search.
      # @return [Array<String>]: The Availability Zones in this region.
      def self.listAZs(region = nil)
        az_list = ['1', '2', '3']

        # Pulled from this chart: https://docs.microsoft.com/en-us/azure/availability-zones/az-overview#services-support-by-region
        az_enabled_regions = ['centralus', 'eastus', 'eastus2', 'westus2', 'francecentral', 'northeurope', 'uksouth', 'westeurope', 'japaneast', 'southeastasia'] 

        if not az_enabled_regions.include?(region)
          az_list = []
        end

        return az_list
      end

      # A non-working example configuration
      def self.config_example
        sample = hosted_config
        sample ||= {
          "region" => "eastus",
          "subscriptionId" => "99999999-9999-9999-9999-999999999999",
        }

        sample["credentials_file"] = "~/.azure/credentials"
        sample["log_bucket_name"]  = "my-mu-s3-bucket"
        sample
      end

      def self.nameVault(deploy, region)
        deploy.getResourceName("", max_length: 23, disallowed_chars: /[^a-z0-9]/i, use_unique_string: region.sub(/^usgov/i, '').slice(0,4).upcase, need_unique_string: true)
      end

      # Do cloud-specific deploy instantiation tasks, such as copying SSH keys
      # around, sticking secrets in buckets, creating resource groups, etc
      # @param deploy [MU::MommaCat]
      def self.initDeploy(deploy)
        deploy.credsUsed.each { |creds|
          next if !credConfig(creds)
          listRegions.each { |region|
            next if !deploy.regionsUsed.include?(region)
            begin
              rg_obj = createResourceGroup(deploy.deploy_id+"-"+region.upcase, region, credentials: creds)
              createVault(rg_obj.name, region, deploy, credentials: creds)
            rescue ::MsRestAzure::AzureOperationError
            end
          }
        }
      end

      # Our credentials could be a Managed Service Identity, or an Enterprise
      # Application Service Principal. Find it, figure out which, and return
      # the appropriate cloud descriptor.
      # @param credentials [String]
      def self.myServiceAccount(credentials)
        cred_hash = MU::Cloud::Azure.getSDKOptions(credentials)

        acct = MU::Cloud::Azure.serviceaccts(credentials: credentials).user_assigned_identities.list_by_subscription().select { |svc_acct|
          (
            svc_acct.client_id == cred_hash[:client_id] and
            svc_acct.id =~ /subscriptions\/#{Regexp.quote(cred_hash[:subscription_id])}\//
          )
        }.first
      end

      # Arguably this should be a first class resource, but for now we'll do
      # it here since we're going to have a generic deployment vault in every
      # resource group.
      # @param rg [String]: The name of the resource group in which we'll reside
      # @param region [String]: The region in which we'll reside
      # @param deploy [MU::MommaCat]: The deployment which we serve
      # @param credentials [String]:
      def self.createVault(rg, region, deploy, credentials: nil)
        cred_hash = MU::Cloud::Azure.getSDKOptions(credentials)
        my_svc_acct = myServiceAccount(credentials)

#        vaultname = deploy.getResourceName(deploy.deploy_id, max_length: 23, disallowed_chars: /[^a-z0-9-]/i, never_gen_unique: true)
        vaultname = nameVault(deploy, region)
        MU::Cloud::Azure.ensureProvider("Microsoft.KeyVault", credentials: credentials)
        sku = MU::Cloud::Azure.keyvault(:Sku).new
        sku.name = "standard" # ...I'm angry about this

        props = MU::Cloud::Azure.keyvault(:VaultProperties).new
        cred_hash[:tenant_id] ||= my_svc_acct.tenant_id if my_svc_acct
        props.tenant_id = cred_hash[:tenant_id] # token credentials don't set this, because of course they don't
        props.tenant_id ||= credConfig(credentials)["directory_id"]
        if !props.tenant_id
          raise MuError.new "Unable to glean our tenant/directory ID from loaded credentials. Add directory_id to the mu.yaml stanza for Azure credential set '#{credConfig(credentials, name_only: true)}' to fix.", details: { "Live credential object" => cred_hash, "Crendential config for #{credConfig(credentials, name_only: true)}" => credConfig(credentials) } # XXX see note in getSDKOptions about possible alternative
        end
        props.enabled_for_deployment = true
        props.sku = sku
        props.access_policies = []

        params = MU::Cloud::Azure.keyvault(:VaultCreateOrUpdateParameters).new
        params.location = region
        params.properties = props

        MU.log "Creating KeyVault #{vaultname} in #{region}"
        resp = MU::Cloud::Azure.keyvault(credentials: credentials).vaults.create_or_update(rg, vaultname, params)

        my_perms = MU::Cloud::Azure.keyvault(:Permissions).new
        my_perms.certificates = ["all"]
        my_perms.keys = ["all"]
        my_perms.secrets = ["all"]
        my_acl = MU::Cloud::Azure.keyvault(:AccessPolicyEntry).new
        if my_svc_acct
          my_acl.object_id = my_svc_acct.principal_id
          my_acl.tenant_id = my_svc_acct.tenant_id
        else
          pp cred_hash
          my_acl.object_id = cred_hash[:client_id]
          my_acl.tenant_id = props.tenant_id
        end
        my_acl.permissions = my_perms

        acl_props = MU::Cloud::Azure.keyvault(:VaultAccessPolicyProperties).new
        acl_props.access_policies = [my_acl]

        acl_params = MU::Cloud::Azure.keyvault(:VaultAccessPolicyParameters).new
        acl_params.properties = acl_props

        MU.log "Adding superuser access policy to vault #{vaultname}", MU::NOTICE, details: acl_params

        resp = MU::Cloud::Azure.keyvault(credentials: credentials).vaults.update_access_policy(rg, vaultname, MU::Cloud::Azure.keyvault(:AccessPolicyUpdateKind)::Add, acl_params)

      end

      @@rg_semaphore = Mutex.new

      # Purge cloud-specific deploy meta-artifacts (SSH keys, resource groups,
      # etc)
      # @param deploy_id [String]
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      def self.cleanDeploy(deploy_id, credentials: nil, noop: false)
        threads = []

        @@rg_semaphore.synchronize {
          MU::Cloud::Azure.resources(credentials: credentials).resource_groups.list.each { |rg|
            if rg.tags and rg.tags["MU-ID"] == deploy_id
              threads << Thread.new(rg) { |rg_obj|
                Thread.abort_on_exception = false
                MU.log "Removing resource group #{rg_obj.name} from #{rg_obj.location}"
                if !noop
                  MU::Cloud::Azure.resources(credentials: credentials).resource_groups.delete(rg_obj.name)
                end
              }
            end
          }
          threads.each { |t|
            t.join
          }
        }
      end

      # Azure resources are deployed into a containing artifact called a Resource Group, which we will map 1:1 with Mu deployments
      # @param name [String]: A name for this resource group
      # @param region [String]: The region in which to create this resource group
      def self.createResourceGroup(name, region, credentials: nil)
        rg_obj = MU::Cloud::Azure.resources(:ResourceGroup).new
        rg_obj.location = region
        rg_obj.tags = MU::MommaCat.listStandardTags
        rg_obj.tags.reject! { |_k, v| v.nil? }

        MU::Cloud::Azure.resources(credentials: credentials).resource_groups.list.each { |rg|
          if rg.name == name and rg.location == region and rg.tags == rg_obj.tags
            MU.log "Resource group #{name} already exists in #{region}", MU::DEBUG, details: rg_obj
            return rg # already exists? Do nothing
          end
        }
        MU.log "Configuring resource group #{name} in #{region}", details: rg_obj
        rg = MU::Cloud::Azure.resources(credentials: credentials).resource_groups.create_or_update(
          name,
          rg_obj
        )

        rg
      end

      # Fetch the cloud descriptor for our standard KeyVault used by a deployment
      # @param deploy [MU::MommaCat]
      # @param region [String]
      # @param credentials [String]
      # @return [Azure::KeyVault::Mgmt::V2018_02_14::Models::Vault]
      def self.getDeployVault(deploy, region, credentials: nil)
        deploy_id = deploy.deploy_id
        rg = deploy_id+"-"+region.upcase
#        vaultname = deploy.getResourceName(deploy.deploy_id, max_length: 23, disallowed_chars: /[^a-z0-9-]/i, never_gen_unique: true)
        vaultname = nameVault(deploy, region)
        MU::Cloud::Azure.keyvault(credentials: credentials).vaults.get(rg, vaultname)
      end

      # Get the Azure descriptor for a particular secret
      # @param deploy [MU::MommaCat]
      # @param name [String]
      # @param region [String]
      # @param credentials [String]
      def self.getVaultSecret(deploy, name, region, credentials: nil)
        vault_desc = getDeployVault(deploy, region, credentials: credentials)
        realname = name.gsub(/[^0-9a-zA-Z-]/, '-')

# XXX we're calling the _async versions of these methods because the SDK is
# broken, see https://github.com/Azure/azure-sdk-for-ruby/issues/2828
        items = MU::Cloud::Azure.keyvault_items(credentials: credentials).get_secret_versions_async(vault_desc.properties.vault_uri, realname).value!.body.value

        if items.empty?
          raise MissingVaultSecret.new "KeyVaultSecret #{realname} not found in vault #{vault_desc.name}", details: MU::Cloud::Azure.keyvault_items(credentials: credentials).get_secrets_async(vault_desc.properties.vault_uri).value!.body.value.map { |i| i.id }
        end
        items.last
      end

      # Plant a Mu deploy secret into a storage bucket somewhere for so our kittens can consume it
      # @param deploy [MU::MommaCat]: The deploy for which we're writing the secret
      # @param name [String]: What to name the secret object
      # @param value [String]: The contents of the secret
      # @param credentials [String]
      # @param region [String]
      def self.writeDeploySecret(deploy, value, name = nil, credentials: nil, region: nil)
        deploy_id = deploy.deploy_id
        name ||= deploy_id+"-secret"
        name.gsub!(/[^0-9a-zA-Z-]/, '-')

        regions = region ? [region] : listRegions

        regions.each { |r|
          next if !deploy.regionsUsed.include?(r)

          vault_desc = getDeployVault(deploy, r, credentials: credentials)
          next if !vault_desc
          vault_url = vault_desc.properties.vault_uri

          MU.log "Writing #{name} to KeyVault #{vault_desc.name}"
          MU.retrier([Faraday::ConnectionFailed], wait: 5, max: 6) {
            MU::Cloud::Azure.keyvault_items(credentials: credentials).set_secret(vault_url, name, value.to_s)
          }
          MU.retrier([MissingVaultSecret], wait: 5, max: 6) {
            resp = getVaultSecret(deploy, name, r, credentials: credentials)
            return resp if region
          }

        }
      end

      # Grant read access to the appropriate KeyVault
      # @param acct [String]: The managed service identity to which we'll grant access
      # @param deploy_id [String]: The deploy for which we're granting the secret
      def self.grantDeploySecretAccess(acct, deploy = MU.deploy, name = nil, credentials: nil)
        listRegions.each { |region|
          next if !deploy.regionsUsed.include?(region)
          rg = deploy.deploy_id+"-"+region.upcase

          vault_desc = getDeployVault(deploy, region, credentials: credentials)

          next if !vault_desc

          perms = MU::Cloud::Azure.keyvault(:Permissions).new
          perms.certificates = ["get"]
          perms.secrets = ["get"]
          acl = MU::Cloud::Azure.keyvault(:AccessPolicyEntry).new
          acl.object_id = acct.principal_id
          acl.tenant_id = acct.tenant_id
          acl.permissions = perms

          acl_props = MU::Cloud::Azure.keyvault(:VaultAccessPolicyProperties).new
          acl_props.access_policies = [acl]

          acl_params = MU::Cloud::Azure.keyvault(:VaultAccessPolicyParameters).new
          acl_params.properties = acl_props

          MU.log "Adding read-only access policy to KeyVault #{vault_desc.properties.vault_uri}", MU::NOTICE, details: acl_params

          resp = MU::Cloud::Azure.keyvault(credentials: credentials).vaults.update_access_policy(rg, vault_desc.name, MU::Cloud::Azure.keyvault(:AccessPolicyUpdateKind)::Add, acl_params)

        }
      end

      # Return the name strings of all known sets of credentials for this cloud
      # @return [Array<String>]
      def self.listCredentials
        if !$MU_CFG['azure']
          return hosted? ? ["#default"] : nil
        end

        $MU_CFG['azure'].keys
      end

      # Return what we think of as a cloud object's habitat.  If this is not
      # applicable, such as for a {Habitat} or {Folder}, returns nil.
      # @param cloudobj [MU::Cloud::Azure]: The resource from which to extract the habitat id
      # @return [String,nil]
      def self.habitat(cloudobj, nolookup: false, deploy: nil)
        nil # we don't know how to do anything with subscriptions yet, really
      end

      @@my_hosted_cfg = nil
      # Return the $MU_CFG data associated with a particular profile/name/set of
      # credentials. If no account name is specified, will return one flagged as
      # default. Returns nil if Azure is not configured. Throws an exception if
      # an account name is specified which does not exist.
      # @param name [String]: The name of the key under 'azure' in mu.yaml to return
      # @return [Hash,nil]
      def self.credConfig (name = nil, name_only: false)
        if !$MU_CFG['azure'] or !$MU_CFG['azure'].is_a?(Hash) or $MU_CFG['azure'].size == 0
          return @@my_hosted_cfg if @@my_hosted_cfg

          if hosted?
            @@my_hosted_cfg = hosted_config
            return name_only ? "#default" : @@my_hosted_cfg
          end

          return nil
        end

        if name.nil?
          $MU_CFG['azure'].each_pair { |set, cfg|
            if cfg['default']
              return name_only ? set : cfg
            end
          }
        else
          if $MU_CFG['azure'][name]
            return name_only ? name : $MU_CFG['azure'][name]
#          elsif @@acct_to_profile_map[name.to_s]
#            return name_only ? name : @@acct_to_profile_map[name.to_s]
          end
# XXX whatever process might lead us to populate @@acct_to_profile_map with some mappings, like projectname -> account profile, goes here
          return nil
        end

      end

      @@instance_types = nil
      # Query the Azure API for a list of valid instance types.
      # @param region [String]: Supported machine types can vary from region to region, so we look for the set we're interested in specifically
      # @return [Hash]
      def self.listInstanceTypes(region = self.myRegion)
        return @@instance_types if @@instance_types and @@instance_types[region]
        if !MU::Cloud::Azure.default_subscription()
          return {}
        end

        @@instance_types ||= {}
        @@instance_types[region] ||= {}
        result = MU::Cloud::Azure.compute.virtual_machine_sizes.list(region)
        raise MuError, "Failed to fetch Azure instance type list" if !result
        result.value.each { |type|
          @@instance_types[region][type.name] ||= {}
          @@instance_types[region][type.name]["memory"] = sprintf("%.1f", type.memory_in_mb/1024.0).to_f
          @@instance_types[region][type.name]["vcpu"] = type.number_of_cores.to_f
          @@instance_types[region][type.name]["ecu"] = type.number_of_cores
        }

        @@instance_types
      end

      # Resolve the administrative Cloud Storage bucket for a given credential
      # set, or return a default.
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [String]
      def self.adminBucketName(credentials = nil)
        "TODO"
      end

      # Resolve the administrative Cloud Storage bucket for a given credential
      # set, or return a default.
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [String]
      def self.adminBucketUrl(credentials = nil)
        "TODO"
      end
      
      #END REQUIRED METHODS


      # Fetch (ALL) Azure instance metadata
      # @return [Hash, nil]
      def self.get_metadata(svc = "instance", api_version = "2020-09-01", args: {}, debug: false, use_cache: true)
        loglevel = debug ? MU::NOTICE : MU::DEBUG
        return @@metadata if svc == "instance" and @@metadata and use_cache
        base_url = "http://169.254.169.254/metadata/#{svc}"
        args["api-version"] = api_version
        arg_str = args.keys.sort.map { |k| k.to_s+"="+CGI.escape(args[k].to_s) }.join("&")

        resp = begin
          raw_resp = Timeout.timeout(3) do
            URI.open("#{base_url}?#{arg_str}","Metadata"=>"true").read
          end
          resp = JSON.parse(raw_resp)

          MU.log "#{svc}: curl -H Metadata:true #{base_url}?#{arg_str}", loglevel, details: resp
          if svc != "instance"
            return resp
          else
            @@metadata = resp
          end
          return @@metadata

        rescue Timeout::Error
          MU.log "Timeout querying Azure Metadata", MU::ERR if debug
          return nil
        rescue StandardError => e
          MU.log "Failed to get Azure MetaData: #{e.inspect}", MU::ERR if debug
          return nil
        end
      end

      # Credentials from the API use a different settings blob for alternate
      # clouds (ex: USGov), so provide a shorthand for fetchingthose based on
      # the environment or region name.
      # @param env [String]
      # @return [Array<MsRestAzure::AzureEnvironments,MsRestAzure::ActiveDirectoryServiceSettings>]
      def self.endpointSettings(env = "AzureCloud")
        env ||= "AzureCloud" # in case of explicit nil

        case env.to_s
        when "AzureUSGovernmentCloud"
          urls = MsRestAzure::AzureEnvironments::AzureUSGovernment
          settings = MsRestAzure::ActiveDirectoryServiceSettings.get_azure_us_government_settings
        when "AzureChinaCloud"
          urls = MsRestAzure::AzureEnvironments::AzureChinaCloud
          settings = ::MsRestAzure::ActiveDirectoryServiceSettings.get_azure_china_settings
        when "AzureGermanCloud"
          urls = MsRestAzure::AzureEnvironments::AzureGermanCloud
          settings = ::MsRestAzure::ActiveDirectoryServiceSettings.get_azure_german_settings
        when "AzureCloud"
          urls = MsRestAzure::AzureEnvironments::AzureCloud
          settings = ::MsRestAzure::ActiveDirectoryServiceSettings.get_azure_settings
        end

        if !settings # maybe we got a region name instead
          case env.to_s
          when /^USGov/i
            urls = MsRestAzure::AzureEnvironments::AzureUSGovernment
            settings = MsRestAzure::ActiveDirectoryServiceSettings.get_azure_us_government_settings
          when /^China/i 
            urls = MsRestAzure::AzureEnvironments::AzureChinaCloud
            settings = MsRestAzure::ActiveDirectoryServiceSettings.get_azure_china_settings
          when /^germany/i
            urls = MsRestAzure::AzureEnvironments::AzureGermanCloud
            settings = MsRestAzure::ActiveDirectoryServiceSettings.get_azure_german_settings
          else
            urls = MsRestAzure::AzureEnvironments::AzureCloud
            settings = MsRestAzure::ActiveDirectoryServiceSettings.get_azure_settings
          end
        end

        [urls, settings]
      end

      # Map our SDK authorization options from MU configuration into an options
      # hash that Azure understands. Raises an exception if any fields aren't
      # available.
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [Hash]
      def self.getSDKOptions(credentials = nil, endpoint: "resource_manager")
        cfg = credConfig(credentials)

# XXX machine credentials don't show the directory_id/tenant_id, which is a problem because we need it for some API calls. Perhaps: create a stub managed identity (which does show it) and authorize using it purely to extract the directory_id

        az_env = ad_settings = nil
        resource_url = Proc.new {
          if endpoint == "vault"
            az_env.key_vault_dns_suffix.sub(/^\./, "https://")
          elsif endpoint == "storage"
            az_env.key_vault_dns_suffix.sub(/^\./, "https://")
          elsif endpoint == "gallery"
            az_env.gallery_endpoint_url
          elsif endpoint == "ad"
            az_env.active_directory_endpoint_url
          else
            az_env.resource_manager_endpoint_url
          end
        }
        if cfg and MU::Cloud::Azure.hosted?
          machine = MU::Cloud::Azure.get_metadata
          az_env, ad_settings = endpointSettings(machine["compute"]["azEnvironment"])

          token = MU::Cloud::Azure.get_metadata("identity/oauth2/token", "2020-09-01", args: { "resource"=>resource_url.call() })
          if !token
            sleep 1
            token = MU::Cloud::Azure.get_metadata("identity/oauth2/token", "2020-09-01", args: { "resource"=>resource_url.call() }, debug: true)
            raise MuError, "Failed to get machine oauth token" if !token
          end

          return {
            credentials: MsRest::TokenCredentials.new(token["access_token"]),
            client_id: token["client_id"],
            base_url: token['resource'],
            subscription: machine["compute"]["subscriptionId"],
            subscription_id: machine["compute"]["subscriptionId"],
            active_directory_settings: ad_settings
          }
        else
          az_env, ad_settings = endpointSettings(cfg['region'])
        end

        return nil if !cfg

        map = { #... from mu.yaml-ese to Azure SDK-ese
          "directory_id" => :tenant_id,
          "client_id" => :client_id,
          "client_secret" => :client_secret,
          "subscription" => :subscription_id
        }

        options = {}

        map.each_pair { |k, v|
          options[v] = cfg[k] if cfg[k]
        }
        
        if cfg['credentials_file']
          file = File.open cfg['credentials_file']
          credfile = JSON.load file
          map.each_pair { |k, v|
            options[v] = credfile[k] if credfile[k]
          }
        end
        options[:active_directory_settings] = ad_settings
        options[:base_url] = resource_url.call()

        missing = []
        map.values.each { |v|
          missing << v if !options[v]
        }

        if missing.size > 0
          if (!credentials or credentials == "#default") and hosted?
            # Let the SDK try to use machine credentials
            return nil
          end
          raise MuError, "Missing fields while trying to load Azure SDK options for credential set #{credentials ? credentials : "<default>" }: #{missing.map { |m| m.to_s }.join(", ")}"
        end

        MU.log "Loaded credential set #{credentials ? credentials : "<default>" }", MU::DEBUG, details: options

        return options
      end

      # Find or allocate a static public IP address resource
      # @param resource_group [String]
      # @param name [String]
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @param region [String]
      # @param tags [Hash<String>]
      # @return [Azure::Network::Mgmt::V2019_02_01::Models::PublicIPAddress]
      def self.fetchPublicIP(resource_group, name, credentials: nil, region: nil, tags: nil)
        if !name or !resource_group
          raise MuError, "Must supply resource_group and name to create or retrieve an Azure PublicIPAddress"
        end
        region ||= MU::Cloud::Azure.myRegion(credentials)

        resp = MU::Cloud::Azure.network(credentials: credentials).public_ipaddresses.get(resource_group, name)
        if !resp
          ip_obj = MU::Cloud::Azure.network(:PublicIPAddress).new
          ip_obj.location = region
          ip_obj.tags = tags if tags
          ip_obj.public_ipallocation_method = "Dynamic"
          MU.log "Allocating PublicIpAddress #{name}", details: ip_obj
          resp = MU::Cloud::Azure.network(credentials: credentials).public_ipaddresses.create_or_update(resource_group, name, ip_obj)
        end

        resp
      end

# BEGIN SDK STUBS
#
      # Azure Subscription Manager API
      # @param model [<Azure::Apis::Subscriptions::Mgmt::V2015_11_01::Models>]: If specified, will return the class ::Azure::Apis::Subscriptions::Mgmt::V2015_11_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.subs(model = nil, alt_object: nil, credentials: nil, model_version: "V2015_11_01")
        require 'azure_mgmt_subscriptions'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Subscriptions").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@subscriptions_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Subscriptions", credentials: credentials, subclass: alt_object)
        end

        return @@subscriptions_api[credentials]
      end

      # An alternative version of the Azure Subscription Manager API, which appears to support subscription creation
      # @param model [<Azure::Apis::Subscriptions::Mgmt::V2018_03_01_preview::Models>]: If specified, will return the class ::Azure::Apis::Subscriptions::Mgmt::V2018_03_01_preview::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.subfactory(model = nil, alt_object: nil, credentials: nil, model_version: "V2018_03_01_preview")
        require 'azure_mgmt_subscriptions'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Subscriptions").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@subscriptions_factory_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Subscriptions", credentials: credentials, profile: "V2018_03_01_preview", subclass: alt_object)
        end

        return @@subscriptions_factory_api[credentials]
      end

      # The Azure SQL API
      # @param model [<Azure::Apis::SQL::Mgmt::V2019_04_01::Models>]: If specified, will return the class ::Azure::Apis::SQL::Mgmt::V2018_06_01_preview::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.sql(model = nil, alt_object: nil, credentials: nil, model_version: "V2014_04_01")
        require 'azure_mgmt_sql'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("SQL").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@sql_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "SQL", credentials: credentials, subclass: alt_object)
        end

        return @@sql_api[credentials]
      end

      # The Azure Compute API
      # @param model [<Azure::Apis::Compute::Mgmt::V2019_04_01::Models>]: If specified, will return the class ::Azure::Apis::Compute::Mgmt::V2019_04_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.compute(model = nil, alt_object: nil, credentials: nil, model_version: "V2020_12_01")
        require 'azure_mgmt_compute'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Compute").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@compute_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Compute", credentials: credentials, subclass: alt_object)
        end

        return @@compute_api[credentials]
      end

      # The Azure Network API
      # @param model [<Azure::Apis::Network::Mgmt::V2019_02_01::Models>]: If specified, will return the class ::Azure::Apis::Network::Mgmt::V2019_02_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.network(model = nil, alt_object: nil, credentials: nil, model_version: "V2019_02_01")
        require 'azure_mgmt_network'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Network").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@network_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Network", credentials: credentials, subclass: alt_object)
        end

        return @@network_api[credentials]
      end

      # The Azure Storage API
      # @param model [<Azure::Apis::Storage::Mgmt::V2019_04_01::Models>]: If specified, will return the class ::Azure::Apis::Storage::Mgmt::V2019_04_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.storage(model = nil, alt_object: nil, credentials: nil, model_version: "V2019_04_01")
        require 'azure_mgmt_storage'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Storage").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@storage_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Storage", credentials: credentials, subclass: alt_object)
        end

        return @@storage_api[credentials]
      end

      # The Azure ApiManagement API
      # @param model [<Azure::Apis::ApiManagement::Mgmt::V2019_01_01::Models>]: If specified, will return the class ::Azure::Apis::ApiManagement::Mgmt::V2019_01_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.apis(model = nil, alt_object: nil, credentials: nil, model_version: "V2019_01_01")
        require 'azure_mgmt_api_management'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("ApiManagement").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@apis_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "ApiManagement", credentials: credentials, subclass: alt_object)
        end

        return @@apis_api[credentials]
      end

      # The Azure MarketplaceOrdering API
      # @param model [<Azure::Apis::MarketplaceOrdering::Mgmt::V2015_06_01::Models>]: If specified, will return the class ::Azure::Apis::MarketplaceOrdering::Mgmt::V2015_06_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.marketplace(model = nil, alt_object: nil, credentials: nil, model_version: "V2015_06_01")
        require 'azure_mgmt_marketplace_ordering'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Resources").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@marketplace_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "MarketplaceOrdering", credentials: credentials, subclass: alt_object)
        end

        return @@marketplace_api[credentials]
      end

      # The Azure Resources API
      # @param model [<Azure::Apis::Resources::Mgmt::V2018_05_01::Models>]: If specified, will return the class ::Azure::Apis::Resources::Mgmt::V2018_05_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.resources(model = nil, alt_object: nil, credentials: nil, model_version: "V2018_05_01")
        require 'azure_mgmt_resources'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Resources").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@resources_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Resources", credentials: credentials, subclass: alt_object)
        end

        return @@resources_api[credentials]
      end

      # The Azure KeyVault API
      # @param model [<Azure::Apis::KeyVault::Mgmt::V2019_09_01::Models>]: If specified, will return the class ::Azure::Apis::KeyVault::Mgmt::V2019_09_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.keyvault(model = nil, alt_object: nil, credentials: nil, model_version: "V2019_09_01")
        require 'azure_mgmt_key_vault'
        load MU.myRoot+'/modules/mu/monkey_patches/key_vault_client.rb' # XXX workarounds for Microsoft's bugs

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("KeyVault").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@keyvault_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "KeyVault", credentials: credentials, subclass: alt_object)
        end

        return @@keyvault_api[credentials]
      end

      # The Azure KeyVault API for items
      # @param model [<Azure::Apis::KeyVault::V7_1::Models>]: If specified, will return the class ::Azure::Apis::KeyVault::V7_1::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.keyvault_items(model = nil, alt_object: nil, credentials: nil, model_version: "V7_1")
        require 'azure_key_vault'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("KeyVault").const_get(model_version).const_get("Models").const_get(model)
        else
          @@keyvault_item_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "KeyVault", credentials: credentials, subclass: alt_object, profile: model_version, path: "Azure::KeyVault::#{model_version}::KeyVaultClient", endpoint: "vault")
        end

        return @@keyvault_item_api[credentials]
      end

      # The Azure Features API
      # @param model [<Azure::Apis::Features::Mgmt::V2015_12_01::Models>]: If specified, will return the class ::Azure::Apis::Features::Mgmt::V2015_12_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.features(model = nil, alt_object: nil, credentials: nil, model_version: "V2015_12_01")
        require 'azure_mgmt_features'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Features").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@features_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Features", credentials: credentials, subclass: alt_object)
        end

        return @@features_api[credentials]
      end

      # The Azure ContainerService API
      # @param model [<Azure::Apis::ContainerService::Mgmt::V2019_04_01::Models>]: If specified, will return the class ::Azure::Apis::ContainerService::Mgmt::V2019_04_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.containers(model = nil, alt_object: nil, credentials: nil, model_version: "V2019_04_01")
        require 'azure_mgmt_container_service'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("ContainerService").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@containers_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "ContainerService", credentials: credentials, subclass: alt_object)
        end

        return @@containers_api[credentials]
      end

      # The Azure ManagedServiceIdentity API
      # @param model [<Azure::Apis::ManagedServiceIdentity::Mgmt::V2015_08_31_preview::Models>]: If specified, will return the class ::Azure::Apis::ManagedServiceIdentity::Mgmt::V2015_08_31_preview::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.serviceaccts(model = nil, alt_object: nil, credentials: nil, model_version: "V2015_08_31_preview")
        require 'azure_mgmt_msi'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("ManagedServiceIdentity").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@service_identity_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "ManagedServiceIdentity", credentials: credentials, subclass: alt_object)
        end

        return @@service_identity_api[credentials]
      end

      # The Azure ManagedApplications API
      # @param model [<Azure::Apis::ManagedApplications::Mgmt::V2018_06_01::Models>]: If specified, will return the class ::Azure::Apis::ManagedServiceIdentity::Mgmt::V2018_06_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.appaccts(model = nil, alt_object: nil, credentials: nil, model_version: "V2018_06_01")
        require 'azure_mgmt_managed_applications'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("ManagedApplications").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@app_identity_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "ManagedApplications", credentials: credentials, subclass: alt_object)
        end

        return @@app_identity_api[credentials]
      end

      # The Azure Web API, whatever that is
      # @param model [<Azure::Apis::Web::Mgmt::V2020_09_01::Models>]: If specified, will return the class ::Azure::Apis::Web::Mgmt::V2020_09_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.web(model = nil, alt_object: nil, credentials: nil, model_version: "V2020_09_01")
        require 'azure_mgmt_web'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Web").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@web_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Web", credentials: credentials, subclass: alt_object)
        end

        return @@web_api[credentials]
      end

      # The Azure Authorization API
      # @param model [<Azure::Apis::Authorization::Mgmt::V2015_07_01::Models>]: If specified, will return the class ::Azure::Apis::Authorization::Mgmt::V2015_07_01::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.authorization(model = nil, alt_object: nil, credentials: nil, model_version: "V2015_07_01", endpoint_profile: "Latest")
        require 'azure_mgmt_authorization'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Authorization").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@authorization_api[credentials] ||= {}
          @@authorization_api[credentials][endpoint_profile] ||= MU::Cloud::Azure::SDKClient.new(api: "Authorization", credentials: credentials, subclass: "AuthorizationManagementClass", profile: endpoint_profile)
        end

        return @@authorization_api[credentials][endpoint_profile]
      end

      # The Azure Billing API
      # @param model [<Azure::Apis::Billing::Mgmt::V2018_03_01_preview::Models>]: If specified, will return the class ::Azure::Apis::Billing::Mgmt::V2018_03_01_preview::Models::model instead of an API client instance
      # @param model_version [String]: Use an alternative model version supported by the SDK when requesting a +model+
      # @param alt_object [String]: Return an instance of something other than the usual API client object
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      # @return [MU::Cloud::Azure::SDKClient]
      def self.billing(model = nil, alt_object: nil, credentials: nil, model_version: "V2018_03_01_preview")
        require 'azure_mgmt_billing'

        if model and model.is_a?(Symbol)
          return Object.const_get("Azure").const_get("Billing").const_get("Mgmt").const_get(model_version).const_get("Models").const_get(model)
        else
          @@billing_api[credentials] ||= MU::Cloud::Azure::SDKClient.new(api: "Billing", credentials: credentials, subclass: alt_object)
        end

        return @@billing_api[credentials]
      end

      # Make sure that a provider is enabled ("Registered" in Azure-ese).
      # @param provider [String]: Provider name, typically formatted like +Microsoft.ContainerService+ 
      # @param force [Boolean]: Run the operation even if the provider already appears to be enabled
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      def self.ensureProvider(provider, force: false, credentials: nil)
        state = MU::Cloud::Azure.resources(credentials: credentials).providers.get(provider)
        if state.registration_state != "Registered" or force
          begin
            if state.registration_state == "NotRegistered" or force
              MU.log "Registering Provider #{provider}", MU::NOTICE
              MU::Cloud::Azure.resources(credentials: credentials).providers.register(provider)
              force = false
              sleep 30
            elsif state.registration_state == "Registering"
              MU.log "Waiting for Provider #{provider} to finish registering", MU::NOTICE, details: state.registration_state
              sleep 30
            end
            state = MU::Cloud::Azure.resources(credentials: credentials).providers.get(provider)
          end while state and state.registration_state != "Registered"
        end
      end

      # Make sure that a feature is enabled ("Registered" in Azure-ese), usually invoked for preview features which are off by default.
      # @param feature_string [String]: The name of a feature, such as +WindowsPreview+
      # @param credentials [String]: The credential set (subscription, effectively) in which to operate
      def self.ensureFeature(feature_string, credentials: nil)
        provider, feature = feature_string.split(/\//)
        feature_state = MU::Cloud::Azure.features(credentials: credentials).features.get(provider, feature)
        changed = false
        begin
          if feature_state
            if feature_state.properties.state == "Registering"
              MU.log "Waiting for Feature #{provider}/#{feature} to finish registering", MU::NOTICE, details: feature_state.properties.state
              sleep 30
            elsif feature_state.properties.state == "NotRegistered"
              MU.log "Registering Feature #{provider}/#{feature}", MU::NOTICE
              MU::Cloud::Azure.features(credentials: credentials).features.register(provider, feature)
              changed = true
              sleep 30
            else
              MU.log "#{provider}/#{feature} registration state: #{feature_state.properties.state}", MU::DEBUG
            end
            feature_state = MU::Cloud::Azure.features(credentials: credentials).features.get(provider, feature)
          end
        end while feature_state and feature_state.properties.state != "Registered"
        ensureProvider(provider, credentials: credentials, force: true) if changed
      end

# END SDK STUBS

# BEGIN SDK CLIENT

      @@authorization_api = {}
      @@subscriptions_api = {}
      @@subscriptions_factory_api = {}
      @@compute_api = {}
      @@sql_api = {}
      @@billing_api = {}
      @@apis_api = {}
      @@network_api = {}
      @@storage_api = {}
      @@resources_api = {}
      @@containers_api = {}
      @@features_api = {}
      @@keyvault_api = {}
      @@keyvault_item_api = {}
      @@apis_api = {}
      @@web_api = {}
      @@marketplace_api = {}
      @@service_identity_api = {}
      @@app_identity_api = {}

      # Generic wrapper for connections to Azure APIs
      class SDKClient
        @api = nil
        @credentials = nil
        @cred_hash = nil
        @wrappers = {}

        attr_reader :issuer
        attr_reader :subclass
        attr_reader :api

        def initialize(api: "Compute", credentials: nil, profile: "Latest", subclass: nil, path: nil, endpoint: nil)
          subclass ||= api.sub(/s$/, '')+"Client"
          @subclass = subclass
          @wrapper_semaphore = Mutex.new
          @wrapper_semaphore.synchronize { 
            @wrappers ||= {}
          }

          @credentials = MU::Cloud::Azure.credConfig(credentials, name_only: true)
          @cred_hash = MU::Cloud::Azure.getSDKOptions(credentials, endpoint: endpoint)
          if !@cred_hash
            raise MuError, "Failed to load Azure credentials #{credentials ? credentials : "<default>"}"
          end

          # There seem to be multiple ways to get at clients, and different 
          # profiles available depending which way you do it, so... try that?
          path ||= "::Azure::#{api}::Profiles::#{profile}::Mgmt::Client"
          begin
            # Standard approach: get a client from a canned, approved profile
            begin
              @api = Object.const_get(path).new(@cred_hash)
            rescue ArgumentError => e
              raise e if e.message !~ /invalid type of credentials/
              @api = Object.const_get(path).new(@cred_hash[:credentials])
            end
          rescue NameError => e
            raise e if !@cred_hash[:client_secret]
            # Weird approach: generate our own credentials object and invoke a
            # client directly from a particular model profile
#            settings = (@credentials['region'] =~ /USGov/) ? ::MsRestAzure::ActiveDirectoryServiceSettings.get_azure_us_government_settings : ::MsRestAzure::ActiveDirectoryServiceSettings.get_azure_settings
            token_provider = MsRestAzure::ApplicationTokenProvider.new(
              @cred_hash[:tenant_id],
              @cred_hash[:client_id],
              @cred_hash[:client_secret],
              @cred_hash[:active_directory_settings]
            )
            @cred_obj = MsRest::TokenCredentials.new(token_provider)
            begin
              modelpath = "::Azure::#{api}::Mgmt::#{profile}::#{@subclass}"
              @api = Object.const_get(modelpath).new(@cred_obj)
              @api.base_url = @cred_hash[:base_url] # XXX verify that this is even needed, as well as whether it's correct
            rescue NameError => e
            pp e.inspect
              raise MuError, "Unable to locate a profile #{profile} of Azure API #{api}. I tried:\n#{path}\n#{modelpath}"
            end
          end
        end

        # For method calls into the Azure API
        # @param method_sym [Symbol]
        # @param arguments [Array]
        def method_missing(method_sym, *arguments)
          aoe_orig = Thread.abort_on_exception
          Thread.abort_on_exception = false
          @wrapper_semaphore.synchronize {
            return @wrappers[method_sym] if @wrappers[method_sym] and arguments.nil?
          } 
          # there's a low-key race condition here, but it's harmless and I'm
          # trying to pin down an odd deadlock condition on cleanup calls
          if !arguments.nil? and arguments.size == 1
            retval = @api.method(method_sym).call(arguments[0])
          elsif !arguments.nil? and arguments.size > 0
            retval = @api.method(method_sym).call(*arguments)
          else
            retval = @api.method(method_sym).call
          end
          deep_retval = ClientCallWrapper.new(retval, method_sym.to_s, self)
          @wrapper_semaphore.synchronize {
            @wrappers[method_sym] = deep_retval
          }
          Thread.abort_on_exception = aoe_orig
          return @wrappers[method_sym]
        end

        # The Azure SDK embeds several "sub-APIs" in each SDK client, and most
        # API calls are made from these second-tier objects. We add an extra
        # wrapper layer for these so that we can gracefully handle errors,
        # retries, etc.
        class ClientCallWrapper

          def initialize(myobject, myname, parent)
            @myobject = myobject
            @myname = myname
            @parent = parent
            @parentname = parent.subclass
          end

          # For method calls into the Azure API
          # @param method_sym [Symbol]
          # @param arguments [Array]
          def method_missing(method_sym, *arguments)
            MU.log "Calling #{@parentname}.#{@myname}.#{method_sym.to_s}", MU::DEBUG, details: arguments

            retries = 0
            begin
              if !arguments.nil? and arguments.size == 1
                retval = @myobject.method(method_sym).call(arguments[0])
              elsif !arguments.nil? and arguments.size > 0
                retval = @myobject.method(method_sym).call(*arguments)
              else
                retval = @myobject.method(method_sym).call
              end
            rescue ::Net::ReadTimeout, ::Faraday::TimeoutError, ::Faraday::ConnectionFailed => e
              sleep 5
              if retries < 12
                MU.log e.message+" calling #{@parentname}.#{@myname}.#{method_sym.to_s}(#{arguments.map { |a| a.to_s }.join(", ")})", MU::DEBUG, details: caller
                retries += 1
                retry
              else
                MU.log e.message+" calling #{@parentname}.#{@myname}.#{method_sym.to_s}(#{arguments.map { |a| a.to_s }.join(", ")})", MU::ERR, details: caller
                raise e
              end
            rescue ::MsRestAzure::AzureOperationError, ::MsRest::HttpOperationError => e
              MU.log "Error calling #{@parent.api.class.name}.#{@myname}.#{method_sym.to_s}", MU::DEBUG, details: arguments
              begin
                parsed = JSON.parse(e.message)
                if parsed["response"] and parsed["response"]["body"]
                  response = JSON.parse(parsed["response"]["body"])
                  err = if response["code"] and response["message"]
                    response
                  elsif response["error"] and response["error"]["code"] and
                        response["error"]["message"]
                    response["error"]
                  end
                  if err
                    if method_sym == :get and
                       ["ResourceNotFound", "NotFound"].include?(err["code"])
                      return nil
                    elsif err["code"] == "AnotherOperationInProgress"
                      sleep 10
                      retry
                    end

#                    MU.log "#{@parent.api.class.name}.#{@myname}.#{method_sym.to_s} returned '"+err["code"]+"' - "+err["message"], MU::WARN, details: caller
#                    MU.log e.backtrace[0], MU::WARN, details: parsed
                    raise MU::Cloud::Azure::APIError.new err["code"]+": "+err["message"]+" (call was #{@parent.api.class.name}.#{@myname}.#{method_sym.to_s})", details: parsed, silent: true
                  end
                end
              rescue JSON::ParserError
              end
#              MU.log e.inspect, MU::ERR, details: caller
#              MU.log e.message, MU::ERR, details: @parent.credentials
            end

            retval
          end

        end

      end
# END SDK CLIENT
    end
  end
end
