# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
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
  # Plugins under this namespace serve as interfaces to cloud providers and
  # other provisioning layers.
  class Cloud
    # An exception denoting an expected, temporary connection failure to a
    # bootstrapping instance, e.g. for Windows instances that must reboot in
    # mid-installation.
    class BootstrapTempFail < MuNonFatal;
    end

    # Exception thrown when a request is made to an unimplemented cloud
    # resource.
    class MuCloudResourceNotImplemented < StandardError;
    end

    generic_class_methods = [:find, :cleanup]
    generic_instance_methods = [:create, :notify, :mu_name, :cloud_id, :config]

    # Initialize empty classes for each of these. We'll fill them with code
    # later; we're doing this here because otherwise the parser yells about
    # missing classes, even though they're created at runtime.

    # Stub base class; real implementations generated at runtime
    class Collection;
    end
    # Stub base class; real implementations generated at runtime
    class Database;
    end
    # Stub base class; real implementations generated at runtime
    class DNSZone;
    end
    # Stub base class; real implementations generated at runtime
    class FirewallRule;
    end
    # Stub base class; real implementations generated at runtime
    class LoadBalancer;
    end
    # Stub base class; real implementations generated at runtime
    class Server;
    end
    # Stub base class; real implementations generated at runtime
    class ServerPool;
    end
    # Stub base class; real implementations generated at runtime
    class VPC;
    end
    # Stub base class; real implementations generated at runtime
    class CacheCluster;
    end
    # Stub base class; real implementations generated at runtime
    class Alarm;
    end
    # Stub base class; real implementations generated at runtime
    class Notification;
    end
    # Stub base class; real implementations generated at runtime
    class Log;
    end

    # The types of cloud resources we can create, as class objects. Include
    # methods a class implementing this resource type must support to be
    # considered valid.
    @@resource_types = {
        :Collection => {
            :has_multiples => false,
            :can_live_in_vpc => false,
            :cfg_name => "collection",
            :cfg_plural => "collections",
            :interface => self.const_get("Collection"),
            :deps_wait_on_my_creation => true,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods
        },
        :Database => {
            :has_multiples => true,
            :can_live_in_vpc => true,
            :cfg_name => "database",
            :cfg_plural => "databases",
            :interface => self.const_get("Database"),
            :deps_wait_on_my_creation => true,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom, :allowHost]
        },
        :DNSZone => {
            :has_multiples => false,
            :can_live_in_vpc => false,
            :cfg_name => "dnszone",
            :cfg_plural => "dnszones",
            :interface => self.const_get("DNSZone"),
            :deps_wait_on_my_creation => true,
            :waits_on_parent_completion => true,
            :class => generic_class_methods + [:genericMuDNSEntry, :createRecordsFromConfig],
            :instance => generic_instance_methods
        },
        :FirewallRule => {
            :has_multiples => false,
            :can_live_in_vpc => true,
            :cfg_name => "firewall_rule",
            :cfg_plural => "firewall_rules",
            :interface => self.const_get("FirewallRule"),
            :deps_wait_on_my_creation => true,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom, :addRule]
        },
        :LoadBalancer => {
            :has_multiples => false,
            :can_live_in_vpc => true,
            :cfg_name => "loadbalancer",
            :cfg_plural => "loadbalancers",
            :interface => self.const_get("LoadBalancer"),
            :deps_wait_on_my_creation => true,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:registerNode]
        },
        :Server => {
            :has_multiples => true,
            :can_live_in_vpc => true,
            :cfg_name => "server",
            :cfg_plural => "servers",
            :interface => self.const_get("Server"),
            :deps_wait_on_my_creation => false,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom, :postBoot, :getSSHConfig, :canonicalIP, :getWindowsAdminPassword, :active?, :groomer, :mu_windows_name, :mu_windows_name=, :reboot]
        },
        :ServerPool => {
            :has_multiples => false,
            :can_live_in_vpc => true,
            :cfg_name => "server_pool",
            :cfg_plural => "server_pools",
            :interface => self.const_get("ServerPool"),
            :deps_wait_on_my_creation => false,
            :waits_on_parent_completion => true,
            :class => generic_class_methods,
            :instance => generic_instance_methods
        },
        :VPC => {
            :has_multiples => false,
            :can_live_in_vpc => false,
            :cfg_name => "vpc",
            :cfg_plural => "vpcs",
            :interface => self.const_get("VPC"),
            :deps_wait_on_my_creation => true,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom, :subnets, :getSubnet, :listSubnets, :findBastion, :findNat]
        },
        :CacheCluster => {
            :has_multiples => true,
            :can_live_in_vpc => true,
            :cfg_name => "cache_cluster",
            :cfg_plural => "cache_clusters",
            :interface => self.const_get("CacheCluster"),
            :deps_wait_on_my_creation => true,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom]
        },
        :Alarm => {
            :has_multiples => false,
            :can_live_in_vpc => false,
            :cfg_name => "alarm",
            :cfg_plural => "alarms",
            :interface => self.const_get("Alarm"),
            :deps_wait_on_my_creation => false,
            :waits_on_parent_completion => true,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom]
        },
        :Notification => {
            :has_multiples => false,
            :can_live_in_vpc => false,
            :cfg_name => "notification",
            :cfg_plural => "notifications",
            :interface => self.const_get("Notification"),
            :deps_wait_on_my_creation => false,
            :waits_on_parent_completion => false,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom]
        },
        :Log => {
            :has_multiples => false,
            :can_live_in_vpc => false,
            :cfg_name => "log",
            :cfg_plural => "logs",
            :interface => self.const_get("Log"),
            :deps_wait_on_my_creation => false,
            :waits_on_parent_completion => true,
            :class => generic_class_methods,
            :instance => generic_instance_methods + [:groom]
        }
    }.freeze


    # A list of supported cloud resource types as Mu classes
    def self.resource_types;
      @@resource_types
    end

    # List of known/supported Cloud providers
    def self.supportedClouds
      ["AWS", "Docker"]
    end

    # Load the container class for each cloud we know about, and inject autoload
    # code for each of its supported resource type classes.
    MU::Cloud.supportedClouds.each { |cloud|
      require "mu/clouds/#{cloud.downcase}"
    }

    # Given a cloud layer and resource type, return the class which implements it.
    # @param cloud [String]: The Cloud layer
    # @param type [String]: The resource type. Can be the full class name, symbolic name, or Basket of Kittens configuration shorthand for the resource type.
    # @return [Class]: The cloud-specific class implementing this resource
    def self.loadCloudType(cloud, type)
      raise MuError, "cloud argument to MU::Cloud.loadCloudType cannot be nil" if cloud.nil?
      # If we've been asked to resolve this object, that means we plan to use
      # it, so go ahead and load it.
      cfg_name = nil
      @@resource_types.each_pair { |name, cloudclass|
        if name == type.to_sym or
            cloudclass[:cfg_name] == type or
            cloudclass[:cfg_plural] == type or
            Object.const_get("MU").const_get("Cloud").const_get(name) == type
          cfg_name = cloudclass[:cfg_name]
          type = name
          break
        end
      }
      if cfg_name.nil?
        puts caller
        raise MuError, "Can't find a cloud resource type named '#{type}'"
      end
      if !File.size?(MU.myRoot+"/modules/mu/clouds/#{cloud.downcase}.rb")
        raise MuError, "Requested to use unsupported provisioning layer #{cloud}"
      end
      begin
        require "mu/clouds/#{cloud.downcase}/#{cfg_name}"
      rescue LoadError => e
        raise MuCloudResourceNotImplemented
      end
      begin
        myclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(type)

        @@resource_types[type.to_sym][:class].each { |class_method|
          if !myclass.respond_to?(class_method)
            raise MuError, "MU::Cloud::#{cloud}::#{type} has not implemented required class method #{class_method}"
          end
        }
        @@resource_types[type.to_sym][:instance].each { |instance_method|
          if !myclass.public_instance_methods.include?(instance_method)
            raise MuError, "MU::Cloud::#{cloud}::#{type} has not implemented required instance method #{instance_method}"
          end
        }

        return myclass
      rescue NameError => e
        raise MuError, "The '#{type}' resource is not supported in cloud #{cloud} (tried MU::#{cloud}::#{type})", e.backtrace
      end
    end

    MU::Cloud.supportedClouds.each { |cloud|
      Object.const_get("MU").const_get("Cloud").const_get(cloud).class_eval {

        # Automatically load supported cloud resource classes when they're
        # referenced.
        def self.const_missing(symbol)
          if MU::Cloud.resource_types.has_key?(symbol.to_sym)
            return MU::Cloud.loadCloudType(name.sub(/.*?::([^:]+)$/, '\1'), symbol)
          else
            raise MuCloudResourceNotImplemented, "No such cloud resource #{name}:#{symbol}"
          end
        end
      }
    }

    @@resource_types.each_pair { |name, attrs|
      Object.const_get("MU").const_get("Cloud").const_get(name).class_eval {
        attr_reader :cloud
        attr_reader :environment
        attr_reader :cloudclass
        attr_reader :cloudobj
        attr_reader :deploy_id
        attr_reader :mu_name
        attr_reader :cloud_id
        attr_reader :config
        attr_reader :deploydata
        attr_reader :destroyed

        def self.shortname
          name.sub(/.*?::([^:]+)$/, '\1')
        end

        def self.cfg_plural
          MU::Cloud.resource_types[shortname.to_sym][:cfg_plural]
        end

        def self.has_multiples
          MU::Cloud.resource_types[shortname.to_sym][:has_multiples]
        end

        def self.cfg_name
          MU::Cloud.resource_types[shortname.to_sym][:cfg_name]
        end

        def self.can_live_in_vpc
          MU::Cloud.resource_types[shortname.to_sym][:can_live_in_vpc]
        end

        def self.waits_on_parent_completion
          MU::Cloud.resource_types[shortname.to_sym][:waits_on_parent_completion]
        end

        def self.deps_wait_on_my_creation
          MU::Cloud.resource_types[shortname.to_sym][:deps_wait_on_my_creation]
        end

        def groomer
          return @cloudobj.groomer if !@cloudobj.nil?
          nil
        end

        # Print something palatable when we're called in a string context.
        def to_s
          fullname = "#{self.class.shortname}"
          if !@cloudobj.nil? and !@cloudobj.mu_name.nil?
            @mu_name ||= @cloudobj.mu_name
          end
          if !@mu_name.nil? and !@mu_name.empty?
            fullname = fullname + " '#{@mu_name}'"
          end
          if !@cloud_id.nil?
            fullname = fullname + " (#{@cloud_id})"
          end
          return fullname
        end

        # @param mommacat [MU::MommaCat]: The deployment containing this cloud resource
        # @param mu_name [String]: Optional- specify the full Mu resource name of an existing resource to load, instead of creating a new one
        # @param cloud_id [String]: Optional- specify the cloud provider's identifier for an existing resource to load, instead of creating a new one
        # @param kitten_cfg [Hash]: The parse configuration for this object from {MU::Config}
        def initialize(mommacat: nil,
                       mu_name: nil,
                       cloud_id: nil,
                       kitten_cfg: nil)
          raise MuError, "Cannot invoke Cloud objects without a configuration" if kitten_cfg.nil?
          @live = true
          @deploy = mommacat
          @config = kitten_cfg
          @cloud_id = cloud_id
          if !@deploy.nil?
            @deploy_id = @deploy.deploy_id
            MU.log "Initializing an instance of #{self.class.name} in #{@deploy_id} #{mu_name}", MU::DEBUG, details: kitten_cfg
          elsif mu_name.nil?
            raise MuError, "Can't instantiate a MU::Cloud object with a live deploy or giving us a mu_name"
          else
            MU.log "Initializing an independent instance of #{self.class.name} named #{mu_name}", MU::DEBUG, details: kitten_cfg
          end
          if !kitten_cfg.has_key?("cloud")
            kitten_cfg['cloud'] = MU::Config.defaultCloud
          end
          @cloud = kitten_cfg['cloud']
          @cloudclass = MU::Cloud.loadCloudType(@cloud, self.class.shortname)
          @environment = kitten_cfg['environment']
          @method_semaphore = Mutex.new
          @method_locks = {}
# XXX require subclass to provide attr_readers of @config and @deploy

          @cloudobj = @cloudclass.new(mommacat: mommacat, kitten_cfg: kitten_cfg, cloud_id: cloud_id, mu_name: mu_name)

          raise MuError, "Unknown error instantiating #{self}" if @cloudobj.nil?

# If we just loaded an existing object, go ahead and prepopulate the
# describe() cache
          if !cloud_id.nil? or !mu_name.nil?
            @cloudobj.describe(cloud_id: cloud_id)
          end

          @deploydata = @cloudobj.deploydata
          @config = @cloudobj.config

# If we're going to be integrated into AD or otherwise need a short
# hostname, generate it now.
          if self.class.shortname == "Server" and (@cloudobj.windows? or @config['active_directory']) and @cloudobj.mu_windows_name.nil?
            if !@deploydata.nil? and !@deploydata['mu_windows_name'].nil?
              @cloudobj.mu_windows_name = @deploydata['mu_windows_name']
            else
              # Use the same random differentiator as the "real" name if we're
              # from a ServerPool. Helpful for admin sanity.
              unq = @cloudobj.mu_name.sub(/^.*?-(...)$/, '\1')
              if @config['basis'] and !unq.nil? and !unq.empty?
                @cloudobj.mu_windows_name = @deploy.getResourceName(@config['name'], max_length: 15, need_unique_string: true, use_unique_string: unq, reuse_unique_string: true)
              else
                @cloudobj.mu_windows_name = @deploy.getResourceName(@config['name'], max_length: 15, need_unique_string: true)
              end
            end
          end

# Register us with our parent deploy so that we can be found by our
# littermates if needed.
          if !@deploy.nil? and !@cloudobj.mu_name.nil? and !@cloudobj.mu_name.empty?
            @deploy.addKitten(self.class.cfg_name, @config['name'], self)
          elsif !@deploy.nil?
            MU.log "#{self} didn't generate a mu_name after being loaded/initialized, dependencies on this resource will probably be confused!", MU::ERR
          end
        end

        # Remove all metadata and cloud resources associated with this object
        def destroy
          if !@cloudobj.nil? and !@cloudobj.groomer.nil?
            @cloudobj.groomer.cleanup
          elsif !@groomer.nil?
            @groomer.cleanup
          end
          if !@deploy.nil?
            if !@cloudobj.nil? and !@config.nil? and !@cloudobj.mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], nil, mu_name: @cloudobj.mu_name, remove: true, triggering_node: @cloudobj)
            elsif !@mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], nil, mu_name: @mu_name, remove: true, triggering_node: self)
            end
            @deploy.removeKitten(self)
          end
          # Make sure that if notify gets called again it won't go returning a
          # bunch of now-bogus metadata.
          @destroyed = true
          if !@cloudobj.nil?
            def @cloudobj.notify
              {}
            end
          else
            def notify
              {}
            end
          end
        end

        def cloud_desc
          describe
          if !@config.nil? and !@cloud_id.nil?
            # The find() method should be returning a Hash with the cloud_id
            # as a key.
            begin
              matches = self.class.find(region: @config['region'], cloud_id: @cloud_id)
              if !matches.nil? and matches.is_a?(Hash) and matches.has_key?(@cloud_id)
                @cloud_desc = matches[@cloud_id]
              else
                MU.log "Failed to find a live #{self.class.shortname} with identifier #{@cloud_id}, which has a record in deploy #{@deploy.deploy_id}", MU::WARN
              end
            rescue Exception => e
              MU.log "Got #{e.inspect} trying to find cloud handle for #{self.class.shortname} #{@mu_name} (#{@cloud_id})", MU::WARN
              raise e
            end
          end
          return @cloud_desc
        end

        # Retrieve all of the known metadata for this resource.
        # @param cloud_id [String]: The cloud platform's identifier for the resource we're describing. Makes lookups more efficient.
        # @param update_cache [Boolean]: Ignore cached data if we have any, instead reconsituting from original sources.
        # @return [Array<Hash>]: mu_name, config, deploydata
        def describe(cloud_id: nil, update_cache: false)
          if cloud_id.nil? and !@cloudobj.nil?
            @cloud_id = @cloudobj.cloud_id
          end
          res_type = self.class.cfg_plural
          res_name = @config['name'] if !@config.nil?
          deploydata = nil
          if !@deploy.nil? and @deploy.is_a?(MU::MommaCat) and
              !@deploy.deployment.nil? and
              !@deploy.deployment[res_type].nil? and
              !@deploy.deployment[res_type][res_name].nil?
            deploydata = @deploy.deployment[res_type][res_name]
          else
            # XXX This should only happen on a brand new resource, but we should
            # probably complain under other circumstances, if we can
            # differentiate them.
          end

          if self.class.has_multiples and !@mu_name.nil? and deploydata.is_a?(Hash) and deploydata.has_key?(@mu_name)
            @deploydata = deploydata[@mu_name]
          elsif deploydata.is_a?(Hash)
            @deploydata = deploydata
          end

          if @cloud_id.nil? and @deploydata.is_a?(Hash)
            if @mu_name.nil? and @deploydata.has_key?('#MU_NAME')
              @mu_name = @deploydata['#MU_NAME']
            end
            if @deploydata.has_key?('cloud_id')
              @cloud_id = @deploydata['cloud_id']
            else
              # XXX temp hack to catch old Amazon-style identifiers. Remove this
              # before supporting any other cloud layers, otherwise name
              # collision is possible.
              ["group_id", "instance_id", "awsname", "identifier", "vpc_id", "id"].each { |identifier|
                if @deploydata.has_key?(identifier)
                  @cloud_id = @deploydata[identifier]
                  if @mu_name.nil? and (identifier == "awsname" or identifier == "identifier" or identifier == "group_id")
                    @mu_name = @deploydata[identifier]
                  end
                  break
                end
              }
            end
          end

          return [@mu_name, @config, @deploydata]
        end

        # Fetch MU::Cloud objects for each of this object's dependencies, and
        # return in an easily-navigable Hash. This can include things listed in
        # @config['dependencies'], implicitly-defined depdendencies such as
        # add_firewall_rules or vpc stanzas, and may refer to objects internal
        # to this deployment or external.  Will populate the instance variables
        # @dependencies (general dependencies, which can only be sibling
        # resources in this deployment), as well as for certain config stanzas
        # which can refer to external resources (@vpc, @loadbalancers,
        # @add_firewall_rules)
        def dependencies
          @dependencies = {} if @dependencies.nil?
          @loadbalancers = [] if @loadbalancers.nil?
          if @config.nil?
            return [@dependencies, @vpc, @loadbalancers]
          end
          @config['dependencies'] = [] if @config['dependencies'].nil?

          # First, general dependencies. These should all be fellow members of
          # the current deployment.
          @config['dependencies'].each { |dep|
            @dependencies[dep['type']] = {} if !@dependencies.has_key?(dep['type'])
            next if @dependencies[dep['type']].has_key?(dep['name'])
            handle = @deploy.findLitterMate(type: dep['type'], name: dep['name']) if !@deploy.nil?
            if !handle.nil?
              MU.log "Loaded dependency for #{self}: #{dep['name']} => #{handle}", MU::DEBUG
              @dependencies[dep['type']][dep['name']] = handle
            else
              # XXX yell under circumstances where we should expect to have
              # our stuff available already?
            end
          }

          # Special dependencies: my containing VPC
          if self.class.can_live_in_vpc and !@config['vpc'].nil?
            MU.log "Loading VPC for #{self}", MU::DEBUG, details: @config['vpc']
            if !@config['vpc']["vpc_name"].nil? and
                @dependencies.has_key?("vpc") and
                @dependencies["vpc"].has_key?(@config['vpc']["vpc_name"])
              @vpc = @dependencies["vpc"][@config['vpc']["vpc_name"]]
            else
              tag_key, tag_value = @config['vpc']['tag'].split(/=/, 2) if !@config['vpc']['tag'].nil?
              if !@config['vpc'].has_key?("vpc_id") and
                  !@config['vpc'].has_key?("deploy_id") and !@deploy.nil?
                @config['vpc']["deploy_id"] = @deploy.deploy_id
              end
              vpcs = MU::MommaCat.findStray(
                @config['cloud'],
                "vpc",
                deploy_id: @config['vpc']["deploy_id"],
                cloud_id: @config['vpc']["vpc_id"],
                name: @config['vpc']["vpc_name"],
                tag_key: tag_key,
                tag_value: tag_value,
                region: @config['vpc']["region"],
                calling_deploy: @deploy,
                dummy_ok: true
              )
              @vpc = vpcs.first if !vpcs.nil? and vpcs.size > 0
            end
            if !@vpc.nil? and (
              @config['vpc'].has_key?("nat_host_id") or
              @config['vpc'].has_key?("nat_host_tag") or
              @config['vpc'].has_key?("nat_host_ip") or
              @config['vpc'].has_key?("nat_host_name")
              )

              nat_tag_key, nat_tag_value = @config['vpc']['nat_host_tag'].split(/=/, 2) if !@config['vpc']['nat_host_tag'].nil?

              # Try to see if we have a NAT Gateway, if not find our NAT Instance 
              @nat = @vpc.findNat(
                nat_cloud_id: @config['vpc']['nat_host_id'],
                nat_filter_key: "vpc-id",
                region: @config['vpc']["region"],
                nat_filter_value: @vpc.cloud_desc.vpc_id
              )

              if @nat.nil?
                @nat = @vpc.findBastion(
                  nat_name: @config['vpc']['nat_host_name'],
                  nat_cloud_id: @config['vpc']['nat_host_id'],
                  nat_tag_key: nat_tag_key,
                  nat_tag_value: nat_tag_value,
                  nat_ip: @config['vpc']['nat_host_ip']
                )
              end
            end
          elsif self.class.cfg_name == "vpc"
            @vpc = self
          end

          # Special dependencies: LoadBalancers I've asked to attach to an
          # instance.
          if @config.has_key?("loadbalancers")
            @loadbalancers = [] if !@loadbalancers
            @config['loadbalancers'].each { |lb|
              MU.log "Loading LoadBalancer for #{self}", MU::DEBUG, details: lb
              if @dependencies.has_key?("loadbalancer") and
                  @dependencies["loadbalancer"].has_key?(lb['concurrent_load_balancer'])
                @loadbalancers << @dependencies["loadbalancer"][lb['concurrent_load_balancer']]
              else
                if !lb.has_key?("existing_load_balancer") and
                    !lb.has_key?("deploy_id") and !@deploy.nil?
                  lb["deploy_id"] = @deploy.deploy_id
                end
                lbs = MU::MommaCat.findStray(
                    @config['cloud'],
                    "loadbalancer",
                    deploy_id: lb["deploy_id"],
                    cloud_id: lb['existing_load_balancer'],
                    name: lb['concurrent_load_balancer'],
                    region: @config["region"],
                    calling_deploy: @deploy,
                    dummy_ok: true
                )
                @loadbalancers << lbs.first if !lbs.nil? and lbs.size > 0
              end
            }
          end

          return [@dependencies, @vpc, @loadbalancers]
        end

        def self.find(*flags)
          MU::Cloud.supportedClouds.each { |cloud|
            begin
              cloudclass = MU::Cloud.loadCloudType(cloud, shortname)
              found = cloudclass.find(flags.first)
              return found if !found.nil? # XXX actually, we should merge all results
            rescue MuCloudResourceNotImplemented
            end
            return nil
          }
        end

        if shortname == "DNSZone"
          def self.genericMuDNSEntry(*flags)
# XXX have this switch on a global config for where Mu puts its DNS
            cloudclass = MU::Cloud.loadCloudType(MU::Config.defaultCloud, "DNSZone")
            cloudclass.genericMuDNSEntry(flags.first)
          end
          def self.createRecordsFromConfig(*flags)
            cloudclass = MU::Cloud.loadCloudType(MU::Config.defaultCloud, "DNSZone")
            if !flags.nil? and flags.size == 1
              cloudclass.createRecordsFromConfig(flags.first)
            else
              cloudclass.createRecordsFromConfig(*flags)
            end
          end
        end

        if shortname == "Server"
          def windows?
            %w{win2k12r2 win2k12 win2k8 win2k8r2 windows}.include?(@config['platform'])
          end

          # Basic setup tasks performed on a new node during its first initial ssh
          # connection. Most of this is terrible Windows glue.
          # @param ssh [Net::SSH::Connection::Session]: The active SSH session to the new node.
          def initialSSHTasks(ssh)
            win_env_fix = %q{echo 'export PATH="$PATH:/cygdrive/c/opscode/chef/embedded/bin"' > "$HOME/chef-client"; echo 'prev_dir="`pwd`"; for __dir in /proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Session\ Manager/Environment;do cd "$__dir"; for __var in `ls * | grep -v TEMP | grep -v TMP`;do __var=`echo $__var | tr "[a-z]" "[A-Z]"`; test -z "${!__var}" && export $__var="`cat $__var`" >/dev/null 2>&1; done; done; cd "$prev_dir"; /cygdrive/c/opscode/chef/bin/chef-client.bat $@' >> "$HOME/chef-client"; chmod 700 "$HOME/chef-client"; ( grep "^alias chef-client=" "$HOME/.bashrc" || echo 'alias chef-client="$HOME/chef-client"' >> "$HOME/.bashrc" ) ; ( grep "^alias mu-groom=" "$HOME/.bashrc" || echo 'alias mu-groom="powershell -File \"c:/Program Files/Amazon/Ec2ConfigService/Scripts/UserScript.ps1\""' >> "$HOME/.bashrc" )}
            win_installer_check = %q{ls /proc/registry/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Installer/}
            lnx_installer_check = %q{ps auxww | awk '{print $11}' | egrep '(/usr/bin/yum|apt-get|dpkg)'}
            lnx_updates_check = %q{( test -f /.mu-installer-ran-updates || ! test -d /var/lib/cloud/instance ) || echo "userdata still running"}
            win_set_pw = nil

            if windows? and !@config['use_cloud_provider_windows_password']
              # This covers both the case where we have a windows password passed from a vault and where we need to use a a random Windows Admin password generated by MU::Cloud::Server.generateWindowsPassword
              pw = @groomer.getSecret(
                  vault: @config['mu_name'],
                  item: "windows_credentials",
                  field: "password"
              )
              win_check_for_pw = %Q{powershell -Command '& {Add-Type -AssemblyName System.DirectoryServices.AccountManagement; $Creds = (New-Object System.Management.Automation.PSCredential("#{@config["windows_admin_username"]}", (ConvertTo-SecureString "#{pw}" -AsPlainText -Force)));$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine); $DS.ValidateCredentials($Creds.GetNetworkCredential().UserName, $Creds.GetNetworkCredential().password); echo $Result}'}
              win_set_pw = %Q{powershell -Command "& {(([adsi]('WinNT://./#{@config["windows_admin_username"]}, user')).psbase.invoke('SetPassword', '#{pw}'))}"}
            end

            # There shouldn't be a use case where a domain joined computer goes through initialSSHTasks. Removing Active Directory specific computer rename.
            set_hostname = true
            hostname = nil
            if !@config['active_directory'].nil?
              if @config['active_directory']['node_type'] == "domain_controller" && @config['active_directory']['domain_controller_hostname']
                hostname = @config['active_directory']['domain_controller_hostname']
                @mu_windows_name = hostname
                set_hostname = true
              else
                # Do we have an AD specific hostname?
                hostname = @mu_windows_name
                set_hostname = true
              end
            else
              hostname = @mu_windows_name
            end
            win_check_for_hostname = %Q{powershell -Command '& {hostname}'}
            win_set_hostname = %Q{powershell -Command "& {Rename-Computer -NewName '#{hostname}' -Force -PassThru -Restart; Restart-Computer -Force}"}

            begin
              # Set our admin password first, if we need to
              if windows? and !win_set_pw.nil? and !win_check_for_pw.nil?
                output = ssh.exec!(win_check_for_pw)
                raise MU::Cloud::BootstrapTempFail, "Got nil output from ssh session, waiting and retrying" if output.nil?
                if !output.match(/True/)
                  MU.log "Setting Windows password for user #{@config['windows_admin_username']}", details: ssh.exec!(win_set_pw)
                end
              end
              if windows?
                output = ssh.exec!(win_env_fix)
                output = ssh.exec!(win_installer_check)
                raise MU::Cloud::BootstrapTempFail, "Got nil output from ssh session, waiting and retrying" if output.nil?
                if output.match(/InProgress/)
                  raise MU::Cloud::BootstrapTempFail, "Windows Installer service is still doing something, need to wait"
                end
                if set_hostname and !@hostname_set and @mu_windows_name
                  output = ssh.exec!(win_check_for_hostname)
                  raise MU::Cloud::BootstrapTempFail, "Got nil output from ssh session, waiting and retrying" if output.nil?
                  if !output.match(/#{@mu_windows_name}/)
                    MU.log "Setting Windows hostname to #{@mu_windows_name}", details: ssh.exec!(win_set_hostname)
                    @hostname_set = true
                    # Reboot from the API too, in case Windows is flailing
                    if !@cloudobj.nil?
                      @cloudobj.reboot
                    else
                      reboot
                    end
                    raise MU::Cloud::BootstrapTempFail, "Set hostname in Windows, waiting for reboot"
                  end
                end
              else
                output = ssh.exec!(lnx_installer_check)
                if !output.nil? and !output.empty?
                  raise MU::Cloud::BootstrapTempFail, "Linux package manager is still doing something, need to wait (#{output})"
                end
                if !@config['skipinitialupdates']
                  output = ssh.exec!(lnx_updates_check)
                  if !output.nil? and output.match(/userdata still running/)
                    raise MU::Cloud::BootstrapTempFail, "Waiting for initial userdata system updates to complete"
                  end
                end
              end
            rescue RuntimeError => e
              raise MU::Cloud::BootstrapTempFail, "Got #{e.inspect} performing initial SSH connect tasks, will try again"
            end

          end


          # @param max_retries [Integer]: Number of connection attempts to make before giving up
          # @param retry_interval [Integer]: Number of seconds to wait between connection attempts
          # @return [Net::SSH::Connection::Session]
          def getSSHSession(max_retries = 12, retry_interval = 30)
            ssh_keydir = Etc.getpwnam(@deploy.mu_user).dir+"/.ssh"
            nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
            session = nil
            retries = 0

            # XXX catch a weird bug in Net::SSH where its exceptions circumvent
            # our regular call stack and we can't catch them.
            Thread.handle_interrupt(Net::SSH::Disconnect => :never) {
              begin
                Thread.handle_interrupt(Net::SSH::Disconnect => :immediate) {
                  MU.log "(Probably harmless) Caught a Net::SSH::Disconnect in #{Thread.current.inspect}", MU::DEBUG, details: Thread.current.backtrace
                }
              ensure
              end
            }
            # XXX WHY is this a thing
            Thread.handle_interrupt(Errno::ECONNREFUSED => :never) {
            }

            forced_windows_reboot = false
            begin
              if !nat_ssh_host.nil?
                proxy_cmd = "ssh -q -o StrictHostKeyChecking=no -W %h:%p #{nat_ssh_user}@#{nat_ssh_host}"
                MU.log "Attempting SSH to #{canonical_ip} (#{@mu_name}) as #{ssh_user} with key #{@deploy.ssh_key_name} using proxy '#{proxy_cmd}'" if retries == 0
                proxy = Net::SSH::Proxy::Command.new(proxy_cmd)
                session = Net::SSH.start(
                    canonical_ip,
                    ssh_user,
                    :config => false,
                    :keys_only => true,
                    :keys => [ssh_keydir+"/"+nat_ssh_key, ssh_keydir+"/"+@deploy.ssh_key_name],
                    :paranoid => false,
                    #           :verbose => :info,
                    :port => 22,
                    :auth_methods => ['publickey'],
                    :proxy => proxy
                )
              else
                MU.log "Attempting SSH to #{canonical_ip} (#{@mu_name}) as #{ssh_user} with key #{ssh_keydir}/#{@deploy.ssh_key_name}" if retries == 0
                session = Net::SSH.start(
                    canonical_ip,
                    ssh_user,
                    :config => false,
                    :keys_only => true,
                    :keys => [ssh_keydir+"/"+@deploy.ssh_key_name],
                    :paranoid => false,
                    #           :verbose => :info,
                    :port => 22,
                    :auth_methods => ['publickey']
                )
              end
              forced_windows_reboot = false
              forced_windows_reboot_twice = false
              retries = 0
            rescue Net::SSH::HostKeyMismatch => e
              MU.log("Remembering new key: #{e.fingerprint}")
              e.remember_host!
              session.close
              retry
            rescue SystemCallError, Timeout::Error, Errno::ECONNRESET, Errno::EHOSTUNREACH, Net::SSH::Proxy::ConnectError, SocketError, Net::SSH::Disconnect, Net::SSH::AuthenticationFailed, IOError, Net::SSH::ConnectionTimeout => e
              begin
                session.close if !session.nil?
              rescue Net::SSH::Disconnect, IOError => e
                if windows?
                  MU.log "Windows has probably closed the ssh session before we could. Waiting before trying again", MU::NOTICE
                else
                  MU.log "ssh session was closed unexpectedly, waiting before trying again", MU::NOTICE
                end
                sleep 10
              end

              if retries < max_retries
                retries = retries + 1
                if retries > max_retries/2 and !forced_windows_reboot_twice
                  forced_windows_reboot = false # another chance to unscrew Windows if it's been flailing for a while
                  forced_windows_reboot_twice = true
                end
                msg = "ssh #{ssh_user}@#{@config['mu_name']}: #{e.message}, waiting #{retry_interval}s (attempt #{retries}/#{max_retries})", MU::WARN
                if retries == 1 or (retries/max_retries <= 0.5 and (retries % 3) == 0)
                  MU.log msg, MU::NOTICE
                elsif retries/max_retries > 0.5
                  MU.log msg, MU::WARN, details: e.inspect
                end
                if e.message.match(/connection closed by remote host/) and windows? and !forced_windows_reboot
                  forced_windows_reboot = true
                  reboot
                end
                sleep retry_interval
                retry
              else
                raise MuError, "#{@config['mu_name']}: #{e.inspect} trying to connect with SSH, max_retries exceeded", e.backtrace
              end
            end
            return session
          end
        end

        # Wrapper for the cleanup class method of underlying cloud object implementations.
        def self.cleanup(*flags)
          MU::Cloud.supportedClouds.each { |cloud|
            begin
              cloudclass = MU::Cloud.loadCloudType(cloud, shortname)
              MU.log "Invoking #{cloudclass}.cleanup", MU::DEBUG, details: flags
              cloudclass.cleanup(flags.first)
            rescue MuCloudResourceNotImplemented
            end
          }
          MU::MommaCat.unlockAll
        end

        # Wrap the instance methods that this cloud resource type has to
        # implement.
        MU::Cloud.resource_types[name.to_sym][:instance].each { |method|
          define_method method do |*args|
            return nil if @cloudobj.nil?
            MU.log "Invoking #{@cloudobj}.#{method}", MU::DEBUG

            # Go ahead and guarantee that we can't accidentally trigger these
            # methods recursively.
            @method_semaphore.synchronize {
              # We're looking for recursion, not contention, so ignore some
              # obviously harmless things.
              if @method_locks.has_key?(method) and method != :findBastion and method != :cloud_id
                MU.log "Double-call to cloud method #{method} for #{self}", MU::DEBUG, details: caller + ["competing call stack:"] + @method_locks[method]
              end
              @method_locks[method] = caller
            }

            # Make sure the describe() caches are fresh
            @cloudobj.describe if method != :describe

            # Don't run through dependencies on simple attr_reader lookups
            if ![:dependencies, :cloud_id, :config, :mu_name].include?(method)
              @cloudobj.dependencies
            end

            retval = nil
            if !args.nil? and args.size == 1
              retval = @cloudobj.method(method).call(args.first)
            elsif !args.nil? and args.size > 0
              retval = @cloudobj.method(method).call(*args)
            else
              retval = @cloudobj.method(method).call
            end
            if (method == :create or method == :groom or method == :postBoot) and
               (!@destroyed and !@cloudobj.destroyed)
              deploydata = @cloudobj.method(:notify).call
              if deploydata.nil? or !deploydata.is_a?(Hash)
                raise MuError, "#{self}'s notify method did not return a Hash of deployment data"
              end
              deploydata['cloud_id'] = @cloudobj.cloud_id if !@cloudobj.cloud_id.nil?
              deploydata['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], deploydata, triggering_node: @cloudobj) if !@deploy.nil?
            elsif method == :notify
              retval['cloud_id'] = @cloudobj.cloud_id if !@cloudobj.cloud_id.nil?
              retval['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], retval, triggering_node: @cloudobj) if !@deploy.nil?
            end
            @method_semaphore.synchronize {
              @method_locks.delete(method)
            }

            @deploydata = @cloudobj.deploydata
            @config = @cloudobj.config
            retval
          end
        } # end instance method list
      } # end dynamic class generation block
    } # end resource type iteration

  end

end
