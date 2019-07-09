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

autoload :WinRM, "winrm"

module MU
  # Plugins under this namespace serve as interfaces to cloud providers and
  # other provisioning layers.
  class Cloud
    # An exception denoting an expected, temporary connection failure to a
    # bootstrapping instance, e.g. for Windows instances that must reboot in
    # mid-installation.
    class BootstrapTempFail < MuNonFatal;
    end

    # An exception we can use with transient Net::SSH errors, which require
    # special handling due to obnoxious asynchronous interrupt behaviors.
    class NetSSHFail < MuNonFatal;
    end

    # Exception thrown when a request is made to an unimplemented cloud
    # resource.
    class MuCloudResourceNotImplemented < StandardError;
    end

    # Exception thrown when a request is made for an unsupported flag or feature
    # in a cloud resource.
    class MuCloudFlagNotImplemented < StandardError;
    end

    # Exception we throw when we attempt to make an API call against a project
    # that is already deleted.
    class MuDefunctHabitat < StandardError;
    end

    # Methods which a cloud resource implementation, e.g. Server, must implement
    generic_class_methods = [:find, :cleanup, :validateConfig, :schema, :isGlobal?]
    generic_instance_methods = [:create, :notify, :mu_name, :cloud_id, :config]

    # Class methods which the base of a cloud implementation must implement
    generic_class_methods_toplevel =  [:required_instance_methods, :myRegion, :listRegions, :listAZs, :hosted?, :hosted_config, :config_example, :writeDeploySecret, :listCredentials, :credConfig, :listInstanceTypes, :adminBucketName, :adminBucketUrl, :habitat]

    PUBLIC_ATTRS = [:config, :mu_name, :cloud, :cloud_id, :environment, :deploy, :deploy_id, :deploydata, :appname, :credentials]

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
    class ContainerCluster;
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
    class Notifier;
    end
    # Stub base class; real implementations generated at runtime
    class Log;
    end
    # Stub base class; real implementations generated at runtime
    class StoragePool;
    end
    # Stub base class; real implementations generated at runtime
    class Function;
    end
    # Stub base class; real implementations generated at runtime
    class SearchDomain;
    end
    # Stub base class; real implementations generated at runtime
    class MsgQueue;
    end
    # Stub base class; real implementations generated at runtime
    class Habitat;
    end
    # Stub base class; real implementations generated at runtime
    class Folder;
    end
    # Stub base class; real implementations generated at runtime
    class User;
    end
    # Stub base class; real implementations generated at runtime
    class Group;
    end
    # Stub base class; real implementations generated at runtime
    class Role;
    end
    # Stub base class; real implementations generated at runtime
    class Endpoint;
    end
    # Stub base class; real implementations generated at runtime
    class Bucket;
    end
    # Stub base class; real implementations generated at runtime
    class NoSQLDB;
    end

    # Denotes a resource implementation which is missing significant
    # functionality or is largely untested.
    ALPHA = "This implementation is **ALPHA** quality. It is experimental, may be missing significant functionality, and has not been widely tested."

    # Denotes a resource implementation which supports most or all key API
    # functionality and has seen at least some non-trivial testing.
    BETA = "This implementation is **BETA** quality. It is substantially complete, but may be missing some functionality or have some features which are untested."

    # Denotes a resource implementation which supports all key API functionality
    # and has been substantially tested on real-world applications.
    RELEASE = "This implementation is considered **RELEASE** quality. It covers all major API features and has been tested with real-world applications."

    # The types of cloud resources we can create, as class objects. Include
    # methods a class implementing this resource type must support to be
    # considered valid.
    @@resource_types = {
      :Folder => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "folder",
        :cfg_plural => "folders",
        :interface => self.const_get("Folder"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods
      },
      :Habitat => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "habitat",
        :cfg_plural => "habitats",
        :interface => self.const_get("Habitat"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods + [:isLive?],
        :instance => generic_instance_methods + [:groom]
      },
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
        :instance => generic_instance_methods + [:groom, :registerNode]
      },
      :Server => {
        :has_multiples => true,
        :can_live_in_vpc => true,
        :cfg_name => "server",
        :cfg_plural => "servers",
        :interface => self.const_get("Server"),
        :deps_wait_on_my_creation => false,
        :waits_on_parent_completion => false,
        :class => generic_class_methods + [:validateInstanceType],
        :instance => generic_instance_methods + [:groom, :postBoot, :getSSHConfig, :canonicalIP, :getWindowsAdminPassword, :active?, :groomer, :mu_windows_name, :mu_windows_name=, :reboot, :addVolume]
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
        :instance => generic_instance_methods + [:groom, :listNodes]
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
      :Notifier => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "notifier",
        :cfg_plural => "notifiers",
        :interface => self.const_get("Notifier"),
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
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :StoragePool => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "storage_pool",
        :cfg_plural => "storage_pools",
        :interface => self.const_get("StoragePool"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :Function => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "function",
        :cfg_plural => "functions",
        :interface => self.const_get("Function"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :Endpoint => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "endpoint",
        :cfg_plural => "endpoints",
        :interface => self.const_get("Endpoint"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :ContainerCluster => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "container_cluster",
        :cfg_plural => "container_clusters",
        :interface => self.const_get("ContainerCluster"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :SearchDomain => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "search_domain",
        :cfg_plural => "search_domains",
        :interface => self.const_get("SearchDomain"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :MsgQueue => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "msg_queue",
        :cfg_plural => "msg_queues",
        :interface => self.const_get("MsgQueue"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :User => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "user",
        :cfg_plural => "users",
        :interface => self.const_get("User"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :Group => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "group",
        :cfg_plural => "groups",
        :interface => self.const_get("Group"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :Role => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "role",
        :cfg_plural => "roles",
        :interface => self.const_get("Role"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :Bucket => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "bucket",
        :cfg_plural => "buckets",
        :interface => self.const_get("Bucket"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      },
      :NoSQLDB => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "nosqldb",
        :cfg_plural => "nosqldbs",
        :interface => self.const_get("NoSQLDB"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => generic_class_methods,
        :instance => generic_instance_methods + [:groom]
      }
    }.freeze


    # A list of supported cloud resource types as Mu classes
    def self.resource_types;
      @@resource_types
    end

    # Shorthand lookup for resource type names. Given any of the shorthand class name, configuration name (singular or plural), or full class name, return all four as a set.
    # @param type [String]: A string that looks like our short or full class name or singular or plural configuration names.
    # @return [Array]: Class name (Symbol), singular config name (String), plural config name (String), full class name (Object)
    def self.getResourceNames(type)
      @@resource_types.each_pair { |name, cloudclass|
        if name == type.to_sym or
            cloudclass[:cfg_name] == type or
            cloudclass[:cfg_plural] == type or
            Object.const_get("MU").const_get("Cloud").const_get(name) == type
          cfg_name = cloudclass[:cfg_name]
          type = name
          return [type.to_sym, cloudclass[:cfg_name], cloudclass[:cfg_plural], Object.const_get("MU").const_get("Cloud").const_get(name), cloudclass]
        end
      }
      [nil, nil, nil, nil, {}]
    end

    # Net::SSH exceptions seem to have their own behavior vis a vis threads,
    # and our regular call stack gets circumvented when they're thrown. Cheat
    # here to catch them gracefully.
    def self.handleNetSSHExceptions
      Thread.handle_interrupt(Net::SSH::Exception => :never) {
        begin
          Thread.handle_interrupt(Net::SSH::Exception => :immediate) {
            MU.log "(Probably harmless) Caught a Net::SSH Exception in #{Thread.current.inspect}", MU::DEBUG, details: Thread.current.backtrace
          }
        ensure
#          raise NetSSHFail, "Net::SSH had a nutty"
        end
      }
    end

    # List of known/supported Cloud providers. This may be modified at runtime
    # if an implemention is defective or missing required methods.
    @@supportedCloudList = ['AWS', 'CloudFormation', 'Google', 'Azure']

    # List of known/supported Cloud providers
    def self.supportedClouds
      @@supportedCloudList
    end

    # Load the container class for each cloud we know about, and inject autoload
    # code for each of its supported resource type classes.
    failed = []
    MU::Cloud.supportedClouds.each { |cloud|
      require "mu/clouds/#{cloud.downcase}"
      cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
      generic_class_methods_toplevel.each { |method|
        if !cloudclass.respond_to?(method)
          MU.log "MU::Cloud::#{cloud} has not implemented required class method #{method}, disabling", MU::ERR
          failed << cloud
        end
      }
    }
    failed.uniq!
    @@supportedCloudList = @@supportedCloudList - failed

    # @return [Mutex]
    def self.userdata_mutex
      @userdata_mutex ||= Mutex.new
    end

    # Fetch our baseline userdata argument (read: "script that runs on first
    # boot") for a given platform.
    # *XXX* both the eval() and the blind File.read() based on the platform
    # variable are dangerous without cleaning. Clean them.
    # @param platform [String]: The target OS.
    # @param template_variables [Hash]: A list of variable substitutions to pass as globals to the ERB parser when loading the userdata script.
    # @param custom_append [String]: Arbitrary extra code to append to our default userdata behavior.
    # @return [String]
    def self.fetchUserdata(platform: "linux", template_variables: {}, custom_append: nil, cloud: "aws", scrub_mu_isms: false)
      return nil if platform.nil? or platform.empty?
      userdata_mutex.synchronize {
        script = ""
        if !scrub_mu_isms
          if template_variables.nil? or !template_variables.is_a?(Hash)
            raise MuError, "My second argument should be a hash of variables to pass into ERB templates"
          end
          $mu = OpenStruct.new(template_variables)
          userdata_dir = File.expand_path(MU.myRoot+"/modules/mu/clouds/#{cloud}/userdata")
          platform = "linux" if %w{centos centos6 centos7 ubuntu ubuntu14 rhel rhel7 rhel71 amazon}.include? platform
          platform = "windows" if %w{win2k12r2 win2k12 win2k8 win2k8r2 win2k16}.include? platform
          erbfile = "#{userdata_dir}/#{platform}.erb"
          if !File.exist?(erbfile)
            MU.log "No such userdata template '#{erbfile}'", MU::WARN, details: caller
            return ""
          end
          userdata = File.read(erbfile)
          begin
            erb = ERB.new(userdata)
            script = erb.result
          rescue NameError => e
            raise MuError, "Error parsing userdata script #{erbfile} as an ERB template: #{e.inspect}"
          end
          MU.log "Parsed #{erbfile} as ERB", MU::DEBUG, details: script
        end

        if !custom_append.nil?
          if custom_append['path'].nil?
            raise MuError, "Got a custom userdata script argument, but no ['path'] component"
          end
          erbfile = File.read(custom_append['path'])
          MU.log "Loaded userdata script from #{custom_append['path']}"
          if custom_append['use_erb']
            begin
              erb = ERB.new(erbfile, 1)
              if custom_append['skip_std']
                script = +erb.result
              else
                script = script+"\n"+erb.result
              end
            rescue NameError => e
              raise MuError, "Error parsing userdata script #{erbfile} as an ERB template: #{e.inspect}"
            end
            MU.log "Parsed #{custom_append['path']} as ERB", MU::DEBUG, details: script
          else
            if custom_append['skip_std']
              script = erbfile
            else
              script = script+"\n"+erbfile
            end
            MU.log "Parsed #{custom_append['path']} as flat file", MU::DEBUG, details: script
          end
        end
        return script
      }
    end

    @cloud_class_cache = {}
    # Given a cloud layer and resource type, return the class which implements it.
    # @param cloud [String]: The Cloud layer
    # @param type [String]: The resource type. Can be the full class name, symbolic name, or Basket of Kittens configuration shorthand for the resource type.
    # @return [Class]: The cloud-specific class implementing this resource
    def self.loadCloudType(cloud, type)
      raise MuError, "cloud argument to MU::Cloud.loadCloudType cannot be nil" if cloud.nil?
      shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
      if @cloud_class_cache.has_key?(cloud) and @cloud_class_cache[cloud].has_key?(type)
        if @cloud_class_cache[cloud][type].nil?
          raise MuError, "The '#{type}' resource is not supported in cloud #{cloud} (tried MU::#{cloud}::#{type})", caller
        end
        return @cloud_class_cache[cloud][type]
      end

      if cfg_name.nil?
        raise MuError, "Can't find a cloud resource type named '#{type}'"
      end
      if !File.size?(MU.myRoot+"/modules/mu/clouds/#{cloud.downcase}.rb")
        raise MuError, "Requested to use unsupported provisioning layer #{cloud}"
      end
      begin
        require "mu/clouds/#{cloud.downcase}/#{cfg_name}"
      rescue LoadError => e
        raise MuCloudResourceNotImplemented, "MU::Cloud::#{cloud} does not currently implement #{shortclass}, or implementation does not load correctly (#{e.message})"
      end
      @cloud_class_cache[cloud] = {} if !@cloud_class_cache.has_key?(cloud)
      begin
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
        myclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(type)
        @@resource_types[type.to_sym][:class].each { |class_method|
          if !myclass.respond_to?(class_method) or myclass.method(class_method).owner.to_s != "#<Class:#{myclass}>"
            raise MuError, "MU::Cloud::#{cloud}::#{type} has not implemented required class method #{class_method}"
          end
        }
        @@resource_types[type.to_sym][:instance].each { |instance_method|
          if !myclass.public_instance_methods.include?(instance_method)
            raise MuCloudResourceNotImplemented, "MU::Cloud::#{cloud}::#{type} has not implemented required instance method #{instance_method}"
          end
        }
        cloudclass.required_instance_methods.each { |instance_method|
          if !myclass.public_instance_methods.include?(instance_method)
            MU.log "MU::Cloud::#{cloud}::#{type} has not implemented required instance method #{instance_method}, will declare as attr_accessor", MU::DEBUG
          end
        }

        @cloud_class_cache[cloud][type] = myclass
        return myclass
      rescue NameError => e
        @cloud_class_cache[cloud][type] = nil
        raise MuCloudResourceNotImplemented, "The '#{type}' resource is not supported in cloud #{cloud} (tried MU::#{cloud}::#{type})", e.backtrace
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
        attr_reader :cloudclass
        attr_reader :cloudobj
        attr_reader :destroyed
        attr_reader :delayed_save

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
        def initialize(**args)
          raise MuError, "Cannot invoke Cloud objects without a configuration" if args[:kitten_cfg].nil?

          # We are a parent wrapper object. Initialize our child object and
          # housekeeping bits accordingly.
          if self.class.name.match(/^MU::Cloud::([^:]+)$/)
            @live = true
            @delayed_save = args[:delayed_save]
            @method_semaphore = Mutex.new
            @method_locks = {}
            if args[:mommacat]
               MU.log "Initializing an instance of #{self.class.name} in #{args[:mommacat].deploy_id} #{mu_name}", MU::DEBUG, details: args[:kitten_cfg]
            elsif args[:mu_name].nil?
              raise MuError, "Can't instantiate a MU::Cloud object with a live deploy or giving us a mu_name"
            else
              MU.log "Initializing a detached #{self.class.name} named #{args[:mu_name]}", MU::DEBUG, details: args[:kitten_cfg]
            end

            my_cloud = args[:kitten_cfg]['cloud'] || MU::Config.defaultCloud
            if my_cloud.nil? or !MU::Cloud.supportedClouds.include?(my_cloud)
              raise MuError, "Can't instantiate a MU::Cloud object without a valid cloud (saw '#{my_cloud}')"
            end
          
            @cloudclass = MU::Cloud.loadCloudType(my_cloud, self.class.shortname)
            @cloudparentclass = Object.const_get("MU").const_get("Cloud").const_get(my_cloud)
            @cloudobj = @cloudclass.new(
              mommacat: args[:mommacat],
              kitten_cfg: args[:kitten_cfg],
              cloud_id: args[:cloud_id],
              mu_name: args[:mu_name]
            )
            raise MuError, "Unknown error instantiating #{self}" if @cloudobj.nil?

# These should actually call the method live instead of caching a static value
            PUBLIC_ATTRS.each { |a|
              instance_variable_set(("@"+a.to_s).to_sym, @cloudobj.send(a))
            }

            # Register with the containing deployment
            if !@deploy.nil? and !@cloudobj.mu_name.nil? and
               !@cloudobj.mu_name.empty? and !args[:delay_descriptor_load]
              describe # XXX is this actually safe here?
              @deploy.addKitten(self.class.cfg_name, @config['name'], self)
            elsif !@deploy.nil?
              MU.log "#{self} didn't generate a mu_name after being loaded/initialized, dependencies on this resource will probably be confused!", MU::ERR
            end


          # We are actually a child object invoking this via super() from its
          # own initialize(), so initialize all the attributes and instance
          # variables we know to be universal.
          else

            # Declare the attributes that everyone should have
            class << self
              PUBLIC_ATTRS.each { |a|
                attr_reader a
              }
            end

# XXX this butchers ::Id and ::Ref objects that might be used by dependencies() to good effect, but we also can't expect our implementations to cope with knowing when a .to_s has to be appended to things at random
            @config = MU::Config.manxify(args[:kitten_cfg]) || MU::Config.manxify(args[:config])

            if !@config
              MU.log "Missing config arguments in setInstanceVariables, can't initialize a cloud object without it", MU::ERR, details: args.keys
              raise MuError, "Missing config arguments in setInstanceVariables"
            end

            @deploy = args[:mommacat] || args[:deploy]

            @credentials = args[:credentials]
            @credentials ||= @config['credentials']

            @cloud = @config['cloud']
            if !@cloud
              if self.class.name.match(/^MU::Cloud::([^:]+)(?:::.+|$)/)
               cloudclass_name = Regexp.last_match[1]
                if MU::Cloud.supportedClouds.include?(cloudclass_name)
                  @cloud = cloudclass_name
                end
              end
            end
            if !@cloud
              raise MuError, "Failed to determine what cloud #{self} should be in!"
            end

            @environment = @config['environment']
            if @deploy
              @deploy_id = @deploy.deploy_id
              @appname = @deploy.appname
            end

            @cloudclass = MU::Cloud.loadCloudType(@cloud, self.class.shortname)
            @cloudparentclass = Object.const_get("MU").const_get("Cloud").const_get(@cloud)

            # A pre-existing object, you say?
            if args[:cloud_id]

# TODO implement ::Id for every cloud... and they should know how to get from
# cloud_desc to a fully-resolved ::Id object, not just the short string

              @cloud_id = args[:cloud_id]
              describe(cloud_id: @cloud_id)
              @habitat_id = habitat_id # effectively, cache this

              # If we can build us an ::Id object for @cloud_id instead of a
              # string, do so.
              begin
                idclass = Object.const_get("MU").const_get("Cloud").const_get(@cloud).const_get("Id")
                long_id = if @deploydata and @deploydata[idclass.idattr.to_s]
                  @deploydata[idclass.idattr.to_s]
                elsif self.respond_to?(idclass.idattr)
                  self.send(idclass.idattr)
                end

                @cloud_id = idclass.new(long_id) if !long_id.nil? and !long_id.empty?
# 1 see if we have the value on the object directly or in deploy data
# 2 set an attr_reader with the value
# 3 rewrite our @cloud_id attribute with a ::Id object
              rescue NameError, MU::Cloud::MuCloudResourceNotImplemented
              end

            end

            # Use pre-existing mu_name (we're probably loading an extant deploy)
            # if available
            if args[:mu_name]
              @mu_name = args[:mu_name]
            # If scrub_mu_isms is set, our mu_name is always just the bare name
            # field of the resource.
            elsif @config['scrub_mu_isms']
              @mu_name = @config['name']
# XXX feck it insert an inheritable method right here? Set a default? How should resource implementations determine whether they're instantiating a new object?
            end

            @tags = {}
            if !@config['scrub_mu_isms']
              @tags = @deploy ? @deploy.listStandardTags : MU::MommaCat.listStandardTags
            end
            if @config['tags']
              @config['tags'].each { |tag|
                @tags[tag['key']] = tag['value']
              }
            end

            if @cloudparentclass.respond_to?(:resourceInitHook)
              @cloudparentclass.resourceInitHook(self, @deploy)
            end

            # Add cloud-specific instance methods for our resource objects to
            # inherit.
            if @cloudparentclass.const_defined?(:AdditionalResourceMethods)
              self.extend @cloudparentclass.const_get(:AdditionalResourceMethods)
            end

            if ["Server", "ServerPool"].include?(self.class.shortname)
              @groomer = MU::Groomer.new(self)
              @groomclass = MU::Groomer.loadGroomer(@config["groomer"])

              if windows? or @config['active_directory'] and !@mu_windows_name
                if !@deploydata.nil? and !@deploydata['mu_windows_name'].nil?
                  @mu_windows_name = @deploydata['mu_windows_name']
                else
                  # Use the same random differentiator as the "real" name if we're
                  # from a ServerPool. Helpful for admin sanity.
                  unq = @mu_name.sub(/^.*?-(...)$/, '\1')
                  if @config['basis'] and !unq.nil? and !unq.empty?
                    @mu_windows_name = @deploy.getResourceName(@config['name'], max_length: 15, need_unique_string: true, use_unique_string: unq, reuse_unique_string: true)
                  else
                    @mu_windows_name = @deploy.getResourceName(@config['name'], max_length: 15, need_unique_string: true)
                  end
                end
              end
              class << self
                attr_reader :groomer
                attr_reader :groomerclass
                attr_accessor :mu_windows_name # XXX might be ok as reader now
              end 
            end
          end


        end

        def cloud
          if @cloud
            @cloud
          elsif @config and @config['cloud']
            @config['cloud']
          elsif self.class.name.match(/^MU::Cloud::([^:]+)::.+/)
            cloudclass_name = Regexp.last_match[1]
            if MU::Cloud.supportedClouds.include?(cloudclass_name)
              cloudclass_name
            else
              nil
            end
          else
            nil
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
              @deploy.notify(self.class.cfg_plural, @config['name'], nil, mu_name: @cloudobj.mu_name, remove: true, triggering_node: @cloudobj, delayed_save: @delayed_save)
            elsif !@mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], nil, mu_name: @mu_name, remove: true, triggering_node: self, delayed_save: @delayed_save)
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

        # Return the cloud object's idea of where it lives (project, account,
        # etc) in the form of an identifier. If not applicable for this object,
        # we expect to return +nil+.
        # @return [String,nil]
        def habitat(nolookup: true)
          return nil if ["folder", "habitat"].include?(self.class.cfg_name)
          if @cloudobj 
            @cloudparentclass.habitat(@cloudobj, nolookup: nolookup, deploy: @deploy)
          else
            @cloudparentclass.habitat(self, nolookup: nolookup, deploy: @deploy)
          end
        end

        def habitat_id(nolookup: false)
          @habitat_id ||= habitat(nolookup: nolookup)
          @habitat_id
        end

        # We're fundamentally a wrapper class, so go ahead and reroute requests
        # that are meant for our wrapped object.
        def method_missing(method_sym, *arguments)
          if @cloudobj
            MU.log "INVOKING #{method_sym.to_s} FROM PARENT CLOUD OBJECT #{self}", MU::DEBUG, details: arguments
            @cloudobj.method(method_sym).call(*arguments)
          else
            raise NoMethodError, method_sym.to_s
          end
        end

        # Merge the passed hash into the existing configuration hash of this
        # cloud object. Currently this is only used by the {MU::Adoption}
        # module. I don't love exposing this to the whole internal API, but I'm
        # probably overthinking that.
        # @param newcfg [Hash]
        def config!(newcfg)
          @config.merge!(newcfg)
        end
        
        def cloud_desc
          describe

          if !@cloudobj.nil?
            if @cloudobj.class.instance_methods(false).include?(:cloud_desc)
              @cloud_desc_cache ||= @cloudobj.cloud_desc
            end
          end
          if !@config.nil? and !@cloud_id.nil? and @cloud_desc_cache.nil?
            # The find() method should be returning a Hash with the cloud_id
            # as a key and a cloud platform descriptor as the value.
            begin
              args = {
                :region => @config['region'],
                :cloud_id => @cloud_id,
                :credentials => @credentials,
                :project => habitat_id, # XXX this belongs in our required_instance_methods hack
                :flags => @config
              }
              @cloudparentclass.required_instance_methods.each { |m|
#                if respond_to?(m)
#                  args[m] = method(m).call
#                else
                  args[m] = instance_variable_get(("@"+m.to_s).to_sym)
#                end
              }

              matches = self.class.find(args)
              if !matches.nil? and matches.is_a?(Hash)
# XXX or if the hash is keyed with an ::Id element, oh boy
#                puts matches[@cloud_id][:self_link]
#                puts matches[@cloud_id][:url]
#                if matches[@cloud_id][:self_link]
#                  @url ||= matches[@cloud_id][:self_link]
#                elsif matches[@cloud_id][:url]
#                  @url ||= matches[@cloud_id][:url]
#                elsif matches[@cloud_id][:arn]
#                  @arn ||= matches[@cloud_id][:arn]
#                end
                if matches[@cloud_id]
                  @cloud_desc_cache = matches[@cloud_id]
                else
                  matches.each_pair { |k, v| # flatten out ::Id objects just in case
                    if @cloud_id.to_s == k.to_s
                      @cloud_desc_cache = v
                      break
                    end
                  }
                end
              end

              if !@cloud_desc_cache
                MU.log "cloud_desc via #{self.class.name}.find() failed to locate a live object.\nWas called by #{caller[0]}", MU::WARN, details: args
              end
            rescue Exception => e
              MU.log "Got #{e.inspect} trying to find cloud handle for #{self.class.shortname} #{@mu_name} (#{@cloud_id})", MU::WARN
              raise e
            end
          end

          return @cloud_desc_cache
        end

        # Retrieve all of the known metadata for this resource.
        # @param cloud_id [String]: The cloud platform's identifier for the resource we're describing. Makes lookups more efficient.
        # @param update_cache [Boolean]: Ignore cached data if we have any, instead reconsituting from original sources.
        # @return [Array<Hash>]: mu_name, config, deploydata
        def describe(cloud_id: nil, update_cache: false)
          if cloud_id.nil? and !@cloudobj.nil?
            @cloud_id ||= @cloudobj.cloud_id
          end
          res_type = self.class.cfg_plural
          res_name = @config['name'] if !@config.nil?
          @credentials ||= @config['credentials'] if !@config.nil?
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
              @cloud_id ||= @deploydata['cloud_id']
            end
          end

          return [@mu_name, @config, @deploydata]
        end

        # Fetch MU::Cloud objects for each of this object's dependencies, and
        # return in an easily-navigable Hash. This can include things listed in
        # @config['dependencies'], implicitly-defined dependencies such as
        # add_firewall_rules or vpc stanzas, and may refer to objects internal
        # to this deployment or external.  Will populate the instance variables
        # @dependencies (general dependencies, which can only be sibling
        # resources in this deployment), as well as for certain config stanzas
        # which can refer to external resources (@vpc, @loadbalancers,
        # @add_firewall_rules)
        def dependencies(use_cache: false, debug: false)
          @dependencies = {} if @dependencies.nil?
          @loadbalancers = [] if @loadbalancers.nil?
          if @config.nil?
            return [@dependencies, @vpc, @loadbalancers]
          end
          if use_cache and @dependencies.size > 0
            return [@dependencies, @vpc, @loadbalancers]
          end
          @config['dependencies'] = [] if @config['dependencies'].nil?

          loglevel = debug ? MU::NOTICE : MU::DEBUG

          # First, general dependencies. These should all be fellow members of
          # the current deployment.
          @config['dependencies'].each { |dep|
            @dependencies[dep['type']] ||= {}
            next if @dependencies[dep['type']].has_key?(dep['name'])
            handle = @deploy.findLitterMate(type: dep['type'], name: dep['name']) if !@deploy.nil?
            if !handle.nil?
              MU.log "Loaded dependency for #{self}: #{dep['name']} => #{handle}", loglevel
              @dependencies[dep['type']][dep['name']] = handle
            else
              # XXX yell under circumstances where we should expect to have
              # our stuff available already?
            end
          }

          # Special dependencies: my containing VPC
          if self.class.can_live_in_vpc and !@config['vpc'].nil?
            if !@config['vpc']["id"].nil? and @config['vpc']["id"].is_a?(MU::Config::Ref) and !@config['vpc']["id"].kitten.nil?
              @vpc = @config['vpc']["id"].kitten
            elsif !@config['vpc']["name"].nil? and @deploy
              MU.log "Attempting findLitterMate on VPC for #{self}", loglevel, details: @config['vpc']

              sib_by_name = @deploy.findLitterMate(name: @config['vpc']['name'], type: "vpcs", return_all: true, habitat: @config['vpc']['project'], debug: debug)
              if sib_by_name.is_a?(Array)
                if sib_by_name.size == 1
                  @vpc = matches.first
                  MU.log "Single VPC match for #{self}", loglevel, details: @vpc.to_s
                else
# XXX ok but this is the wrong place for this really the config parser needs to sort this out somehow
                  # we got multiple matches, try to pick one by preferred subnet
                  # behavior
                  MU.log "Sorting a bunch of VPC matches for #{self}", loglevel, details: sib_by_name.map { |s| s.to_s }.join(", ")
                  sib_by_name.each { |sibling|
                    all_private = sibling.subnets.map { |s| s.private? }.all?(true)
                    all_public = sibling.subnets.map { |s| s.private? }.all?(false)
                    if all_private and ["private", "all_private"].include?(@config['vpc']['subnet_pref'])
                      @vpc = sibling
                      break
                    elsif all_public and ["public", "all_public"].include?(@config['vpc']['subnet_pref'])
                      @vpc = sibling
                      break
                    else
                      MU.log "Got multiple matching VPCs for #{@mu_name}, so I'm arbitrarily choosing #{sibling.mu_name}"
                      @vpc = sibling
                      break
                    end
                  }
                end
              else
                @vpc = sib_by_name
                MU.log "Found exact VPC match for #{self}", loglevel, details: sib_by_name.to_s
              end
            else
              MU.log "No shortcuts available to fetch VPC for #{self}", loglevel, details: @config['vpc']
            end

            if !@vpc and !@config['vpc']["name"].nil? and
                @dependencies.has_key?("vpc") and
                @dependencies["vpc"].has_key?(@config['vpc']["name"])
              MU.log "Grabbing VPC I see in @dependencies['vpc']['#{@config['vpc']["name"]}'] for #{self}", loglevel, details: @config['vpc']
              @vpc = @dependencies["vpc"][@config['vpc']["name"]]
            elsif !@vpc
              tag_key, tag_value = @config['vpc']['tag'].split(/=/, 2) if !@config['vpc']['tag'].nil?
              if !@config['vpc'].has_key?("id") and
                  !@config['vpc'].has_key?("deploy_id") and !@deploy.nil?
                @config['vpc']["deploy_id"] = @deploy.deploy_id
              end
              MU.log "Doing findStray for VPC for #{self}", loglevel, details: @config['vpc']
              vpcs = MU::MommaCat.findStray(
                @config['cloud'],
                "vpc",
                deploy_id: @config['vpc']["deploy_id"],
                cloud_id: @config['vpc']["id"],
                name: @config['vpc']["name"],
                tag_key: tag_key,
                tag_value: tag_value,
                flags: { "project" => @config['vpc']['project'] },
                region: @config['vpc']["region"],
                calling_deploy: @deploy,
                dummy_ok: true,
                debug: debug
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

              @nat = @vpc.findBastion(
                nat_name: @config['vpc']['nat_host_name'],
                nat_cloud_id: @config['vpc']['nat_host_id'],
                nat_tag_key: nat_tag_key,
                nat_tag_value: nat_tag_value,
                nat_ip: @config['vpc']['nat_host_ip']
              )

              if @nat.nil?
                if !@vpc.cloud_desc.nil?
                  @nat = @vpc.findNat(
                    nat_cloud_id: @config['vpc']['nat_host_id'],
                    nat_filter_key: "vpc-id",
                    region: @config['vpc']["region"],
                    nat_filter_value: @vpc.cloud_id,
                    credentials: @config['credentials']
                  )
                else
                  @nat = @vpc.findNat(
                    nat_cloud_id: @config['vpc']['nat_host_id'],
                    region: @config['vpc']["region"],
                    credentials: @config['credentials']
                  )
                end
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

        # Defaults any resources that don't declare their release-readiness to
        # ALPHA. That'll learn 'em.
        def self.quality
          MU::Cloud::ALPHA
        end

        # Return a list of "container" artifacts, by class, that apply to this
        # resource type in a cloud provider. This is so methods that call find
        # know whether to call +find+ with identifiers for parent resources.
        # This is similar in purpose to the +isGlobal?+ resource class method,
        # which tells our search functions whether or not a resource scopes to
        # a region.  In almost all cases this is one-entry list consisting of
        # +:Habitat+. Notable exceptions include most implementations of
        # +Habitat+, which either reside inside a +:Folder+ or nothing at all;
        # whereas a +:Folder+ tends to not have any containing parent. Very few
        # resource implementations will need to override this.
        # A +nil+ entry in this list is interpreted as "this resource can be
        # global."
        # @return [Array<Symbol,nil>]
        def self.canLiveIn
          if self.shortname == "Folder"
            [nil, :Folder]
          elsif self.shortname == "Habitat"
            [:Folder]
          else
            [:Habitat]
          end
        end

        def self.find(*flags)
          allfound = {}

          MU::Cloud.supportedClouds.each { |cloud|
            begin
              args = flags.first
              # skip this cloud if we have a region argument that makes no
              # sense there
              cloudbase = Object.const_get("MU").const_get("Cloud").const_get(cloud)
              if args[:region] and cloudbase.respond_to?(:listRegions)
                next if !cloudbase.listRegions(credentials: args[:credentials]).include?(args[:region])
              end
              begin
                cloudclass = MU::Cloud.loadCloudType(cloud, shortname)
              rescue MU::MuError => e
                next
              end

              found = cloudclass.find(args)
              if !found.nil?
                if found.is_a?(Hash)
                  allfound.merge!(found)
                else
                  raise MuError, "#{cloudclass}.find returned a non-Hash result"
                end
              end
            rescue MuCloudResourceNotImplemented
            end
          }
          allfound
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
            return true if %w{win2k16 win2k12r2 win2k12 win2k8 win2k8r2 windows}.include?(@config['platform'])
            begin
              return true if cloud_desc.respond_to?(:platform) and cloud_desc.platform == "Windows"
# XXX ^ that's AWS-speak, doesn't cover GCP or anything else; maybe we should require cloud layers to implement this so we can just call @cloudobj.windows?
            rescue MU::MuError
              return false
            end
            false
          end

          # Gracefully message and attempt to accommodate the common transient errors peculiar to Windows nodes
          # @param e [Exception]: The exception that we're handling
          # @param retries [Integer]: The current number of retries, which we'll increment and pass back to the caller
          # @param rebootable_fails [Integer]: The current number of reboot-worthy failures, which we'll increment and pass back to the caller
          # @param max_retries [Integer]: Maximum number of retries to attempt; we'll raise an exception if this is exceeded
          # @param reboot_on_problems [Boolean]: Whether we should try to reboot a "stuck" machine
          # @param retry_interval [Integer]: How many seconds to wait before returning for another attempt
          def handleWindowsFail(e, retries, rebootable_fails, max_retries: 30, reboot_on_problems: false, retry_interval: 45)
            msg = "WinRM connection to https://"+@mu_name+":5986/wsman: #{e.message}, waiting #{retry_interval}s (attempt #{retries}/#{max_retries})"
            if e.class.name == "WinRM::WinRMAuthorizationError" or e.message.match(/execution expired/) and reboot_on_problems
              if rebootable_fails > 0 and (rebootable_fails % 5) == 0
                MU.log "#{@mu_name} still misbehaving, forcing Stop and Start from API", MU::WARN
                reboot(true) # vicious API stop/start
                sleep retry_interval*3
                rebootable_fails = 0
              else
                if rebootable_fails == 3
                  MU.log "#{@mu_name} misbehaving, attempting to reboot from API", MU::WARN
                  reboot # graceful API restart
                  sleep retry_interval*2
                end
                rebootable_fails = rebootable_fails + 1
              end
            end
            if retries < max_retries
              if retries == 1 or (retries/max_retries <= 0.5 and (retries % 3) == 0 and retries != 0)
                MU.log msg, MU::NOTICE
              elsif retries/max_retries > 0.5
                MU.log msg, MU::WARN, details: e.inspect
              end
              sleep retry_interval
              retries = retries + 1
            else
              raise MuError, "#{@mu_name}: #{e.inspect} trying to connect with WinRM, max_retries exceeded", e.backtrace
            end
            return [retries, rebootable_fails]
          end

          def windowsRebootPending?(shell = nil)
            if shell.nil?
              shell = getWinRMSession(1, 30)
            end
#              if (Get-Item "HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/WindowsUpdate/Auto Update/RebootRequired" -EA Ignore) { exit 1 }
            cmd = %Q{
              if (Get-ChildItem "HKLM:/Software/Microsoft/Windows/CurrentVersion/Component Based Servicing/RebootPending" -EA Ignore) {
                echo "Component Based Servicing/RebootPending is true"
                exit 1
              }
              if (Get-ItemProperty "HKLM:/SYSTEM/CurrentControlSet/Control/Session Manager" -Name PendingFileRenameOperations -EA Ignore) {
                echo "Control/Session Manager/PendingFileRenameOperations is true"
                exit 1
              }
              try { 
                $util = [wmiclass]"\\\\.\\root\\ccm\\clientsdk:CCM_ClientUtilities"
                $status = $util.DetermineIfRebootPending()
                if(($status -ne $null) -and $status.RebootPending){
                  echo "WMI says RebootPending is true"
                  exit 1
                }
              } catch {
                exit 0
              }
              exit 0
            }
            resp = shell.run(cmd)
            returnval = resp.exitcode == 0 ? false : true
            shell.close
            returnval
          end

          # Basic setup tasks performed on a new node during its first WinRM 
          # connection. Most of this is terrible Windows glue.
          # @param shell [WinRM::Shells::Powershell]: An active Powershell session to the new node.
          def initialWinRMTasks(shell)
            retries = 0
            rebootable_fails = 0
            begin
              if !@config['use_cloud_provider_windows_password']
                pw = @groomer.getSecret(
                  vault: @config['mu_name'],
                  item: "windows_credentials",
                  field: "password"
                )
                win_check_for_pw = %Q{Add-Type -AssemblyName System.DirectoryServices.AccountManagement; $Creds = (New-Object System.Management.Automation.PSCredential("#{@config["windows_admin_username"]}", (ConvertTo-SecureString "#{pw}" -AsPlainText -Force)));$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine); $DS.ValidateCredentials($Creds.GetNetworkCredential().UserName, $Creds.GetNetworkCredential().password); echo $Result}
                resp = shell.run(win_check_for_pw)
                if resp.stdout.chomp != "True"
                  win_set_pw = %Q{(([adsi]('WinNT://./#{@config["windows_admin_username"]}, user')).psbase.invoke('SetPassword', '#{pw}'))}
                  resp = shell.run(win_set_pw)
                  puts resp.stdout
                  MU.log "Resetting Windows host password", MU::NOTICE, details: resp.stdout
                end
              end

              # Install Cygwin here, because for some reason it breaks inside Chef
              # XXX would love to not do this here
              pkgs = ["bash", "mintty", "vim", "curl", "openssl", "wget", "lynx", "openssh"]
              admin_home = "c:/bin/cygwin/home/#{@config["windows_admin_username"]}"
              install_cygwin = %Q{
                If (!(Test-Path "c:/bin/cygwin/Cygwin.bat")){
                  $WebClient = New-Object System.Net.WebClient
                  $WebClient.DownloadFile("http://cygwin.com/setup-x86_64.exe","$env:Temp/setup-x86_64.exe")
                  Start-Process -wait -FilePath $env:Temp/setup-x86_64.exe -ArgumentList "-q -n -l $env:Temp/cygwin -R c:/bin/cygwin -s http://mirror.cs.vt.edu/pub/cygwin/cygwin/ -P #{pkgs.join(',')}"
                }
                if(!(Test-Path #{admin_home})){
                  New-Item -type directory -path #{admin_home}
                }
                if(!(Test-Path #{admin_home}/.ssh)){
                  New-Item -type directory -path #{admin_home}/.ssh
                }
                if(!(Test-Path #{admin_home}/.ssh/authorized_keys)){
                  New-Item #{admin_home}/.ssh/authorized_keys -type file -force -value "#{@deploy.ssh_public_key}"
                }
              }
              resp = shell.run(install_cygwin)
              if resp.exitcode != 0
                MU.log "Failed at installing Cygwin", MU::ERR, details: resp
              end

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
              resp = shell.run(%Q{hostname})

              if resp.stdout.chomp != hostname
                resp = shell.run(%Q{Rename-Computer -NewName '#{hostname}' -Force -PassThru -Restart; Restart-Computer -Force})
                MU.log "Renaming Windows host to #{hostname}; this will trigger a reboot", MU::NOTICE, details: resp.stdout
                reboot(true)
                sleep 30
              end
            rescue WinRM::WinRMError, HTTPClient::ConnectTimeoutError => e
              retries, rebootable_fails = handleWindowsFail(e, retries, rebootable_fails, max_retries: 10, reboot_on_problems: true, retry_interval: 30)
              retry
            end
          end


          # Basic setup tasks performed on a new node during its first initial
          # ssh connection. Most of this is terrible Windows glue.
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
            win_set_hostname = %Q{powershell -Command "& {Rename-Computer -NewName '#{hostname}' -Force -PassThru -Restart; Restart-Computer -Force }"}

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

          # Get a privileged Powershell session on the server in question, using SSL-encrypted WinRM with certificate authentication.
          # @param max_retries [Integer]:
          # @param retry_interval [Integer]:
          # @param timeout [Integer]:
          # @param winrm_retries [Integer]:
          # @param reboot_on_problems [Boolean]:
          def getWinRMSession(max_retries = 40, retry_interval = 60, timeout: 30, winrm_retries: 5, reboot_on_problems: false)
            nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
            @mu_name ||= @config['mu_name']

            conn = nil
            shell = nil
            opts = nil
            # and now, a thing I really don't want to do
            MU::MommaCat.addInstanceToEtcHosts(canonical_ip, @mu_name)

            # catch exceptions that circumvent our regular call stack
            Thread.abort_on_exception = false
            Thread.handle_interrupt(WinRM::WinRMWSManFault => :never) {
              begin
                Thread.handle_interrupt(WinRM::WinRMWSManFault => :immediate) {
                  MU.log "(Probably harmless) Caught a WinRM::WinRMWSManFault in #{Thread.current.inspect}", MU::DEBUG, details: Thread.current.backtrace
                }
              ensure
                # Reraise something useful
              end
            }

            retries = 0
            rebootable_fails = 0
            begin
              MU.log "Calling WinRM on #{@mu_name}", MU::DEBUG, details: opts
              opts = {
                endpoint: 'https://'+@mu_name+':5986/wsman',
                retry_limit: winrm_retries,
                no_ssl_peer_verification: true, # XXX this should not be necessary; we get 'hostname "foo" does not match the server certificate' even when it clearly does match
                ca_trust_path: "#{MU.mySSLDir}/Mu_CA.pem",
                transport: :ssl,
                operation_timeout: timeout,
                client_cert: "#{MU.mySSLDir}/#{@mu_name}-winrm.crt",
                client_key: "#{MU.mySSLDir}/#{@mu_name}-winrm.key"
              }
              conn = WinRM::Connection.new(opts)
              MU.log "WinRM connection to #{@mu_name} created", MU::DEBUG, details: conn
              shell = conn.shell(:powershell)
              shell.run('ipconfig') # verify that we can do something
            rescue Errno::EHOSTUNREACH, Errno::ECONNREFUSED, HTTPClient::ConnectTimeoutError, OpenSSL::SSL::SSLError, SocketError, WinRM::WinRMError, Timeout::Error => e
              retries, rebootable_fails = handleWindowsFail(e, retries, rebootable_fails, max_retries: max_retries, reboot_on_problems: reboot_on_problems, retry_interval: retry_interval)
              retry
            ensure
              MU::MommaCat.removeInstanceFromEtcHosts(@mu_name)
            end

            shell
          end

          # @param max_retries [Integer]: Number of connection attempts to make before giving up
          # @param retry_interval [Integer]: Number of seconds to wait between connection attempts
          # @return [Net::SSH::Connection::Session]
          def getSSHSession(max_retries = 12, retry_interval = 30)
            ssh_keydir = Etc.getpwnam(@deploy.mu_user).dir+"/.ssh"
            nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
            session = nil
            retries = 0

            # XXX WHY is this a thing
            Thread.handle_interrupt(Errno::ECONNREFUSED => :never) {
            }

            begin
              MU::Cloud.handleNetSSHExceptions
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
                    :verify_host_key => false,
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
                    :verify_host_key => false,
                    #           :verbose => :info,
                    :port => 22,
                    :auth_methods => ['publickey']
                )
              end
              retries = 0
            rescue Net::SSH::HostKeyMismatch => e
              MU.log("Remembering new key: #{e.fingerprint}")
              e.remember_host!
              session.close
              retry
            rescue SystemCallError, Timeout::Error, Errno::ECONNRESET, Errno::EHOSTUNREACH, Net::SSH::Proxy::ConnectError, SocketError, Net::SSH::Disconnect, Net::SSH::AuthenticationFailed, IOError, Net::SSH::ConnectionTimeout, Net::SSH::Proxy::ConnectError, MU::Cloud::NetSSHFail => e
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
                msg = "ssh #{ssh_user}@#{@config['mu_name']}: #{e.message}, waiting #{retry_interval}s (attempt #{retries}/#{max_retries})", MU::WARN
                if retries == 1 or (retries/max_retries <= 0.5 and (retries % 3) == 0)
                  MU.log msg, MU::NOTICE
                elsif retries/max_retries > 0.5
                  MU.log msg, MU::WARN, details: e.inspect
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
          params = flags.first
          clouds = MU::Cloud.supportedClouds
          if params[:cloud]
            clouds = [params[:cloud]]
            params.delete(:cloud)
          end
          clouds.each { |cloud|
            begin
              cloudclass = MU::Cloud.loadCloudType(cloud, shortname)
              raise MuCloudResourceNotImplemented if !cloudclass.respond_to?(:cleanup) or cloudclass.method(:cleanup).owner.to_s != "#<Class:#{cloudclass}>"
              MU.log "Invoking #{cloudclass}.cleanup from #{shortname}", MU::DEBUG, details: flags
              cloudclass.cleanup(params)
            rescue MuCloudResourceNotImplemented
              MU.log "No #{cloud} implementation of #{shortname}.cleanup, skipping", MU::DEBUG, details: flags
            end
          }
          MU::MommaCat.unlockAll
        end

        # A hook that is always called just before each instance method is
        # invoked, so that we can ensure that repetitive setup tasks (like
        # resolving +:resource_group+ for Azure resources) have always been
        # done.
        def resourceInitHook
          @cloud ||= cloud
          if @cloudparentclass.respond_to?(:resourceInitHook)
            @cloudparentclass.resourceInitHook(@cloudobj, @deploy)
          end
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
              @deploydata ||= deploydata # XXX I don't remember why we're not just doing this from the get-go; maybe because we prefer some mangling occurring in @deploy.notify?
              if deploydata.nil? or !deploydata.is_a?(Hash)
                MU.log "#{self} notify method did not return a Hash of deployment data, attempting to fill in with cloud descriptor #{@cloudobj.cloud_id}", MU::WARN
                deploydata = MU.structToHash(@cloudobj.cloud_desc)
                raise MuError, "Failed to collect metadata about #{self}" if deploydata.nil?
              end
              deploydata['cloud_id'] ||= @cloudobj.cloud_id if !@cloudobj.cloud_id.nil?
              deploydata['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
              deploydata['nodename'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
              deploydata.delete("#MUOBJECT")
              @deploy.notify(self.class.cfg_plural, @config['name'], deploydata, triggering_node: @cloudobj, delayed_save: @delayed_save) if !@deploy.nil?
            elsif method == :notify
              retval['cloud_id'] = @cloudobj.cloud_id.to_s if !@cloudobj.cloud_id.nil?
              retval['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
              @deploy.notify(self.class.cfg_plural, @config['name'], retval, triggering_node: @cloudobj, delayed_save: @delayed_save) if !@deploy.nil?
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
