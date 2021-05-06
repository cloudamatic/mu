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
    @@generic_class_methods = [:find, :cleanup, :validateConfig, :schema, :isGlobal?]
    @@generic_instance_methods = [:create, :notify, :mu_name, :cloud_id, :config]

    # Class methods which the base of a cloud implementation must implement
    @@generic_class_methods_toplevel =  [:required_instance_methods, :myRegion, :listRegions, :listAZs, :hosted?, :hosted_config, :config_example, :writeDeploySecret, :listCredentials, :credConfig, :listInstanceTypes, :adminBucketName, :adminBucketUrl, :listHabitats, :habitat, :virtual?]

    # Public attributes which will be available on all instantiated cloud resource objects
    #
    # +:config+: The fully-resolved {MU::Config} hash describing the object, aka the Basket of Kittens entry
    #
    # +:mu_name+: The unique internal name of the object, if one already exists
    #
    # +:cloud+: The cloud in which this object is resident
    #
    # +:cloud_id+: The cloud provider's official identifier for this object
    #
    # +:environment+: The declared environment string for the deployment of which this object is a member
    #
    # +:deploy:+ The {MU::MommaCat} object representing the deployment of which this object is a member
    #
    # +:deploy_id:+ The unique string which identifies the deployment of which this object is a member
    #
    # +:deploydata:+ A Hash containing all metadata reported by resources in this deploy method, via their +notify+ methods
    #
    # +:appname:+ The declared application name of this deployment
    #
    # +:credentials:+ The name of the cloud provider credential set from +mu.yaml+ which is used to manage this object
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
    # Stub base class; real implementations generated at runtime
    class Job;
    end
    # Stub base class; real implementations generated at runtime
    class CDN;
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
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods
      },
      :Habitat => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "habitat",
        :cfg_plural => "habitats",
        :interface => self.const_get("Habitat"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods + [:isLive?],
        :instance => @@generic_instance_methods + [:groom]
      },
      :Collection => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "collection",
        :cfg_plural => "collections",
        :interface => self.const_get("Collection"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods
      },
      :Database => {
        :has_multiples => true,
        :can_live_in_vpc => true,
        :cfg_name => "database",
        :cfg_plural => "databases",
        :interface => self.const_get("Database"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom, :allowHost]
      },
      :DNSZone => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "dnszone",
        :cfg_plural => "dnszones",
        :interface => self.const_get("DNSZone"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods + [:genericMuDNSEntry, :createRecordsFromConfig],
        :instance => @@generic_instance_methods
      },
      :FirewallRule => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "firewall_rule",
        :cfg_plural => "firewall_rules",
        :interface => self.const_get("FirewallRule"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom, :addRule]
      },
      :LoadBalancer => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "loadbalancer",
        :cfg_plural => "loadbalancers",
        :interface => self.const_get("LoadBalancer"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom, :registerTarget]
      },
      :Server => {
        :has_multiples => true,
        :can_live_in_vpc => true,
        :cfg_name => "server",
        :cfg_plural => "servers",
        :interface => self.const_get("Server"),
        :deps_wait_on_my_creation => false,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods + [:validateInstanceType, :imageTimeStamp],
        :instance => @@generic_instance_methods + [:groom, :postBoot, :getSSHConfig, :canonicalIP, :getWindowsAdminPassword, :active?, :groomer, :mu_windows_name, :mu_windows_name=, :reboot, :addVolume, :genericNAT, :listIPs]
      },
      :ServerPool => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "server_pool",
        :cfg_plural => "server_pools",
        :interface => self.const_get("ServerPool"),
        :deps_wait_on_my_creation => false,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom, :listNodes]
      },
      :VPC => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "vpc",
        :cfg_plural => "vpcs",
        :interface => self.const_get("VPC"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom, :subnets, :getSubnet, :findBastion, :findNat]
      },
      :CacheCluster => {
        :has_multiples => true,
        :can_live_in_vpc => true,
        :cfg_name => "cache_cluster",
        :cfg_plural => "cache_clusters",
        :interface => self.const_get("CacheCluster"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Alarm => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "alarm",
        :cfg_plural => "alarms",
        :interface => self.const_get("Alarm"),
        :deps_wait_on_my_creation => false,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Notifier => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "notifier",
        :cfg_plural => "notifiers",
        :interface => self.const_get("Notifier"),
        :deps_wait_on_my_creation => false,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Log => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "log",
        :cfg_plural => "logs",
        :interface => self.const_get("Log"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :StoragePool => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "storage_pool",
        :cfg_plural => "storage_pools",
        :interface => self.const_get("StoragePool"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Function => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "function",
        :cfg_plural => "functions",
        :interface => self.const_get("Function"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Endpoint => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "endpoint",
        :cfg_plural => "endpoints",
        :interface => self.const_get("Endpoint"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :ContainerCluster => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "container_cluster",
        :cfg_plural => "container_clusters",
        :interface => self.const_get("ContainerCluster"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :SearchDomain => {
        :has_multiples => false,
        :can_live_in_vpc => true,
        :cfg_name => "search_domain",
        :cfg_plural => "search_domains",
        :interface => self.const_get("SearchDomain"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :MsgQueue => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "msg_queue",
        :cfg_plural => "msg_queues",
        :interface => self.const_get("MsgQueue"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :User => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "user",
        :cfg_plural => "users",
        :interface => self.const_get("User"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Group => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "group",
        :cfg_plural => "groups",
        :interface => self.const_get("Group"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Role => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "role",
        :cfg_plural => "roles",
        :interface => self.const_get("Role"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Bucket => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "bucket",
        :cfg_plural => "buckets",
        :interface => self.const_get("Bucket"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => true,
        :class => @@generic_class_methods + [:upload],
        :instance => @@generic_instance_methods + [:groom, :upload]
      },
      :NoSQLDB => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "nosqldb",
        :cfg_plural => "nosqldbs",
        :interface => self.const_get("NoSQLDB"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :Job => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "job",
        :cfg_plural => "jobs",
        :interface => self.const_get("Job"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      },
      :CDN => {
        :has_multiples => false,
        :can_live_in_vpc => false,
        :cfg_name => "cdn",
        :cfg_plural => "cdns",
        :interface => self.const_get("CDN"),
        :deps_wait_on_my_creation => true,
        :waits_on_parent_completion => false,
        :class => @@generic_class_methods,
        :instance => @@generic_instance_methods + [:groom]
      }
    }.freeze

    # A list of supported cloud resource types as Mu classes
    def self.resource_types;
      @@resource_types
    end

    # Shorthand lookup for resource type names. Given any of the shorthand class name, configuration name (singular or plural), or full class name, return all four as a set.
    # @param type [String]: A string that looks like our short or full class name or singular or plural configuration names.
    # @param assert [Boolean]: Raise an exception if the type isn't valid
    # @return [Array]: Class name (Symbol), singular config name (String), plural config name (String), full class name (Object)
    def self.getResourceNames(type, assert = true)
      if !type
        if assert
          raise MuError, "nil resource type requested in getResourceNames"
        else
          return [nil, nil, nil, nil, {}]
        end
      end
      @@resource_types.each_pair { |name, cloudclass|
        if name == type.to_sym or
            cloudclass[:cfg_name] == type or
            cloudclass[:cfg_plural] == type or
            MU::Cloud.const_get(name) == type
          type = name
          return [type.to_sym, cloudclass[:cfg_name], cloudclass[:cfg_plural], MU::Cloud.const_get(name), cloudclass]
        end
      }
      if assert
        raise MuError, "Invalid resource type #{type} requested in getResourceNames"
      end

      [nil, nil, nil, nil, {}]
    end

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
    def self.fetchUserdata(platform: "linux", template_variables: {}, custom_append: nil, cloud: "AWS", scrub_mu_isms: false, credentials: nil)
      return nil if platform.nil? or platform.empty?
      userdata_mutex.synchronize {
        script = ""
        if !scrub_mu_isms
          if template_variables.nil? or !template_variables.is_a?(Hash)
            raise MuError, "My second argument should be a hash of variables to pass into ERB templates"
          end
          template_variables["credentials"] ||= credentials
          $mu = OpenStruct.new(template_variables)
          userdata_dir = File.expand_path(MU.myRoot+"/modules/mu/providers/#{cloud.downcase}/userdata")

          platform = if %w{win2k12r2 win2k12 win2k8 win2k8r2 win2k16 windows win2k19}.include?(platform)
            "windows"
          else
            "linux"
          end

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

    # Given a resource type, validate that it's legit and return its base class from the {MU::Cloud} module
    # @param type [String]
    # @return [MU::Cloud]
    def self.loadBaseType(type)
      raise MuError, "Argument to MU::Cloud.loadBaseType cannot be nil" if type.nil?
      shortclass, cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(type)
      if !shortclass
        raise MuCloudResourceNotImplemented, "#{type} does not appear to be a valid resource type"
      end
      Object.const_get("MU").const_get("Cloud").const_get(shortclass)
    end

    @cloud_class_cache = {}
    # Given a cloud layer and resource type, return the class which implements it.
    # @param cloud [String]: The Cloud layer
    # @param type [String]: The resource type. Can be the full class name, symbolic name, or Basket of Kittens configuration shorthand for the resource type.
    # @return [Class]: The cloud-specific class implementing this resource
    def self.resourceClass(cloud, type)
      raise MuError, "cloud argument to MU::Cloud.resourceClass cannot be nil" if cloud.nil?
      shortclass, cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(type)
      if @cloud_class_cache.has_key?(cloud) and @cloud_class_cache[cloud].has_key?(type)
        if @cloud_class_cache[cloud][type].nil?
          raise MuError, "The '#{type}' resource is not supported in cloud #{cloud} (tried MU::#{cloud}::#{type})", caller
        end
        return @cloud_class_cache[cloud][type]
      end

      if cfg_name.nil?
        raise MuError, "Can't find a cloud resource type named '#{type}'"
      end
      if !File.size?(MU.myRoot+"/modules/mu/providers/#{cloud.downcase}.rb")
        raise MuError, "Requested to use unsupported provisioning layer #{cloud}"
      end
      begin
        require "mu/providers/#{cloud.downcase}/#{cfg_name}"
      rescue LoadError => e
        raise MuCloudResourceNotImplemented, "MU::Cloud::#{cloud} does not currently implement #{shortclass}, or implementation does not load correctly (#{e.message})"
      end

      @cloud_class_cache[cloud] = {} if !@cloud_class_cache.has_key?(cloud)
      begin
        cloudclass = const_get("MU").const_get("Cloud").const_get(cloud)
        myclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(shortclass)

        @@resource_types[shortclass.to_sym][:class].each { |class_method|
          if !myclass.respond_to?(class_method) or myclass.method(class_method).owner.to_s != "#<Class:#{myclass}>"
            raise MuError, "MU::Cloud::#{cloud}::#{shortclass} has not implemented required class method #{class_method}"
          end
        }
        @@resource_types[shortclass.to_sym][:instance].each { |instance_method|
          if !myclass.public_instance_methods.include?(instance_method)
            raise MuCloudResourceNotImplemented, "MU::Cloud::#{cloud}::#{shortclass} has not implemented required instance method #{instance_method}"
          end
        }
        cloudclass.required_instance_methods.each { |instance_method|
          if !myclass.public_instance_methods.include?(instance_method)
            MU.log "MU::Cloud::#{cloud}::#{shortclass} has not implemented required instance method #{instance_method}, will declare as attr_accessor", MU::DEBUG
          end
        }

        @cloud_class_cache[cloud][type] = myclass

        return myclass
      rescue NameError => e
        @cloud_class_cache[cloud][type] = nil
        raise MuCloudResourceNotImplemented, "The '#{type}' resource is not supported in cloud #{cloud} (tried MU::Cloud::#{cloud}::#{shortclass})", e.backtrace
      end
    end

    require 'mu/cloud/machine_images'
    require 'mu/cloud/resource_base'
    require 'mu/cloud/providers'

  end

end
