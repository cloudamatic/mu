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

require 'rubygems'
require 'bundler/setup'
require 'yaml'
require 'socket'
require 'net/http'
gem 'aws-sdk-core'
autoload :Aws, "aws-sdk-core"
gem 'nokogiri'
autoload :Nokogiri, "nokogiri"
gem 'simple-password-gen'
autoload :Password, "simple-password-gen"
autoload :Resolv, 'resolv'
gem 'netaddr'
autoload :NetAddr, 'netaddr'

# weird magic (possibly unnecessary)
class Object
  # weird magic (possibly unnecessary)
  def metaclass
    class << self;
      self;
    end
  end
end

ENV['HOME'] = Etc.getpwuid(Process.uid).dir

require 'mu/logger'
module MU

  # Wrapper class for fatal Exceptions. Gives our internals something to
  # inherit that will log an error message appropriately before bubbling up.
  class MuError < StandardError
    def initialize(message = nil)
      MU.log message, MU::ERR if !message.nil?
      if MU.verbosity == MU::Logger::SILENT
        super
      else
        super ""
      end
    end
  end

  # Wrapper class for temporary Exceptions. Gives our internals something to
  # inherit that will log a notice message appropriately before bubbling up.
  class MuNonFatal < StandardError
    def initialize(message = nil)
      MU.log message, MU::NOTICE if !message.nil?
      if MU.verbosity == MU::Logger::SILENT
        super
      else
        super ""
      end
    end
  end

  if !ENV.has_key?("MU_LIBDIR") and ENV.has_key?("MU_INSTALLDIR")
    ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
  else
    ENV['MU_LIBDIR'] = File.realpath(File.expand_path(File.dirname(__FILE__))+"/../")
  end
  # Mu's installation directory.
  @@myRoot = File.expand_path(ENV['MU_LIBDIR'])
  # Mu's installation directory.
  # @return [String]
  def self.myRoot;
    @@myRoot
  end


  # The main (root) Mu user's data directory.
  @@mainDataDir = File.expand_path(@@myRoot+"/../var")
  # The main (root) Mu user's data directory.
  # @return [String]
  def self.mainDataDir;
    @@mainDataDir
  end

  # The Mu config directory
  @@etcDir = File.expand_path(@@myRoot+"/../etc")
  # The Mu config directory
  # @return [String]
  def self.etcDir;
    @@etcDir
  end

  # The Mu install directory
  @@installDir = File.expand_path(@@myRoot+"/..")
  # The Mu install directory
  # @return [String]
  def self.installDir;
    @@installDir
  end

  # Mu's main metadata directory (also the deployment metadata for the 'mu'
  @@globals = Hash.new
  @@globals[Thread.current.object_id] = Hash.new
  # Rig us up to share some global class variables (as MU.var_name).
  # These values are PER-THREAD, so that things like Momma Cat can be more or
  # less thread-safe with global values.
  def self.globals;
    @@globals
  end

  @@global_var_semaphore = Mutex.new

  # Set one of our global per-thread variables.
  def self.setVar(name, value)
    @@global_var_semaphore.synchronize {
      @@globals[Thread.current.object_id] ||= Hash.new
      @@globals[Thread.current.object_id][name] ||= Hash.new
      @@globals[Thread.current.object_id][name] = value
    }
  end

  # Copy the set of global variables in use by another thread, typically our
  # parent thread.
  def self.dupGlobals(parent_thread_id)
    @@globals[parent_thread_id].each_pair { |name, value|
      setVar(name, value)
    }
  end

  # Expunge all global variables.
  def self.purgeGlobals
    @@globals.delete(Thread.current.object_id)
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.mommacat;
    @@globals[Thread.current.object_id]['mommacat']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.deploy_id;
    @@globals[Thread.current.object_id]['deploy_id']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.appname;
    @@globals[Thread.current.object_id]['appname']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.environment;
    @@globals[Thread.current.object_id]['environment']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.timestamp;
    @@globals[Thread.current.object_id]['timestamp']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.seed;
    @@globals[Thread.current.object_id]['seed']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.handle;
    @@globals[Thread.current.object_id]['handle']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.chef_user;
    if @@globals.has_key?(Thread.current.object_id) and @@globals[Thread.current.object_id].has_key?('chef_user')
      @@globals[Thread.current.object_id]['chef_user']
    elsif Etc.getpwuid(Process.uid).name == "root"
      return "mu"
    else
      return Etc.getpwuid(Process.uid).name
    end
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.mu_user
    if @@globals.has_key?(Thread.current.object_id) and @@globals[Thread.current.object_id].has_key?('mu_user')
      return @@globals[Thread.current.object_id]['mu_user']
    elsif Etc.getpwuid(Process.uid).name == "root"
      return "mu"
    else
      return Etc.getpwuid(Process.uid).name
    end
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.curRegion
    @@globals[Thread.current.object_id]['curRegion'] ||= myRegion || ENV['EC2_REGION']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.syncLitterThread;
    @@globals[Thread.current.object_id]['syncLitterThread']
  end

  # Mu's deployment metadata directory.
  @myDataDir = File.expand_path(ENV['MU_DATADIR']) if ENV.has_key?("MU_DATADIR")
  @myDataDir = @@mainDataDir if @myDataDir.nil?
  # Mu's deployment metadata directory.
  def self.dataDir(for_user = MU.mu_user)
    if for_user.nil? or for_user.empty? or for_user == "mu" or for_user == "root"
      return @myDataDir
    else
      for_user ||= MU.mu_user
      basepath = Etc.getpwnam(for_user).dir+"/.mu"
      Dir.mkdir(basepath, 0755) if !Dir.exists?(basepath)
      Dir.mkdir(basepath+"/var", 0755) if !Dir.exists?(basepath+"/var")
      return basepath+"/var"
    end
  end

  # The verbose logging flag merits a default value.
  def self.verbosity
    if @@globals[Thread.current.object_id].nil? or @@globals[Thread.current.object_id]['verbosity'].nil?
      MU.setVar("verbosity", MU::Logger::NORMAL)
    end
    @@globals[Thread.current.object_id]['verbosity']
  end

  # Set parameters parameters for calls to {MU#log}
  def self.setLogging(verbosity, webify_logs = false, handle = STDOUT)
    MU.setVar("verbosity", verbosity)
    @@logger ||= MU::Logger.new(verbosity, webify_logs, handle)
    @@logger.html = webify_logs
    @@logger.verbosity = verbosity
    @@logger.handle = handle
  end

  setLogging(MU::Logger::NORMAL, false)

  # Shortcut to get SUMMARY messages from the global MU::Logger instance
  # @return [Array<String>]
  def self.summary
    @@logger.summary
  end

  # Shortcut to invoke {MU::Logger#log}
  def self.log(msg, level = MU::INFO, details: nil, html: html = false, verbosity: MU.verbosity)
    return if (level == MU::DEBUG and verbosity <= MU::Logger::LOUD)
    return if verbosity == MU::Logger::SILENT

    if (level == MU::ERR or
        level == MU::WARN or
        level == MU::DEBUG or
        verbosity >= MU::Logger::LOUD or
        (level == MU::NOTICE and !details.nil?)
    )
      # TODO add more stuff to details here (e.g. call stack)
      extra = nil
      if Thread.current.thread_variable_get("name") and (level > MU::NOTICE or verbosity >= MU::Logger::LOUD)
        extra = Hash.new
        extra = {
          :thread => Thread.current.object_id,
          :name => Thread.current.thread_variable_get("name")
        }
      end
      if !details.nil?
        extra = Hash.new if extra.nil?
        extra[:details] = details
      end
      @@logger.log(msg, level, details: extra, verbosity: MU::Logger::LOUD, html: html)
    else
      @@logger.log(msg, level, html: html, verbosity: verbosity)
    end
  end

  # For log entries that should only be logged when we're in verbose mode
  DEBUG = 0.freeze
  # For ordinary log entries
  INFO = 1.freeze
  # For more interesting log entries which are not errors
  NOTICE = 2.freeze
  # Log entries for non-fatal errors
  WARN = 3.freeze
  # Log entries for non-fatal errors
  WARNING = 3.freeze
  # Log entries for fatal errors
  ERR = 4.freeze
  # Log entries for fatal errors
  ERROR = 4.freeze
  # Log entries that will be held and displayed/emailed at the end of deploy,
  # cleanup, etc.
  SUMMARY = 5.freeze


  autoload :Cleanup, 'mu/cleanup'
  autoload :Deploy, 'mu/deploy'
  autoload :MommaCat, 'mu/mommacat'
  autoload :Master, 'mu/master'
  require 'mu/cloud'
  require 'mu/groomer'

  # Little hack to initialize library-only environments' config files
  if !$MU_CFG
    require "#{@@myRoot}/bin/mu-load-config.rb"

    if !$MU_CFG['auto_detection_done'] and (!$MU_CFG['multiuser'] or !cfgExists?)
      MU.log "Auto-detecting cloud providers"
      new_cfg = $MU_CFG.dup
      examples = {}
      MU::Cloud.supportedClouds.each { |cloud|
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
        begin
          if cloudclass.hosted? and !$MU_CFG[cloud.downcase]
            cfg_blob = cloudclass.hosted_config
            if cfg_blob
              new_cfg[cloud.downcase] = cfg_blob
              MU.log "Adding #{cloud} stanza to #{cfgPath}", MU::NOTICE
            end
          elsif !$MU_CFG[cloud.downcase] and !cloudclass.config_example.nil?
            examples[cloud.downcase] = cloudclass.config_example
          end
        rescue NoMethodError => e
          # missing .hosted? is normal for dummy layers like CloudFormation
          MU.log e.message, MU::WARN
        end
      }
      new_cfg['auto_detection_done'] = true
      if new_cfg != $MU_CFG or !cfgExists?
        MU.log "Generating #{cfgPath}"
        saveMuConfig(new_cfg, examples) # XXX and reload it
      end
    end
  end

  @@my_private_ip = nil
  @@my_public_ip = nil
  @@mu_public_addr = nil
  @@mu_public_ip = nil
  if $MU_CFG['aws'] # XXX this should be abstracted to elsewhere
    @@my_private_ip = MU::Cloud::AWS.getAWSMetaData("local-ipv4")
    @@my_public_ip = MU::Cloud::AWS.getAWSMetaData("public-ipv4")
    @@mu_public_addr = @@my_public_ip
    @@mu_public_ip = @@my_public_ip
  end
  if !$MU_CFG.nil? and !$MU_CFG['public_address'].nil? and !$MU_CFG['public_address'].empty? and @@my_public_ip != $MU_CFG['public_address']
    @@mu_public_addr = $MU_CFG['public_address']
    if !@@mu_public_addr.match(/^\d+\.\d+\.\d+\.\d+$/)
      resolver = Resolv::DNS.new
      @@mu_public_ip = resolver.getaddress(@@mu_public_addr).to_s
    else
      @@mu_public_ip = @@mu_public_addr
    end
  elsif !@@my_public_ip.nil? and !@@my_public_ip.empty?
    @@mu_public_addr = @@my_public_ip
    @@mu_public_ip = @@my_public_ip
  else
    @@mu_public_addr = @@my_private_ip
    @@mu_public_ip = @@my_private_ip
  end

  # This machine's private IP address
  def self.my_private_ip;
    @@my_private_ip
  end

  # This machine's public IP address
  def self.my_public_ip;
    @@my_public_ip
  end

  # Public Mu server name, not necessarily the same as MU.my_public_ip (an be a proxy, load balancer, etc)
  def self.mu_public_ip;
    @@mu_public_ip
  end

  # Public Mu server IP address, not necessarily the same as MU.my_public_ip (an be a proxy, load balancer, etc)
  def self.mu_public_addr;
    @@mu_public_addr
  end


  mu_user = Etc.getpwuid(Process.uid).name
  chef_user = Etc.getpwuid(Process.uid).name.gsub(/\./, "")
  chef_user = "mu" if chef_user == "root"

  MU.setVar("chef_user", chef_user)
  MU.setVar("mu_user", mu_user)

  @userlist = nil

  # Fetch the email address of a given Mu user
  def self.userEmail(user = MU.mu_user)
    @userlist ||= MU::Master.listUsers
    user = "mu" if user == "root"
    if Dir.exists?("#{MU.mainDataDir}/users/#{user}")
      return File.read("#{MU.mainDataDir}/users/#{user}/email").chomp
    elsif @userlist.has_key?(user)
      return @userlist[user]['email']
    else
      MU.log "Attempted to load nonexistent user #{user}", MU::ERR
      return nil
    end
  end

  # Fetch the real-world name of a given Mu user
  def self.userName(user = MU.mu_user)
    @userlist ||= MU::Master.listUsers
    if Dir.exists?("#{MU.mainDataDir}/users/#{user}")
      return File.read("#{MU.mainDataDir}/users/#{user}/realname").chomp
    elsif @userlist.has_key?(user)
      return @userlist[user]['email']
    else
      MU.log "Attempted to load nonexistent user #{user}", MU::ERR
      return nil
    end
  end


  # XXX these guys to move into mu/groomer
  # List of known/supported grooming agents (configuration management tools)
  def self.supportedGroomers
    ["Chef", "Ansible"]
  end

  MU.supportedGroomers.each { |groomer|
    require "mu/groomers/#{groomer.downcase}"
  }
  # @param groomer [String]: The grooming agent to load.
  # @return [Class]: The class object implementing this groomer agent
  def self.loadGroomer(groomer)
    if !File.size?(MU.myRoot+"/modules/mu/groomers/#{groomer.downcase}.rb")
      raise MuError, "Requested to use unsupported grooming agent #{groomer}"
    end
    require "mu/groomers/#{groomer.downcase}"
    return Object.const_get("MU").const_get("Groomer").const_get(groomer)
  end

  @@myRegion_var = nil
  # Find the cloud provider region where this master resides, if any
  def self.myRegion
    if MU::Cloud::Google.hosted?
      zone = MU::Cloud::Google.getGoogleMetaData("instance/zone")
      @@myRegion_var = zone.gsub(/^.*?\/|\-\d+$/, "")
    elsif MU::Cloud::AWS.hosted?
      @@myRegion_var ||= MU::Cloud::AWS.myRegion
    else
      @@myRegion_var = nil
    end
    @@myRegion_var
  end

  require 'mu/config'

  # Figure out what cloud provider we're in, if any.
  # @return [String]: Google, AWS, etc. Returns nil if we don't seem to be in a cloud.
  def self.myCloud
    if MU::Cloud::Google.hosted?
      @@myInstanceId = MU::Cloud::Google.getGoogleMetaData("instance/name")
      return "Google"
    elsif MU::Cloud::AWS.hosted?
      @@myInstanceId = MU::Cloud::AWS.getAWSMetaData("instance-id")
      return "AWS"
    end
    nil
  end

  # Wrapper for {MU::Cloud::AWS.account_number}
  def self.account_number
    if !@@globals[Thread.current.object_id].nil? and
       !@@globals[Thread.current.object_id]['account_number'].nil?
      return @@globals[Thread.current.object_id]['account_number']
    end
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['account_number'] = MU::Cloud::AWS.account_number
    @@globals[Thread.current.object_id]['account_number']
  end

  # The cloud instance identifier of this Mu master
  def self.myInstanceId
    return nil if MU.myCloud.nil?
    @@myInstanceId # MU.myCloud will have set this, since it's our test variable
  end

  # If our Mu master is hosted in a cloud provider, we can use this to get its
  # cloud API descriptor.
  def self.myCloudDescriptor;
    @@myCloudDescriptor
  end

  @@myAZ_var = nil
  # Find the cloud provider availability zone where this master resides, if any
  def self.myAZ
    if MU::Cloud::Google.hosted?
      zone = MU::Cloud::Google.getGoogleMetaData("instance/zone")
      @@myAZ_var = zone.gsub(/.*?\//, "")
    elsif MU::Cloud::AWS.hosted?
      return nil if MU.myCloudDescriptor.nil?
      begin
        @@myAZ_var ||= MU.myCloudDescriptor.placement.availability_zone
      rescue Aws::EC2::Errors::InternalError => e
        MU.log "Got #{e.inspect} on MU::Cloud::AWS.ec2(region: #{MU.myRegion}).describe_instances(instance_ids: [#{@@myInstanceId}])", MU::WARN
        sleep 10
      end
    end
    @@myAZ_var
  end

  @@myCloudDescriptor = nil
  if MU::Cloud::Google.hosted?
    @@myCloudDescriptor = MU::Cloud::Google.compute.get_instance(
      MU::Cloud::Google.myProject,
      MU.myAZ,
      MU.myInstanceId
    )
  elsif MU::Cloud::AWS.hosted?
    begin
      @@myCloudDescriptor = MU::Cloud::AWS.ec2(region: MU.myRegion).describe_instances(instance_ids: [MU.myInstanceId]).reservations.first.instances.first
    rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
    rescue Aws::Errors::MissingCredentialsError => e
      MU.log "I'm hosted in AWS, but I can't make API calls. Does this instance have an appropriate IAM profile?", MU::WARN
    end
  end


  @@myVPC_var = nil
  # The VPC/Network in which this Mu master resides
  # XXX account for Google and non-cloud situations
  def self.myVPC
    return nil if MU.myCloudDescriptor.nil?
    begin
      if MU::Cloud::AWS.hosted?
        @@myVPC_var ||= MU.myCloudDescriptor.vpc_id
      elsif MU::Cloud::Google.hosted?
        @@myVPC_var = MU.myCloudDescriptor.network_interfaces.first.network.gsub(/.*?\/([^\/]+)$/, '\1')
      else
        nil
      end
    rescue Aws::EC2::Errors::InternalError => e
      MU.log "Got #{e.inspect} on MU::Cloud::AWS.ec2(region: #{MU.myRegion}).describe_instances(instance_ids: [#{@@myInstanceId}])", MU::WARN
      sleep 10
    end
    @@myVPC_var
  end

  @@mySubnets_var = nil
  # The AWS Subnets associated with the VPC this MU Master is in
  # XXX account for Google and non-cloud situations
  def self.mySubnets
    @@mySubnets_var ||= MU::Cloud::AWS.ec2(region: MU.myRegion).describe_subnets(
      filters: [
        {
          name: "vpc-id", 
          values: [MU.myVPC]
        }
      ]
    ).subnets
  end

  # The version of Chef we will install on nodes.
  @@chefVersion = "14.0.190"
  # The version of Chef we will install on nodes.
  # @return [String]
  def self.chefVersion;
    @@chefVersion
  end

  # Mu's SSL certificate directory
  @@mySSLDir = MU.dataDir+"/ssl" if MU.dataDir
  @@mySSLDir ||= File.realpath(File.expand_path(File.dirname(__FILE__))+"/../var/ssl")
  # Mu's SSL certificate directory
  # @return [String]
  def self.mySSLDir
    @@mySSLDir
  end

  # Recursively compare two hashes. Intended to see when cloud API descriptions
  # of existing resources differ from proposed changes so we know when to
  # bother updating.
  # @param hash1 [Hash]: The first hash
  # @param hash2 [Hash]: The second hash
  # @param missing_is_default [Boolean]: Assume that any element missing from hash2 but present in hash1 is a default value to be ignored
  # @return [Boolean]
  def self.hashCmp(hash1, hash2, missing_is_default: false)
    return false if hash1.nil?
    hash2.each_pair { |k, v|
      if hash1[k].nil?
        return false
      end
    }
    if !missing_is_default
      hash1.each_pair { |k, v|
        if hash2[k].nil?
          return false
        end
      }
    end

    hash1.each_pair { |k, v|
      if hash1[k].is_a?(Array) 
        return false if !missing_is_default and hash2[k].nil?
        if !hash2[k].nil?
          hash2[k].each { |item|
            if !hash1[k].include?(item)
              return false
            end
          }
        end
      elsif hash1[k].is_a?(Hash) and !hash2[k].nil?
        result = hashCmp(hash1[k], hash2[k], missing_is_default: missing_is_default)
        return false if !result
      else
        if missing_is_default
          return false if !hash2[k].nil? and hash1[k] != hash2[k]
        else
          return false if hash1[k] != hash2[k]
        end
      end
    }
    true
  end

  # Given a hash, or an array that might contain a hash, change all of the keys
  # to symbols. Useful for formatting option parameters to some APIs.
  def self.strToSym(obj)
    if obj.is_a?(Hash)
      newhash = {}
      obj.each_pair { |k, v|
        if v.is_a?(Hash) or v.is_a?(Array)
          newhash[k.to_sym] = MU.strToSym(v)
        else
          newhash[k.to_sym] = v
        end
      }
      newhash
    elsif obj.is_a?(Array)
      newarr = []
      obj.each { |v|
        if v.is_a?(Hash) or v.is_a?(Array)
          newarr << MU.strToSym(v)
        else
          newarr << v
        end
      }
      newarr
    end
  end


  # Recursively turn a Ruby OpenStruct into a Hash
  # @param struct [OpenStruct]
  # @param stringify_keys [Boolean]
  # @return [Hash]
  def self.structToHash(struct, stringify_keys: false)
    google_struct = false
    begin
      google_struct = struct.class.ancestors.include?(::Google::Apis::Core::Hashable)
    rescue NameError
    end

    aws_struct = false
    begin
      aws_struct = struct.class.ancestors.include?(::Seahorse::Client::Response)
    rescue NameError
    end

    if struct.is_a?(Struct) or struct.class.ancestors.include?(Struct) or
       google_struct or aws_struct

      hash = struct.to_h
      if stringify_keys
        newhash = {}
        hash.each_pair { |k, v|
          newhash[k.to_s] = v
        }
        hash = newhash 
      end

      hash.each_pair { |key, value|
        hash[key] = self.structToHash(value, stringify_keys: stringify_keys)
      }
      return hash
    elsif struct.is_a?(Hash)
      if stringify_keys
        newhash = {}
        struct.each_pair { |k, v|
          newhash[k.to_s] = v
        }
        struct = newhash 
      end
      struct.each_pair { |key, value|
        struct[key] = self.structToHash(value, stringify_keys: stringify_keys)
      }
      return struct
    elsif struct.is_a?(Array)
      struct.map! { |elt|
        self.structToHash(elt, stringify_keys: stringify_keys)
      }
    else
      return struct
    end
  end

  # Generate a random password which will satisfy the complexity requirements of stock Amazon Windows AMIs.
  # return [String]: A password string.
  def self.generateWindowsPassword
    # We have dopey complexity requirements, be stringent here.
    # I'll be nice and not condense this into one elegant-but-unreadable regular expression
    attempts = 0
    safe_metachars = Regexp.escape('~!@#%^&*_-+=`|(){}[]:;<>,.?')
    begin
      if attempts > 25
        MU.log "Failed to generate an adequate Windows password after #{attempts}", MU::ERR
        raise MuError, "Failed to generate an adequate Windows password after #{attempts}"
      end
      winpass = Password.random(14..16)
      attempts += 1
    end while winpass.nil? or !winpass.match(/[A-Z]/) or !winpass.match(/[a-z]/) or !winpass.match(/\d/) or !winpass.match(/[#{safe_metachars}]/) or winpass.match(/[^\w\d#{safe_metachars}]/)

    MU.log "Generated Windows password after #{attempts} attempts", MU::DEBUG
    return winpass
  end


  # Return the name of the Mu log and key bucket for this Mu server. Not
  # necessarily in any specific cloud provider.
  # @return [String]
  def self.adminBucketName(platform = nil, credentials: nil)
    return nil if platform and !MU::Cloud.supportedClouds.include?(platform)

    clouds = platform.nil? ? MU::Cloud.supportedClouds : [platform]
    clouds.each { |cloud|
      cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
      bucketname = cloudclass.adminBucketName(credentials)
      begin
        if platform or (cloudclass.hosted? and platform.nil?) or cloud == MU::Config.defaultCloud
          return bucketname
        end
      end
    }

    return bucketname
  end


end
