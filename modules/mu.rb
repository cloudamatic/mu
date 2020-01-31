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

# Mu extensions to Ruby's {Hash} type for internal Mu use
class Hash

  # Strip extraneous fields out of a {MU::Config} hash to make it suitable for
  # shorthand printing, such as with <tt>mu-adopt --diff</tt>
  def self.bok_minimize(o)
    if o.is_a?(Hash)
      newhash = o.reject { |k, v|
        !v.is_a?(Array) and !v.is_a?(Hash) and !["name", "id", "cloud_id"].include?(k)
      }
#      newhash.delete("cloud_id") if newhash["name"] or newhash["id"]
      newhash.each_pair { |k, v|
        newhash[k] = bok_minimize(v)
      }
      newhash.reject! { |_k, v| v.nil? or v.empty? }
      newhash = newhash.values.first if newhash.size == 1
      return newhash
    elsif o.is_a?(Array)
      newarray = []
      o.each { |v|
        newvalue = bok_minimize(v)
        newarray << newvalue if !newvalue.nil? and !newvalue.empty?
      }
      newarray = newarray.first if newarray.size == 1
      return newarray
    end

    o
  end

  # A comparison function for sorting arrays of hashes
  def <=>(other)
    return 1 if other.nil? or self.size > other.size
    return -1 if other.size > self.size
    # Sort any array children we have
    self.each_pair { |k, v|
      self[k] = v.sort if v.is_a?(Array)
    }
    other.each_pair { |k, v|
      other[k] = v.sort if v.is_a?(Array)
    }
    return 0 if self == other # that was easy!
    # compare elements and decide who's "bigger" based on their totals?
    0
  end

  # Recursively compare two hashes
  def diff(with, on = self, level: 0, parents: [])
    return if with.nil? and on.nil?
    if with.nil? or on.nil? or with.class != on.class
      return # XXX ...however we're flagging differences
    end
    return if on == with

    tree = ""
    indentsize = 0
    parents.each { |p|
      tree += (" " * indentsize) + p + " => \n"
      indentsize += 2
    }
    indent = (" " * indentsize)

    changes = []
    if on.is_a?(Hash)
      on_unique = (on.keys - with.keys)
      with_unique = (with.keys - on.keys)
      shared = (with.keys & on.keys)
      shared.each { |k|
        diff(with[k], on[k], level: level+1, parents: parents + [k])
      }
      on_unique.each { |k|
        changes << "- ".red+PP.pp({k => on[k] }, '')
      }
      with_unique.each { |k|
        changes << "+ ".green+PP.pp({k => with[k]}, '')
      }
    elsif on.is_a?(Array)
      return if with == on
      # special case- Basket of Kittens lists of declared resources of a type;
      # we use this to decide if we can compare two array elements as if they
      # should be equivalent
      # We also implement comparison operators for {Hash} and our various
      # custom objects which we might find in here so that we can get away with
      # sorting arrays full of weird, non-primitive types.
      done = []
#      before_a = on.dup
#      after_a = on.dup.sort
#      before_b = with.dup
#      after_b = with.dup.sort
      on.sort.each { |elt|
        if elt.is_a?(Hash) and elt['name'] or elt['entity']# or elt['cloud_id']
          with.sort.each { |other_elt|
            if (elt['name'] and other_elt['name'] == elt['name']) or
               (elt['name'].nil? and !elt["id"].nil? and elt["id"] == other_elt["id"]) or
               (elt['name'].nil? and elt["id"].nil? and
                !elt["entity"].nil? and !other_elt["entity"].nil? and
                 (
                   (elt["entity"]["id"] and elt["entity"]["id"] == other_elt["entity"]["id"]) or
                   (elt["entity"]["name"] and elt["entity"]["name"] == other_elt["entity"]["name"])
                 )
               )
              break if elt == other_elt
              done << elt
              done << other_elt
              namestr = if elt['type']
                "#{elt['type']}[#{elt['name']}]"
              elsif elt['name']
                elt['name']
              elsif elt['entity'] and elt["entity"]["id"]
                elt['entity']['id']
              end

              diff(other_elt, elt, level: level+1, parents: parents + [namestr])
              break
            end
          }
        end
      }
      on_unique = (on - with) - done
      with_unique = (with - on) - done
#    if on_unique.size > 0 or with_unique.size > 0
#      if before_a != after_a
#        MU.log "A BEFORE", MU::NOTICE, details: before_a
#        MU.log "A AFTER", MU::NOTICE, details: after_a
#      end
#      if before_b != after_b
#        MU.log "B BEFORE", MU::NOTICE, details: before_b
#        MU.log "B AFTER", MU::NOTICE, details: after_b
#      end
#    end
      on_unique.each { |e|
        changes << if e.is_a?(Hash)
          "- ".red+PP.pp(Hash.bok_minimize(e), '').gsub(/\n/, "\n  "+(indent))
        else
          "- ".red+e.to_s
        end
      }
      with_unique.each { |e|
        changes << if e.is_a?(Hash)
          "+ ".green+PP.pp(Hash.bok_minimize(e), '').gsub(/\n/, "\n  "+(indent))
        else
          "+ ".green+e.to_s
        end
      }
    else
      if on != with
        changes << "-".red+" #{on.to_s}"
        changes << "+".green+" #{with.to_s}"
      end
    end

    if changes.size > 0
      puts tree
      changes.each { |c|
        puts indent+c
      }
    end
  end

  # Implement a merge! that just updates each hash leaf as needed, not 
  # trashing the branch on the way there.
  def deep_merge!(with, on = self)

    if on and with and with.is_a?(Hash)
      with.each_pair { |k, v|
        if !on[k] or !on[k].is_a?(Hash)
          on[k] = v
        else
          deep_merge!(with[k], on[k])
        end
      }
    elsif with
      on = with
    end

    on
  end
end

ENV['HOME'] = Etc.getpwuid(Process.uid).dir

require 'mu/logger'
module MU

  # Subclass core thread so we can gracefully handle it when we hit system
  # thread limits. Back off and wait makes sense for us, since most of our
  # threads are terminal (in the dependency sense) and this is unlikely to get
  # us deadlocks.
  class Thread < ::Thread
    @@mu_global_threads = []
    @@mu_global_thread_semaphore = Mutex.new

    def initialize(*args, &block)
      @@mu_global_thread_semaphore.synchronize {
        @@mu_global_threads.reject! { |t| t.nil? or !t.status }
      }
      newguy = nil
      start = Time.now
      begin
        newguy = super(*args, &block)
        if newguy.nil?
          MU.log "I somehow got a nil trying to create a thread", MU::WARN, details: caller
          sleep 1
        end
      rescue ::ThreadError => e
        if e.message.match(/Resource temporarily unavailable/)
          toomany = @@mu_global_threads.size
          MU.log "Hit the wall at #{toomany.to_s} threads, waiting until there are fewer", MU::WARN
          if @@mu_global_threads.size >= toomany
            sleep 1
            begin
              @@mu_global_thread_semaphore.synchronize {
                @@mu_global_threads.each { |t|
                  next if t == ::Thread.current
                  t.join(0.1)
                }
                @@mu_global_threads.reject! { |t| t.nil? or !t.status }
              }
              if (Time.now - start) > 150
                MU.log "Failed to get a free thread slot after 150 seconds- are we in a deadlock situation?", MU::ERR, details: caller
                raise e
              end
            end while @@mu_global_threads.size >= toomany
          end
          retry
        else
          raise e
        end
      end while newguy.nil?

      @@mu_global_thread_semaphore.synchronize {
        @@mu_global_threads << newguy
      }

    end
  end

  # Wrapper class for fatal Exceptions. Gives our internals something to
  # inherit that will log an error message appropriately before bubbling up.
  class MuError < StandardError
    def initialize(message = nil)
      MU.log message, MU::ERR, details: caller[2] if !message.nil?
      if MU.verbosity == MU::Logger::SILENT
        super ""
      else
        super message
      end
    end
  end

  # Wrapper class for temporary Exceptions. Gives our internals something to
  # inherit that will log a notice message appropriately before bubbling up.
  class MuNonFatal < StandardError
    def initialize(message = nil)
      MU.log message, MU::NOTICE if !message.nil?
      if MU.verbosity == MU::Logger::SILENT
        super ""
      else
        super message
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

  # utility routine for sorting semantic versioning strings
  def self.version_sort(a, b)
    a_parts = a.split(/[^a-z0-9]/)
    b_parts = b.split(/[^a-z0-9]/)
    for i in 0..a_parts.size
      matchval = if a_parts[i] and b_parts[i] and
                    a_parts[i].match(/^\d+/) and b_parts[i].match(/^\d+/)
        a_parts[i].to_i <=> b_parts[i].to_i
      elsif a_parts[i] and !b_parts[i]
        1
      elsif !a_parts[i] and b_parts[i]
        -1
      else
        a_parts[i] <=> b_parts[i]
      end
      return matchval if matchval != 0
    end
    0
  end

  # Front our global $MU_CFG hash with a read-only copy
  def self.muCfg
    Marshal.load(Marshal.dump($MU_CFG)).freeze
  end

  # Returns true if we're running without a full systemwide Mu Master install,
  # typically as a gem.
  def self.localOnly
    ((Gem.paths and Gem.paths.home and File.realpath(File.expand_path(File.dirname(__FILE__))).match(/^#{Gem.paths.home}/)) or !Dir.exist?("/opt/mu"))
  end

  # Are we operating in a gem?
  def self.inGem?
    return @in_gem if defined? @in_gem

    if Gem.paths and Gem.paths.home and File.dirname(__FILE__).match(/^#{Gem.paths.home}/)
      @in_gem = true
    elsif Gem.paths and Gem.paths.path and !Gem.paths.path.empty?
      Gem.paths.path.each { |p|
        if File.dirname(__FILE__).match(/^#{Regexp.quote(p)}/)
          @in_gem = true
        end
      }
      @in_gem = false if !defined? @in_gem
    else
      @in_gem = false
    end
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
    @@globals[parent_thread_id] ||= {}
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
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['mommacat']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.deploy_id;
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['deploy_id']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.appname;
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['appname']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.environment;
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['environment']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.timestamp;
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['timestamp']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.seed;
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['seed']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.handle;
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['handle']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.chef_user;
    @@globals[Thread.current.object_id] ||= {}
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
    @@globals[Thread.current.object_id] ||= {}
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
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['curRegion'] ||= myRegion || ENV['EC2_REGION']
  end

  # Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
  def self.syncLitterThread;
    @@globals[Thread.current.object_id] ||= {}
    @@globals[Thread.current.object_id]['syncLitterThread']
  end

  # Mu's deployment metadata directory.
  @myDataDir = File.expand_path(ENV['MU_DATADIR']) if ENV.has_key?("MU_DATADIR")
  @myDataDir = @@mainDataDir if @myDataDir.nil?
  # Mu's deployment metadata directory.
  def self.dataDir(for_user = MU.mu_user)
    if !localOnly and
       ((Process.uid == 0 and (for_user.nil? or for_user.empty?)) or
        for_user == "mu" or for_user == "root")
      return @myDataDir
    else
      for_user ||= MU.mu_user
      basepath = Etc.getpwnam(for_user).dir+"/.mu"
      Dir.mkdir(basepath, 0755) if !Dir.exist?(basepath)
      Dir.mkdir(basepath+"/var", 0755) if !Dir.exist?(basepath+"/var")
      return basepath+"/var"
    end
  end

  # Return the verbosity setting of the default @@logger object
  def self.verbosity
    @@logger ? @@logger.verbosity : MU::Logger::NORMAL
  end

  # Set parameters parameters for calls to {MU#log}
  def self.setLogging(verbosity, webify_logs = false, handle = STDOUT, color = true)
    @@logger ||= MU::Logger.new(verbosity, webify_logs, handle, color)
    @@logger.html = webify_logs
    @@logger.verbosity = verbosity
    @@logger.handle = handle
    @@logger.color = color
  end

  setLogging(MU::Logger::NORMAL, false)

  # Shortcut to get SUMMARY messages from the global MU::Logger instance
  # @return [Array<String>]
  def self.summary
    @@logger.summary
  end

  # Shortcut to invoke {MU::Logger#log}
  def self.log(msg, level = MU::INFO, details: nil, html: false, verbosity: nil, color: true)
    return if (level == MU::DEBUG and verbosity and verbosity <= MU::Logger::LOUD)
    return if verbosity and verbosity == MU::Logger::SILENT

    if (level == MU::ERR or
        level == MU::WARN or
        level == MU::DEBUG or
        (verbosity and verbosity >= MU::Logger::LOUD) or
        (level == MU::NOTICE and !details.nil?)) and
        Thread.current.thread_variable_get("name")
      newdetails = {
        :thread => Thread.current.object_id,
        :name => Thread.current.thread_variable_get("name")
      }
      newdetails[:details] = details.dup if details
      details = newdetails
    end

    @@logger.log(msg, level, details: details, html: html, verbosity: verbosity, color: color)
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
  def self.detectCloudProviders
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
            MU.log "Adding auto-detected #{cloud} stanza", MU::NOTICE
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
    new_cfg
  end

  if !$MU_CFG
    require "#{@@myRoot}/bin/mu-load-config.rb"
    if !$MU_CFG['auto_detection_done'] and (!$MU_CFG['multiuser'] or !cfgExists?)
      detectCloudProviders
    end
  end

  @@mommacat_port = 2260
  if !$MU_CFG.nil? and !$MU_CFG['mommacat_port'].nil? and
     !$MU_CFG['mommacat_port'] != "" and $MU_CFG['mommacat_port'].to_i > 0 and
     $MU_CFG['mommacat_port'].to_i < 65536
    @@mommacat_port = $MU_CFG['mommacat_port'].to_i
  end
  # The port on which the Momma Cat daemon should listen for requests
  # @return [Integer]
  def self.mommaCatPort
    @@mommacat_port
  end

  @@my_private_ip = nil
  @@my_public_ip = nil
  @@mu_public_addr = nil
  @@mu_public_ip = nil
  if MU::Cloud::AWS.hosted?
    @@my_private_ip = MU::Cloud::AWS.getAWSMetaData("local-ipv4")
    @@my_public_ip = MU::Cloud::AWS.getAWSMetaData("public-ipv4")
    @@mu_public_addr = @@my_public_ip
    @@mu_public_ip = @@my_public_ip
  end
  if !$MU_CFG.nil? and !$MU_CFG['public_address'].nil? and
     !$MU_CFG['public_address'].empty? and @@my_public_ip != $MU_CFG['public_address']
    @@mu_public_addr = $MU_CFG['public_address']
    if !@@mu_public_addr.match(/^\d+\.\d+\.\d+\.\d+$/)
      hostname = IO.readlines("/etc/hostname")[0].gsub /\n/, ''

      hostlines = File.open('/etc/hosts').grep(/.*#{hostname}.*/)
      if hostlines and !hostlines.empty?
        @@mu_public_ip = hostlines.first.match(/^\d+\.\d+\.\d+\.\d+/)[0]
      end
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
    if Dir.exist?("#{MU.mainDataDir}/users/#{user}") and
       File.readable?("#{MU.mainDataDir}/users/#{user}/email") and
       File.size?("#{MU.mainDataDir}/users/#{user}/email")
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
    if Dir.exist?("#{MU.mainDataDir}/users/#{user}") and
       File.readable?("#{MU.mainDataDir}/users/#{user}/realname") and
       File.size?("#{MU.mainDataDir}/users/#{user}/realname")
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

  # The version of Chef we will install on nodes.
  @@chefVersion = "14.0.190"
  # The version of Chef we will install on nodes.
  # @return [String]
  def self.chefVersion
    @@chefVersion
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
    elsif MU::Cloud::Azure.hosted?
      @@myRegion_var ||= MU::Cloud::Azure.myRegion
    else
      @@myRegion_var = nil
    end
    @@myRegion_var
  end

  require 'mu/config'
  require 'mu/adoption'

  # Figure out what cloud provider we're in, if any.
  # @return [String]: Google, AWS, etc. Returns nil if we don't seem to be in a cloud.
  def self.myCloud
    if MU::Cloud::Google.hosted?
      @@myInstanceId = MU::Cloud::Google.getGoogleMetaData("instance/name")
      return "Google"
    elsif MU::Cloud::AWS.hosted?
      @@myInstanceId = MU::Cloud::AWS.getAWSMetaData("instance-id")
      return "AWS"
    elsif MU::Cloud::Azure.hosted?
      metadata = MU::Cloud::Azure.get_metadata()["compute"]
      @@myInstanceId = MU::Cloud::Azure::Id.new("/subscriptions/"+metadata["subscriptionId"]+"/resourceGroups/"+metadata["resourceGroupName"]+"/providers/Microsoft.Compute/virtualMachines/"+metadata["name"])
      return "Azure"
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

    azure_struct = false
    begin
      azure_struct = struct.class.ancestors.include?(::MsRestAzure) or struct.class.name.match(/Azure::.*?::Mgmt::.*?::Models::/)
    rescue NameError
    end

    if struct.is_a?(Struct) or struct.class.ancestors.include?(Struct) or
       google_struct or aws_struct or azure_struct

      hash = if azure_struct
        MU::Cloud::Azure.respToHash(struct)
      else
        struct.to_h
      end

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
    elsif struct.is_a?(MU::Config::Ref)
      struct = struct.to_h
    elsif struct.is_a?(MU::Cloud::Azure::Id)
      struct = struct.to_s
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
    elsif struct.is_a?(String)
      # Cleanse weird encoding problems
      return struct.dup.to_s.force_encoding("ASCII-8BIT").encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
    else
      return struct
    end
  end

  @@myCloudDescriptor = nil
  if MU.myCloud
    svrclass = const_get("MU").const_get("Cloud").const_get(MU.myCloud).const_get("Server")
    found = svrclass.find(cloud_id: @@myInstanceId, region: MU.myRegion) # XXX need habitat arg for google et al
#    found = MU::MommaCat.findStray(MU.myCloud, "server", cloud_id: @@myInstanceId, dummy_ok: true, region: MU.myRegion)
    if !found.nil? and found.size == 1
      @@myCloudDescriptor = found.values.first
    end
  end


  @@myVPCObj_var = nil
  # The VPC/Network in which this Mu master resides
  def self.myVPCObj
    return nil if MU.myCloud.nil?
    return @@myVPCObj_var if @@myVPCObj_var
    cloudclass = const_get("MU").const_get("Cloud").const_get(MU.myCloud)
    @@myVPCObj_var ||= cloudclass.myVPCObj
    @@myVPCObj_var
  end

  @@myVPC_var = nil
  # The VPC/Network in which this Mu master resides
  def self.myVPC
    return nil if MU.myCloud.nil?
    return @@myVPC_var if @@myVPC_var
    my_vpc_desc = MU.myVPCObj
    @@myVPC_var ||= my_vpc_desc.cloud_id if my_vpc_desc
    @@myVPC_var
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
    hash2.keys.each { |k|
      if hash1[k].nil?
        return false
      end
    }
    if !missing_is_default
      hash1.keys.each { |k|
        if hash2[k].nil?
          return false
        end
      }
    end

    hash1.keys.each { |k|
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


  # Generate a random password which will satisfy the complexity requirements of stock Amazon Windows AMIs.
  # return [String]: A password string.
  def self.generateWindowsPassword(safe_pattern: '~!@#%^&*_-+=`|(){}[]:;<>,.?', retries: 25)
    # We have dopey complexity requirements, be stringent here.
    # I'll be nice and not condense this into one elegant-but-unreadable regular expression
    attempts = 0
    safe_metachars = Regexp.escape(safe_pattern)
    begin
      if attempts > retries
        MU.log "Failed to generate an adequate Windows password after #{attempts}", MU::ERR
        raise MuError, "Failed to generate an adequate Windows password after #{attempts}"
      end
      winpass = Password.random(14..16)
      attempts += 1
    end while winpass.nil? or !winpass.match(/^[a-z]/i) or !winpass.match(/[A-Z]/) or !winpass.match(/[a-z]/) or !winpass.match(/\d/) or !winpass.match(/[#{safe_metachars}]/) or winpass.match(/[^\w\d#{safe_metachars}]/)

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
