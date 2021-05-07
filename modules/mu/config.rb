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

require 'rubygems'
require 'json'
require 'erb'
require 'pp'
require 'json-schema'
require 'net/http'
require 'mu/config/schema_helpers'
require 'mu/config/tail'
require 'mu/config/ref'
require 'mu/config/doc_helpers'
autoload :GraphViz, 'graphviz'
autoload :ChronicDuration, 'chronic_duration'

module MU

  # Methods and structures for parsing Mu's configuration files. See also {MU::Config::BasketofKittens}.
  class Config
    # Exception class for BoK parse or validation errors
    class ValidationError < MU::MuError
    end
    # Exception class for duplicate resource names
    class DuplicateNameError < MU::MuError
    end
    # Exception class for deploy parameter (mu-deploy -p foo=bar) errors
    class DeployParamError < MuError
    end

    attr_accessor :nat_routes
    attr_reader :skipinitialupdates

    @@config_path = nil
    # The path to the most recently loaded configuration file
    attr_reader :config_path
    # The path to the most recently loaded configuration file
    def self.config_path
      @@config_path
    end

    attr_reader :config

    @@parameters = {}
    @@user_supplied_parameters = {}
    attr_reader :parameters
    # Accessor for parameters to our Basket of Kittens
    def self.parameters
      @@parameters
    end
    @@tails = {}
    attr_reader :tails
    # Accessor for tails in our Basket of Kittens. This should be a superset of
    # user-supplied parameters. It also has machine-generated parameterized
    # behaviors.
    def self.tails
      @@tails
    end

    # Run through a config hash and return a version with all
    # {MU::Config::Tail} endpoints converted to plain strings. Useful for cloud
    # layers that don't care about the metadata in Tails.
    # @param config [Hash]: The configuration tree to convert
    # @return [Hash]: The modified configuration
    def self.manxify(config, remove_runtime_keys: false)
      if config.is_a?(Hash)
        newhash = {}
        config.each_pair { |key, val|
          next if remove_runtime_keys and (key.nil? or key.match(/^#MU_/))
          next if val.is_a?(Array) and val.empty?
          newhash[key] = self.manxify(val, remove_runtime_keys: remove_runtime_keys)
        }
        config = newhash
      elsif config.is_a?(Array)
        newarray = []
        config.each { |val|
          newarray << self.manxify(val, remove_runtime_keys: remove_runtime_keys)
        }
        config = newarray
      elsif config.is_a?(MU::Config::Tail)
        return config.to_s
      elsif config.is_a?(MU::Config::Ref)
        return self.manxify(config.to_h,  remove_runtime_keys: remove_runtime_keys)
      end
      return config
    end

    # Make a deep copy of a config hash and pare it down to only primitive
    # types, even at the leaves.
    # @param config [Hash]
    # @return [Hash]
    def self.stripConfig(config)
      MU::Config.manxify(Marshal.load(Marshal.dump(MU.structToHash(config.dup))), remove_runtime_keys: true)
    end

    # Load up our YAML or JSON and parse it through ERB, optionally substituting
    # externally-supplied parameters.
    def resolveConfig(path: @@config_path, param_pass: false, cloud: nil)
      config = nil
      @param_pass = param_pass

      if cloud
        MU.log "Exposing cloud variable to ERB with value of #{cloud}", MU::DEBUG
      end

      # Catch calls to missing variables in Basket of Kittens files when being
      # parsed by ERB, and replace with placeholders for parameters. This
      # method_missing is only defined innside {MU::Config.resolveConfig}
      def method_missing(var_name)
        if @param_pass
          "MU::Config.getTail PLACEHOLDER #{var_name} REDLOHECALP"
        else
          tail = getTail(var_name.to_s)

          if tail.is_a?(Array)
            if @param_pass
              return tail.map {|f| f.values.first.to_s }.join(",")
            else
              # Don't try to jam complex types into a string file format, just
              # sub them back in later from a placeholder.
              return "MU::Config.getTail PLACEHOLDER #{var_name} REDLOHECALP"
            end
          else
            if @param_pass
              tail.to_s
            else
              return "MU::Config.getTail PLACEHOLDER #{var_name} REDLOHECALP"
            end
          end
        end
      end

      # A check for the existence of a user-supplied parameter value that can
      # be easily run in an ERB block in a Basket of Kittens.
      def parameter?(var_name)
        @@user_supplied_parameters.has_key?(var_name)
      end

      # Instead of resolving a parameter, leave a placeholder for a
      # cloud-specific variable that will be generated at runtime. Canonical
      # use case: referring to a CloudFormation variable by reference, like
      # "AWS::StackName" or "SomeChildTemplate.OutputVariableName."
      # @param code [String]: A string consistent of code which will be understood by the Cloud layer, e.g. '"Ref" : "AWS::StackName"' (CloudFormation)
      # @param placeholder [Object]: A placeholder value to use at the config parser stage, if the default string will not pass validation.
      def cloudCode(code, placeholder = "CLOUDCODEPLACEHOLDER")
        var_name = code.gsub(/[^a-z0-9]/i, "_")
        placeholder = code if placeholder.nil?
        getTail(var_name, value: placeholder, runtimecode: code)
        "MU::Config.getTail PLACEHOLDER #{var_name} REDLOHECALP"
      end

      # Make sure our parameter values are all available in the local namespace
      # that ERB will be using, minus any that conflict with existing variables
      erb_binding = get_binding(@@tails.keys.sort)
      @@tails.each_pair { |key, tail|
        next if !tail.is_a?(MU::Config::Tail) or tail.is_list_element
        # XXX figure out what to do with lists
        begin
          erb_binding.local_variable_set(key.to_sym, tail.to_s)
        rescue NameError
          MU.log "Binding #{key} = #{tail.to_s}", MU::DEBUG
          erb_binding.local_variable_set(key.to_sym, tail.to_s)
        end
      }

      # Figure out what kind of file we're loading. We handle includes 
      # differently if YAML is involved. These globals get used inside
      # templates. They're globals on purpose. Stop whining.
      $file_format = MU::Config.guessFormat(path)
      $yaml_refs = {}
      erb = ERB.new(File.read(path), nil, "<>")
      erb.filename = path

      begin
        raw_text = erb.result(erb_binding)
      rescue NameError => e
        loc = e.backtrace[0].sub(/:(\d+):.*/, ':\1')
        msg = if e.message.match(/wrong constant name Config.getTail PLACEHOLDER ([^\s]+) REDLOHECALP/)
          "Variable '#{Regexp.last_match[1]}' referenced in config, but not defined. Missing required parameter?"
        else
          e.message
        end
        raise ValidationError, msg+" at "+loc
      end
      raw_json = nil

      # If we're working in YAML, do some magic to make includes work better.
      yaml_parse_error = nil
      if $file_format == :yaml
        begin
          raw_json = JSON.generate(YAML.load(MU::Config.resolveYAMLAnchors(raw_text)))
        rescue Psych::SyntaxError => e
          raw_json = raw_text
          yaml_parse_error = e.message
        end
      else
        raw_json = raw_text
      end

      begin
        config = JSON.parse(raw_json)
        if @@parameters['cloud']
          config['cloud'] ||= @@parameters['cloud'].to_s
        end
        if param_pass and config.is_a?(Hash)
          config.keys.each { |key|
            if key != "parameters"
              if key == "appname" and @@parameters["myAppName"].nil?
                $myAppName = config["appname"].upcase.dup
                $myAppName.freeze
                @@parameters["myAppName"] = getTail("myAppName", value: config["appname"].upcase, pseudo: true).to_s
              end
              config.delete(key)
            end
          }
        elsif config.is_a?(Hash)
          config.delete("parameters")
        end
      rescue JSON::ParserError => e
        badconf = File.new("/tmp/badconf.#{$$}", File::CREAT|File::TRUNC|File::RDWR, 0400)
        badconf.puts raw_text
        badconf.close
        if !yaml_parse_error.nil? and !path.match(/\.json/)
          MU.log "YAML Error parsing #{path}! Complete file dumped to /tmp/badconf.#{$$}", MU::ERR, details: yaml_parse_error
        else
          MU.log "JSON Error parsing #{path}! Complete file dumped to /tmp/badconf.#{$$}", MU::ERR, details: e.message
        end
        raise ValidationError
      end

      undef :method_missing
      return [MU::Config.fixDashes(config), raw_text]
    end

    attr_reader :kittens
    attr_reader :updating
    attr_reader :existing_deploy
    attr_reader :kittencfg_semaphore

    # Load, resolve, and validate a configuration file ("Basket of Kittens").
    # @param path [String]: The path to the master config file to load. Note that this can include other configuration files via ERB.
    # @param skipinitialupdates [Boolean]: Whether to forcibly apply the *skipinitialupdates* flag to nodes created by this configuration.
    # @param params [Hash]: Optional name-value parameter pairs, which will be passed to our configuration files as ERB variables.
    # @param cloud [String]: Sets a parameter named 'cloud', and insert it as the default cloud platform if not already declared
    # @return [Hash]: The complete validated configuration for a deployment.
    def initialize(path, skipinitialupdates = false, params: {}, updating: nil, default_credentials: nil, cloud: nil)
      $myPublicIp ||= MU.mu_public_ip
      $myRoot ||= MU.myRoot
      $myRoot.freeze

      $myAZ ||= MU.myAZ.freeze
      $myAZ.freeze
      $myRegion ||= MU.curRegion.freeze
      $myRegion.freeze
      
      @kittens = {}
      @kittencfg_semaphore = Mutex.new
      @@config_path = path
      @admin_firewall_rules = []
      @skipinitialupdates = skipinitialupdates
      @updating = updating
      if @updating
        @existing_deploy = MU::MommaCat.new(@updating)
      end
      @default_credentials = default_credentials

      ok = true
      params.each_pair { |name, value|
        begin
          raise DeployParamError, "Parameter must be formatted as name=value" if value.nil? or value.empty?
          raise DeployParamError, "Parameter name must be a legal Ruby variable name" if name.match(/[^A-Za-z0-9_]/)
          raise DeployParamError, "Parameter values cannot contain quotes" if value.match(/["']/)
          eval("defined? $#{name} and raise DeployParamError, 'Parameter name reserved'")
          @@parameters[name] = value
          @@user_supplied_parameters[name] = value
          eval("$#{name}='#{value}'") # support old-style $global parameter refs
          MU.log "Passing variable $#{name} into #{@@config_path} with value '#{value}'"
        rescue RuntimeError, SyntaxError => e
          ok = false
          MU.log "Error setting $#{name}='#{value}': #{e.message}", MU::ERR
        end
      }

      if cloud and !@@parameters["cloud"]
        if !MU::Cloud.availableClouds.include?(cloud)
          ok = false
          MU.log "Provider '#{cloud}' is not listed as an available cloud", MU::ERR, details: MU::Cloud.availableClouds
        else
          @@parameters["cloud"] = getTail("cloud", value: cloud, pseudo: true)
          @@user_supplied_parameters["cloud"] = cloud
          eval("$cloud='#{cloud}'") # support old-style $global parameter refs
        end
      end
      raise ValidationError if !ok

      # Run our input through the ERB renderer, a first pass just to extract
      # the parameters section so that we can resolve all of those to variables
      # for the rest of the config to reference.
      # XXX Figure out how to make include() add parameters for us. Right now
      # you can't specify parameters in an included file, because ERB is what's
      # doing the including, and parameters need to already be resolved so that
      # ERB can use them.
      param_cfg, _raw_erb_params_only = resolveConfig(path: @@config_path, param_pass: true, cloud: cloud)
      if param_cfg.has_key?("parameters")
        param_cfg["parameters"].each { |param|
          if param.has_key?("default") and param["default"].nil?
            param["default"] = ""
          end
        }
      end

      # Set up special Tail objects for our automatic pseudo-parameters
      getTail("myPublicIp", value: $myPublicIp, pseudo: true)
      getTail("myRoot", value: $myRoot, pseudo: true)
      getTail("myAZ", value: $myAZ, pseudo: true)
      getTail("myRegion", value: $myRegion, pseudo: true)

      if param_cfg.has_key?("parameters") and !param_cfg["parameters"].nil? and param_cfg["parameters"].size > 0
        param_cfg["parameters"].each { |param|
          param['valid_values'] ||= []
          if !@@parameters.has_key?(param['name'])
            if param.has_key?("default")
              @@parameters[param['name']] = param['default'].nil? ? "" : param['default']
            elsif param["required"] or !param.has_key?("required")
              MU.log "Required parameter '#{param['name']}' not supplied", MU::ERR
              ok = false
              next
            else # not required, no default
              next
            end
          end
          if param.has_key?("cloudtype")
            getTail(param['name'], value: @@parameters[param['name']], cloudtype: param["cloudtype"], valid_values: param['valid_values'], description: param['description'], prettyname: param['prettyname'], list_of: param['list_of'], flat_list: param['list'])
          else
            getTail(param['name'], value: @@parameters[param['name']], valid_values: param['valid_values'], description: param['description'], prettyname: param['prettyname'], list_of: param['list_of'], flat_list: param['list'])
          end
        }
      end

      raise ValidationError if !ok
      @@parameters.each_pair { |name, val|
        next if @@tails.has_key?(name) and @@tails[name].is_a?(MU::Config::Tail) and @@tails[name].pseudo
        # Parameters can have limited parameterization of their own
        if @@tails[name].to_s.match(/^(.*?)MU::Config.getTail PLACEHOLDER (.+?) REDLOHECALP(.*)/)
          @@tails[name] = getTail(name, value: @@tails[$2])
        end

        if respond_to?(name.to_sym)
          MU.log "Parameter name '#{name}' reserved", MU::ERR
          ok = false
          next
        end
        MU.log "Passing variable '#{name}' into #{path} with value '#{val}'"
      }
      raise DeployParamError, "One or more invalid parameters specified" if !ok
      $parameters = @@parameters.dup
      $parameters.freeze

      tmp_cfg, _raw_erb = resolveConfig(path: @@config_path, cloud: cloud)

      # Convert parameter entries that constitute whole config keys into
      # {MU::Config::Tail} objects.
      def resolveTails(tree, indent= "")
        if tree.is_a?(Hash)
          tree.each_pair { |key, val|
            tree[key] = resolveTails(val, indent+" ")
          }
        elsif tree.is_a?(Array)
          newtree = []
          tree.each { |item|
            newtree << resolveTails(item, indent+" ")
          }
          tree = newtree
        elsif tree.is_a?(String) and tree.match(/^(.*?)MU::Config.getTail PLACEHOLDER (.+?) REDLOHECALP(.*)/)
          tree = getTail($2, prefix: $1, suffix: $3)
          if tree.nil? and @@tails.has_key?($2) # XXX why necessary?
            tree = @@tails[$2]
          end
        end
        return tree
      end
      @config = resolveTails(tmp_cfg)
      @config.merge!(param_cfg)

      if !@config.has_key?('admins') or @config['admins'].size == 0
        @config['admins'] = [
          {
            "name" => MU.chef_user == "mu" ? "Mu Administrator" : MU.userName,
            "email" => MU.userEmail
          }
        ]
      end

      @config['credentials'] ||= @default_credentials

      if @config['cloud'] and !MU::Cloud.availableClouds.include?(@config['cloud'])
        if MU::Cloud.supportedClouds.include?(@config['cloud'])
          MU.log "Cloud provider #{@config['cloud']} declared, but no #{@config['cloud']} credentials available", MU::ERR
        else
          MU.log "Cloud provider #{@config['cloud']} is not supported", MU::ERR, details: MU::Cloud.supportedClouds
        end
        exit 1
      end

      MU::Cloud.resource_types.values.map { |v| v[:cfg_plural] }.each { |type|
        if @config[type]
          @config[type].each { |k|
            next if !k.is_a?(Hash)
            applyInheritedDefaults(k, type)
          }
        end
      }
      applySchemaDefaults(@config, MU::Config.schema)

      validate # individual resources validate when added now, necessary because the schema can change depending on what cloud they're targeting
#      XXX but now we're not validating top-level keys, argh
#pp @config
#raise "DERP"
      @config.freeze
    end

    # Insert a dependency into the config hash of a resource, with sensible
    # error checking and de-duplication.
    # @param resource [Hash]
    # @param name [String]
    # @param type [String]
    # @param phase [String]
    # @param no_create_wait [Boolean]
    def self.addDependency(resource, name, type, their_phase: "create", my_phase: nil)
      if ![nil, "create", "groom"].include?(their_phase)
        raise MuError, "Invalid their_phase '#{their_phase}' while adding dependency #{type} #{name} to #{resource['name']}"
      end
      resource['dependencies'] ||= []
      _shortclass, cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(type)

      resource['dependencies'].each { |dep|
        if dep['type'] == cfg_name and dep['name'].to_s == name.to_s
          dep["their_phase"] = their_phase if their_phase
          dep["my_phase"] = my_phase if my_phase
          return
        end
      }

      newdep = {
        "type" => cfg_name,
        "name"  => name.to_s
      }
      newdep["their_phase"] = their_phase if their_phase
      newdep["my_phase"] = my_phase if my_phase

      resource['dependencies'] << newdep

    end

    # See if a given resource is configured in the current stack
    # @param name [String]: The name of the resource being checked
    # @param type [String]: The type of resource being checked
    # @return [Boolean]
    def haveLitterMate?(name, type, has_multiple: false)
      @kittencfg_semaphore.synchronize {
        matches = []
        _shortclass, _cfg_name, cfg_plural, _classname = MU::Cloud.getResourceNames(type)
        if @kittens[cfg_plural]
          @kittens[cfg_plural].each { |kitten|
            if kitten['name'].to_s == name.to_s or
               kitten['virtual_name'].to_s == name.to_s or
               (has_multiple and name.nil?)
              if has_multiple
                matches << kitten
              else
                return kitten
              end
            end
          }
        end
        if has_multiple
          return matches
        else
          return false
        end
      }
    end

    # Remove a resource from the current stack
    # @param name [String]: The name of the resource being removed
    # @param type [String]: The type of resource being removed
    def removeKitten(name, type)
      @kittencfg_semaphore.synchronize {
        _shortclass, _cfg_name, cfg_plural, _classname = MU::Cloud.getResourceNames(type)
        deletia = nil
        if @kittens[cfg_plural]
          @kittens[cfg_plural].each { |kitten|
            if kitten['name'] == name
              deletia = kitten
              break
            end
          }
          @kittens[type].delete(deletia) if !deletia.nil?
        end
      }
    end

    # Insert a resource into the current stack
    # @param descriptor [Hash]: The configuration description, as from a Basket of Kittens
    # @param type [String]: The type of resource being added
    # @param delay_validation [Boolean]: Whether to hold off on calling the resource's validateConfig method
    # @param ignore_duplicates [Boolean]: Do not raise an exception if we attempt to insert a resource with a +name+ field that's already in use
    def insertKitten(descriptor, type, delay_validation = false, ignore_duplicates: false, overwrite: false)
      append = false
      start = Time.now

      shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
      MU.log "insertKitten on #{cfg_name} #{descriptor['name']} (delay_validation: #{delay_validation.to_s})", MU::DEBUG, details: caller[0]

      if overwrite
        removeKitten(descriptor['name'], type)
      end

      if !ignore_duplicates and haveLitterMate?(descriptor['name'], cfg_name)
#        raise DuplicateNameError, "A #{shortclass} named #{descriptor['name']} has already been inserted into this configuration"
      end

      @kittencfg_semaphore.synchronize {
        append = !@kittens[cfg_plural].include?(descriptor)

        # Skip if this kitten has already been validated and appended
        if !append and descriptor["#MU_VALIDATED"]
          return true
        end
      }
      ok = true

      if descriptor['cloud'] and
         !MU::Cloud.availableClouds.include?(descriptor['cloud'])
        if MU::Cloud.supportedClouds.include?(descriptor['cloud'])
          MU.log "#{cfg_name} #{descriptor['name']} is configured with cloud #{descriptor['cloud']}, but no #{descriptor['cloud']} credentials available", MU::ERR
        else
          MU.log "#{cfg_name} #{descriptor['name']}: Cloud provider #{descriptor['cloud']} is not supported", MU::ERR, details: MU::Cloud.supportedClouds
        end
        return false
      end

      descriptor["#MU_CLOUDCLASS"] = classname

      applyInheritedDefaults(descriptor, cfg_plural)

      # Meld defaults from our global schema and, if applicable, from our
      # cloud-specific schema.
      schemaclass = Object.const_get("MU").const_get("Config").const_get(shortclass)
      myschema = Marshal.load(Marshal.dump(MU::Config.schema["properties"][cfg_plural]["items"]))
      more_required, more_schema = MU::Cloud.resourceClass(descriptor["cloud"], type).schema(self)
      if more_schema
        MU::Config.schemaMerge(myschema["properties"], more_schema, descriptor["cloud"])
      end
      myschema["required"] ||= []
      if more_required
        myschema["required"].concat(more_required)
        myschema["required"].uniq!
      end

      descriptor = applySchemaDefaults(descriptor, myschema, type: shortclass)
      MU.log "Schema check on #{descriptor['cloud']} #{cfg_name} #{descriptor['name']}", MU::DEBUG, details: myschema

      if (descriptor["region"] and descriptor["region"].empty?) or
         (descriptor['cloud'] == "Google" and ["firewall_rule", "vpc"].include?(cfg_name))
        descriptor.delete("region")
      end

      # Make sure a sensible region has been targeted, if applicable
      classobj = MU::Cloud.cloudClass(descriptor["cloud"])
      if descriptor["region"]
        valid_regions = classobj.listRegions
        if !valid_regions.include?(descriptor["region"])
          MU.log "Known regions for cloud '#{descriptor['cloud']}' do not include '#{descriptor["region"]}'", MU::ERR, details: valid_regions
          ok = false
        end
      end

      if descriptor.has_key?('project')
        if descriptor['project'].nil?
          descriptor.delete('project')
        elsif haveLitterMate?(descriptor['project'], "habitats")
          MU::Config.addDependency(descriptor, descriptor['project'], "habitat")
        end
      end

      # Does this resource go in a VPC?
      if !descriptor["vpc"].nil? and !delay_validation
        # Quietly fix old vpc reference style
        if descriptor['vpc']['vpc_id']
          descriptor['vpc']['id'] ||= descriptor['vpc']['vpc_id']
          descriptor['vpc'].delete('vpc_id')
        end
        if descriptor['vpc']['vpc_name']
          descriptor['vpc']['name'] = descriptor['vpc']['vpc_name']
          descriptor['vpc'].delete('vpc_name')
        end

        descriptor['vpc']['cloud'] = descriptor['cloud']
        if descriptor['credentials']
          descriptor['vpc']['credentials'] ||= descriptor['credentials']
        end
        if descriptor['vpc']['region'].nil? and !descriptor['region'].nil? and !descriptor['region'].empty? and descriptor['vpc']['cloud'] != "Google"
          descriptor['vpc']['region'] = descriptor['region']
        end

        # If we're using a VPC in this deploy, set it as a dependency
        if !descriptor["vpc"]["name"].nil? and
           haveLitterMate?(descriptor["vpc"]["name"], "vpcs") and
           descriptor["vpc"]['deploy_id'].nil? and
           descriptor["vpc"]['id'].nil? and
           !(cfg_name == "vpc" and descriptor['name'] == descriptor['vpc']['name'])
          MU::Config.addDependency(descriptor, descriptor['vpc']['name'], "vpc")
          siblingvpc = haveLitterMate?(descriptor["vpc"]["name"], "vpcs")

          if siblingvpc and siblingvpc['bastion'] and
             ["server", "server_pool", "container_cluster"].include?(cfg_name) and
             !descriptor['bastion']
            if descriptor['name'] != siblingvpc['bastion']['name']
              MU::Config.addDependency(descriptor, siblingvpc['bastion']['name'], "server")
            end
          end

          # things that live in subnets need their VPCs to be fully
          # resolved before we can proceed
          if ["server", "server_pool", "loadbalancer", "database", "cache_cluster", "container_cluster", "storage_pool"].include?(cfg_name)
            if !siblingvpc["#MU_VALIDATED"]
              ok = false if !insertKitten(siblingvpc, "vpcs", overwrite: overwrite)
            end
          end
          if !MU::Config::VPC.processReference(descriptor['vpc'],
                                  cfg_plural,
                                  descriptor,
                                  self,
                                  dflt_region: descriptor['region'],
                                  credentials: descriptor['credentials'],
                                  dflt_project: descriptor['project'],
                                  sibling_vpcs: @kittens['vpcs'])
            ok = false
          end

          # If we're using a VPC from somewhere else, make sure the flippin'
          # thing exists, and also fetch its id now so later search routines
          # don't have to work so hard.
        else
          if !MU::Config::VPC.processReference(descriptor["vpc"],
                                  cfg_plural,
                                  descriptor,
                                  self,
                                  credentials: descriptor['credentials'],
                                  dflt_project: descriptor['project'],
                                  dflt_region: descriptor['region'])
            ok = false
          end
        end

        # if we didn't specify credentials but can inherit some from our target
        # VPC, do so
        if descriptor["vpc"]["credentials"]
          descriptor["credentials"] ||= descriptor["vpc"]["credentials"] 
        end

        # Clean crud out of auto-created VPC declarations so they don't trip
        # the schema validator when it's invoked later.
        if !["server", "server_pool", "database"].include?(cfg_name)
          descriptor['vpc'].delete("nat_ssh_user")
        end
        if descriptor['vpc']['cloud'] == "Google"
          descriptor['vpc'].delete("region")
        end
        if ["firewall_rule", "function"].include?(cfg_name)
          descriptor['vpc'].delete("subnet_pref")
        end
      end

      # Does it have generic ingress rules?
      fwname = cfg_name+descriptor['name']

      if (descriptor['ingress_rules'] or
         ["server", "server_pool", "database", "cache_cluster"].include?(cfg_name))
        descriptor['ingress_rules'] ||= []

        acl = haveLitterMate?(fwname, "firewall_rules")
        already_exists = !acl.nil?

        acl ||= {
          "name" => fwname,
          "rules" => descriptor['ingress_rules'],
          "region" => descriptor['region'],
          "credentials" => descriptor["credentials"]
        }
        if !MU::Cloud.resourceClass(descriptor["cloud"], "FirewallRule").isGlobal?
          acl['region'] = descriptor['region']
          acl['region'] ||= classobj.myRegion(acl['credentials'])
        else
          acl.delete("region")
        end
        if descriptor["vpc"]
          acl["vpc"] = descriptor['vpc'].dup
          acl["vpc"].delete("subnet_pref")
        end

        ["optional_tags", "tags", "cloud", "project"].each { |param|
          acl[param] = descriptor[param] if descriptor[param]
        }
        descriptor["add_firewall_rules"] ||= []
        descriptor["add_firewall_rules"] << {"name" => fwname, "type" => "firewall_rules" } # XXX why the duck is there a type argument required here?
        descriptor["add_firewall_rules"].uniq!

        acl = resolveIntraStackFirewallRefs(acl, delay_validation)
        ok = false if !insertKitten(acl, "firewall_rules", delay_validation, overwrite: already_exists)
      end

      # Does it declare association with any sibling LoadBalancers?
      if !descriptor["loadbalancers"].nil?
        descriptor["loadbalancers"].each { |lb|
          if !lb["concurrent_load_balancer"].nil?
            MU::Config.addDependency(descriptor, lb["concurrent_load_balancer"], "loadbalancer")
          end
        }
      end

      # Does it want to know about Storage Pools?
      if !descriptor["storage_pools"].nil?
        descriptor["storage_pools"].each { |sp|
          if sp["name"]
            MU::Config.addDependency(descriptor, sp["name"], "storage_pool")
          end
        }
      end

      # Does it declare association with first-class firewall_rules?
      if !descriptor["add_firewall_rules"].nil?
        descriptor["add_firewall_rules"].each { |acl_include|
          next if !acl_include["name"] and !acl_include["rule_name"]
          acl_include["name"] ||= acl_include["rule_name"]
          if haveLitterMate?(acl_include["name"], "firewall_rules")
            MU::Config.addDependency(descriptor, acl_include["name"], "firewall_rule", my_phase: ((cfg_name == "vpc") ? "groom" : "create"))
          elsif acl_include["name"]
            MU.log shortclass.to_s+" #{descriptor['name']} depends on FirewallRule #{acl_include["name"]}, but no such rule declared.", MU::ERR
            ok = false
          end
        }
      end

      # Does it declare some alarms?
      if descriptor["alarms"] && !descriptor["alarms"].empty?
        descriptor["alarms"].each { |alarm|
          alarm["name"] = "#{cfg_name}-#{descriptor["name"]}-#{alarm["name"]}"
          alarm['dimensions'] ||= []
          alarm["namespace"] ||= descriptor['name']
          alarm["credentials"] = descriptor["credentials"]
          alarm["#TARGETCLASS"] = cfg_name
          alarm["#TARGETNAME"] = descriptor['name']
          alarm['cloud'] = descriptor['cloud']

          ok = false if !insertKitten(alarm, "alarms", true, overwrite: overwrite)
        }
        descriptor.delete("alarms")
      end

      # Does it want to meld another deployment's resources into its metadata?
      if !descriptor["existing_deploys"].nil? and
         !descriptor["existing_deploys"].empty?
        descriptor["existing_deploys"].each { |ext_deploy|
          if ext_deploy["cloud_type"].nil?
            MU.log "You must provide a cloud_type", MU::ERR
            ok = false
          end

          if ext_deploy["cloud_id"]
            found = MU::MommaCat.findStray(
              descriptor['cloud'],
              ext_deploy["cloud_type"],
              cloud_id: ext_deploy["cloud_id"],
              region: descriptor['region'],
              dummy_ok: false
            ).first

            if found.nil?
              MU.log "Couldn't find existing #{ext_deploy["cloud_type"]} resource #{ext_deploy["cloud_id"]}", MU::ERR
              ok = false
            end
          elsif ext_deploy["mu_name"] && ext_deploy["deploy_id"]
            found = MU::MommaCat.findStray(
              descriptor['cloud'],
              ext_deploy["cloud_type"],
              deploy_id: ext_deploy["deploy_id"],
              mu_name: ext_deploy["mu_name"],
              region: descriptor['region'],
              dummy_ok: false
            ).first

            if found.nil?
              MU.log "Couldn't find existing #{ext_deploy["cloud_type"]} resource - #{ext_deploy["mu_name"]} / #{ext_deploy["deploy_id"]}", MU::ERR
              ok = false
            end
          else
            MU.log "Trying to find existing deploy, but either the cloud_id is not valid or no mu_name and deploy_id where provided", MU::ERR
            ok = false
          end
        }
      end

      if !delay_validation
        # Call the generic validation for the resource type, first and foremost
        # XXX this might have to be at the top of this insertKitten instead of
        # here
        ok = false if !schemaclass.validate(descriptor, self)

        plain_cfg = MU::Config.stripConfig(descriptor)
        plain_cfg.delete("#MU_CLOUDCLASS")
        plain_cfg.delete("#MU_VALIDATION_ATTEMPTED")
        plain_cfg.delete("#TARGETCLASS")
        plain_cfg.delete("#TARGETNAME")
        plain_cfg.delete("parent_block") if cfg_plural == "vpcs"
        begin
          JSON::Validator.validate!(myschema, plain_cfg)
        rescue JSON::Schema::ValidationError
          puts PP.pp(plain_cfg, '').bold
          # Use fully_validate to get the complete error list, save some time
          errors = JSON::Validator.fully_validate(myschema, plain_cfg)
          realerrors = []
          errors.each { |err|
            if !err.match(/The property '.+?' of type MU::Config::Tail did not match the following type:/)
              realerrors << err
            end
          }
          if realerrors.size > 0
            MU.log "Validation error on #{descriptor['cloud']} #{cfg_name} #{descriptor['name']} (insertKitten called from #{caller[1]} with delay_validation=#{delay_validation}) #{@@config_path}!\n"+realerrors.join("\n"), MU::ERR, details: descriptor
            raise ValidationError, "Validation error on #{descriptor['cloud']} #{cfg_name} #{descriptor['name']} #{@@config_path}!\n"+realerrors.join("\n")
          end
        end

        # Run the cloud class's deeper validation, unless we've already failed
        # on stuff that will cause spurious alarms further in
        if ok
          parser = MU::Cloud.resourceClass(descriptor['cloud'], type)
          original_descriptor = MU::Config.stripConfig(descriptor)
          passed = parser.validateConfig(descriptor, self)

          if !passed
            descriptor = original_descriptor
            ok = false
          end

          # Make sure we've been configured with the right credentials
          cloudbase = MU::Cloud.cloudClass(descriptor['cloud'])
          credcfg = cloudbase.credConfig(descriptor['credentials'])
          if !credcfg or credcfg.empty?
            raise ValidationError, "#{descriptor['cloud']} #{cfg_name} #{descriptor['name']} declares credential set #{descriptor['credentials']}, but no such credentials exist for that cloud provider"
          end

          descriptor['#MU_VALIDATED'] = true
        end
      end

      descriptor["dependencies"].uniq! if descriptor["dependencies"]

      @kittencfg_semaphore.synchronize {
        @kittens[cfg_plural] << descriptor if append
      }

      MU.log "insertKitten completed #{cfg_name} #{descriptor['name']} in #{sprintf("%.2fs", Time.now-start)}", MU::DEBUG

      ok
    end

    # For our resources which specify intra-stack dependencies, make sure those
    # dependencies are actually declared.
    def check_dependencies
      ok = true

      @config.each_pair { |type, values|
        next if !values.instance_of?(Array)
        _shortclass, cfg_name, _cfg_plural, _classname = MU::Cloud.getResourceNames(type, false)
        next if !cfg_name
        values.each { |resource|
          next if !resource.kind_of?(Hash) or resource["dependencies"].nil?
          addme = []
          deleteme = []

          resource["dependencies"].each { |dependency|
            dependency["their_phase"] ||= dependency["phase"]
            dependency.delete("phase")
            dependency["my_phase"] ||= dependency["no_create_wait"] ? "groom" : "create"
            dependency.delete("no_create_wait")
            # make sure the thing we depend on really exists
            sibling = haveLitterMate?(dependency['name'], dependency['type'])
            if !sibling
              MU.log "Missing dependency: #{type}{#{resource['name']}} needs #{cfg_name}{#{dependency['name']}}", MU::ERR
              ok = false
              next
            end

            # Fudge dependency declarations to quash virtual_names that we know
            # are extraneous. Note that wee can't do all virtual names here; we
            # have no way to guess which of a collection of resources is the
            # real correct one.
            if sibling['virtual_name'] == dependency['name']
              real_resources = []
              found_exact = false
              resource["dependencies"].each { |dep_again|
                if dep_again['type'] == dependency['type'] and sibling['name'] == dep_again['name']
                  dependency['name'] = sibling['name']
                  found_exact = true
                  break
                end
              }
              if !found_exact
                all_siblings = haveLitterMate?(dependency['name'], dependency['type'], has_multiple: true)
                if all_siblings.size > 0
                  all_siblings.each { |s|
                    newguy = dependency.clone
                    newguy['name'] = s['name']
                    addme << newguy
                  }
                  deleteme << dependency
                  MU.log "Expanding dependency which maps to virtual resources to all matching real resources", MU::NOTICE, details: { sibling['virtual_name'] => addme }
                  next
                end
              end
            end

            if dependency['their_phase'] == "groom"
              sibling['dependencies'].each { |sib_dep|
                next if sib_dep['type'] != cfg_name or sib_dep['their_phase'] != "groom"
                cousin = haveLitterMate?(sib_dep['name'], sib_dep['type'])
                if cousin and cousin['name'] == resource['name']
                  MU.log "Circular dependency between #{type} #{resource['name']} <=> #{dependency['type']} #{dependency['name']}", MU::ERR, details: [ resource['name'] => dependency, sibling['name'] => sib_dep ]
                  ok = false
                end
              }
            end

            # Check for a circular relationship that will lead to a deadlock
            # when creating resource. This only goes one layer deep, and does
            # not consider groom-phase deadlocks.
            if dependency['their_phase'] == "groom" or
               dependency['my_phase'] == "groom" or (
                 !MU::Cloud.resourceClass(sibling['cloud'], type).deps_wait_on_my_creation and
                 !MU::Cloud.resourceClass(resource['cloud'], type).waits_on_parent_completion
               )
              next
            end

            if sibling['dependencies']
              sibling['dependencies'].each { |sib_dep|
                next if sib_dep['type'] != cfg_name or sib_dep['my_phase'] == "groom"
                cousin = haveLitterMate?(sib_dep['name'], sib_dep['type'])
                if cousin and cousin['name'] == resource['name']
                  MU.log "Circular dependency between #{type} #{resource['name']} <=> #{dependency['type']} #{dependency['name']}", MU::ERR, details: [ resource['name'] => dependency, sibling['name'] => sib_dep ]
                  ok = false
                end
              }
            end
          }
          resource["dependencies"].reject! { |dep| deleteme.include?(dep) }
          resource["dependencies"].concat(addme)
          resource["dependencies"].uniq!

        }
      }

      ok
    end

    # Ugly text-manipulation to recursively resolve some placeholder strings
    # we put in for ERB include() directives.
    # @param lines [String]
    # @return [String]
    def self.resolveYAMLAnchors(lines)
      new_text = ""
      lines.each_line { |line|
        if line.match(/# MU::Config\.include PLACEHOLDER /)
          $yaml_refs.each_pair { |anchor, data|
            if line.sub!(/^(\s+).*?# MU::Config\.include PLACEHOLDER #{Regexp.quote(anchor)} REDLOHECALP/, "")
              indent = $1
              MU::Config.resolveYAMLAnchors(data).each_line { |addline|
                line = line + indent + addline
              }
              break
            end
          }
        end
        new_text = new_text + line
      }
      return new_text
    end

    # Given a path to a config file, try to guess whether it's YAML or JSON.
    # @param path [String]: The path to the file to check.
    def self.guessFormat(path)
      raw = File.read(path)
      # Rip out ERB references that will bollocks parser syntax, first.
      stripped = raw.gsub(/<%.*?%>,?/, "").gsub(/,[\n\s]*([\]\}])/, '\1')
      begin
        JSON.parse(stripped)
      rescue JSON::ParserError
        begin
          YAML.load(raw.gsub(/<%.*?%>/, ""))
        rescue Psych::SyntaxError
          # Ok, well neither of those worked, let's assume that filenames are
          # meaningful.
          if path.match(/\.(yaml|yml)$/i)
            MU.log "Guessing that #{path} is YAML based on filename", MU::DEBUG
            return :yaml
          elsif path.match(/\.(json|jsn|js)$/i)
            MU.log "Guessing that #{path} is JSON based on filename", MU::DEBUG
            return :json
          else
            # For real? Ok, let's try the dumbest possible method.
            dashes = raw.match(/\-/)
            braces = raw.match(/[{}]/)
            if dashes.size > braces.size
              MU.log "Guessing that #{path} is YAML by... counting dashes.", MU::NOTICE
              return :yaml
            elsif braces.size > dashes.size
              MU.log "Guessing that #{path} is JSON by... counting braces.", MU::NOTICE
              return :json
            else
              raise "Unable to guess composition of #{path} by any means"
            end
          end
        end
        MU.log "Guessing that #{path} is YAML based on parser", MU::DEBUG
        return :yaml
      end
      MU.log "Guessing that #{path} is JSON based on parser", MU::NOTICE
      return :json
    end

    # We used to be inconsistent about config keys using dashes versus
    # underscores. Now we've standardized on the latter. Be polite and
    # translate for older configs, since we're not fussed about name collisions.
    def self.fixDashes(conf)
      if conf.is_a?(Hash)
        newhash = Hash.new
        conf.each_pair { |key, val|
          if val.is_a?(Hash) or val.is_a?(Array)
            val = self.fixDashes(val)
          end
          if key.match(/-/)
            MU.log "Replacing #{key} with #{key.gsub(/-/, "_")}", MU::DEBUG
            newhash[key.gsub(/-/, "_")] = val
          else
            newhash[key] = val
          end
        }
        return newhash
      elsif conf.is_a?(Array)
        conf.map! { |val|
          if val.is_a?(Hash) or val.is_a?(Array)
            self.fixDashes(val)
          else
            val
          end
        }
      end

      return conf
    end

    @skipinitialupdates = false

    # This can be called with ERB from within a stack config file, like so:
    # <%= Config.include("drupal.json") %>
    # It will first try the literal path you pass it, and if it fails to find
    # that it will look in the directory containing the main (top-level) config.
    def self.include(file, binding = nil, param_pass = false)
      loglevel = param_pass ? MU::NOTICE : MU::DEBUG
      retries = 0
      orig_filename = file
      assume_type = nil
      if file.match(/(js|json|jsn)$/i)
        assume_type = :json
      elsif file.match(/(yaml|yml)$/i)
        assume_type = :yaml
      end
      begin
        erb = ERB.new(File.read(file), nil, "<>")
      rescue Errno::ENOENT
        retries = retries + 1
        if retries == 1
          file = File.dirname(MU::Config.config_path)+"/"+orig_filename
          retry
        elsif retries == 2
          file = File.dirname(MU.myRoot)+"/lib/demo/"+orig_filename
          retry
        else
          raise ValidationError, "Couldn't read #{file} included from #{MU::Config.config_path}"
        end
      end
      begin
        # Include as just a drop-in block of text if the filename doesn't imply
        # a particular format, or if we're melding JSON into JSON.
        if ($file_format == :json and assume_type == :json) or assume_type.nil?
          MU.log "Including #{file} as uninterpreted text", loglevel
          return erb.result(binding)
        end
        # ...otherwise, try to parse into something useful so we can meld
        # differing file formats, or work around YAML's annoying dependence
        # on indentation.
        parsed_cfg = nil
        begin
          parsed_cfg = JSON.parse(erb.result(binding))
#          parsed_as = :json
        rescue JSON::ParserError => e
          MU.log e.inspect, MU::DEBUG
          begin
            parsed_cfg = YAML.load(MU::Config.resolveYAMLAnchors(erb.result(binding)))
#            parsed_as = :yaml
          rescue Psych::SyntaxError => e
            MU.log e.inspect, MU::DEBUG
            MU.log "#{file} parsed neither as JSON nor as YAML, including as raw text", MU::WARN if @param_pass
            return erb.result(binding)
          end
        end
        if $file_format == :json
          MU.log "Including #{file} as interpreted JSON", loglevel
          return JSON.generate(parsed_cfg)
        else
          MU.log "Including #{file} as interpreted YAML", loglevel
          $yaml_refs[file] = ""+YAML.dump(parsed_cfg).sub(/^---\n/, "")
          return "# MU::Config.include PLACEHOLDER #{file} REDLOHECALP"
        end
      rescue SyntaxError
        raise ValidationError, "ERB in #{file} threw a syntax error"
      end
    end

    @@bindings = {}
    # Keep a cache of bindings we've created as sandbox contexts for ERB
    # processing, so we don't keep reloading the entire Mu library inside new
    # ones.
    def self.global_bindings
      @@bindings
    end

    private

    # (see #include)
    def include(file)
      MU::Config.include(file, get_binding(@@tails.keys.sort), @param_pass)
    end

    # Namespace magic to pass to ERB's result method.
    def get_binding(keyset)
      environment = $environment
      myPublicIp = $myPublicIp
      myRoot = $myRoot
      myAZ = $myAZ
      myRegion = $myRegion
      myAppName = $myAppName

#      return MU::Config.global_bindings[keyset] if MU::Config.global_bindings[keyset]
      MU::Config.global_bindings[keyset] = binding
      MU::Config.global_bindings[keyset]
    end

    def validate(config = @config)
      ok = true

      count = 0
      @kittens ||= {}
      types = MU::Cloud.resource_types.values.map { |v| v[:cfg_plural] }

      types.each { |type|
        @kittens[type] = config[type]
        @kittens[type] ||= []
        @kittens[type].each { |k|
          applyInheritedDefaults(k, type)
        }
        count = count + @kittens[type].size
      }


      if count == 0
        MU.log "You must declare at least one resource to create", MU::ERR
        ok = false
      end

      @nat_routes ||= {}
      types.each { |type|
        @kittens[type].each { |descriptor|
          ok = false if !insertKitten(descriptor, type)
        }
      }

      newrules = []
      @kittens["firewall_rules"].each { |acl|
        newrules << resolveIntraStackFirewallRefs(acl)
      }
      @kittens["firewall_rules"] = newrules

      # VPCs do complex things in their cloud-layer validation that other
      # resources tend to need, like subnet allocation, so hit them early.
      @kittens["vpcs"].each { |vpc|
        ok = false if !insertKitten(vpc, "vpcs")
      }

      # Make sure validation has been called for all on-the-fly generated
      # resources.
      validated_something_new = false
      begin
        validated_something_new = false
        types.each { |type|
          @kittens[type].each { |descriptor|
            if !descriptor["#MU_VALIDATION_ATTEMPTED"]
              validated_something_new = true
              ok = false if !insertKitten(descriptor, type)
              descriptor["#MU_VALIDATION_ATTEMPTED"] = true
            end
          }
        }
      end while validated_something_new

      # Do another pass of resolving intra-stack VPC peering, in case an
      # early-parsing VPC needs more details from a later-parsing one
      @kittens["vpcs"].each { |vpc|
        ok = false if !MU::Config::VPC.resolvePeers(vpc, self)
      }

      # add some default holes to allow dependent instances into databases
      @kittens["databases"].each { |db|
        if db['port'].nil?
          db['port'] = 3306 if ["mysql", "aurora"].include?(db['engine'])
          db['port'] = 5432 if ["postgres"].include?(db['engine'])
          db['port'] = 1433 if db['engine'].match(/^sqlserver\-/)
          db['port'] = 1521 if db['engine'].match(/^oracle\-/)
        end

        ruleset = haveLitterMate?("database"+db['name'], "firewall_rules")
        if ruleset
          ["server_pools", "servers"].each { |type|
            _shortclass, cfg_name, cfg_plural, _classname = MU::Cloud.getResourceNames(type)
            @kittens[cfg_plural].each { |server|
              server["dependencies"].each { |dep|
                if dep["type"] == "database" and dep["name"] == db["name"]
                  # XXX this is AWS-specific, I think. We need to use source_tags to make this happen in Google. This logic probably needs to be dumped into the database layer.
                  ruleset["rules"] << {
                    "proto" => "tcp",
                    "port" => db["port"],
                    "sgs" => [cfg_name+server['name']]
                  }
                  MU::Config.addDependency(ruleset, cfg_name+server['name'], "firewall_rule", my_phase: "groom")
                end
              }
            }
          }
        end
      }

      seen = []
      # XXX seem to be not detecting duplicate admin firewall_rules in adminFirewallRuleset
      @admin_firewall_rules.each { |acl|
        next if seen.include?(acl['name'])
        ok = false if !insertKitten(acl, "firewall_rules")
        seen << acl['name']
      }
      types.each { |type|
        config[type] = @kittens[type] if @kittens[type].size > 0
      }
      ok = false if !check_dependencies

      # TODO enforce uniqueness of resource names
      raise ValidationError if !ok

# XXX Does commenting this out make sense? Do we want to apply it to top-level
# keys and ignore resources, which validate when insertKitten is called now?
#      begin
#        JSON::Validator.validate!(MU::Config.schema, plain_cfg)
#      rescue JSON::Schema::ValidationError => e
#        # Use fully_validate to get the complete error list, save some time
#        errors = JSON::Validator.fully_validate(MU::Config.schema, plain_cfg)
#        realerrors = []
#        errors.each { |err|
#          if !err.match(/The property '.+?' of type MU::Config::Tail did not match the following type:/)
#            realerrors << err
#          end
#        }
#        if realerrors.size > 0
#          raise ValidationError, "Validation error in #{@@config_path}!\n"+realerrors.join("\n")
#        end
#      end
    end

    failed = []

    # Load all of the config stub files at the Ruby level
    MU::Cloud.resource_types.each_pair { |type, cfg|
      begin
        require "mu/config/#{cfg[:cfg_name]}"
      rescue LoadError
#        raise MuError, "MU::Config implemention of #{type} missing from modules/mu/config/#{cfg[:cfg_name]}.rb"
        MU.log "MU::Config::#{type} stub class is missing", MU::ERR
        failed << type
        next
      end
    }

    MU::Cloud.resource_types.each_pair { |type, cfg|
      begin
        schema, valid = loadResourceSchema(type)
        failed << type if !valid
        next if failed.include?(type)
        @@schema["properties"][cfg[:cfg_plural]] = {
          "type" => "array",
          "items" => schema
        }
      rescue NameError => e
        failed << type
        MU.log "Error loading #{type} schema from mu/config/#{cfg[:cfg_name]}", MU::ERR, details: "\t"+e.inspect+"\n\t"+e.backtrace[0]
      end
    }
    failed.uniq!
    if failed.size > 0
      raise MuError, "Resource type config loaders failed checks, aborting"
    end

  end #class
end #module
