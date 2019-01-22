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
autoload :GraphViz, 'graphviz'
autoload :ChronicDuration, 'chronic_duration'

module MU

  # Methods and structures for parsing Mu's configuration files. See also {MU::Config::BasketofKittens}.
  class Config
    # Exception class for BoK parse or validation errors
    class ValidationError < MU::MuError
    end
    # Exception class for deploy parameter (mu-deploy -p foo=bar) errors
    class DeployParamError < MuError
    end

    # The default cloud provider for new resources. Must exist in MU.supportedClouds
    def self.defaultCloud
      begin
        MU.myCloud
      rescue NoMethodError
        "AWS"
      end
# XXX this can be more generic (loop through supportedClouds and try this)
      if MU::Cloud::Google.hosted?
        "Google"
      elsif MU::Cloud::AWS.hosted?
        "AWS"
      end
    end

    # The default grooming agent for new resources. Must exist in MU.supportedGroomers.
    def self.defaultGroomer
      "Chef"
    end

    attr_accessor :nat_routes
    attr_reader :skipinitialupdates

    attr_reader :google_images
    @@google_images = YAML.load(File.read("#{MU.myRoot}/modules/mu/defaults/google_images.yaml"))
    if File.exists?("#{MU.etcDir}/google_images.yaml")
      custom = YAML.load(File.read("#{MU.etcDir}/google_images.yaml"))
      @@google_images.merge!(custom) { |key, oldval, newval|
        if !oldval.is_a?(Hash) and !newval.nil?
          if !newval.nil?
            newval
          else
            oldval
          end
        else
          oldval.merge(newval)
        end
      }
    end
    # The list of known Google Images which we can use for a given platform
    def self.google_images
      @@google_images
    end

    attr_reader :amazon_images
    @@amazon_images = YAML.load(File.read("#{MU.myRoot}/modules/mu/defaults/amazon_images.yaml"))
    if File.exists?("#{MU.etcDir}/amazon_images.yaml")
      custom = YAML.load(File.read("#{MU.etcDir}/amazon_images.yaml"))
      @@amazon_images.merge!(custom) { |key, oldval, newval|
        if !oldval.is_a?(Hash) and !newval.nil?
          if !newval.nil?
            newval
          else
            oldval
          end
        else
          oldval.merge(newval)
        end
      }
    end
    # The list of known Amazon AMIs, by region, which we can use for a given
    # platform.
    def self.amazon_images
      @@amazon_images
    end

    @@config_path = nil
    # The path to the most recently loaded configuration file
    attr_reader :config_path
    # The path to the most recently loaded configuration file
    def self.config_path
      @@config_path
    end

    # Accessor for our Basket of Kittens schema definition
    def self.schema
      @@schema
    end

    # Deep merge a configuration hash so we can meld different cloud providers'
    # schemas together, while preserving documentation differences
    def self.schemaMerge(orig, new, cloud)
      if new.is_a?(Hash)
        new.each_pair { |k, v|
          if orig and orig.has_key?(k)
            schemaMerge(orig[k], new[k], cloud)
          elsif orig
            orig[k] = new[k]
          else
            orig = new
          end
        }
      elsif orig.is_a?(Array) and new
        orig.concat(new)
        orig.uniq!
      elsif new.is_a?(String)
        orig ||= ""
        orig += "\n#{cloud.upcase}: "+new
      else
# XXX I think this is a NOOP?
      end
    end

    # Accessor for our Basket of Kittens schema definition, with various
    # cloud-specific details merged so we can generate documentation for them.
    def self.docSchema
      docschema = Marshal.load(Marshal.dump(@@schema))
      only_children = {}
      MU::Cloud.resource_types.each_pair { |classname, attrs|
        MU::Cloud.supportedClouds.each { |cloud|
          begin
            require "mu/clouds/#{cloud.downcase}/#{attrs[:cfg_name]}"
          rescue LoadError => e
            next
          end
          res_class = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(classname)
          required, res_schema = res_class.schema(self)
          res_schema.each { |key, cfg|
            if !docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
              only_children[attrs[:cfg_plural]] ||= {}
              only_children[attrs[:cfg_plural]][key] ||= {}
              only_children[attrs[:cfg_plural]][key][cloud] = cfg
            end
          }
        }
      }

      # recursively chase down description fields in arrays and objects of our
      # schema and prepend stuff to them for documentation
      def self.prepend_descriptions(prefix, cfg)
#        cfg["description"] ||= ""
#        cfg["description"] = prefix+cfg["description"]
        cfg["prefix"] = prefix
        if cfg["type"] == "array" and cfg["items"]
          cfg["items"] = prepend_descriptions(prefix, cfg["items"])
        elsif cfg["type"] == "object" and cfg["properties"]
          cfg["properties"].each_pair { |key, subcfg|
            cfg["properties"][key] = prepend_descriptions(prefix, cfg["properties"][key])
          }
        end
        cfg
      end

      MU::Cloud.resource_types.each_pair { |classname, attrs|
        MU::Cloud.supportedClouds.each { |cloud|
          res_class = nil
          begin
            res_class = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(classname)
          rescue MU::Cloud::MuCloudResourceNotImplemented
            next
          end
          required, res_schema = res_class.schema(self)
          next if required.size == 0 and res_schema.size == 0
          res_schema.each { |key, cfg|
            cfg["description"] ||= ""
            cfg["description"] = "+"+cloud.upcase+"+: "+cfg["description"]
            if docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
              schemaMerge(docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key], cfg, cloud)
              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["description"] ||= ""
              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["description"] += "\n"+cfg["description"]
              MU.log "Munging #{cloud}-specific #{classname.to_s} schema into BasketofKittens => #{attrs[:cfg_plural]} => #{key}", MU::DEBUG, details: docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
            else
              if only_children[attrs[:cfg_plural]][key]
                prefix = only_children[attrs[:cfg_plural]][key].keys.map{ |x| x.upcase }.join(" & ")+" ONLY"
                cfg = prepend_descriptions(prefix, cfg)
              end

              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key] = cfg
            end
            docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["clouds"] = {}
            docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["clouds"][cloud] = cfg
          }

          docschema['required'].concat(required)
          docschema['required'].uniq!
        }
      }

      docschema
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
    def self.manxify(config)
      if config.is_a?(Hash)
        config.each_pair { |key, val|
          config[key] = self.manxify(val)
        }
      elsif config.is_a?(Array)
        config.each { |val|
          val = self.manxify(val)
        }
      elsif config.is_a?(MU::Config::Tail)
        return config.to_s
      end
      return config
    end

    # A wrapper for config leaves that came from ERB parameters instead of raw
    # YAML or JSON. Will behave like a string for things that expect that
    # sort of thing. Code that needs to know that this leaf was the result of
    # a parameter will be able to tell by the object class being something
    # other than a plain string, array, or hash.
    class Tail
      @value = nil
      @name = nil
      @prettyname = nil
      @description = nil
      @prefix = ""
      @suffix = ""
      @is_list_element = false
      @pseudo = false
      @runtimecode = nil
      @valid_values = []
      @index = 0
      attr_reader :description
      attr_reader :pseudo
      attr_reader :index
      attr_reader :value
      attr_reader :runtimecode
      attr_reader :valid_values
      attr_reader :is_list_element

      def initialize(name, value, prettyname = nil, cloudtype = "String", valid_values = [], description = "", is_list_element = false, prefix: "", suffix: "", pseudo: false, runtimecode: nil, index: 0)
        @name = name
        @value = value
        @valid_values = valid_values
        @pseudo = pseudo
        @index = index
        @runtimecode = runtimecode
        @cloudtype = cloudtype
        @is_list_element = is_list_element
        @description ||= 
          if !description.nil?
            description
          else
            ""
          end
        @prettyname ||= 
          if !prettyname.nil?
            prettyname
          else
            @name.capitalize.gsub(/[^a-z0-9]/i, "")
          end
        @prefix = prefix if !prefix.nil?
        @suffix = suffix if !suffix.nil?
      end
 
      # Return the parameter name of this Tail
      def getName
        @name
      end
      # Return the platform-specific cloud type of this Tail
      def getCloudType
        @cloudtype
      end
      # Return the human-friendly name of this Tail
      def getPrettyName
        @prettyname
      end
      # Walk like a String
      def to_s
        @prefix+@value+@suffix
      end
      # Quack like a String
      def to_str
        to_s
      end
      # Upcase like a String
      def upcase
        to_s.upcase
      end
      # Downcase like a String
      def downcase
        to_s.downcase
      end
      # Check for emptiness like a String
      def empty?
        to_s.empty?
      end
      # Match like a String
      def match(*args)
        to_s.match(*args)
      end
      # Check for equality like a String
      def ==(o)
        (o.class == self.class or o.class == "String") && o.to_s == to_s
      end
      # Perform global substitutions like a String
      def gsub(*args)
        to_s.gsub(*args)
      end
    end

    # Wrapper method for creating a {MU::Config::Tail} object as a reference to
    # a parameter that's valid in the loaded configuration.
    # @param param [<String>]: The name of the parameter to which this should be tied.
    # @param value [<String>]: The value of the parameter to return when asked
    # @param prettyname [<String>]: A human-friendly parameter name to be used when generating CloudFormation templates and the like
    # @param cloudtype [<String>]: A platform-specific identifier used by cloud layers to identify a parameter's type, e.g. AWS::EC2::VPC::Id
    # @param valid_values [Array<String>]: A list of acceptable String values for the given parameter.
    # @param description [<String>]: A long-form description of what the parameter does.
    # @param list_of [<String>]: Indicates that the value should be treated as a member of a list (array) by the cloud layer.
    # @param prefix [<String>]: A static String that should be prefixed to the stored value when queried
    # @param suffix [<String>]: A static String that should be appended to the stored value when queried
    # @param pseudo [<Boolean>]: This is a pseudo-parameter, automatically provided, and not available as user input.
    # @param runtimecode [<String>]: Actual code to allow the cloud layer to interpret literally in its own idiom, e.g. '"Ref" : "AWS::StackName"' for CloudFormation
    def getTail(param, value: nil, prettyname: nil, cloudtype: "String", valid_values: [], description: nil, list_of: nil, prefix: "", suffix: "", pseudo: false, runtimecode: nil)
      if value.nil?
        if @@parameters.nil? or !@@parameters.has_key?(param)
          MU.log "Parameter '#{param}' (#{param.class.name}) referenced in config but not provided (#{caller[0]})", MU::DEBUG, details: @@parameters
          return nil
#          raise DeployParamError
        else
          value = @@parameters[param]
        end
      end
      if !prettyname.nil?
        prettyname.gsub!(/[^a-z0-9]/i, "") # comply with CloudFormation restrictions
      end
      if value.is_a?(MU::Config::Tail)
        MU.log "Parameter #{param} is using a nested parameter as a value. This rarely works, depending on the target cloud. YMMV.", MU::WARN
        tail = MU::Config::Tail.new(param, value, prettyname, cloudtype, valid_values, description, prefix: prefix, suffix: suffix, pseudo: pseudo, runtimecode: runtimecode)
      elsif !list_of.nil? or (@@tails.has_key?(param) and @@tails[param].is_a?(Array))
        tail = []
        count = 0
        value.split(/\s*,\s*/).each { |subval|
          if @@tails.has_key?(param) and !@@tails[param][count].nil?
            subval = @@tails[param][count].values.first.to_s if subval.nil?
            list_of = @@tails[param][count].values.first.getName if list_of.nil?
            prettyname = @@tails[param][count].values.first.getPrettyName if prettyname.nil?
            description = @@tails[param][count].values.first.description if description.nil?
            valid_values = @@tails[param][count].values.first.valid_values if valid_values.nil? or valid_values.empty?
            cloudtype = @@tails[param][count].values.first.getCloudType if @@tails[param][count].values.first.getCloudType != "String"
          end
          prettyname = param.capitalize if prettyname.nil?
          tail << { list_of => MU::Config::Tail.new(list_of, subval, prettyname, cloudtype, valid_values, description, true, pseudo: pseudo, index: count) }
          count = count + 1
        }
      else
        if @@tails.has_key?(param)
          pseudo = @@tails[param].pseudo
          value = @@tails[param].to_s if value.nil?
          prettyname = @@tails[param].getPrettyName if prettyname.nil?
          description = @@tails[param].description if description.nil?
          valid_values = @@tails[param].valid_values if valid_values.nil? or valid_values.empty?
          cloudtype = @@tails[param].getCloudType if @@tails[param].getCloudType != "String"
        end
        tail = MU::Config::Tail.new(param, value, prettyname, cloudtype, valid_values, description, prefix: prefix, suffix: suffix, pseudo: pseudo, runtimecode: runtimecode)
      end

      if valid_values and valid_values.size > 0 and value
        if !valid_values.include?(value)
          raise DeployParamError, "Invalid parameter value '#{value}' supplied for '#{param}'"
        end
      end
      @@tails[param] = tail

      tail
    end

    # Load up our YAML or JSON and parse it through ERB, optionally substituting
    # externally-supplied parameters.
    def resolveConfig(path: @@config_path, param_pass: false)
      config = nil
      @param_pass = param_pass

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
            return "MU::Config.getTail PLACEHOLDER #{var_name} REDLOHECALP"
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

      # Figure out what kind of file we're loading. We handle includes 
      # differently if YAML is involved. These globals get used inside
      # templates. They're globals on purpose. Stop whining.
      $file_format = MU::Config.guessFormat(path)
      $yaml_refs = {}
      erb = ERB.new(File.read(path), nil, "<>")
      raw_text = erb.result(get_binding)
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
        if param_pass
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
        else
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
    attr_reader :kittencfg_semaphore

    # Load, resolve, and validate a configuration file ("Basket of Kittens").
    # @param path [String]: The path to the master config file to load. Note that this can include other configuration files via ERB.
    # @param skipinitialupdates [Boolean]: Whether to forcibly apply the *skipinitialupdates* flag to nodes created by this configuration.
    # @param params [Hash]: Optional name-value parameter pairs, which will be passed to our configuration files as ERB variables.
    # @return [Hash]: The complete validated configuration for a deployment.
    def initialize(path, skipinitialupdates = false, params: params = Hash.new, updating: nil)
      $myPublicIp = MU::Cloud::AWS.getAWSMetaData("public-ipv4")
      $myRoot = MU.myRoot
      $myRoot.freeze

      $myAZ = MU.myAZ.freeze
      $myAZ.freeze
      $myRegion = MU.curRegion.freeze
      $myRegion.freeze
      
      $myAppName = nil

      @kittens = {}
      @kittencfg_semaphore = Mutex.new
      @@config_path = path
      @admin_firewall_rules = []
      @skipinitialupdates = skipinitialupdates
      @updating = updating

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
      raise ValidationError if !ok

      # Run our input through the ERB renderer, a first pass just to extract
      # the parameters section so that we can resolve all of those to variables
      # for the rest of the config to reference.
      # XXX Figure out how to make include() add parameters for us. Right now
      # you can't specify parameters in an included file, because ERB is what's
      # doing the including, and parameters need to already be resolved so that
      # ERB can use them.
      param_cfg, raw_erb_params_only = resolveConfig(path: @@config_path, param_pass: true)
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
            end
            if param.has_key?("cloudtype")
              getTail(param['name'], value: @@parameters[param['name']], cloudtype: param["cloudtype"], valid_values: param['valid_values'], description: param['description'], prettyname: param['prettyname'], list_of: param['list_of'])
            else
              getTail(param['name'], value: @@parameters[param['name']], valid_values: param['valid_values'], description: param['description'], prettyname: param['prettyname'], list_of: param['list_of'])
            end
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
      $parameters = @@parameters
      $parameters.freeze

      tmp_cfg, raw_erb = resolveConfig(path: @@config_path)

      # Convert parameter entries that constitute whole config keys into
      # MU::Config::Tail objects.
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
      MU::Config.set_defaults(@config, MU::Config.schema)
      validate # individual resources validate when added now, necessary because the schema can change depending on what cloud they're targeting
#      XXX but now we're not validating top-level keys, argh
#pp @config
#raise "DERP"
      return @config.freeze
    end

    # Output the dependencies of this BoK stack as a directed acyclic graph.
    # Very useful for debugging.
    def visualizeDependencies
      # GraphViz won't like MU::Config::Tail, pare down to plain Strings
      config = MU::Config.manxify(Marshal.load(Marshal.dump(@config)))
      begin
        g = GraphViz.new(:G, :type => :digraph)
        # Generate a GraphViz node for each resource in this stack
        nodes = {}
        MU::Cloud.resource_types.each_pair { |classname, attrs|
          nodes[attrs[:cfg_name]] = {}
          if config.has_key?(attrs[:cfg_plural]) and config[attrs[:cfg_plural]]
            config[attrs[:cfg_plural]].each { |resource|
              nodes[attrs[:cfg_name]][resource['name']] = g.add_nodes("#{classname}: #{resource['name']}")
            }
          end
        }
        # Now add edges corresponding to the dependencies they list
        MU::Cloud.resource_types.each_pair { |classname, attrs|
          if config.has_key?(attrs[:cfg_plural]) and config[attrs[:cfg_plural]]
            config[attrs[:cfg_plural]].each { |resource|
              if resource.has_key?("dependencies")
                me = nodes[attrs[:cfg_name]][resource['name']]
                resource["dependencies"].each { |dep|
                  parent = nodes[dep['type']][dep['name']]
                  g.add_edges(me, parent)
                }
              end
            }
          end
        }
        # Spew some output?
        MU.log "Emitting dependency graph as /tmp/#{config['appname']}.jpg", MU::NOTICE
        g.output(:jpg => "/tmp/#{config['appname']}.jpg")
      rescue Exception => e
        MU.log "Failed to generate GraphViz dependency tree: #{e.inspect}. This should only matter to developers.", MU::WARN, details: e.backtrace
      end
    end

    # Take the schema we've defined and create a dummy Ruby class tree out of
    # it, basically so we can leverage Yard to document it.
    def self.emitSchemaAsRuby
      kittenpath = "#{MU.myRoot}/modules/mu/kittens.rb"
      MU.log "Converting Basket of Kittens schema to Ruby objects in #{kittenpath}"
      dummy_kitten_class = File.new(kittenpath, File::CREAT|File::TRUNC|File::RDWR, 0644)
      dummy_kitten_class.puts "### THIS FILE IS AUTOMATICALLY GENERATED, DO NOT EDIT ###"
      dummy_kitten_class.puts ""
      dummy_kitten_class.puts "module MU"
      dummy_kitten_class.puts "class Config"
      dummy_kitten_class.puts "\t# The configuration file format for Mu application stacks."
      self.printSchema(dummy_kitten_class, ["BasketofKittens"], MU::Config.docSchema)
      dummy_kitten_class.puts "end"
      dummy_kitten_class.puts "end"
      dummy_kitten_class.close

    end

    # Take an IP block and split it into a more-or-less arbitrary number of
    # subnets.
    # @param ip_block [String]: CIDR of the network to subdivide
    # @param subnets_desired [Integer]: Number of subnets we want back
    # @param max_mask [Integer]: The highest netmask we're allowed to use for a subnet (various by cloud provider)
    # @return [MU::Config::Tail]: Resulting subnet tails, or nil if an error occurred.
    def divideNetwork(ip_block, subnets_desired, max_mask = 28)
      cidr = NetAddr::IPv4Net.parse(ip_block.to_s)

      # Ugly but reliable method of landing on the right subnet size
      subnet_bits = cidr.netmask.prefix_len
      begin
        subnet_bits += 1

        if subnet_bits > max_mask
          MU.log "Can't subdivide #{cidr.to_s} into #{subnets_desired.to_s}", MU::ERR
          raise MuError, "Subnets smaller than /#{max_mask} not permitted"
        end
      end while cidr.subnet_count(subnet_bits) < subnets_desired

      if cidr.subnet_count(subnet_bits) > subnets_desired
        MU.log "Requested #{subnets_desired.to_s} subnets from #{cidr.to_s}, leaving #{(cidr.subnet_count(subnet_bits)-subnets_desired).to_s} unused /#{subnet_bits.to_s}s available", MU::NOTICE
      end

      begin
        subnets = []
        (0..subnets_desired).each { |x|
          subnets << cidr.nth_subnet(subnet_bits, x).to_s
        }
      rescue RuntimeError => e
        if e.message.match(/exceeds subnets available for allocation/)
          MU.log e.message, MU::ERR
          MU.log "I'm attempting to create #{subnets_desired} subnets (one public and one private for each Availability Zone), of #{subnet_size} addresses each, but that's too many for a /#{cidr.netmask.prefix_len} network. Either declare a larger network, or explicitly declare a list of subnets with few enough entries to fit.", MU::ERR
          return nil
        else
          raise e
        end
      end

      subnets = getTail("subnetblocks", value: subnets.join(","), cloudtype: "CommaDelimitedList", description: "IP Address ranges to be used for VPC subnets", prettyname: "SubnetIpBlocks", list_of: "ip_block").map { |tail| tail["ip_block"] }
      subnets
    end

    # See if a given resource is configured in the current stack
    # @param name [String]: The name of the resource being checked
    # @param type [String]: The type of resource being checked
    # @return [Boolean]
    def haveLitterMate?(name, type)
      @kittencfg_semaphore.synchronize {
        shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
        @kittens[cfg_plural].each { |kitten|
          return kitten if kitten['name'] == name.to_s
        }
      }
      false
    end

    # Remove a resource from the current stack
    # @param name [String]: The name of the resource being removed
    # @param type [String]: The type of resource being removed
    def removeKitten(name, type)
      @kittencfg_semaphore.synchronize {
        shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
        deletia = nil
        @kittens[cfg_plural].each { |kitten|
          if kitten['name'] == name
            deletia = kitten
            break
          end
        }
        @kittens[type].delete(deletia) if !deletia.nil?
      }
    end

    # FirewallRules can reference other FirewallRules, which means we need to do
    # an extra pass to make sure we get all intra-stack dependencies correct.
    # @param acl [Hash]: The configuration hash for the FirewallRule to check
    # @return [Hash]
    def resolveIntraStackFirewallRefs(acl)
      acl["rules"].each { |acl_include|
        if acl_include['sgs']
          acl_include['sgs'].each { |sg_ref|
            if haveLitterMate?(sg_ref, "firewall_rules")
              acl["dependencies"] ||= []
              found = false
              acl["dependencies"].each { |dep|
                if dep["type"] == "firewall_rule" and dep["name"] == sg_ref
                  dep["no_create_wait"] = true
                  found = true
                end
              }
              if !found
                acl["dependencies"] << {
                  "type" => "firewall_rule",
                  "name" => sg_ref,
                  "no_create_wait" => true
                }
              end
              siblingfw = haveLitterMate?(sg_ref, "firewall_rules")
              if !siblingfw["#MU_VALIDATED"]
# XXX raise failure somehow
                insertKitten(siblingfw, "firewall_rules")
              end
            end
          }
        end
      }
      acl
    end

    # Insert a resource into the current stack
    # @param descriptor [Hash]: The configuration description, as from a Basket of Kittens
    # @param type [String]: The type of resource being added
    # @param delay_validation [Boolean]: Whether to hold off on calling the resource's validateConfig method
    def insertKitten(descriptor, type, delay_validation = false)
      append = false

      @kittencfg_semaphore.synchronize {
        append = !@kittens[type].include?(descriptor)

        # Skip if this kitten has already been validated and appended
        if !append and descriptor["#MU_VALIDATED"]
          return true
        end
      }
      ok = true

      shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
      descriptor["#MU_CLOUDCLASS"] = classname
      inheritDefaults(descriptor, cfg_plural)
      schemaclass = Object.const_get("MU").const_get("Config").const_get(shortclass)

      if (descriptor["region"] and descriptor["region"].empty?) or
         (descriptor['cloud'] == "Google" and ["firewall_rule", "vpc"].include?(cfg_name))
        descriptor.delete("region")
      end

      # Make sure a sensible region has been targeted, if applicable
      if descriptor["region"]
        classobj = Object.const_get("MU").const_get("Cloud").const_get(descriptor["cloud"])
        valid_regions = classobj.listRegions
        if !valid_regions.include?(descriptor["region"])
          MU.log "Known regions for cloud '#{descriptor['cloud']}' do not include '#{descriptor["region"]}'", MU::ERR, details: valid_regions
          ok = false
        end
      end

      # Does this resource go in a VPC?
      if !descriptor["vpc"].nil? and !delay_validation
        descriptor['vpc']['cloud'] = descriptor['cloud']
        if descriptor['credentials']
          descriptor['vpc']['credentials'] ||= descriptor['credentials']
        end
        if descriptor['vpc']['region'].nil? and !descriptor['region'].nil? and !descriptor['region'].empty? and descriptor['vpc']['cloud'] != "Google"
          descriptor['vpc']['region'] = descriptor['region']
        end

        # If we're using a VPC in this deploy, set it as a dependency
        if !descriptor["vpc"]["vpc_name"].nil? and
           haveLitterMate?(descriptor["vpc"]["vpc_name"], "vpcs") and
           descriptor["vpc"]['deploy_id'].nil? and
           descriptor["vpc"]['vpc_id'].nil?
          descriptor["dependencies"] << {
            "type" => "vpc",
            "name" => descriptor["vpc"]["vpc_name"]
          }

          siblingvpc = haveLitterMate?(descriptor["vpc"]["vpc_name"], "vpcs")
          # things that live in subnets need their VPCs to be fully
          # resolved before we can proceed
          if ["server", "server_pool", "loadbalancer", "database", "cache_cluster", "container_cluster", "storage_pool"].include?(cfg_name)
            if !siblingvpc["#MU_VALIDATED"]
              ok = false if !insertKitten(siblingvpc, "vpcs")
            end
          end
          if !MU::Config::VPC.processReference(descriptor['vpc'],
                                  cfg_plural,
                                  shortclass.to_s+" '#{descriptor['name']}'",
                                  self,
                                  dflt_region: descriptor['region'],
                                  is_sibling: true,
                                  credentials: descriptor['credentials'],
                                  sibling_vpcs: @kittens['vpcs'])
            ok = false
          end

          # If we're using a VPC from somewhere else, make sure the flippin'
          # thing exists, and also fetch its id now so later search routines
          # don't have to work so hard.
        else
          if !MU::Config::VPC.processReference(descriptor["vpc"], cfg_plural,
                                  "#{shortclass} #{descriptor['name']}",
                                  self,
                                  credentials: descriptor['credentials'],
                                  dflt_region: descriptor['region'])
            MU.log "insertKitten was called from #{caller[0]}", MU::ERR
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

      if !haveLitterMate?(fwname, "firewall_rules") and
         (descriptor['ingress_rules'] or
         ["server", "server_pool", "database"].include?(cfg_name))
        descriptor['ingress_rules'] ||= []

        acl = {
          "name" => fwname,
          "rules" => descriptor['ingress_rules'],
          "region" => descriptor['region'],
          "credentials" => descriptor["credentials"]
        }
        acl["vpc"] = descriptor['vpc'].dup if descriptor['vpc']
        ["optional_tags", "tags", "cloud", "project"].each { |param|
          acl[param] = descriptor[param] if descriptor[param]
        }
        descriptor["add_firewall_rules"] = [] if descriptor["add_firewall_rules"].nil?
        descriptor["add_firewall_rules"] << {"rule_name" => fwname}
        acl = resolveIntraStackFirewallRefs(acl)
        ok = false if !insertKitten(acl, "firewall_rules")
      end

      # Does it declare association with any sibling LoadBalancers?
      if !descriptor["loadbalancers"].nil?
        descriptor["loadbalancers"].each { |lb|
          if !lb["concurrent_load_balancer"].nil?
            descriptor["dependencies"] << {
              "type" => "loadbalancer",
              "name" => lb["concurrent_load_balancer"]
            }
          end
        }
      end

      # Does it want to know about Storage Pools?
      if !descriptor["storage_pools"].nil?
        descriptor["storage_pools"].each { |sp|
          if sp["name"]
            descriptor["dependencies"] << {
              "type" => "storage_pool",
              "name" => sp["name"]
            }
          end
        }
      end

      # Does it declare association with first-class firewall_rules?
      if !descriptor["add_firewall_rules"].nil?
        descriptor["add_firewall_rules"].each { |acl_include|
          if haveLitterMate?(acl_include["rule_name"], "firewall_rules")
            descriptor["dependencies"] << {
              "type" => "firewall_rule",
              "name" => acl_include["rule_name"]
            }
            siblingfw = haveLitterMate?(acl_include["rule_name"], "firewall_rules")
            if !siblingfw["#MU_VALIDATED"]
              ok = false if !insertKitten(siblingfw, "firewall_rules")
            end
          elsif acl_include["rule_name"]
            MU.log shortclass.to_s+" #{descriptor['name']} depends on FirewallRule #{acl_include["rule_name"]}, but no such rule declared.", MU::ERR
            ok = false
          end
        }
      end

      # Does it declare some alarms?
      if descriptor["alarms"] && !descriptor["alarms"].empty?
        descriptor["alarms"].each { |alarm|
          alarm["name"] = "#{cfg_name}-#{descriptor["name"]}-#{alarm["name"]}"
          alarm['dimensions'] = [] if !alarm['dimensions']
          alarm["credentials"] = descriptor["credentials"]
          alarm["#TARGETCLASS"] = cfg_name
          alarm["#TARGETNAME"] = descriptor['name']
          alarm['cloud'] = descriptor['cloud']

          ok = false if !insertKitten(alarm, "alarms", true)
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

        # Merge the cloud-specific JSON schema and validate against it
        myschema = Marshal.load(Marshal.dump(MU::Config.schema["properties"][cfg_plural]["items"]))
        more_required, more_schema = Object.const_get("MU").const_get("Cloud").const_get(descriptor["cloud"]).const_get(shortclass.to_s).schema(self)

        if more_schema
          MU::Config.schemaMerge(myschema["properties"], more_schema, descriptor["cloud"])
          MU::Config.set_defaults(descriptor, myschema)
        end
        myschema["required"] ||= []
        myschema["required"].concat(more_required)
        myschema["required"].uniq!
        MU.log "Schema check on #{descriptor['cloud']} #{cfg_name} #{descriptor['name']}", MU::DEBUG, details: myschema

        plain_cfg = MU::Config.manxify(Marshal.load(Marshal.dump(descriptor)))
        plain_cfg.delete("#MU_CLOUDCLASS")
        plain_cfg.delete("#TARGETCLASS")
        plain_cfg.delete("#TARGETNAME")
        plain_cfg.delete("parent_block") if cfg_plural == "vpcs"
        begin
          JSON::Validator.validate!(myschema, plain_cfg)
        rescue JSON::Schema::ValidationError => e
          pp plain_cfg
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
          parser = Object.const_get("MU").const_get("Cloud").const_get(descriptor["cloud"]).const_get(shortclass.to_s)
          plain_descriptor = MU::Config.manxify(Marshal.load(Marshal.dump(descriptor)))
          return false if !parser.validateConfig(plain_descriptor, self)

          descriptor.merge!(plain_descriptor)
          descriptor['#MU_VALIDATED'] = true
        end

      end

      descriptor["dependencies"].uniq!

      @kittencfg_semaphore.synchronize {
        @kittens[cfg_plural] << descriptor if append
      }
      ok
    end

    allregions = []
    allregions.concat(MU::Cloud::AWS.listRegions) if MU::Cloud::AWS.myRegion
    allregions.concat(MU::Cloud::Google.listRegions) if MU::Cloud::Google.defaultProject

    # Configuration chunk for choosing a provider region
    # @return [Hash]
    def self.region_primitive
      allregions = []
      allregions.concat(MU::Cloud::AWS.listRegions) if MU::Cloud::AWS.myRegion
      allregions.concat(MU::Cloud::Google.listRegions) if MU::Cloud::Google.defaultProject
      {
        "type" => "string",
        "enum" => allregions
      }
    end

    # Configuration chunk for choosing a set of cloud credentials
    # @return [Hash]
    def self.credentials_primitive
      {
          "type" => "string",
          "description" => "Specify a non-default set of credentials to use when authenticating to cloud provider APIs, as listed in `mu.yaml` under each provider's subsection."
      }
    end

    # Configuration chunk for creating resource tags as an array of key/value
    # pairs.
    # @return [Hash]
    def self.optional_tags_primitive
      {
        "type" => "boolean",
        "description" => "Tag the resource with our optional tags (+MU-HANDLE+, +MU-MASTER-NAME+, +MU-OWNER+).",
        "default" => true
      }
    end

    # Configuration chunk for creating resource tags as an array of key/value
    # pairs.
    # @return [Hash]
    def self.tags_primitive
      {
        "type" => "array",
        "minItems" => 1,
        "items" => {
          "description" => "Tags to apply to this resource. Will apply at the cloud provider level and in Chef, where applicable.",
          "type" => "object",
          "title" => "tags",
          "required" => ["key", "value"],
          "additionalProperties" => false,
          "properties" => {
            "key" => {
              "type" => "string",
            },
            "value" => {
              "type" => "string",
            }
          }
        }
      }
    end

    # Configuration chunk for choosing a cloud provider
    # @return [Hash]
    def self.cloud_primitive
      {
        "type" => "string",
        "default" => MU::Config.defaultCloud,
        "enum" => MU::Cloud.supportedClouds
      }
    end

    # Generate configuration for the general-pursose ADMIN firewall rulesets
    # (security groups in AWS). Note that these are unique to regions and
    # individual VPCs (as well as Classic, which is just a degenerate case of
    # a VPC for our purposes.
    # @param vpc [Hash]: A VPC reference as defined in our config schema. This originates with the calling resource, so we'll peel out just what we need (a name or cloud id of a VPC).
    # @param admin_ip [String]: Optional string of an extra IP address to allow blanket access to the calling resource.
    # @param cloud [String]: The parent resource's cloud plugin identifier
    # @param region [String]: Cloud provider region, if applicable.
    # @return [Hash<String>]: A dependency description that the calling resource can then add to itself.
    def adminFirewallRuleset(vpc: nil, admin_ip: nil, region: nil, cloud: nil, credentials: nil)
      if !cloud or (cloud == "AWS" and !region)
        raise MuError, "Cannot call adminFirewallRuleset without specifying the parent's region and cloud provider"
      end
      hosts = Array.new
      hosts << "#{MU.my_public_ip}/32" if MU.my_public_ip
      hosts << "#{MU.my_private_ip}/32" if MU.my_private_ip
      hosts << "#{MU.mu_public_ip}/32" if MU.mu_public_ip
      hosts << "#{admin_ip}/32" if admin_ip
      hosts.uniq!
      name = "admin"
      name += credentials.to_s if credentials
      realvpc = nil

      if vpc
        realvpc = {}
        realvpc['vpc_id'] = vpc['vpc_id'] if !vpc['vpc_id'].nil?
        realvpc['vpc_name'] = vpc['vpc_name'] if !vpc['vpc_name'].nil?
        realvpc['deploy_id'] = vpc['deploy_id'] if !vpc['deploy_id'].nil?
        if !realvpc['vpc_id'].nil? and !realvpc['vpc_id'].empty?
          # Stupid kludge for Google cloud_ids which are sometimes URLs and
          # sometimes not. Requirements are inconsistent from scenario to
          # scenario.
          name = name + "-" + realvpc['vpc_id'].gsub(/.*\//, "")
          realvpc['vpc_id'] = getTail("vpc_id", value: realvpc['vpc_id'], prettyname: "Admin Firewall Ruleset #{name} Target VPC",  cloudtype: "AWS::EC2::VPC::Id") if realvpc["vpc_id"].is_a?(String)
        elsif !realvpc['vpc_name'].nil?
          name = name + "-" + realvpc['vpc_name']
        end
      end

      hosts.uniq!

      rules = []
      if cloud == "Google"
        rules = [
          { "ingress" => true, "proto" => "all", "hosts" => hosts },
          { "egress" => true, "proto" => "all", "hosts" => hosts }
        ]
      else
        rules = [
          { "proto" => "tcp", "port_range" => "0-65535", "hosts" => hosts },
          { "proto" => "udp", "port_range" => "0-65535", "hosts" => hosts },
          { "proto" => "icmp", "port_range" => "-1", "hosts" => hosts }
        ]
      end

      acl = {"name" => name, "rules" => rules, "vpc" => realvpc, "cloud" => cloud, "admin" => true, "credentials" => credentials }
      acl.delete("vpc") if !acl["vpc"]
      acl["region"] == region if !region.nil? and !region.empty?
      @admin_firewall_rules << acl if !@admin_firewall_rules.include?(acl)
      return {"type" => "firewall_rule", "name" => name}
    end

    private

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
      rescue JSON::ParserError => e
        begin
          YAML.load(raw.gsub(/<%.*?%>/, ""))
        rescue Psych::SyntaxError => e
          # Ok, well neither of those worked, let's assume that filenames are
          # meaningful.
          if path.match(/\.(yaml|yml)$/i)
            MU.log "Guessing that #{path} is YAML based on filename", MU::NOTICE
            return :yaml
          elsif path.match(/\.(json|jsn|js)$/i)
            MU.log "Guessing that #{path} is JSON based on filename", MU::NOTICE
            return :json
          else
            # For real? Ok, let's try the dumbest possible method.
            dashes = raw.match(/\-/)
            braces = raw.match(/[{}]/)
            if dashes.size > braces.size
              MU.log "Guessing that #{path} is YAML by... counting dashes.", MU::WARN
              return :yaml
            elsif braces.size > dashes.size
              MU.log "Guessing that #{path} is JSON by... counting braces.", MU::WARN
              return :json
            else
              raise "Unable to guess composition of #{path} by any means"
            end
          end
        end
        MU.log "Guessing that #{path} is YAML based on parser", MU::NOTICE
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
      rescue Errno::ENOENT => e
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
          parsed_as = :json
        rescue JSON::ParserError => e
          MU.log e.inspect, MU::DEBUG
          begin
            parsed_cfg = YAML.load(MU::Config.resolveYAMLAnchors(erb.result(binding)))
            parsed_as = :yaml
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
      rescue SyntaxError => e
        raise ValidationError, "ERB in #{file} threw a syntax error"
      end
    end

    # (see #include)
    def include(file)
      MU::Config.include(file, get_binding, param_pass = @param_pass)
    end

    # Namespace magic to pass to ERB's result method.
    def get_binding
      binding
    end

    def self.set_defaults(conf_chunk = config, schema_chunk = schema, depth = 0, siblings = nil)
      return if schema_chunk.nil?

      if conf_chunk != nil and schema_chunk["properties"].kind_of?(Hash) and conf_chunk.is_a?(Hash)
        if schema_chunk["properties"]["creation_style"].nil? or
            schema_chunk["properties"]["creation_style"] != "existing"
          schema_chunk["properties"].each_pair { |key, subschema|
            new_val = self.set_defaults(conf_chunk[key], subschema, depth+1, conf_chunk)
            conf_chunk[key] = new_val if new_val != nil
          }
        end
      elsif schema_chunk["type"] == "array" and conf_chunk.kind_of?(Array)
        conf_chunk.map! { |item|
          self.set_defaults(item, schema_chunk["items"], depth+1, conf_chunk)
        }
      else
        if conf_chunk.nil? and !schema_chunk["default_if"].nil? and !siblings.nil?
          schema_chunk["default_if"].each { |cond|
            if siblings[cond["key_is"]] == cond["value_is"]
              return cond["set"]
            end
          }
        end
        if conf_chunk.nil? and schema_chunk["default"] != nil
          return schema_chunk["default"]
        end
      end
      return conf_chunk
    end

    # For our resources which specify intra-stack dependencies, make sure those
    # dependencies are actually declared.
    # TODO check for loops
    def self.check_dependencies(config)
      ok = true
      config.each { |type|
        if type.instance_of?(Array)
          type.each { |container|
            if container.instance_of?(Array)
              container.each { |resource|
                if resource.kind_of?(Hash) and resource["dependencies"] != nil
                  resource["dependencies"].each { |dependency|
                    collection = dependency["type"]+"s"
                    found = false
                    names_seen = []
                    if config[collection] != nil
                      config[collection].each { |service|
                        names_seen << service["name"].to_s
                        found = true if service["name"].to_s == dependency["name"].to_s
                      }
                    end
                    if !found
                      MU.log "Missing dependency: #{type[0]}{#{resource['name']}} needs #{collection}{#{dependency['name']}}", MU::ERR, details: names_seen
                      ok = false
                    end
                  }
                end
              }
            end
          }
        end
      }
      return ok
    end


    # Verify that a server or server_pool has a valid AD config referencing
    # valid Vaults for credentials.
    def self.check_vault_refs(server)
      ok = true
      server['vault_access'] = [] if server['vault_access'].nil?
      server['groomer'] ||= "Chef"
      groomclass = MU::Groomer.loadGroomer(server['groomer'])

      begin
        if !server['active_directory'].nil?
          ["domain_admin_vault", "domain_join_vault"].each { |vault_class|
            server['vault_access'] << {
                "vault" => server['active_directory'][vault_class]['vault'],
                "item" => server['active_directory'][vault_class]['item']
            }
            item = groomclass.getSecret(
                vault: server['active_directory'][vault_class]['vault'],
                item: server['active_directory'][vault_class]['item'],
            )
            ["username_field", "password_field"].each { |field|
              if !item.has_key?(server['active_directory'][vault_class][field])
                ok = false
                MU.log "I don't see a value named #{field} in Chef Vault #{server['active_directory'][vault_class]['vault']}:#{server['active_directory'][vault_class]['item']}", MU::ERR
              end
            }
          }
        end

        if !server['windows_auth_vault'].nil?
          server['use_cloud_provider_windows_password'] = false

          server['vault_access'] << {
              "vault" => server['windows_auth_vault']['vault'],
              "item" => server['windows_auth_vault']['item']
          }
          item = groomclass.getSecret(
            vault: server['windows_auth_vault']['vault'],
            item: server['windows_auth_vault']['item']
          )
          ["password_field", "ec2config_password_field", "sshd_password_field"].each { |field|
            if !item.has_key?(server['windows_auth_vault'][field])
              MU.log "No value named #{field} in Chef Vault #{server['windows_auth_vault']['vault']}:#{server['windows_auth_vault']['item']}, will use a generated password.", MU::NOTICE
              server['windows_auth_vault'].delete(field)
            end
          }
        end
        # Check all of the non-special ones while we're at it
        server['vault_access'].each { |v|
          next if v['vault'] == "splunk" and v['item'] == "admin_user"
          item = groomclass.getSecret(vault: v['vault'], item: v['item'])
        }
      rescue MuError
        MU.log "Can't load a Chef Vault I was configured to use. Does it exist?", MU::ERR
        ok = false
      end
      return ok
    end

    
    # Given a bare hash describing a resource, insert default values which can
    # be inherited from the current live parent configuration.
    # @param kitten [Hash]: A resource descriptor
    # @param type [String]: The type of resource this is ("servers" etc)
    def inheritDefaults(kitten, type)
      kitten['cloud'] ||= MU::Config.defaultCloud
      cloudclass = Object.const_get("MU").const_get("Cloud").const_get(kitten['cloud'])
#XXX 'credentials' should probably happen here too
      schema_fields = ["region", "us_only", "scrub_mu_isms", "credentials"]
      if kitten['cloud'] == "Google"
        kitten["project"] ||= MU::Cloud::Google.defaultProject
        schema_fields << "project"
        if kitten['region'].nil? and !kitten['#MU_CLOUDCLASS'].nil? and
           ![MU::Cloud::VPC, MU::Cloud::FirewallRule].include?(kitten['#MU_CLOUDCLASS'])
          if MU::Cloud::Google.myRegion.nil?
            raise ValidationError, "Google resource declared without a region, but no default Google region declared in mu.yaml"
          end
          kitten['region'] ||= MU::Cloud::Google.myRegion
        end
      else
        if MU::Cloud::AWS.myRegion.nil?
          raise ValidationError, "AWS resource declared without a region, but no default AWS region found"
        end
        kitten['region'] ||= MU::Cloud::AWS.myRegion
      end

      kitten['us_only'] ||= @config['us_only']
      kitten['us_only'] ||= false

      kitten['scrub_mu_isms'] ||= @config['scrub_mu_isms']
      kitten['scrub_mu_isms'] ||= false

      kitten['credentials'] ||= @config['credentials']
      kitten['credentials'] ||= cloudclass.credConfig(name_only: true)

      kitten["dependencies"] ||= []

      # Make sure the schema knows about these "new" fields, so that validation
      # doesn't trip over them.
      schema_fields.each { |field|
        if @@schema["properties"][field]
          MU.log "Adding #{field} to schema for #{type} #{kitten['cloud']}", MU::DEBUG, details: @@schema["properties"][field]
          @@schema["properties"][type]["items"]["properties"][field] ||= @@schema["properties"][field]
        end
      }
    end

    def validate(config = @config)
      ok = true
      plain_cfg = MU::Config.manxify(Marshal.load(Marshal.dump(config)))

      count = 0
      @kittens ||= {}
      types = MU::Cloud.resource_types.values.map { |v| v[:cfg_plural] }

      types.each { |type|
        @kittens[type] = config[type]
        @kittens[type] ||= []
        @kittens[type].each { |k|
          inheritDefaults(k, type)
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

      @kittens["firewall_rules"].each { |acl|
        acl = resolveIntraStackFirewallRefs(acl)
      }

      # Make sure validation has been called for all on-the-fly generated
      # resources.
      types.each { |type|
        @kittens[type].each { |descriptor|
          if !descriptor["#MU_VALIDATED"]
            ok = false if !insertKitten(descriptor, type)
          end
        }
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
            shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
            @kittens[cfg_plural].each { |server|
              server["dependencies"].each { |dep|
                if dep["type"] == "database" and dep["name"] == db["name"]
                  # XXX this is AWS-specific, I think. We need to use source_tags to make this happen in Google. This logic probably needs to be dumped into the database layer.
                  ruleset["rules"] << {
                    "proto" => "tcp",
                    "port" => db["port"],
                    "sgs" => [cfg_name+server['name']]
                  }

                  ruleset["dependencies"] << {
                    "name" => cfg_name+server['name'],
                    "type" => "firewall_rule",
                    "no_create_wait" => true
                  }
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
      ok = false if !MU::Config.check_dependencies(config)

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


    # Emit our Basket of Kittesn schema in a format that YARD can comprehend
    # and turn into documentation.
    def self.printSchema(dummy_kitten_class, class_hierarchy, schema, in_array = false, required = false, prefix: nil)
      return if schema.nil?
      if schema["type"] == "object"
        printme = Array.new
        if !schema["properties"].nil?
          # order sub-elements by whether they're required, so we can use YARD's
          # grouping tags on them
          if !schema["required"].nil? and schema["required"].size > 0
            prop_list = schema["properties"].keys.sort_by { |name|
              schema["required"].include?(name) ? 0 : 1
            }
          else
            prop_list = schema["properties"].keys
          end
          req = false
          printme << "# @!group Optional parameters" if schema["required"].nil? or schema["required"].size == 0
          prop_list.each { |name|
            prop = schema["properties"][name]
            if !schema["required"].nil? and schema["required"].include?(name)
              printme << "# @!group Required parameters" if !req
              req = true
            else
              if req
                printme << "# @!endgroup"
                printme << "# @!group Optional parameters"
              end
              req = false
            end

            printme << self.printSchema(dummy_kitten_class, class_hierarchy+ [name], prop, false, req, prefix: schema["prefix"])
          }
          printme << "# @!endgroup"
        end

        tabs = 1
        class_hierarchy.each { |classname|
          if classname == class_hierarchy.last and !schema['description'].nil?
            dummy_kitten_class.puts ["\t"].cycle(tabs).to_a.join('') + "# #{schema['description']}\n"
          end
          dummy_kitten_class.puts ["\t"].cycle(tabs).to_a.join('') + "class #{classname}"
          tabs = tabs + 1
        }
        printme.each { |lines|
          if !lines.nil? and lines.is_a?(String)
            lines.lines.each { |line|
              dummy_kitten_class.puts ["\t"].cycle(tabs).to_a.join('') + line
            }
          end
        }

        class_hierarchy.each { |classname|
          tabs = tabs - 1
          dummy_kitten_class.puts ["\t"].cycle(tabs).to_a.join('') + "end"
        }

        # And now that we've dealt with our children, pass our own rendered
        # commentary back up to our caller.
        name = class_hierarchy.last
        if in_array
          type = "Array<#{class_hierarchy.join("::")}>"
        else
          type = class_hierarchy.join("::")
        end

        docstring = "\n"
        docstring = docstring + "# **REQUIRED**\n" if required
        docstring = docstring + "# **"+schema["prefix"]+"**\n" if schema["prefix"]
        docstring = docstring + "# #{schema['description'].gsub(/\n/, "\n#")}\n" if !schema['description'].nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "# @see #{class_hierarchy.join("::")}\n"
        docstring = docstring + "attr_accessor :#{name}"
        return docstring

      elsif schema["type"] == "array"
        return self.printSchema(dummy_kitten_class, class_hierarchy, schema['items'], true, required, prefix: prefix)
      else
        name = class_hierarchy.last
        if schema['type'].nil?
          MU.log "Couldn't determine schema type in #{class_hierarchy.join(" => ")}", MU::WARN, details: schema
          return nil
        end
        if in_array
          type = "Array<#{schema['type'].capitalize}>"
        else
          type = schema['type'].capitalize
        end
        docstring = "\n"

        prefixes = []
        prefixes << "# **REQUIRED**" if required and schema['default'].nil?
        prefixes << "# **"+schema["prefix"]+"**" if schema["prefix"]
        prefixes << "# **Default: `#{schema['default']}`**" if !schema['default'].nil?
        if !schema['enum'].nil? and !schema["enum"].empty?
          prefixes << "# **Must be one of: `#{schema['enum'].join(', ')}`**"
        elsif !schema['pattern'].nil?
          # XXX unquoted regex chars confuse the hell out of YARD. How do we
          # quote {}[] etc in YARD-speak?
          prefixes << "# **Must match pattern `#{schema['pattern'].gsub(/\n/, "\n#")}`**"
        end

        if prefixes.size > 0
          docstring += prefixes.join(",\n")
          if schema['description'] and schema['description'].size > 1
            docstring += " - "
          end
          docstring += "\n"
        end

        docstring = docstring + "# #{schema['description'].gsub(/\n/, "\n#")}\n" if !schema['description'].nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "attr_accessor :#{name}"

        return docstring
      end

      return nil
    end

    def self.dependencies_primitive
      {
        "type" => "array",
        "items" => {
            "type" => "object",
            "description" => "Declare other objects which this resource requires. This resource will wait until the others are available to create itself.",
            "required" => ["name", "type"],
            "additionalProperties" => false,
            "properties" => {
                "name" => {"type" => "string"},
                "type" => {
                    "type" => "string",
                    "enum" => MU::Cloud.resource_types.values.map { |v| v[:cfg_name] }
                },
                "phase" => {
                  "type" => "string",
                  "description" => "Which part of the creation process of the resource we depend on should we wait for before starting our own creation? Defaults are usually sensible, but sometimes you want, say, a Server to wait on another Server to be completely ready (through its groom phase) before starting up.",
                  "enum" => ["create", "groom"]
                },
                "no_create_wait" => {
                    "type" => "boolean",
                    "default" => false,
                    "description" => "By default, it's assumed that we want to wait on our parents' creation phase, in addition to whatever is declared in this stanza. Setting this flag will bypass waiting on our parent resource's creation, so that our create or groom phase can instead depend only on the parent's groom phase. "
                }
            }
        }
      }
    end

    CIDR_PATTERN = "^\\d+\\.\\d+\\.\\d+\\.\\d+\/[0-9]{1,2}$"
    CIDR_DESCRIPTION = "CIDR-formatted IP block, e.g. 1.2.3.4/32"
    CIDR_PRIMITIVE = {
      "type" => "string",
      "pattern" => CIDR_PATTERN,
      "description" => CIDR_DESCRIPTION
    }

    # Have a default value available for config schema elements that take an
    # email address.
    # @return [String]
    def self.notification_email 
      if MU.chef_user == "mu"
        ENV['MU_ADMIN_EMAIL']
      else
        MU.userEmail
      end
    end

    @@schema = {
      "$schema" => "http://json-schema.org/draft-04/schema#",
      "title" => "MU Application",
      "type" => "object",
      "description" => "A MU application stack, consisting of at least one resource.",
      "required" => ["admins", "appname"],
      "properties" => {
        "appname" => {
            "type" => "string",
            "description" => "A name for your application stack. Should be short, but easy to differentiate from other applications.",
        },
        "scrub_mu_isms" => {
            "type" => "boolean",
            "description" => "When 'cloud' is set to 'CloudFormation,' use this flag to strip out Mu-specific artifacts (tags, standard userdata, naming conventions, etc) to yield a clean, source-agnostic template. Setting this flag here will override declarations in individual resources."
        },
        "project" => {
          "type" => "string",
          "description" => "GOOGLE: The project into which to deploy resources",
          "default" => MU::Cloud::Google.defaultProject
        },
        "region" => MU::Config.region_primitive,
        "credentials" => MU::Config.credentials_primitive,
        "us_only" => {
            "type" => "boolean",
            "description" => "For resources which span regions, restrict to regions inside the United States",
            "default" => false
        },
        "conditions" => {
            "type" => "array",
            "items" => {
              "type" => "object",
              "required" => ["name", "cloudcode"],
              "description" => "CloudFormation-specific. Define Conditions as in http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/conditions-section-structure.html. Arguments must use the cloudCode() macro.",
              "properties" => {
                "name" => { "required" => true, "type" => "string" },
                "cloudcode" => { "required" => true, "type" => "string" },
              }
            }
        },
        "parameters" => {
            "type" => "array",
            "items" => {
                "type" => "object",
                "title" => "parameter",
                "description" => "Parameters to be substituted elsewhere in this Basket of Kittens as ERB variables (<%= varname %>)",
                "additionalProperties" => false,
                "properties" => {
                  "name" => { "required" => true, "type" => "string" },
                  "default" => { "type" => "string" },
                  "list_of" => {
                    "type" => "string",
                    "description" => "Treat the value as a comma-separated list of values with this key name, equivalent to CloudFormation's various List<> types. For example, set to 'subnet_id' to pass values as an array of subnet identifiers as the 'subnets' argument of a VPC stanza."
                  },
                  "prettyname" => {
                    "type" => "string",
                    "description" => "An alternative name to use when generating parameter fields in, for example, CloudFormation templates"
                  },
                  "description" => {"type" => "string"},
                  "cloudtype" => {
                    "type" => "string",
                    "description" => "A platform-specific string describing the type of validation to use for this parameter. E.g. when generating a CloudFormation template, set to AWS::EC2::Image::Id to validate input as an AMI identifier."
                  },
                  "required" => {
                    "type" => "boolean",
                    "default" => true
                  },
                  "valid_values" => {
                    "type" => "array",
                    "description" => "List of valid values for this parameter. Can only be a list of static strings, for now.",
                    "items" => {
                      "type" => "string"
                    }
                  }
                }
            }
        },
        # TODO availability zones (or an array thereof) 

        "admins" => {
          "type" => "array",
          "items" => {
            "type" => "object",
            "title" => "admin",
            "description" => "Administrative contacts for this application stack. Will be automatically set to invoking Mu user, if not specified.",
            "required" => ["name", "email"],
            "additionalProperties" => false,
            "properties" => {
              "name" => {"type" => "string"},
              "email" => {"type" => "string"},
              "public_key" => {
                "type" => "string",
                "description" => "An OpenSSH-style public key string. This will be installed on all instances created in this deployment."
              }
            }
          },
          "minItems" => 1,
          "uniqueItems" => true
        }
      },
      "additionalProperties" => false
    }

    failed = []

    # Load all of the config stub files at the Ruby level
    MU::Cloud.resource_types.each_pair { |type, cfg|
      begin
        require "mu/config/#{cfg[:cfg_name]}"
      rescue LoadError => e
#        raise MuError, "MU::Config implemention of #{type} missing from modules/mu/config/#{cfg[:cfg_name]}.rb"
        MU.log "MU::Config::#{type} stub class is missing", MU::ERR
        failed << type
        next
      end
    }

    MU::Cloud.resource_types.each_pair { |type, cfg|
      begin
        schemaclass = Object.const_get("MU").const_get("Config").const_get(type)
        [:schema, :validate].each { |method|
          if !schemaclass.respond_to?(method)
            MU.log "MU::Config::#{type}.#{method.to_s} doesn't seem to be implemented", MU::ERR
            failed << type
          end
        }
        next if failed.include?(type)
        @@schema["properties"][cfg[:cfg_plural]] = {
          "type" => "array",
          "items" => schemaclass.schema
        }
        @@schema["properties"][cfg[:cfg_plural]]["items"]["properties"]["dependencies"] = MU::Config.dependencies_primitive
        @@schema["properties"][cfg[:cfg_plural]]["items"]["properties"]["cloud"] = MU::Config.cloud_primitive
        @@schema["properties"][cfg[:cfg_plural]]["items"]["properties"]["credentials"] = MU::Config.credentials_primitive
        @@schema["properties"][cfg[:cfg_plural]]["items"]["title"] = type.to_s
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
