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
    # Exception class for duplicate resource names
    class DuplicateNameError < MU::MuError
    end
    # Exception class for deploy parameter (mu-deploy -p foo=bar) errors
    class DeployParamError < MuError
    end

    # The default cloud provider for new resources. Must exist in MU.supportedClouds
    # return [String]
    def self.defaultCloud
      configured = {}
      MU::Cloud.supportedClouds.each { |cloud|
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
        if $MU_CFG[cloud.downcase] and !$MU_CFG[cloud.downcase].empty?
          configured[cloud] = $MU_CFG[cloud.downcase].size
          configured[cloud] += 0.5 if cloudclass.hosted? # tiebreaker
        end
      }
      if configured.size > 0
        return configured.keys.sort { |a, b|
          configured[b] <=> configured[a]
        }.first
      else
        MU::Cloud.supportedClouds.each { |cloud|
          cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
          return cloud if cloudclass.hosted?
        }
        return MU::Cloud.supportedClouds.first
      end
    end

    # The default grooming agent for new resources. Must exist in MU.supportedGroomers.
    def self.defaultGroomer
      MU.localOnly ? "Ansible" : "Chef"
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

    # Accessor for our Basket of Kittens schema definition
    def self.schema
      @@schema
    end

    # Deep merge a configuration hash so we can meld different cloud providers'
    # schemas together, while preserving documentation differences
    def self.schemaMerge(orig, new, cloud)
      if new.is_a?(Hash)
        new.each_pair { |k, v|
          if cloud and k == "description" and v.is_a?(String) and !v.match(/\b#{Regexp.quote(cloud.upcase)}\b/) and !v.empty?
            new[k] = "+"+cloud.upcase+"+: "+v
          end
          if orig and orig.has_key?(k)
          elsif orig
            orig[k] = new[k]
          else
            orig = new
          end
          schemaMerge(orig[k], new[k], cloud)
        }
      elsif orig.is_a?(Array) and new
        orig.concat(new)
        orig.uniq!
      elsif new.is_a?(String)
        orig ||= ""
        orig += "\n" if !orig.empty? 
        orig += "+#{cloud.upcase}+: "+new
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
          docschema["properties"][attrs[:cfg_plural]]["items"]["description"] ||= ""
          docschema["properties"][attrs[:cfg_plural]]["items"]["description"] += "\n#\n# `#{cloud}`: "+res_class.quality
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
            if !cfg["description"].empty?
              cfg["description"] = "\n# +"+cloud.upcase+"+: "+cfg["description"]
            end
            if docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
              schemaMerge(docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key], cfg, cloud)
              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["description"] ||= ""
              docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]["description"] += "\n"+(cfg["description"].match(/^#/) ? "" : "# ")+cfg["description"]
              MU.log "Munging #{cloud}-specific #{classname.to_s} schema into BasketofKittens => #{attrs[:cfg_plural]} => #{key}", MU::DEBUG, details: docschema["properties"][attrs[:cfg_plural]]["items"]["properties"][key]
            else
              if only_children[attrs[:cfg_plural]][key]
                prefix = only_children[attrs[:cfg_plural]][key].keys.map{ |x| x.upcase }.join(" & ")+" ONLY"
                cfg["description"].gsub!(/^\n#/, '') # so we don't leave the description blank in the "optional parameters" section
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
    def self.manxify(config, remove_runtime_keys: false)
      if config.is_a?(Hash)
        newhash = {}
        config.each_pair { |key, val|
          next if remove_runtime_keys and key.match(/^#MU_/)
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

    # A wrapper class for resources to refer to other resources, whether they
    # be a sibling object in the current deploy, an object in another deploy,
    # or a plain cloud id from outside of Mu.
    class Ref
      attr_reader :name 
      attr_reader :type 
      attr_reader :cloud 
      attr_reader :deploy_id 
      attr_reader :region 
      attr_reader :credentials 
      attr_reader :habitat
      attr_reader :mommacat
      attr_reader :tag_key 
      attr_reader :tag_value
      attr_reader :obj 

      @@refs = []
      @@ref_semaphore = Mutex.new

      # Little bit of a factory pattern... given a hash of options for a {MU::Config::Ref} objects, first see if we have an existing one that matches our more immutable attributes (+cloud+, +id+, etc). If we do, return that. If we do not, create one, add that to our inventory, and return that instead.
      # @param cfg [Hash]: 
      # @return [MU::Config::Ref]
      def self.get(cfg)
        return cfg if cfg.is_a?(MU::Config::Ref)
        checkfields = cfg.keys.map { |k| k.to_sym }
        required = [:id, :type]

        @@ref_semaphore.synchronize {
          match = nil
          @@refs.each { |ref|
            saw_mismatch = false
            saw_match = false
            needed_values = []
            checkfields.each { |field|
              next if !cfg[field]
              ext_value = ref.instance_variable_get("@#{field.to_s}".to_sym)
              if !ext_value
                needed_values << field
                next
              end
              if cfg[field] != ext_value
                saw_mismatch = true
              elsif required.include?(field) and cfg[field] == ext_value
                saw_match = true
              end
            }
            if saw_match and !saw_mismatch
              # populate empty fields we got from this request
              if needed_values.size > 0
                newref = ref.dup
                needed_values.each { |field|
                  newref.instance_variable_set("@#{field.to_s}".to_sym, cfg[field])
                  if !newref.respond_to?(field)
                    newref.singleton_class.instance_eval { attr_reader field.to_sym }
                  end
                }
                @@refs << newref
                return newref
              else
                return ref
              end
            end
          }

        }

        # if we get here, there was no match
        newref = MU::Config::Ref.new(cfg)
        @@ref_semaphore.synchronize {
          @@refs << newref
          return newref
        }
      end

      # @param cfg [Hash]: A Basket of Kittens configuration hash containing
      # lookup information for a cloud object
      def initialize(cfg)
        cfg.keys.each { |field|
          next if field == "tag"
          if !cfg[field].nil?
            self.instance_variable_set("@#{field}".to_sym, cfg[field])
          elsif !cfg[field.to_sym].nil?
            self.instance_variable_set("@#{field.to_s}".to_sym, cfg[field.to_sym])
          end
          self.singleton_class.instance_eval { attr_reader field.to_sym }
        }
        if cfg['tag'] and cfg['tag']['key'] and
           !cfg['tag']['key'].empty? and cfg['tag']['value']
          @tag_key = cfg['tag']['key']
          @tag_value = cfg['tag']['value']
        end

        if @deploy_id and !@mommacat
          @mommacat = MU::MommaCat.getLitter(@deploy_id, set_context_to_me: false)
        elsif @mommacat and !@deploy_id
          @deploy_id = @mommacat.deploy_id
        end

        kitten if @mommacat # try to populate the actual cloud object for this
      end

      # Comparison operator
      def <=>(other)
        return 1 if other.nil?
        self.to_s <=> other.to_s
      end

      # Base configuration schema for declared kittens referencing other cloud objects. This is essentially a set of filters that we're going to pass to {MU::MommaCat.findStray}.
      # @param aliases [Array<Hash>]: Key => value mappings to set backwards-compatibility aliases for attributes, such as the ubiquitous +vpc_id+ (+vpc_id+ => +id+).
      # @return [Hash]
      def self.schema(aliases = [], type: nil, parent_obj: nil, desc: nil)
        parent_obj ||= caller[1].gsub(/.*?\/([^\.\/]+)\.rb:.*/, '\1')
        desc ||= "Reference a #{type ? "'#{type}' resource" : "resource" } from this #{parent_obj ? "'#{parent_obj}'" : "" } resource"
        schema = {
          "type" => "object",
          "#MU_REFERENCE" => true,
          "minProperties" => 1,
          "description" => desc,
          "properties" => {
            "id" => {
              "type" => "string",
              "description" => "Cloud identifier of a resource we want to reference, typically used when leveraging resources not managed by MU"
            },
            "name" => {
              "type" => "string",
              "description" => "The short (internal Mu) name of a resource we're attempting to reference. Typically used when referring to a sibling resource elsewhere in the same deploy, or in another known Mu deploy in conjunction with +deploy_id+."
            },
            "type" => {
              "type" => "string",
              "description" => "The resource type we're attempting to reference.",
              "enum" => MU::Cloud.resource_types.values.map { |t| t[:cfg_plural] }
            },
            "deploy_id" => {
              "type" => "string",
              "description" => "Our target resource should be found in this Mu deploy."
            },
            "credentials" => MU::Config.credentials_primitive,
            "region" => MU::Config.region_primitive,
            "cloud" => MU::Config.cloud_primitive,
            "tag" => {
              "type" => "object",
              "description" => "If the target resource supports tagging and our resource implementations +find+ method supports it, we can attempt to locate it by tag.",
              "properties" => {
                "key" => {
                  "type" => "string",
                  "description" => "The tag or label key to search against"
                },
                "value" => {
                  "type" => "string",
                  "description" => "The tag or label value to match"
                }
              }
            }
          }
        }
        if !["folders", "habitats"].include?(type)
          schema["properties"]["habitat"] = MU::Config::Habitat.reference
        end

        if !type.nil?
          schema["required"] = ["type"]
          schema["properties"]["type"]["default"] = type
          schema["properties"]["type"]["enum"] = [type]
        end

        aliases.each { |a|
          a.each_pair { |k, v|
            if schema["properties"][v]
              schema["properties"][k] = schema["properties"][v].dup
              schema["properties"][k]["description"] = "Alias for <tt>#{v}</tt>"
            else
              MU.log "Reference schema alias #{k} wants to alias #{v}, but no such attribute exists", MU::WARN, details: caller[4]
            end
          }
        }

        schema
      end

      # Decompose into a plain-jane {MU::Config::BasketOfKittens} hash fragment,
      # of the sort that would have been used to declare this reference in the
      # first place.
      def to_h
        me = { }

        self.instance_variables.each { |var|
          next if [:@obj, :@mommacat, :@tag_key, :@tag_value].include?(var)
          val = self.instance_variable_get(var)
          next if val.nil?
          val = val.to_h if val.is_a?(MU::Config::Ref)
          me[var.to_s.sub(/^@/, '')] = val
        }
        if @tag_key and !@tag_key.empty?
          me['tag'] = {
            'key' => @tag_key,
            'value' => @tag_value
          }
        end
        me
      end

      # Getter for the #{id} instance variable that attempts to populate it if
      # it's not set.
      # @return [String,nil]
      def id
        return @id if @id
        kitten # if it's not defined, attempt to define it
        @id
      end

      # Alias for {id}
      # @return [String,nil]
      def cloud_id
        id
      end

      # Return a {MU::Cloud} object for this reference. This is only meant to be
      # called in a live deploy, which is to say that if called during initial
      # configuration parsing, results may be incorrect.
      # @param mommacat [MU::MommaCat]: A deploy object which will be searched for the referenced resource if provided, before restoring to broader, less efficient searches.
      def kitten(mommacat = @mommacat)
        return nil if !@cloud or !@type

        if @obj
          @deploy_id ||= @obj.deploy_id
          @id ||= @obj.cloud_id
          @name ||= @obj.config['name']
          return @obj
        end

        if mommacat
          @obj = mommacat.findLitterMate(type: @type, name: @name, cloud_id: @id, credentials: @credentials, debug: false)
          if @obj # initialize missing attributes, if we can
            @id ||= @obj.cloud_id
            @mommacat ||= mommacat
            @obj.intoDeploy(@mommacat) # make real sure these are set
            @deploy_id ||= mommacat.deploy_id
            if !@name
              if @obj.config and @obj.config['name']
                @name = @obj.config['name']
              elsif @obj.mu_name
if @type == "folders"
MU.log "would assign name '#{@obj.mu_name}' in ref to this folder if I were feeling aggressive", MU::WARN, details: self.to_h
end
#                @name = @obj.mu_name
              end
            end
            return @obj
          else
#            MU.log "Failed to find a live '#{@type.to_s}' object named #{@name}#{@id ? " (#{@id})" : "" }#{ @habitat ? " in habitat #{@habitat}" : "" }", MU::WARN, details: self
          end
        end

        if !@obj and !(@cloud == "Google" and @id and @type == "users" and MU::Cloud::Google::User.cannedServiceAcctName?(@id))

          begin
            hab_arg = if @habitat.nil?
              [nil]
            elsif @habitat.is_a?(MU::Config::Ref)
              [@habitat.id]
            elsif @habitat.is_a?(Hash)
              [@habitat["id"]]
            else
              [@habitat.to_s]
            end

            found = MU::MommaCat.findStray(
              @cloud,
              @type,
              name: @name,
              cloud_id: @id,
              deploy_id: @deploy_id,
              region: @region,
              habitats: hab_arg,
              credentials: @credentials,
              dummy_ok: (["habitats", "folders", "users", "groups"].include?(@type))
            )
            @obj ||= found.first if found
          rescue ThreadError => e
            # Sometimes MommaCat calls us in a potential deadlock situation;
            # don't be the cause of a fatal error if so, we don't need this
            # object that badly.
            raise e if !e.message.match(/recursive locking/)
rescue SystemExit => e
# XXX this is temporary, to cope with some debug stuff that's in findStray
# for the nonce
return
          end
        end

        if @obj
          @deploy_id ||= @obj.deploy_id
          @id ||= @obj.cloud_id
          @name ||= @obj.config['name']
        end

        @obj
      end

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
        @bindings = {}
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
        @prefix.to_s+@value.to_s+@suffix.to_s
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
      # Concatenate like a string
      def +(o)
        return to_s if o.nil?
        to_s + o.to_s
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

      raw_text = erb.result(erb_binding)
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
    # @return [Hash]: The complete validated configuration for a deployment.
    def initialize(path, skipinitialupdates = false, params: {}, updating: nil, default_credentials: nil)
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
              next
            else # not required, no default
              next
            end
          end
          if param.has_key?("cloudtype")
            getTail(param['name'], value: @@parameters[param['name']], cloudtype: param["cloudtype"], valid_values: param['valid_values'], description: param['description'], prettyname: param['prettyname'], list_of: param['list_of'])
          else
            getTail(param['name'], value: @@parameters[param['name']], valid_values: param['valid_values'], description: param['description'], prettyname: param['prettyname'], list_of: param['list_of'])
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

      tmp_cfg, raw_erb = resolveConfig(path: @@config_path)

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

      types = MU::Cloud.resource_types.values.map { |v| v[:cfg_plural] }

      MU::Cloud.resource_types.values.map { |v| v[:cfg_plural] }.each { |type|
        if @config[type]
          @config[type].each { |k|
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

    # Output the dependencies of this BoK stack as a directed acyclic graph.
    # Very useful for debugging.
    def visualizeDependencies
      # GraphViz won't like MU::Config::Tail, pare down to plain Strings
      config = MU::Config.stripConfig(@config)
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

    # Generate a documentation-friendly dummy Ruby class for our mu.yaml main
    # config.
    def self.emitConfigAsRuby
      example = %Q{---
public_address: 1.2.3.4
mu_admin_email: egtlabs@eglobaltech.com
mu_admin_name: Joe Schmoe
mommacat_port: 2260
banner: My Example Mu Master
mu_repository: git://github.com/cloudamatic/mu.git
repos:
- https://github.com/cloudamatic/mu_demo_platform
allow_invade_foreign_vpcs: true
ansible_dir:
aws:
  egtdev:
    region: us-east-1
    log_bucket_name: egt-mu-log-bucket
    default: true
    name: egtdev
  personal:
    region: us-east-2
    log_bucket_name: my-mu-log-bucket
    name: personal
  google:
    egtlabs:
      project: egt-labs-admin
      credentials_file: /opt/mu/etc/google.json
      region: us-east4
      log_bucket_name: hexabucket-761234
      default: true
}
      mu_yaml_schema = eval(%Q{
$NOOP = true
load "#{MU.myRoot}/bin/mu-configure"
$CONFIGURABLES
})
      return if mu_yaml_schema.nil? or !mu_yaml_schema.is_a?(Hash)
      muyamlpath = "#{MU.myRoot}/modules/mu/mu.yaml.rb"
      MU.log "Converting mu.yaml schema to Ruby objects in #{muyamlpath}"
      muyaml_rb = File.new(muyamlpath, File::CREAT|File::TRUNC|File::RDWR, 0644)
      muyaml_rb.puts "# Configuration schema for mu.yaml. See also {https://github.com/cloudamatic/mu/wiki/Configuration the Mu wiki}."
      muyaml_rb.puts "#"
      muyaml_rb.puts "# Example:"
      muyaml_rb.puts "#"
      muyaml_rb.puts "# <pre>"
      example.split(/\n/).each { |line|
        muyaml_rb.puts "#      "+line+"    " # markdooooown
      }
      muyaml_rb.puts "# </pre>"
      muyaml_rb.puts "module MuYAML"
      muyaml_rb.puts "\t# The configuration file format for Mu's main config file."
      self.printMuYamlSchema(muyaml_rb, [], { "subtree" => mu_yaml_schema })
      muyaml_rb.puts "end"
      muyaml_rb.close
    end

    # Take the schema we've defined and create a dummy Ruby class tree out of
    # it, basically so we can leverage Yard to document it.
    def self.emitSchemaAsRuby
      kittenpath = "#{MU.myRoot}/modules/mu/kittens.rb"
      MU.log "Converting Basket of Kittens schema to Ruby objects in #{kittenpath}"
      kitten_rb = File.new(kittenpath, File::CREAT|File::TRUNC|File::RDWR, 0644)
      kitten_rb.puts "### THIS FILE IS AUTOMATICALLY GENERATED, DO NOT EDIT ###"
      kitten_rb.puts "#"
      kitten_rb.puts "#"
      kitten_rb.puts "#"
      kitten_rb.puts "module MU"
      kitten_rb.puts "class Config"
      kitten_rb.puts "\t# The configuration file format for Mu application stacks."
      self.printSchema(kitten_rb, ["BasketofKittens"], MU::Config.docSchema)
      kitten_rb.puts "end"
      kitten_rb.puts "end"
      kitten_rb.close

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
    def haveLitterMate?(name, type, has_multiple: false)
      @kittencfg_semaphore.synchronize {
        matches = []
        shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
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
        shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
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

    # FirewallRules can reference other FirewallRules, which means we need to do
    # an extra pass to make sure we get all intra-stack dependencies correct.
    # @param acl [Hash]: The configuration hash for the FirewallRule to check
    # @return [Hash]
    def resolveIntraStackFirewallRefs(acl, delay_validation = false)
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
                insertKitten(siblingfw, "firewall_rules", delay_validation: delay_validation)
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
    # @param ignore_duplicates [Boolean]: Do not raise an exception if we attempt to insert a resource with a +name+ field that's already in use
    def insertKitten(descriptor, type, delay_validation = false, ignore_duplicates: false)
      append = false
      start = Time.now
      shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
      MU.log "insertKitten on #{cfg_name} #{descriptor['name']} (delay_validation: #{delay_validation.to_s})", MU::DEBUG, details: caller[0]

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

      descriptor["#MU_CLOUDCLASS"] = classname

      applyInheritedDefaults(descriptor, cfg_plural)

      # Meld defaults from our global schema and, if applicable, from our
      # cloud-specific schema.
      schemaclass = Object.const_get("MU").const_get("Config").const_get(shortclass)
      myschema = Marshal.load(Marshal.dump(MU::Config.schema["properties"][cfg_plural]["items"]))
      more_required, more_schema = Object.const_get("MU").const_get("Cloud").const_get(descriptor["cloud"]).const_get(shortclass.to_s).schema(self)
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
      classobj = Object.const_get("MU").const_get("Cloud").const_get(descriptor["cloud"])
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
          descriptor['dependencies'] ||= []
          descriptor['dependencies'] << {
            "type" => "habitat",
            "name" => descriptor['project']
          }
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
           descriptor["vpc"]['id'].nil?
          descriptor["dependencies"] << {
            "type" => "vpc",
            "name" => descriptor["vpc"]["name"],
          }
          siblingvpc = haveLitterMate?(descriptor["vpc"]["name"], "vpcs")

          if siblingvpc and siblingvpc['bastion'] and
             ["server", "server_pool", "container_cluster"].include?(cfg_name) and
             !descriptor['bastion']
            if descriptor['name'] != siblingvpc['bastion'].to_h['name']
              descriptor["dependencies"] << {
                "type" => "server",
                "name" => siblingvpc['bastion'].to_h['name']
              }
            end
          end

          # things that live in subnets need their VPCs to be fully
          # resolved before we can proceed
          if ["server", "server_pool", "loadbalancer", "database", "cache_cluster", "container_cluster", "storage_pool"].include?(cfg_name)
            if !siblingvpc["#MU_VALIDATED"]
              ok = false if !insertKitten(siblingvpc, "vpcs")
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

      if !haveLitterMate?(fwname, "firewall_rules") and
         (descriptor['ingress_rules'] or
         ["server", "server_pool", "database"].include?(cfg_name))
        descriptor['ingress_rules'] ||= []
        fw_classobj = Object.const_get("MU").const_get("Cloud").const_get(descriptor["cloud"]).const_get("FirewallRule")

        acl = {
          "name" => fwname,
          "rules" => descriptor['ingress_rules'],
          "region" => descriptor['region'],
          "credentials" => descriptor["credentials"]
        }
        if !fw_classobj.isGlobal?
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
        descriptor["add_firewall_rules"] = [] if descriptor["add_firewall_rules"].nil?
        descriptor["add_firewall_rules"] << {"rule_name" => fwname, "type" => "firewall_rules" } # XXX why the duck is there a type argument required here?
        acl = resolveIntraStackFirewallRefs(acl, delay_validation)
        ok = false if !insertKitten(acl, "firewall_rules", delay_validation)
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
              ok = false if !insertKitten(siblingfw, "firewall_rules", delay_validation)
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
          alarm['dimensions'] ||= []
          alarm["namespace"] ||= descriptor['name']
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

        plain_cfg = MU::Config.stripConfig(descriptor)
        plain_cfg.delete("#MU_CLOUDCLASS")
        plain_cfg.delete("#MU_VALIDATION_ATTEMPTED")
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
          original_descriptor = MU::Config.stripConfig(descriptor)
          passed = parser.validateConfig(descriptor, self)

          if !passed
            descriptor = original_descriptor
            ok = false
          end

          # Make sure we've been configured with the right credentials
          cloudbase = Object.const_get("MU").const_get("Cloud").const_get(descriptor['cloud'])
          credcfg = cloudbase.credConfig(descriptor['credentials'])
          if !credcfg or credcfg.empty?
            raise ValidationError, "#{descriptor['cloud']} #{cfg_name} #{descriptor['name']} declares credential set #{descriptor['credentials']}, but no such credentials exist for that cloud provider"
          end

          descriptor['#MU_VALIDATED'] = true
        end
      end

      descriptor["dependencies"].uniq!

      @kittencfg_semaphore.synchronize {
        @kittens[cfg_plural] << descriptor if append
      }

      ok
    end

    @@allregions = []
    MU::Cloud.availableClouds.each { |cloud|
      cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
      regions = cloudclass.listRegions()
      @@allregions.concat(regions) if regions
    }

    # Configuration chunk for choosing a provider region
    # @return [Hash]
    def self.region_primitive
      if !@@allregions or @@allregions.empty?
        @@allregions = []
        MU::Cloud.availableClouds.each { |cloud|
          cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
          return @allregions if !cloudclass.listRegions()
          @@allregions.concat(cloudclass.listRegions())
        }
      end
      {
        "type" => "string",
        "enum" => @@allregions
      }
    end

    # Configuration chunk for choosing a set of cloud credentials
    # @return [Hash]
    def self.credentials_primitive
      {
          "type" => "string",
          "description" => "Specify a non-default set of credentials to use when authenticating to cloud provider APIs, as listed in `mu.yaml` under each provider's subsection. If "
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
          "description" => "Tags to apply to this resource. Will apply at the cloud provider level and in node groomers, where applicable.",
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
#        "default" => MU::Config.defaultCloud, # applyInheritedDefaults does this better
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
    def adminFirewallRuleset(vpc: nil, admin_ip: nil, region: nil, cloud: nil, credentials: nil, rules_only: false)
      if !cloud or (cloud == "AWS" and !region)
        raise MuError, "Cannot call adminFirewallRuleset without specifying the parent's region and cloud provider"
      end
      hosts = Array.new
      hosts << "#{MU.my_public_ip}/32" if MU.my_public_ip
      hosts << "#{MU.my_private_ip}/32" if MU.my_private_ip
      hosts << "#{MU.mu_public_ip}/32" if MU.mu_public_ip
      hosts << "#{admin_ip}/32" if admin_ip
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

      resclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get("FirewallRule")

      if rules_only
        return rules
      end

      name = "admin"
      name += credentials.to_s if credentials
      realvpc = nil
      if vpc
        realvpc = {}
        ['vpc_name', 'vpc_id'].each { |p|
          if vpc[p]
            vpc[p.sub(/^vpc_/, '')] = vpc[p] 
            vpc.delete(p)
          end
        }
        ['cloud', 'id', 'name', 'deploy_id', 'habitat', 'credentials'].each { |field|
          realvpc[field] = vpc[field] if !vpc[field].nil?
        }
        if !realvpc['id'].nil? and !realvpc['id'].empty?
          # Stupid kludge for Google cloud_ids which are sometimes URLs and
          # sometimes not. Requirements are inconsistent from scenario to
          # scenario.
          name = name + "-" + realvpc['id'].gsub(/.*\//, "")
          realvpc['id'] = getTail("id", value: realvpc['id'], prettyname: "Admin Firewall Ruleset #{name} Target VPC",  cloudtype: "AWS::EC2::VPC::Id") if realvpc["id"].is_a?(String)
        elsif !realvpc['name'].nil?
          name = name + "-" + realvpc['name']
        end
      end


      acl = {"name" => name, "rules" => rules, "vpc" => realvpc, "cloud" => cloud, "admin" => true, "credentials" => credentials }
      acl.delete("vpc") if !acl["vpc"]
      if !resclass.isGlobal? and !region.nil? and !region.empty?
        acl["region"] = region
      end
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
      MU::Config.include(file, get_binding(@@tails.keys.sort), param_pass = @param_pass)
    end

    @@bindings = {}
    # Keep a cache of bindings we've created as sandbox contexts for ERB
    # processing, so we don't keep reloading the entire Mu library inside new
    # ones.
    def self.global_bindings
      @@bindings
    end

    # Namespace magic to pass to ERB's result method.
    def get_binding(keyset)
#      return MU::Config.global_bindings[keyset] if MU::Config.global_bindings[keyset]
      MU::Config.global_bindings[keyset] = binding
      MU::Config.global_bindings[keyset]
    end

    def applySchemaDefaults(conf_chunk = config, schema_chunk = schema, depth = 0, siblings = nil, type: nil)
      return if schema_chunk.nil?

      if conf_chunk != nil and schema_chunk["properties"].kind_of?(Hash) and conf_chunk.is_a?(Hash)

        if schema_chunk["properties"]["creation_style"].nil? or
            schema_chunk["properties"]["creation_style"] != "existing"
          schema_chunk["properties"].each_pair { |key, subschema|
            shortclass = if conf_chunk[key]
              shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(key)
              shortclass
            else
              nil
            end

            new_val = applySchemaDefaults(conf_chunk[key], subschema, depth+1, conf_chunk, type: shortclass).dup

            conf_chunk[key] = Marshal.load(Marshal.dump(new_val)) if !new_val.nil?
          }
        end
      elsif schema_chunk["type"] == "array" and conf_chunk.kind_of?(Array)
        conf_chunk.map! { |item|
          # If we're working on a resource type, go get implementation-specific
          # schema information so that we set those defaults correctly.
          realschema = if type and schema_chunk["items"] and schema_chunk["items"]["properties"] and item["cloud"]

            cloudclass = Object.const_get("MU").const_get("Cloud").const_get(item["cloud"]).const_get(type)
            toplevel_required, cloudschema = cloudclass.schema(self)

            newschema = schema_chunk["items"].dup
            newschema["properties"].merge!(cloudschema)
            newschema
          else
            schema_chunk["items"].dup
          end

          applySchemaDefaults(item, realschema, depth+1, conf_chunk, type: type).dup
        }
      else
        if conf_chunk.nil? and !schema_chunk["default_if"].nil? and !siblings.nil?
          schema_chunk["default_if"].each { |cond|
            if siblings[cond["key_is"]] == cond["value_is"]
              return Marshal.load(Marshal.dump(cond["set"]))
            end
          }
        end
        if conf_chunk.nil? and schema_chunk["default"] != nil
          return Marshal.load(Marshal.dump(schema_chunk["default"]))
        end
      end

      return conf_chunk
    end

    # For our resources which specify intra-stack dependencies, make sure those
    # dependencies are actually declared.
    # TODO check for loops
    def self.check_dependencies(config)
      ok = true

      config.each_pair { |type, values|
        if values.instance_of?(Array)
          values.each { |resource|
            if resource.kind_of?(Hash) and !resource["dependencies"].nil?
              append = []
              delete = []
              resource["dependencies"].each { |dependency|
                shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(dependency["type"])
                found = false
                names_seen = []
                if !config[cfg_plural].nil?
                  config[cfg_plural].each { |service|
                    names_seen << service["name"].to_s
                    found = true if service["name"].to_s == dependency["name"].to_s
                    if service["virtual_name"] 
                      names_seen << service["virtual_name"].to_s
                      if service["virtual_name"].to_s == dependency["name"].to_s
                        found = true
                        append_me = dependency.dup
                        append_me['name'] = service['name']
                        append << append_me
                        delete << dependency
                      end
                    end
                  }
                end
                if !found
                  MU.log "Missing dependency: #{type}{#{resource['name']}} needs #{cfg_name}{#{dependency['name']}}", MU::ERR, details: names_seen
                  ok = false
                end
              }
              if append.size > 0
                append.uniq!
                resource["dependencies"].concat(append)
              end
              if delete.size > 0
                delete.each { |delete_me|
                  resource["dependencies"].delete(delete_me)
                }
              end
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
      server['groomer'] ||= self.defaultGroomer
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
    # be inherited from its parent or from the root of the BoK.
    # @param kitten [Hash]: A resource descriptor
    # @param type [String]: The type of resource this is ("servers" etc)
    def applyInheritedDefaults(kitten, type)
      kitten['cloud'] ||= @config['cloud']
      kitten['cloud'] ||= MU::Config.defaultCloud

      cloudclass = Object.const_get("MU").const_get("Cloud").const_get(kitten['cloud'])
      shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
      resclass = Object.const_get("MU").const_get("Cloud").const_get(kitten['cloud']).const_get(shortclass)

      schema_fields = ["us_only", "scrub_mu_isms", "credentials", "billing_acct"]
      if !resclass.isGlobal?
        kitten['region'] ||= @config['region']
        kitten['region'] ||= cloudclass.myRegion(kitten['credentials'])
        schema_fields << "region"
      end

      kitten['credentials'] ||= @config['credentials']
      kitten['credentials'] ||= cloudclass.credConfig(name_only: true)

      kitten['us_only'] ||= @config['us_only']
      kitten['us_only'] ||= false

      kitten['scrub_mu_isms'] ||= @config['scrub_mu_isms']
      kitten['scrub_mu_isms'] ||= false

      if kitten['cloud'] == "Google"
# TODO this should be cloud-generic (handle AWS accounts, Azure subscriptions)
        if resclass.canLiveIn.include?(:Habitat)
          kitten["project"] ||= MU::Cloud::Google.defaultProject(kitten['credentials'])
          schema_fields << "project"
        end
        if kitten['region'].nil? and !kitten['#MU_CLOUDCLASS'].nil? and
           !resclass.isGlobal? and
           ![MU::Cloud::VPC, MU::Cloud::FirewallRule].include?(kitten['#MU_CLOUDCLASS'])
          if MU::Cloud::Google.myRegion((kitten['credentials'])).nil?
            raise ValidationError, "Google '#{type}' resource '#{kitten['name']}' declared without a region, but no default Google region declared in mu.yaml under #{kitten['credentials'].nil? ? "default" : kitten['credentials']} credential set" 
          end
          kitten['region'] ||= MU::Cloud::Google.myRegion
        end
      elsif kitten["cloud"] == "AWS" and !resclass.isGlobal? and !kitten['region']
        if MU::Cloud::AWS.myRegion.nil?
          raise ValidationError, "AWS resource declared without a region, but no default AWS region found"
        end
        kitten['region'] ||= MU::Cloud::AWS.myRegion
      end


      kitten['billing_acct'] ||= @config['billing_acct'] if @config['billing_acct']

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

      @kittens["firewall_rules"].each { |acl|
        acl = resolveIntraStackFirewallRefs(acl)
      }

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

    # Emit our mu.yaml schema in a format that YARD can comprehend and turn into
    # documentation.
    def self.printMuYamlSchema(muyaml_rb, class_hierarchy, schema, in_array = false, required = false, prefix: nil)
      return if schema.nil?
      if schema["subtree"]
        printme = Array.new
        # order sub-elements by whether they're required, so we can use YARD's
        # grouping tags on them
        have_required = schema["subtree"].keys.any? { |k| schema["subtree"][k]["required"] }
        prop_list = schema["subtree"].keys.sort { |a, b|
          if schema["subtree"][a]["required"] and !schema["subtree"][b]["required"]
            -1
          elsif !schema["subtree"][a]["required"] and schema["subtree"][b]["required"]
            1
          else
            a <=> b
          end
        }

        req = false
        printme << "# @!group Optional parameters" if !have_required
        prop_list.each { |name|
          prop = schema["subtree"][name]
          if prop["required"]
            printme << "# @!group Required parameters" if !req
            req = true
          else
            if req
              printme << "# @!endgroup"
              printme << "# @!group Optional parameters"
            end
            req = false
          end

          printme << self.printMuYamlSchema(muyaml_rb, class_hierarchy+ [name], prop, false, req)
        }
        printme << "# @!endgroup"

        desc = (schema['desc'] || schema['title'])

        tabs = 1
        class_hierarchy.each { |classname|
          if classname == class_hierarchy.last and desc
            muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + "# #{desc}\n"
          end
          muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + "class #{classname}"
          tabs = tabs + 1
        }
        printme.each { |lines|
          if !lines.nil? and lines.is_a?(String)
            lines.lines.each { |line|
              muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + line
            }
          end
        }

        class_hierarchy.each { |classname|
          tabs = tabs - 1
          muyaml_rb.puts ["\t"].cycle(tabs).to_a.join('') + "end"
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
#        docstring = docstring + "# **"+schema["prefix"]+"**\n" if schema["prefix"]
        docstring = docstring + "# #{desc.gsub(/\n/, "\n#")}\n" if desc
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "# @see #{class_hierarchy.join("::")}\n"
        docstring = docstring + "attr_accessor :#{name}"
        return docstring

      else
        in_array = schema["array"]
        name = class_hierarchy.last
        type = if schema['boolean']
          "Boolean"
        else
          "String"
        end
        if in_array
          type = "Array<#{type}>"
        end
        docstring = "\n"

        prefixes = []
        prefixes << "# **REQUIRED**" if schema["required"] and schema['default'].nil?
#        prefixes << "# **"+schema["prefix"]+"**" if schema["prefix"]
        prefixes << "# **Default: `#{schema['default']}`**" if !schema['default'].nil?
        if !schema['pattern'].nil?
          # XXX unquoted regex chars confuse the hell out of YARD. How do we
          # quote {}[] etc in YARD-speak?
          prefixes << "# **Must match pattern `#{schema['pattern'].to_s.gsub(/\n/, "\n#")}`**"
        end

        desc = (schema['desc'] || schema['title'])
        if prefixes.size > 0
          docstring += prefixes.join(",\n")
          if desc and desc.size > 1
            docstring += " - "
          end
          docstring += "\n"
        end

        docstring = docstring + "# #{desc.gsub(/\n/, "\n#")}\n" if !desc.nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "attr_accessor :#{name}"

        return docstring
      end

    end

    # Emit our Basket of Kittens schema in a format that YARD can comprehend
    # and turn into documentation.
    def self.printSchema(kitten_rb, class_hierarchy, schema, in_array = false, required = false, prefix: nil)
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

            printme << self.printSchema(kitten_rb, class_hierarchy+ [name], prop, false, req, prefix: schema["prefix"])
          }
          printme << "# @!endgroup"
        end

        tabs = 1
        class_hierarchy.each { |classname|
          if classname == class_hierarchy.last and !schema['description'].nil?
            kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + "# #{schema['description']}\n"
          end
          kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + "class #{classname}"
          tabs = tabs + 1
        }
        printme.each { |lines|
          if !lines.nil? and lines.is_a?(String)
            lines.lines.each { |line|
              kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + line
            }
          end
        }

        class_hierarchy.each { |classname|
          tabs = tabs - 1
          kitten_rb.puts ["\t"].cycle(tabs).to_a.join('') + "end"
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
        return self.printSchema(kitten_rb, class_hierarchy, schema['items'], true, required, prefix: prefix)
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

    # Load and validate the schema for an individual resource class, optionally
    # merging cloud-specific schema components.
    # @param type [String]: The resource type to load
    # @param cloud [String]: A specific cloud, whose implementation's schema of this resource we will merge
    # @return [Hash]
    def self.loadResourceSchema(type, cloud: nil)
      valid = true
      shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
      schemaclass = Object.const_get("MU").const_get("Config").const_get(shortclass)

      [:schema, :validate].each { |method|
        if !schemaclass.respond_to?(method)
          MU.log "MU::Config::#{type}.#{method.to_s} doesn't seem to be implemented", MU::ERR
          return [nil, false] if method == :schema
          valid = false
        end
      }

      schema = schemaclass.schema.dup

      schema["properties"]["virtual_name"] = {
        "description" => "Internal use.",
        "type" => "string"
      }
      schema["properties"]["dependencies"] = MU::Config.dependencies_primitive
      schema["properties"]["cloud"] = MU::Config.cloud_primitive
      schema["properties"]["credentials"] = MU::Config.credentials_primitive
      schema["title"] = type.to_s

      if cloud
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(shortclass)

        if cloudclass.respond_to?(:schema)
          reqd, cloudschema = cloudclass.schema
          cloudschema.each { |key, cfg|
            if schema["properties"][key]
              schemaMerge(schema["properties"][key], cfg, cloud)
            else
              schema["properties"][key] = cfg.dup
            end
          }
        else
          MU.log "MU::Cloud::#{cloud}::#{type}.#{method.to_s} doesn't seem to be implemented", MU::ERR
          valid = false
        end

      end

      return [schema, valid]
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
          "description" => "**GOOGLE ONLY**: The project into which to deploy resources"
        },
        "billing_acct" => {
          "type" => "string",
          "description" => "**GOOGLE ONLY**: Billing account ID to associate with a newly-created Google Project. If not specified, will attempt to locate a billing account associated with the default project for our credentials.",
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
