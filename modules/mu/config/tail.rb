# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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

  # Methods and structures for parsing Mu's configuration files. See also {MU::Config::BasketofKittens}.
  class Config

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
      attr_reader :is_flat_list

      def initialize(name, value, prettyname = nil, cloudtype = "String", valid_values = [], description = "", is_list_element = false, prefix: "", suffix: "", pseudo: false, runtimecode: nil, index: 0, is_flat_list: false)
        @name = name
        @bindings = {}
        @value = value
        @valid_values = valid_values
        @pseudo = pseudo
        @index = index
        @is_flat_list = is_flat_list
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

      # Lets callers access us like a {Hash}
      # @param attribute [String,Symbol]
      def [](attribute)
        if respond_to?(attribute.to_sym)
          send(attribute.to_sym)
        else
          nil
        end
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
    def getTail(param, value: nil, prettyname: nil, cloudtype: "String", valid_values: [], description: nil, list_of: nil, flat_list: false, prefix: "", suffix: "", pseudo: false, runtimecode: nil)
      param = param.gsub(/[^a-z0-9_]/i, "_")
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
      elsif !list_of.nil? or flat_list or (@@tails.has_key?(param) and @@tails[param].is_a?(Array))
        tail = []
        count = 0
        value.split(/\s*,\s*/).each { |subval|
          if @@tails.has_key?(param) and !@@tails[param][count].nil?
            src = @@tails[param][count].is_a?(Hash) ? @@tails[param][count].values.first : @@tails[param][count]
            subval ||= src.to_s
            is_flat_list = !(@@tails[param][count].is_a?(Hash))
            list_of ||= src.getName
            prettyname ||= src.getPrettyName
            description ||= src.description
            valid_values = src.valid_values if valid_values.nil? or valid_values.empty?
            cloudtype = src.getCloudType if src.getCloudType != "String"
          end
          prettyname = param.capitalize if prettyname.nil?
          if !is_flat_list and list_of
            tail << { list_of => MU::Config::Tail.new(list_of, subval, prettyname, cloudtype, valid_values, description, true, pseudo: pseudo, index: count) }
          else
            tail << MU::Config::Tail.new(param, subval, prettyname, cloudtype, valid_values, description, true, pseudo: pseudo, index: count, is_flat_list: true)
          end
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
  end
end
