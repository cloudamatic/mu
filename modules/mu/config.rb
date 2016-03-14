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
      "AWS"
    end

    # The default grooming agent for new resources. Must exist in MU.supportedGroomers.
    def self.defaultGroomer
      "Chef"
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
    attr_reader :schema
    # Accessor for our Basket of Kittens schema definition
    def self.schema
      @@schema
    end

    attr_reader :config


    # Load a configuration file ("Basket of Kittens").
    # @param path [String]: The path to the master config file to load. Note that this can include other configuration files via ERB.
    # @param skipinitialupdates [Boolean]: Whether to forcibly apply the *skipinitialupdates* flag to nodes created by this configuration.
    # @param params [Hash]: Optional name-value parameter pairs, which will be passed to our configuration files as ERB variables.
    # @return [Hash]: The complete validated configuration for a deployment.
    def initialize(path, skipinitialupdates = false, params: params = Hash.new)
      $myPublicIp = MU::Cloud::AWS.getAWSMetaData("public-ipv4")
      $myRoot = MU.myRoot

      $myAZ = MU.myAZ
      $myRegion = MU.curRegion

      @@config_path = path
      @skipinitialupdates = skipinitialupdates

      ok = true
      params.each_pair { |name, value|
        begin
          raise DeployParamError, "Parameter must be formatted as name=value" if value.nil? or value.empty?
          raise DeployParamError, "Parameter name must be a legal Ruby variable name" if name.match(/[^A-Za-z0-9_]/)
          raise DeployParamError, "Parameter values cannot contain quotes" if value.match(/["']/)
          eval("defined? $#{name} and raise DeployParamError, 'Parameter name reserved'")
          eval("$#{name} = '#{value}'")
          MU.log "Passing variable $#{name} into #{@@config_path} with value '#{value}'"
        rescue RuntimeError, SyntaxError => e
          ok = false
          MU.log "Error setting $#{name}='#{value}': #{e.message}", MU::ERR
        end
      }
      raise ValidationError if !ok

      # Figure out what kind of fail we're loading. We handle includes 
      # differently if YAML is involved.
      $file_format = MU::Config.guessFormat(@@config_path)
      $yaml_refs = {}

      # Run our input through the ERB renderer.
      erb = ERB.new(File.read(@@config_path))
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
        @config = JSON.parse(raw_json)
      rescue JSON::ParserError => e
        badconf = File.new("/tmp/badconf.#{$$}", File::CREAT|File::TRUNC|File::RDWR, 0400)
        badconf.puts raw_text
        badconf.close
        if !yaml_parse_error.nil? and !@@config_path.match(/\.json/)
          MU.log "YAML Error parsing #{@@config_path}! Complete file dumped to /tmp/badconf.#{$$}", MU::ERR, details: yaml_parse_error
        else
          MU.log "JSON Error parsing #{@@config_path}! Complete file dumped to /tmp/badconf.#{$$}", MU::ERR, details: e.message
        end
        raise ValidationError
      end
      @config = MU::Config.fixDashes(@config)
      if !@config.has_key?('admins') or @config['admins'].size == 0
        if MU.chef_user == "mu"
          @config['admins'] = [{"name" => "Mu Administrator", "email" => ENV['MU_ADMIN_EMAIL']}]
        else
          @config['admins'] = [{"name" => MU.userName, "email" => MU.userEmail}]
        end
      end
      MU::Config.set_defaults(@config, MU::Config.schema)
      MU::Config.validate(@config)

      return @config.freeze
    end

    # Output the dependencies of this BoK stack as a directed acyclic graph.
    # Very useful for debugging.
    def visualizeDependencies
      # XXX no idea why this is necessary
      $LOAD_PATH << "/usr/local/ruby-current/lib/ruby/gems/2.1.0/gems/ruby-graphviz-1.2.2/lib/"

      g = GraphViz.new(:G, :type => :digraph)
      # Generate a GraphViz node for each resource in this stack
      nodes = {}
      MU::Cloud.resource_types.each_pair { |classname, attrs|
        nodes[attrs[:cfg_name]] = {}
        if @config.has_key?(attrs[:cfg_plural])
          @config[attrs[:cfg_plural]].each { |resource|
            nodes[attrs[:cfg_name]][resource['name']] = g.add_nodes("#{classname}: #{resource['name']}")
          }
        end
      }
      # Now add edges corresponding to the dependencies they list
      MU::Cloud.resource_types.each_pair { |classname, attrs|
        if @config.has_key?(attrs[:cfg_plural])
          @config[attrs[:cfg_plural]].each { |resource|
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
      MU.log "Emitting dependency graph as /tmp/#{@config['appname']}.jpg", MU::NOTICE
      g.output(:jpg => "/tmp/#{@config['appname']}.jpg")
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
      self.printSchema(dummy_kitten_class, ["BasketofKittens"], @@schema)
      dummy_kitten_class.puts "end"
      dummy_kitten_class.puts "end"
      dummy_kitten_class.close

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
    def self.include(file, binding = nil)
      retries = 0
      orig_filename = file
      assume_type = nil
      if file.match(/(js|json|jsn)$/i)
        assume_type = :json
      elsif file.match(/(yaml|yml)$/i)
        assume_type = :yaml
      end
      begin
        erb = ERB.new(File.read(file))
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
          MU.log "Including #{file} as uninterpreted text", MU::NOTICE
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
            MU.log "#{file} parsed neither as JSON nor as YAML, including as raw text", MU::WARN
            return erb.result(binding)
          end
        end
        if $file_format == :json
          MU.log "Including #{file} as interpreted JSON", MU::NOTICE
          return JSON.generate(parsed_cfg)
        else
          MU.log "Including #{file} as interpreted YAML", MU::NOTICE
          $yaml_refs[file] = ""+YAML.dump(parsed_cfg).sub(/^---\n/, "")
          return "# MU::Config.include PLACEHOLDER #{file} REDLOHECALP"
        end
      rescue SyntaxError => e
        raise ValidationError, "ERB in #{file} threw a syntax error"
      end
    end

    # (see #include)
    def include(file)
      MU::Config.include(file, get_binding)
    end

    # Namespace magic to pass to ERB's result method.
    def get_binding
      binding
    end

    def self.schema
      @@schema
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
                    if config[collection] != nil
                      config[collection].each { |server|
                        found = true if server["name"] == dependency["name"]
                      }
                    end
                    if !found
                      MU.log "Missing dependency: #{type[0]}{#{resource['name']}} needs #{collection}{#{dependency['name']}}", MU::ERR
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


    # Pick apart an external VPC reference, validate it, and resolve it and its
    # various subnets and NAT hosts to live resources.
    def self.processVPCReference(vpc_block, parent_name, is_sibling: false, sibling_vpcs: [], dflt_region: MU.curRegion)
      puts vpc_block.ancestors if !vpc_block.is_a?(Hash)
      if !vpc_block.is_a?(Hash) and vpc_block.kind_of?(MU::Cloud::VPC)
        return true
      end
      ok = true

      if vpc_block['region'].nil? or
          vpc_block['region'] = dflt_region
      end

      # First, dig up the enclosing VPC 
      tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?
      if !is_sibling
        begin

          found = MU::MommaCat.findStray(
              vpc_block['cloud'],
              "vpc",
              deploy_id: vpc_block["deploy_id"],
              cloud_id: vpc_block["vpc_id"],
              name: vpc_block["vpc_name"],
              tag_key: tag_key,
              tag_value: tag_value,
              region: vpc_block["region"],
              dummy_ok: true
          )
          ext_vpc = found.first if found.size == 1
        rescue Exception => e
          raise MuError, e.inspect, e.backtrace
        ensure
          if !ext_vpc
            MU.log "Couldn't resolve VPC reference to a unique live VPC in #{parent_name}", MU::ERR, details: vpc_block
            return false
          elsif !vpc_block["vpc_id"]
            MU.log "Resolved VPC to #{ext_vpc.cloud_id} in #{parent_name}", MU::DEBUG, details: vpc_block
            vpc_block["vpc_id"] = ext_vpc.cloud_id
          end
        end

        # Other !is_sibling logic for external vpcs
        # Next, the NAT host, if there is one
        if (vpc_block['nat_host_name'] or vpc_block['nat_host_ip'] or vpc_block['nat_host_tag'])
          if !vpc_block['nat_host_tag'].nil?
            nat_tag_key, nat_tag_value = vpc_block['nat_host_tag'].split(/=/, 2)
          else
            nat_tag_key, nat_tag_value = [tag_key, tag_value]
          end

          ext_nat = ext_vpc.findBastion(
              nat_name: vpc_block["nat_host_name"],
              nat_cloud_id: vpc_block["nat_host_id"],
              nat_tag_key: nat_tag_key,
              nat_tag_value: nat_tag_value,
              nat_ip: vpc_block['nat_host_ip']
          )
					ssh_keydir = Etc.getpwnam(MU.mu_user).dir+"/.ssh"
					if !vpc_block['nat_ssh_key'].nil? and !File.exists?(ssh_keydir+"/"+vpc_block['nat_ssh_key'])
              MU.log "Couldn't find alternate NAT key #{ssh_keydir}/#{vpc_block['nat_ssh_key']} in #{parent_name}", MU::ERR, details: vpc_block
              return false
					end

          if !ext_nat
            if vpc_block["nat_host_id"].nil? and nat_tag_key.nil? and vpc_block['nat_host_ip'].nil? and vpc_block["deploy_id"].nil?
              MU.log "Couldn't resolve NAT host to a live instance in #{parent_name}.", MU::DEBUG, details: vpc_block
            else
              MU.log "Couldn't resolve NAT host to a live instance in #{parent_name}", MU::ERR, details: vpc_block
              return false
            end
          elsif !vpc_block["nat_host_id"]
            MU.log "Resolved NAT host to #{ext_nat.cloud_id} in #{parent_name}", MU::DEBUG, details: vpc_block
            vpc_block["nat_host_id"] = ext_nat.cloud_id
            vpc_block.delete('nat_host_name')
            vpc_block.delete('nat_host_ip')
            vpc_block.delete('nat_host_tag')
          end
        end

        # Some resources specify multiple subnets...
        if vpc_block.has_key?("subnets")
          vpc_block['subnets'].each { |subnet|
            tag_key, tag_value = subnet['tag'].split(/=/, 2) if !subnet['tag'].nil?
            begin
              ext_subnet = ext_vpc.getSubnet(cloud_id: subnet['subnet_id'], name: subnet['subnet_name'], tag_key: tag_key, tag_value: tag_value)
            rescue MuError
            end

            if ext_subnet.nil?
              ok = false
              MU.log "Couldn't resolve subnet reference in #{parent_name}'s list to a live subnet (#{vpc_block})", MU::ERR, details: caller
            elsif !subnet['subnet_id']
              subnet['subnet_id'] = ext_subnet.cloud_id
              subnet.delete('subnet_name')
              subnet.delete('tag')
              MU.log "Resolved subnet reference in #{parent_name} to #{ext_subnet.cloud_id}", MU::DEBUG, details: subnet
            end
          }
          # ...others single subnets
        elsif vpc_block.has_key?('subnet_name') or vpc_block.has_key?('subnet_id')
          tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?
          begin
            ext_subnet = ext_vpc.getSubnet(cloud_id: vpc_block['subnet_id'], name: vpc_block['subnet_name'], tag_key: tag_key, tag_value: tag_value)
          rescue MuError
          end

          if ext_subnet.nil?
            ok = false
            MU.log "Couldn't resolve subnet reference in #{parent_name} to a live subnet", MU::ERR, details: vpc_block
          elsif !vpc_block['subnet_id']
            vpc_block['subnet_id'] = ext_subnet.cloud_id
            vpc_block.delete('subnet_name')
            MU.log "Resolved subnet reference in #{parent_name} to #{ext_subnet.cloud_id}", MU::DEBUG, details: vpc_block
          end
        end
      end

      # ...and other times we get to pick

      # First decide whether we should pay attention to subnet_prefs.
      honor_subnet_prefs = true
      if vpc_block['subnets']
        vpc_block['subnets'].each { |subnet|
          if subnet['subnet_id'] or subnet['subnet_name']
            honor_subnet_prefs=false
          end
        }
      elsif (vpc_block['subnet_name'] or vpc_block['subnet_id'])
        honor_subnet_prefs=false
      end

      if vpc_block['subnet_pref'] and honor_subnet_prefs
        private_subnets = []
        private_subnets_map = {}
        public_subnets = []
        nat_routes = {}
        subnet_ptr = "subnet_id"
        if !is_sibling
          ext_vpc.subnets.each { |subnet|
            if subnet.private?
              private_subnets << {"subnet_id" => subnet.cloud_id}
              private_subnets_map[subnet.cloud_id] = subnet
            else
              public_subnets << {"subnet_id" => subnet.cloud_id}
            end
          }
        else
          sibling_vpcs.each { |ext_vpc|
            if ext_vpc['name'] == vpc_block['vpc_name']
              subnet_ptr = "subnet_name"
              ext_vpc['subnets'].each { |subnet|
                if subnet['is_public'] # NAT nonsense calculated elsewhere, ew
                  public_subnets << {"subnet_name" => subnet['name']}
                else
                  private_subnets << {"subnet_name" => subnet['name']}
                  nat_routes[subnet['name']] = [] if nat_routes[subnet['name']].nil?
                  if !subnet['nat_host_name'].nil?
                    nat_routes[subnet['name']] << subnet['nat_host_name']
                  end
                end
              }
              break
            end
          }
        end

        if public_subnets.size == 0 and private_subnets == 0
          MU.log "Couldn't find any subnets for #{parent_name}", MU::ERR
          return false
        end

        case vpc_block['subnet_pref']
          when "public"
            if !public_subnets.nil? and public_subnets.size > 0
              vpc_block.merge!(public_subnets[rand(public_subnets.length)])
            else
              MU.log "Public subnet requested for #{parent_name}, but none found in #{vpc_block}", MU::ERR
              return false
            end
          when "private"
            vpc_block.merge!(private_subnets[rand(private_subnets.length)])
            if !is_sibling
              vpc_block['nat_host_id'] = private_subnets_map[vpc_block[subnet_ptr]].defaultRoute
            elsif nat_routes.has_key?(vpc_block[subnet_ptr])
              vpc_block['nat_host_name'] == nat_routes[vpc_block[subnet_ptr]]
            end
          when "any"
            vpc_block.merge!(public_subnets.concat(private_subnets)[rand(public_subnets.length+private_subnets.length)])
          when "all"
            vpc_block['subnets'] = []
            public_subnets.each { |subnet|
              vpc_block['subnets'] << subnet
            }
            private_subnets.each { |subnet|
              vpc_block['subnets'] << subnet
            }
          when "all_public"
            vpc_block['subnets'] = []
            public_subnets.each { |subnet|
              vpc_block['subnets'] << subnet
            }
          when "all_private"
            vpc_block['subnets'] = []
            private_subnets.each { |subnet|
              vpc_block['subnets'] << subnet
              if !is_sibling and vpc_block['nat_host_id'].nil?
                vpc_block['nat_host_id'] = private_subnets_map[subnet[subnet_ptr]].defaultRoute
              elsif nat_routes.has_key?(subnet) and vpc_block['nat_host_name'].nil?
                vpc_block['nat_host_name'] == nat_routes[subnet]
              end
            }
        end
      end

      if ok
        vpc_block.delete('deploy_id')
        vpc_block.delete('nat_host_id') if vpc_block.has_key?('nat_host_id') and !vpc_block['nat_host_id'].nil? and !vpc_block['nat_host_id'].match(/^i-/)
        vpc_block.delete('vpc_name') if vpc_block.has_key?('vpc_id')
        vpc_block.delete('deploy_id')
        vpc_block.delete('tag')
        MU.log "Resolved VPC resources for #{parent_name}", MU::DEBUG, details: vpc_block
      end

      return ok
    end

    # Verify that a server or server_pool has a valid AD config referencing
    # valid Vaults for credentials.
    def self.check_vault_refs(server)
      ok = true
      server['vault_access'] = [] if server['vault_access'].nil?
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

    @admin_firewall_rules = []
    # Generate configuration for the general-pursose ADMIN firewall rulesets
    # (security groups in AWS). Note that these are unique to regions and
    # individual VPCs (as well as Classic, which is just a degenerate case of
    # a VPC for our purposes.
    # @param vpc [Hash]: A VPC reference as defined in our config schema. This originates with the calling resource, so we'll peel out just what we need (a name or cloud id of a VPC).
    # @param admin_ip [String]: Optional string of an extra IP address to allow blanket access to the calling resource.
    # @param cloud [String]: The parent resource's cloud plugin identifier
    # @param region [String]: Cloud provider region, if applicable.
    # @return [Hash<String>]: A dependency description that the calling resource can then add to itself.
    def self.genAdminFirewallRuleset(vpc: nil, admin_ip: nil, region: nil, cloud: nil)
      if !cloud or !region
        raise MuError, "Cannot call genAdminFirewallRuleset without specifying the parent's region and cloud provider"
      end
      hosts = Array.new
      hosts << "#{MU.my_public_ip}/32" if MU.my_public_ip
      hosts << "#{MU.my_private_ip}/32" if MU.my_private_ip
      hosts << "#{MU.mu_public_ip}/32" if MU.mu_public_ip
      hosts << "#{admin_ip}/32" if admin_ip
      hosts.uniq!
      name = "admin"
      realvpc = nil
      if vpc
        realvpc = {}
        realvpc['vpc_id'] = vpc['vpc_id']
        realvpc['vpc_name'] = vpc['vpc_name']
        if !realvpc['vpc_id'].nil?
          name = name + "-" + realvpc['vpc_id']
        elsif !realvpc['vpc_name'].nil?
          name = name + "-" + realvpc['vpc_name']
        end
      end

      hosts.uniq!

      rules = [
          {
              "proto" => "tcp",
              "port_range" => "0-65535",
              "hosts" => hosts
          },
          {
              "proto" => "udp",
              "port_range" => "0-65535",
              "hosts" => hosts
          },
          {
              "proto" => "icmp",
              "port_range" => "-1",
              "hosts" => hosts
          }
      ]

      acl = {"name" => name, "rules" => rules, "vpc" => realvpc, "region" => region, "cloud" => cloud, "admin" => true}
      @admin_firewall_rules << acl if !@admin_firewall_rules.include?(acl)
      return {"type" => "firewall_rule", "name" => name}
    end
    
    def self.validate_alarm_config(alarm)
      ok = true

      if alarm["namespace"].nil?
        MU.log "You must specify 'namespace' when creating an alarm", MU::ERR
        ok = false
      end

      if alarm["metric_name"].nil?
        MU.log "You must specify 'metric_name' when creating an alarm", MU::ERR
        ok = false
      end

      if alarm["statistic"].nil?
        MU.log "You must specify 'statistic' when creating an alarm", MU::ERR
        ok = false
      end

      if alarm["period"].nil?
        MU.log "You must specify 'period' when creating an alarm", MU::ERR
        ok = false
      end

      if alarm["evaluation_periods"].nil?
        MU.log "You must specify 'evaluation_periods' when creating an alarm", MU::ERR
        ok = false
      end

      if alarm["threshold"].nil?
        MU.log "You must specify 'threshold' when creating an alarm", MU::ERR
        ok = false
      end

      if alarm["comparison_operator"].nil?
        MU.log "You must specify 'comparison_operator' when creating an alarm", MU::ERR
        ok = false
      end

      if alarm["enable_notifications"]
        if alarm["comparison_operator"].nil?
          MU.log "You must specify 'comparison_operator' when creating an alarm", MU::ERR
          ok = false
        end

        if alarm["notification_group"].nil?
          MU.log "You must specify 'notification_group' when 'enable_notifications' is set to true", MU::ERR
          ok = false
        end

        if alarm["notification_type"].nil?
          MU.log "You must specify 'notification_type' when 'enable_notifications' is set to true", MU::ERR
          ok = false
        end

        if alarm["notification_endpoint"].nil?
          MU.log "You must specify 'notification_endpoint' when 'enable_notifications' is set to true", MU::ERR
          ok = false
        end
      end
      
      if alarm["dimensions"]
        alarm["dimensions"].each{ |dimension|
          if dimension["mu_name"] && dimension["cloud_id"]
            MU.log "You can only specfiy 'mu_name' or 'cloud_id'", MU::ERR
            ok = false
          end

          if dimension["cloud_class"].nil?
            ok = false
            MU.log "You must specify 'cloud_class'", MU::ERR
          end
        }
      end

      return ok
    end

    def self.validate(config)
      ok = true
      begin
        JSON::Validator.validate!(MU::Config.schema, config)
      rescue JSON::Schema::ValidationError => e
        # Use fully_validate to get the complete error list, save some time
        errors = JSON::Validator.fully_validate(schema, config)
        raise ValidationError, "Validation error in #{@@config_path}!\n"+errors.join("\t\n")
      end

      databases = config['databases']
      servers = config['servers']
      server_pools = config['server_pools']
      cache_clusters = config['cache_clusters']
      alarms = config['alarms']
      logs = config['logs']
      loadbalancers = config['loadbalancers']
      collections = config['collections']
      firewall_rules = config['firewall_rules']
      dnszones = config['dnszones']
      vpcs = config['vpcs']

      databases = Array.new if databases.nil?
      servers = Array.new if servers.nil?
      server_pools = Array.new if server_pools.nil?
      cache_clusters = Array.new if cache_clusters.nil?
      alarms = Array.new if alarms.nil?
      logs = Array.new if logs.nil?
      loadbalancers = Array.new if loadbalancers.nil?
      collections = Array.new if collections.nil?
      firewall_rules = Array.new if firewall_rules.nil?
      vpcs = Array.new if vpcs.nil?
      dnszones = Array.new if dnszones.nil?

      if databases.size < 1 and servers.size < 1 and server_pools.size < 1 and loadbalancers.size < 1 and collections.size < 1 and firewall_rules.size < 1 and vpcs.size < 1 and dnszones.size < 1 and cache_clusters.size < 1 and alarms.size < 1 and logs.size < 1
        MU.log "You must declare at least one resource to create", MU::ERR
        ok = false
      end

      config['region'] = MU.curRegion if config['region'].nil?
      # Stashing some shorthand to any servers we'll be building, in case
      # some of them are NATs
      server_names = Array.new
      servers.each { |server|
        server_names << server['name']
      }

      server_names = Array.new
      vpc_names = Array.new
      nat_routes = Hash.new
      vpcs.each { |vpc|
        vpc["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("VPC")
        vpc['region'] = config['region'] if vpc['region'].nil?
        vpc["dependencies"] = Array.new if vpc["dependencies"].nil?
        subnet_routes = Hash.new
        public_routes = Array.new
        vpc['subnets'].each { |subnet|
          subnet_routes[subnet['route_table']] = Array.new if subnet_routes[subnet['route_table']].nil?
          subnet_routes[subnet['route_table']] << subnet['name']
        }
        
        if vpc['endpoint_policy'] && !vpc['endpoint_policy'].empty?
          if !vpc['endpoint']
            MU.log "'endpoint_policy' is declared however endpoint is not set", MU::ERR
            ok = false
          end

          attributes = %w{Effect Action Resource Principal Sid}
          vpc['endpoint_policy'].each { |rule|
            rule.keys.each { |key|
              if !attributes.include?(key)
                MU.log "'Attribute #{key} can't be used in 'endpoint_policy'", MU::ERR
                ok = false
              end
            }
          }
        end

        nat_gateway_route_tables = []
        nat_gateway_added = false
        vpc['route_tables'].each { |table|
          routes = []
          table['routes'].each { |route|
            if routes.include?(route['destination_network'])
              MU.log "Duplicate routes to #{route['destination_network']} in route table #{table['name']}", MU::ERR
              ok = false
            else
              routes << route['destination_network']
            end

            if (route['nat_host_name'] or route['nat_host_id'])
              route.delete("gateway") if route['gateway'] == '#INTERNET'
            end
            if !route['nat_host_name'].nil? and server_names.include?(route['nat_host_name'])
              subnet_routes[table['name']].each { |subnet|
                nat_routes[subnet] = route['nat_host_name']
              }
              vpc['dependencies'] << {
                  "type" => "server",
                  "name" => route['nat_host_name']
              }
            end
            
            vpc['subnets'].each { |subnet|
              if route['gateway'] == '#INTERNET'
                if table['name'] == subnet['route_table']
                  subnet['is_public'] = true
                  if vpc['create_nat_gateway']
                    if vpc['nat_gateway_multi_az']
                      subnet['create_nat_gateway'] = true
                    else
                      if nat_gateway_added
                        subnet['create_nat_gateway'] = false
                      else
                        subnet['create_nat_gateway'] = true 
                        nat_gateway_added = true
                      end
                    end
                  end
                else
                  subnet['is_public'] = false
                end
                if !nat_routes[subnet['name']].nil?
                  subnet['nat_host_name'] = nat_routes[subnet['name']]
                end
              elsif route['gateway'] == '#NAT'
                if table['name'] == subnet['route_table']
                  if route['nat_host_name'] or route['nat_host_id']
                    MU.log "You can either use a NAT gateway or a NAT server, not both.", MU::ERR
                    ok = false
                  end

                  subnet['is_public'] = false
                  nat_gateway_route_tables << table
                end
              end
            }
          }
        }

        nat_gateway_route_tables.uniq!
        if nat_gateway_route_tables.size < 2 && vpc['nat_gateway_multi_az']
          MU.log "'nat_gateway_multi_az' is enabled but only one route table exists. For multi-az support create one private route table per AZ", MU::ERR
          ok = false
        end

        if nat_gateway_route_tables.size > 0 && !vpc['create_nat_gateway']
          MU.log "There are route tables with a NAT gateway route, but create_nat_gateway is set to false. Setting to true", MU::NOTICE
          vpc['create_nat_gateway'] = true
        end

        vpc_names << vpc['name']
      }

      # Now go back through and identify peering connections involving any of
      # the VPCs we've declared. XXX Note that it's real easy to create a
      # circular dependency here. Ugh.
      vpcs.each { |vpc|
        if !vpc["peers"].nil?
          vpc["peers"].each { |peer|
            peer['region'] = config['region'] if peer['region'].nil?
            peer['cloud'] = vpc['cloud'] if peer['cloud'].nil?
            peer["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("VPC")
            # If we're peering with a VPC in this deploy, set it as a dependency
            if !peer['vpc']["vpc_name"].nil? and vpc_names.include?(peer['vpc']["vpc_name"]) and peer['deploy_id'].nil?
              vpc["dependencies"] << {
                  "type" => "vpc",
                  "name" => peer['vpc']["vpc_name"]
              }
              # If we're using a VPC from somewhere else, make sure the flippin'
              # thing exists, and also fetch its id now so later search routines
              # don't have to work so hard.
            else
              if !peer['account'].nil? and peer['account'] != MU.account_number
                if peer['vpc']["vpc_id"].nil?
                  MU.log "VPC peering connections to non-local accounts must specify the vpc_id of the peer.", MU::ERR
                  ok = false
                end
              elsif !processVPCReference(peer['vpc'], "vpc '#{vpc['name']}'", dflt_region: config['region'])
                ok = false
              end
            end
          }
        end
      }

      dnszones.each { |zone|
        zone["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("DNSZone")
        zone['region'] = config['region'] if zone['region'].nil?
        # ext_zone = MU::Cloud::DNSZone.find(cloud_id: zone['name']).values.first

        # if !ext_zone.nil?
          # MU.log "DNS zone #{zone['name']} already exists", MU::ERR
          # ok = false
        # end
        if !zone["records"].nil?
          zone["records"].each { |record|
            route_types = 0
            route_types = route_types + 1 if !record['weight'].nil?
            route_types = route_types + 1 if !record['geo_location'].nil?
            route_types = route_types + 1 if !record['region'].nil?
            route_types = route_types + 1 if !record['failover'].nil?
            if route_types > 1
              MU.log "At most one of weight, location, region, and failover can be specified in a record.", MU::ERR, details: record
              ok = false
            end
            if !record['healthcheck'].nil?
              if route_types == 0
                MU.log "Health check in a DNS zone only valid with Weighted, Location-based, Latency-based, or Failover routing.", MU::ERR, details: record
                ok = false
              end
            end
            if !record['geo_location'].nil?
              if !record['geo_location']['continent_code'].nil? and (!record['geo_location']['country_code'].nil? or !record['geo_location']['subdivision_code'].nil?)
                MU.log "Location routing cannot mix continent_code with other location specifiers.", MU::ERR, details: record
                ok = false
              end
              if record['geo_location']['country_code'].nil? and !record['geo_location']['subdivision_code'].nil?
                MU.log "Cannot specify subdivision_code without country_code.", MU::ERR, details: record
                ok = false
              end
            end
          }
        end
        if !zone["vpcs"].nil?
          zone["vpcs"].each { |vpc|
            vpc['region'] = config['region'] if vpc['region'].nil?
            vpc['cloud'] = zone['cloud'] if vpc['cloud'].nil?
            if !vpc["vpc_name"].nil? and vpc_names.include?(vpc["vpc_name"]) and zone['deploy_id'].nil?
              zone["dependencies"] << {
                  "type" => "vpc",
                  "name" => vpc["vpc_name"]
              }
              # If we're using a VPC from somewhere else, make sure the flippin'
              # thing exists, and also fetch its id now so later search routines
              # don't have to work so hard.
            else
              if !zone['account'].nil? and zone['account'] != MU.account_number
                if vpc["vpc_id"].nil?
                  MU.log "VPC DNS access to non-local accounts must specify the vpc_id of the vpc.", MU::ERR
                  ok = false
                end
              elsif !processVPCReference(vpc, "vpc '#{zone['name']}'", dflt_region: config['region'])
                ok = false
              end
            end
          }
        end
      }

      firewall_rule_names = Array.new
      firewall_rules.each { |acl|
        firewall_rule_names << acl['name']
      }

      resolveFirewall = Proc.new { |acl|
        firewall_rule_names << acl['name']
        acl['region'] = config['region'] if acl['region'].nil?
        acl["dependencies"] = Array.new if acl["dependencies"].nil?
        acl["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("FirewallRule")

        if !acl["vpc_name"].nil? or !acl["vpc_id"].nil?
          acl['vpc'] = Hash.new
          acl['vpc']['vpc_id'] = acl["vpc_id"] if !acl["vpc_id"].nil?
          acl['vpc']['vpc_name'] = acl["vpc_name"] if !acl["vpc_name"].nil?
        end
        if !acl["vpc"].nil?
          acl['vpc']['region'] = acl['region'] if acl['vpc']['region'].nil?
          acl["vpc"]['cloud'] = acl['cloud'] if acl["vpc"]['cloud'].nil?
          # If we're using a VPC in this deploy, set it as a dependency
          if !acl["vpc"]["vpc_name"].nil? and vpc_names.include?(acl["vpc"]["vpc_name"]) and acl["vpc"]['deploy_id'].nil?
            acl["dependencies"] << {
                "type" => "vpc",
                "name" => acl["vpc"]["vpc_name"]
            }
            # If we're using a VPC from somewhere else, make sure the flippin'
            # thing exists, and also fetch its id now so later search routines
            # don't have to work so hard.
          else
            # Drop meaningless subnet references
            acl['vpc'].delete("subnets")
            acl['vpc'].delete("subnet_id")
            acl['vpc'].delete("subnet_name")
            acl['vpc'].delete("subnet_pref")
            if !processVPCReference(acl["vpc"], "firewall_rule #{acl['name']}", dflt_region: config['region'])
              ok = false
            end
          end
        end

        acl['rules'].each { |rule|
          if !rule['sgs'].nil?
            rule['sgs'].each { |sg_name|
              if firewall_rule_names.include?(sg_name)
                acl["dependencies"] << {
                    "type" => "firewall_rule",
                    "name" => sg_name
                }
              else
                MU.log "Didn't see #{sg_name} anywhere, is that ok?", MU::WARN
              end
            }
          end
          if !rule['lbs'].nil?
            rule['lbs'].each { |lb_name|
              acl["dependencies"] << {
                  "type" => "loadbalancer",
                  "name" => lb_name,
                  "phase" => "groom"
              }
            }
          end
        }
        acl['dependencies'].uniq!
        acl
      }

      firewall_rules.each { |acl|
        acl = resolveFirewall.call(acl)
      }

      loadbalancers.each { |lb|
        lb['region'] = config['region'] if lb['region'].nil?
        lb["dependencies"] = Array.new if lb["dependencies"].nil?
        lb["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("LoadBalancer")
        if !lb["vpc"].nil?
          lb['vpc']['region'] = lb['region'] if lb['vpc']['region'].nil?
          lb['vpc']['cloud'] = lb['cloud'] if lb['vpc']['cloud'].nil?
          # If we're using a VPC in this deploy, set it as a dependency
          if !lb["vpc"]["vpc_name"].nil? and vpc_names.include?(lb["vpc"]["vpc_name"]) and lb["vpc"]['deploy_id'].nil?
            lb["dependencies"] << {
                "type" => "vpc",
                "name" => lb["vpc"]["vpc_name"]
            }
            if !processVPCReference(lb['vpc'],
                                    "loadbalancer '#{lb['name']}'",
                                    dflt_region: config['region'],
                                    is_sibling: true,
                                    sibling_vpcs: vpcs)
              ok = false
            end

            # If we're using a VPC from somewhere else, make sure the flippin'
            # thing exists, and also fetch its id now so later search routines
            # don't have to work so hard.
          else
            if !processVPCReference(lb["vpc"],
                                    "loadbalancer #{lb['name']}",
                                    dflt_region: config['region'])
              ok = false
            end
          end
        end
        if !lb['ingress_rules'].nil?
          fwname = "lb"+lb['name']
          firewall_rule_names << fwname
          acl = {"name" => fwname, "rules" => lb['ingress_rules'], "region" => lb['region']}
          acl["vpc"] = lb['vpc'].dup if !lb['vpc'].nil?
          firewall_rules << resolveFirewall.call(acl)
          lb["add_firewall_rules"] = [] if lb["add_firewall_rules"].nil?
          lb["add_firewall_rules"] << {"rule_name" => fwname}
        end
        if !lb["add_firewall_rules"].nil?
          lb["add_firewall_rules"].each { |acl_include|
            if firewall_rule_names.include?(acl_include["rule_name"])
              lb["dependencies"] << {
                  "type" => "firewall_rule",
                  "name" => acl_include["rule_name"]
              }
            end
          }
        end

        lb['listeners'].each { |listener|
          if !listener["ssl_certificate_name"].nil?
            if lb['cloud'] == "AWS"
              resp = MU::Cloud::AWS.iam.get_server_certificate(server_certificate_name: listener["ssl_certificate_name"])
              if resp.nil?
                MU.log "Requested SSL certificate #{listener["ssl_certificate_name"]}, but no such cert exists", MU::ERR
                ok = false
              else
                listener["ssl_certificate_id"] = resp.server_certificate.server_certificate_metadata.arn
                MU.log "Using SSL cert #{listener["ssl_certificate_id"]} on port #{listener['lb_port']} in ELB #{lb['name']}"
              end
            end
          end
        }
        lb['dependencies'] << genAdminFirewallRuleset(vpc: lb['vpc'], region: lb['region'], cloud: lb['cloud'])
        
        if lb["alarms"] && !lb["alarms"].empty?
          lb["alarms"].each { |alarm|
            alarm["namespace"] = "AWS/ELB" if alarm["namespace"].nil?
            ok = false unless validate_alarm_config(alarm)
          }
        end
      }

      collections.each { |stack|
        stack['region'] = config['region'] if stack['region'].nil?
        stack["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("Collection")
      }

      server_pools.each { |pool|
        if server_names.include?(pool['name'])
          MU.log "Can't use name #{pool['name']} more than once in servers/server_pools"
          ok = false
        end
        server_names << pool['name']
        pool['region'] = config['region'] if pool['region'].nil?
        pool["dependencies"] = Array.new if pool["dependencies"].nil?
        pool["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("ServerPool")
        pool["#MU_GROOMER"] = MU::Groomer.loadGroomer(pool['groomer'])
        pool['skipinitialupdates'] = true if @skipinitialupdates
        if pool["basis"]["server"] != nil
          pool["dependencies"] << {"type" => "server", "name" => pool["basis"]["server"]}
        end
        if !pool['static_ip'].nil? and !pool['ip'].nil?
          ok = false
          MU.log "Server Pools cannot assign specific static IPs.", MU::ERR
        end
        pool['vault_access'] = [] if pool['vault_access'].nil?
        pool['vault_access'] << {"vault" => "splunk", "item" => "admin_user"}
        ok = false if !check_vault_refs(pool)

        if pool["alarms"] && !pool["alarms"].empty?
          pool["alarms"].each { |alarm|
            alarm["namespace"] = "AWS/EC2" if alarm["namespace"].nil?
            ok = false unless validate_alarm_config(alarm)
          }
        end

        if pool["basis"]["launch_config"] != nil
          launch = pool["basis"]["launch_config"]
          if !launch['generate_iam_role']
            if !launch['iam_role']
              MU.log "Must set iam_role if generate_iam_role set to false", MU::ERR
              ok = false
            end
            if !launch['iam_policies'].nil? and launch['iam_policies'].size > 0
              MU.log "Cannot mix iam_policies with generate_iam_role set to false", MU::ERR
              ok = false
            end
          end
          if launch["server"].nil? and launch["instance_id"].nil? and launch["ami_id"].nil?
            if MU::Config.amazon_images.has_key?(pool['platform']) and
                MU::Config.amazon_images[pool['platform']].has_key?(pool['region'])
              launch['ami_id'] = MU::Config.amazon_images[pool['platform']][pool['region']]
            else
              ok = false
              MU.log "One of the following MUST be specified for launch_config: server, ami_id, instance_id.", MU::ERR
            end
          end
          if launch["server"] != nil
            pool["dependencies"] << {"type" => "server", "name" => launch["server"]}
            servers.each { |server|
              if server["name"] == launch["server"]
                server["create_ami"] = true
              end
            }
          end
        end
        if pool["region"].nil? and pool["zones"].nil? and pool["vpc_zone_identifier"].nil? and pool["vpc"].nil?
          ok = false
          MU.log "One of the following MUST be specified for Server Pools: region, zones, vpc_zone_identifier, vpc.", MU::ERR
        end

        if !pool["scaling_policies"].nil?
          pool["scaling_policies"].each { |policy|
            if policy['type'] != "PercentChangeInCapacity" and !policy['min_adjustment_magnitude'].nil?
              MU.log "Cannot specify scaling policy min_adjustment_magnitude if type is not PercentChangeInCapacity", MU::ERR
              ok = false
            end

            if policy["policy_type"] == "SimpleScaling"
              unless policy["cooldown"] && policy["adjustment"]
                MU.log "You must specify 'cooldown' and 'adjustment' when 'policy_type' is set to 'SimpleScaling'", MU::ERR
                ok = false
              end
            elsif policy["policy_type"] == "StepScaling"
              if policy["step_adjustments"].nil? || policy["step_adjustments"].empty?
                MU.log "You must specify 'step_adjustments' when 'policy_type' is set to 'StepScaling'", MU::ERR
                ok = false
              end

              policy["step_adjustments"].each{ |step|
                if step["adjustment"].nil?
                  MU.log "You must specify 'adjustment' for 'step_adjustments' when 'policy_type' is set to 'StepScaling'", MU::ERR
                  ok = false
                end

                if step["adjustment"] >= 1 && policy["estimated_instance_warmup"].nil?
                  MU.log "You must specify 'estimated_instance_warmup' when 'policy_type' is set to 'StepScaling' and adding capacity", MU::ERR
                  ok = false
                end

                if step["lower_bound"].nil? && step["upper_bound"].nil?
                  MU.log "You must specify 'lower_bound' and/or upper_bound for 'step_adjustments' when 'policy_type' is set to 'StepScaling'", MU::ERR
                  ok = false
                end
              }
            end

            if policy["alarms"] && !policy["alarms"].empty?
              policy["alarms"].each { |alarm|
                alarm["namespace"] = "AWS/EC2" if alarm["namespace"].nil?
                ok = false unless validate_alarm_config(alarm)
              }
            end
          }
        end
# TODO make sure any load balancer we ask for has the same VPC configured
        if !pool["loadbalancers"].nil?
          pool["loadbalancers"].each { |lb|
            if lb["concurrent_load_balancer"] != nil
              pool["dependencies"] << {
                  "type" => "loadbalancer",
                  "name" => lb["concurrent_load_balancer"]
              }
            end
          }
        end
        if !pool["vpc"].nil?
          pool['vpc']['region'] = pool['region'] if pool['vpc']['region'].nil?
          pool["vpc"]['cloud'] = pool['cloud'] if pool["vpc"]['cloud'].nil?
          # If we're using a VPC in this deploy, set it as a dependency
          if !pool["vpc"]["vpc_name"].nil? and vpc_names.include?(pool["vpc"]["vpc_name"]) and pool["vpc"]["deploy_id"].nil?
            pool["dependencies"] << {
                "type" => "vpc",
                "name" => pool["vpc"]["vpc_name"]
            }
            if !pool["vpc"]["subnet_name"].nil? and nat_routes.has_key?(pool["vpc"]["subnet_name"])
              pool["dependencies"] << {
                  "type" => "pool",
                  "name" => nat_routes[subnet["subnet_name"]],
                  "phase" => "groom"
              }
            end
            if !processVPCReference(pool["vpc"], "server_pool #{pool['name']}", dflt_region: config['region'], is_sibling: true, sibling_vpcs: vpcs)
              ok = false
            end
          else
            # If we're using a VPC from somewhere else, make sure the flippin'
            # thing exists, and also fetch its id now so later search routines
            # don't have to work so hard.
            if !processVPCReference(pool["vpc"], "server_pool #{pool['name']}", dflt_region: config['region'])
              ok = false
            end
          end
        end
        if !pool['ingress_rules'].nil?
          fwname = "pool"+pool['name']
          firewall_rule_names << fwname
          acl = {"name" => fwname, "rules" => pool['ingress_rules'], "region" => pool['region']}
          acl["vpc"] = pool['vpc'].dup if !pool['vpc'].nil?
          firewall_rules << resolveFirewall.call(acl)
          pool["add_firewall_rules"] = [] if pool["add_firewall_rules"].nil?
          pool["add_firewall_rules"] << {"rule_name" => fwname}
        end
        pool["dependencies"].uniq!
        if !pool["add_firewall_rules"].nil?
          pool["add_firewall_rules"].each { |acl_include|
            if firewall_rule_names.include?(acl_include["rule_name"])
              pool["dependencies"] << {
                  "type" => "firewall_rule",
                  "name" => acl_include["rule_name"]
              }
            end
          }
        end
        pool['dependencies'] << genAdminFirewallRuleset(vpc: pool['vpc'], region: pool['region'], cloud: pool['cloud'])
      }

      read_replicas = []
      database_names = []
      cluster_nodes = []
      databases.each { |db|
        db['region'] = config['region'] if db['region'].nil?
        db["dependencies"] = Array.new if db["dependencies"].nil?
        db["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("Database")
        database_names << db['name']
        db['ingress_rules'] ||= []
        if db['collection']
          # XXX don't do this if 'true' was explicitly asked for (as distinct
          # from default)
          db['publicly_accessible'] = false
        end
        if !db['password'].nil? and (db['password'].length < 8 or db['password'].match(/[\/\\@\s]/))
          MU.log "Database password '#{db['password']}' doesn't meet RDS requirements. Must be > 8 chars and have only ASCII characters other than /, @, \", or [space].", MU::ERR
          ok = false
        end
        if db["multi_az_on_create"] and db["multi_az_on_deploy"]
          MU.log "Both of multi_az_on_create and multi_az_on_deploy cannot be true", MU::ERR
          ok = false
        end

        if db['auth_vault'] && !db['auth_vault'].empty?
          groomclass = MU::Groomer.loadGroomer(db['groomer'])
          if db['password']
            MU.log "Database password and database auth_vault can't both be used.", MU::ERR
            ok = false
          end

          begin
            item = groomclass.getSecret(vault: db['auth_vault']['vault'], item: db['auth_vault']['item'])
            if !item.has_key?(db['auth_vault']['password_field'])
              MU.log "No value named password_field in Chef Vault #{db['auth_vault']['vault']}:#{db['auth_vault']['item']}, will use an auto generated password.", MU::NOTICE
              db['auth_vault'].delete(field)
            end
          rescue MuError
            ok = false
          end
        end

        if db.has_key?("db_parameter_group_parameters") || db.has_key?("cluster_parameter_group_parameters")
          if db["parameter_group_family"].nil?
            MU.log "parameter_group_family must be set when setting db_parameter_group_parameters", MU::ERR
            ok = false
          end
        end

        # Adding rules for Database instance storage. This varies depending on storage type and database type. 
        if db["storage_type"] == "standard" or db["storage_type"] == "gp2"
          if db["engine"] == "postgres" or db["engine"] == "mysql"
            if !(5..6144).include? db["storage"]
              MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 5 to 6144 GB for #{db["storage_type"]} volume types", MU::ERR
              ok = false
            end
          elsif %w{oracle-se1 oracle-se oracle-ee}.include? db["engine"]
            if !(10..6144).include? db["storage"]
              MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 10 to 6144 GB for #{db["storage_type"]} volume types", MU::ERR
              ok = false
            end
          elsif %w{sqlserver-ex sqlserver-web}.include? db["engine"]
            if !(20..4096).include? db["storage"]
              MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 20 to 4096 GB for #{db["storage_type"]} volume types", MU::ERR
              ok = false
            end
          elsif %w{sqlserver-ee sqlserver-se}.include? db["engine"]
            if !(200..4096).include? db["storage"]
              MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 200 to 4096 GB for #{db["storage_type"]} volume types", MU::ERR
              ok = false
            end
          end
        elsif db["storage_type"] == "io1"
          if %w{postgres mysql oracle-se1 oracle-se oracle-ee}.include? db["engine"]
            if !(100..6144).include? db["storage"]
              MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 100 to 6144 GB for #{db["storage_type"]} volume types", MU::ERR
              ok = false
            end
          elsif %w{sqlserver-ex sqlserver-web}.include? db["engine"]
            if !(100..4096).include? db["storage"]
              MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 100 to 4096 GB for #{db["storage_type"]} volume types", MU::ERR
              ok = false
            end
          elsif %w{sqlserver-ee sqlserver-se}.include? db["engine"]
            if !(200..4096).include? db["storage"]
              MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 200 to 4096 GB #{db["storage_type"]} volume types", MU::ERR
              ok = false
            end
          end
        end

        db_cluster_engines = %w{aurora}
        db["create_cluster"] = 
          if db_cluster_engines.include?(db["engine"])
            true
          else
            false
          end

        if db["create_cluster"]
          if db["cluster_node_count"] < 1
            MU.log "You are trying to create a database cluster but cluster_node_count is set to #{db["cluster_node_count"]}", MU::ERR
            ok = false
          end

          MU.log "'storage' is not supported when creating a database cluster, disregarding", MU::NOTICE if db["storage"]
          MU.log "'multi_az_on_create' and multi_az_on_deploy are not supported when creating a database cluster, disregarding", MU::NOTICE if db["storage"] if db["multi_az_on_create"] || db["multi_az_on_deploy"]
        end

        db["license_model"] =
          if db["engine"] == "postgres"
            "postgresql-license"
          elsif db["engine"] == "mysql"
            "general-public-license"
          end

        if db["size"].nil?
          MU.log "You must specify 'size' when creating a new database or a database from a snapshot.", MU::ERR
          ok = false
        end

        if db["creation_style"] == "new" and db["storage"].nil?
          unless db["create_cluster"]
            MU.log "You must specify 'storage' when creating a new database.", MU::ERR
            ok = false
          end
        end

        if db["creation_style"] == "point_in_time" && db["restore_time"].nil?
          ok = false
          MU.log "You must provide restore_time when creation_style is point_in_time", MU::ERR
        end

        if %w{existing new_snapshot existing_snapshot point_in_time}.include?(db["creation_style"])
          if db["identifier"].nil?
            ok = false
            MU.log "Using existing database (or snapshot thereof), but no identifier given", MU::ERR
          end
        end

        if !db["run_sql_on_deploy"].nil? and (db["engine"] != "postgres" and db["engine"] != "mysql")
          ok = false
          MU.log "Running SQL on deploy is only supported for postgres and mysql databases", MU::ERR
        end

        if db["alarms"] && !db["alarms"].empty?
          db["alarms"].each { |alarm|
            alarm["namespace"] = "AWS/RDS" if alarm["namespace"].nil?
            ok = false unless validate_alarm_config(alarm)
          }
        end

        if db["collection"]
          db["dependencies"] << {
              "type" => "collection",
              "name" => db["collection"]
          }
        end

        if !db['ingress_rules'].nil?
          fwname = "db"+db['name']
          firewall_rule_names << fwname
          acl = {"name" => fwname, "rules" => db['ingress_rules'], "region" => db['region']}
          acl["vpc"] = db['vpc'].dup if !db['vpc'].nil?
          firewall_rules << resolveFirewall.call(acl)
          db["add_firewall_rules"] = [] if db["add_firewall_rules"].nil?
          db["add_firewall_rules"] << {"rule_name" => fwname}
        end
        if !db["add_firewall_rules"].nil?
          db["add_firewall_rules"].each { |acl_include|
            if firewall_rule_names.include?(acl_include["rule_name"])
              db["dependencies"] << {
                  "type" => "firewall_rule",
                  "name" => acl_include["rule_name"]
              }
            end
          }
        end

        if !db["vpc"].nil?
          if db["vpc"]["subnet_pref"] and !db["vpc"]["subnets"]
            if %w{all any public private}.include? db["vpc"]["subnet_pref"]
              MU.log "subnet_pref #{db["vpc"]["subnet_pref"]} is not supported for database instance.", MU::ERR
              ok = false
            elsif db["vpc"]["subnet_pref"] == "all_public" and !db['publicly_accessible']
              MU.log "Setting publicly_accessible to true, since deploying into public subnets.", MU::WARN
              db['publicly_accessible'] = true
            elsif db["vpc"]["subnet_pref"] == "all_private" and db['publicly_accessible']
              MU.log "Setting publicly_accessible to false, since  deploying into private subnets.", MU::NOTICE
              db['publicly_accessible'] = false
            end
          end

          db['vpc']['region'] = db['region'] if db['vpc']['region'].nil?
          db["vpc"]['cloud'] = db['cloud'] if db["vpc"]['cloud'].nil?
          # If we're using a VPC in this deploy, set it as a dependency
          if !db["vpc"]["vpc_name"].nil? and vpc_names.include?(db["vpc"]["vpc_name"]) and db["vpc"]["deploy_id"].nil?
            db["dependencies"] << {
                "type" => "vpc",
                "name" => db["vpc"]["vpc_name"]
            }

            if !processVPCReference(
              db["vpc"],
              "database #{db['name']}",
              dflt_region: config['region'],
              is_sibling: true,
              sibling_vpcs: vpcs
            )
              ok = false
            end
          else
            # If we're using a VPC from somewhere else, make sure the flippin'
            # thing exists, and also fetch its id now so later search routines
            # don't have to work so hard.
            if !processVPCReference(db["vpc"], "database #{db['name']}", dflt_region: config['region'])
              ok = false
            end
          end
        end
        db['dependencies'] << genAdminFirewallRuleset(vpc: db['vpc'], region: db['region'], cloud: db['cloud'])

        if db["create_read_replica"] or db['read_replica_of']
          if db["engine"] != "postgres" and db["engine"] != "mysql"
            MU.log "Read replica(s) database instances only supported for postgres and mysql. #{db["engine"]} not supported.", MU::ERR
            ok = false
          end
        end

        # Automatically manufacture another database object, which will serve
        # as a read replica of this one, if we've asked for it.
        if db['create_read_replica']
          replica = Marshal.load(Marshal.dump(db))
          replica['name'] = db['name']+"-replica"
          database_names << replica['name']
          replica['create_read_replica'] = false
          replica['read_replica_of'] = {
              "db_name" => db['name'],
              "cloud" => db['cloud'],
              "region" => db['region'] # XXX might want to allow override of this
          }
          replica['dependencies'] << {
              "type" => "database",
              "name" => db["name"],
              "phase" => "groom"
          }
          read_replicas << replica
        end

        # Do database cluster nodes the same way we do read replicas
        if db["create_cluster"]
          (1..db["cluster_node_count"]).each{ |num|
            node = Marshal.load(Marshal.dump(db))
            node["name"] = "#{db['name']}-#{num}"
            database_names << node["name"]
            node["create_cluster"] = false
            node["creation_style"] = "new"
            node["add_cluster_node"] = true
            node["member_of_cluster"] = {
              "db_name" => db['name'],
              "cloud" => db['cloud'],
              "region" => db['region']
            }
            # AWS will figure out for us which database instance is the writer/master so we can create all of them concurrently.
            node['dependencies'] << {
              "type" => "database",
              "name" => db["name"],
              "phase" => "groom"
            }
            cluster_nodes << node

            # Alarms are set on each DB cluster node, not on the cluster iteslf 
            if node.has_key?("alarms") && !node["alarms"].empty?
              node["alarms"].each{ |alarm|
                alarm["name"] = "#{alarm["name"]}-#{node["name"]}"
              }
            end
          }

          db.delete("alarms") if db.has_key?("alarms")
        end
      }
      databases.concat(read_replicas)
      databases.concat(cluster_nodes)
      databases.each { |db|
        if !db['read_replica_of'].nil?
          rr = db['read_replica_of']
          if !rr['db_name'].nil?
            if !database_names.include?(rr['db_name'])
              MU.log "Read replica #{db['name']} references sibling source #{rr['db_name']}, but I have no such database", MU::ERR
              ok = false
            end
          else
            rr['cloud'] = db['cloud'] if rr['cloud'].nil?
            tag_key, tag_value = rr['tag'].split(/=/, 2) if !rr['tag'].nil?
            found = MU::MommaCat.findStray(
                rr['cloud'],
                "database",
                deploy_id: rr["deploy_id"],
                cloud_id: rr["db_id"],
                tag_key: tag_key,
                tag_value: tag_value,
                region: rr["region"],
                dummy_ok: true
            )
            ext_database = found.first if !found.nil? and found.size == 1
            if !ext_database
              MU.log "Couldn't resolve Database reference to a unique live Database in #{db['name']}", MU::ERR, details: rr
              ok = false
            end
          end
        elsif db["member_of_cluster"]
          rr = db["member_of_cluster"]
          if rr['db_name']
            if !database_names.include?(rr['db_name'])
              MU.log "Cluster node #{db['name']} references sibling source #{rr['db_name']}, but I have no such database", MU::ERR
              ok = false
            end
          else
            rr['cloud'] = db['cloud'] if rr['cloud'].nil?
            tag_key, tag_value = rr['tag'].split(/=/, 2) if !rr['tag'].nil?
            found = MU::MommaCat.findStray(
                rr['cloud'],
                "database",
                deploy_id: rr["deploy_id"],
                cloud_id: rr["db_id"],
                tag_key: tag_key,
                tag_value: tag_value,
                region: rr["region"],
                dummy_ok: true
            )
            ext_database = found.first if !found.nil? and found.size == 1
            if !ext_database
              MU.log "Couldn't resolve Database reference to a unique live Database in #{db['name']}", MU::ERR, details: rr
              ok = false
            end
          end
        end
      }

      cache_clusters.each { |cluster|
        cluster['region'] = config['region'] if cluster['region'].nil?
        cluster["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("CacheCluster")
        cluster["dependencies"] = [] if cluster["dependencies"].nil?

        if cluster["creation_style"] != "new" && cluster["identifier"].nil?
          MU.log "creation_style is set to #{cluster['creation_style']} but no identifier was provided. Either set creation_style to new or provide an identifier", MU::ERR
          ok = false
        end

        if cluster.has_key?("parameter_group_parameters") && cluster["parameter_group_family"].nil?
          MU.log "parameter_group_family must be set when setting parameter_group_parameters", MU::ERR
          ok = false
        end
        
        if cluster["size"].nil?
          MU.log "You must specify 'size' when creating a cache cluster.", MU::ERR
          ok = false
        end

        if !cluster.has_key?("node_count")
          MU.log "node_count not specified.", MU::ERR
          ok = false
        end

        if cluster["node_count"] < 1
          MU.log "node_count must be above 1.", MU::ERR
          ok = false
        end

        if cluster["node_count"] > 1 && !cluster["multi_az"]
          MU.log "node_count is set to #{cluster["node_count"]} but multi_az is disbaled. either set multi_az to true or set node_count to 1", MU::ERR
          ok = false
        end

        if cluster["engine"] == "redis"
          # We aren't required to create a cache replication group for a single redis cache cluster, 
          # however AWS console does exactly that, ss such we will follow that behavior.
          cluster["create_replication_group"] = true
          cluster["automatic_failover"] = cluster["multi_az"]

          # Some instance types don't support snapshotting 
          if %w{cache.t2.micro cache.t2.small cache.t2.medium}.include?(cluster["size"])
            if cluster.has_key?("snapshot_retention_limit") || cluster.has_key?("snapshot_window")
              MU.log "Can't set snapshot_retention_limit or snapshot_window on #{cluster["size"]}", MU::ERR
              ok = false
            end
          end
        elsif cluster["engine"] == "memcached"
          cluster["create_replication_group"] = false
          cluster["az_mode"] = cluster["multi_az"] ? "cross-az" : "single-az"

          if cluster["node_count"] > 20
            MU.log "#{cluster['engine']} supports up to 20 nodes per cache cluster", MU::ERR
            ok = false
          end

          # memcached doesn't support snapshots
          if cluster.has_key?("snapshot_retention_limit") || cluster.has_key?("snapshot_window")
            MU.log "Can't set snapshot_retention_limit or snapshot_window on #{cluster["engine"]}", MU::ERR
            ok = false
          end 
        end

        if cluster["alarms"] && !cluster["alarms"].empty?
          cluster["alarms"].each { |alarm|
            alarm["namespace"] = "AWS/ElastiCache" if alarm["namespace"].nil?
            ok = false unless validate_alarm_config(alarm)
          }
        end

        if cluster['ingress_rules']
          fwname = "cache#{cluster['name']}"
          firewall_rule_names << fwname
          acl = {"name" => fwname, "rules" => cluster['ingress_rules'], "region" => cluster['region']}
          acl["vpc"] = cluster['vpc'].dup if cluster['vpc']
          firewall_rules << resolveFirewall.call(acl)
          cluster["add_firewall_rules"] = [] if cluster["add_firewall_rules"].nil?
          cluster["add_firewall_rules"] << {"rule_name" => fwname}
        end

        if cluster["add_firewall_rules"]
          cluster["add_firewall_rules"].each { |acl_include|
            if firewall_rule_names.include?(acl_include["rule_name"])
              cluster["dependencies"] << {
                "type" => "firewall_rule",
                "name" => acl_include["rule_name"]
              }
            end
          }
        end

        if cluster["vpc"] && !cluster["vpc"].empty?
          if cluster["vpc"]["subnet_pref"] and !cluster["vpc"]["subnets"]
            if %w{all any public private}.include? cluster["vpc"]["subnet_pref"]
              MU.log "subnet_pref #{cluster["vpc"]["subnet_pref"]} is not supported for cache clusters.", MU::ERR
              ok = false
            end
          end

          cluster['vpc']['region'] = cluster['region'] if cluster['vpc']['region'].nil?
          cluster["vpc"]['cloud'] = cluster['cloud'] if cluster["vpc"]['cloud'].nil?
          # If we're using a VPC in this deploy, set it as a dependency
          if cluster["vpc"]["vpc_name"] and vpc_names.include?(cluster["vpc"]["vpc_name"]) and cluster["vpc"]["deploy_id"].nil?
            cluster["dependencies"] << {
              "type" => "vpc",
              "name" => cluster["vpc"]["vpc_name"]
            }

            if !processVPCReference(
              cluster["vpc"],
              "cache_cluster #{cluster['name']}",
              dflt_region: config['region'],
              is_sibling: true,
              sibling_vpcs: vpcs
            )
              ok = false
            end
          else
            if !processVPCReference(cluster["vpc"], "cache_cluster #{cluster['name']}", dflt_region: config['region'])
              ok = false
            end
          end
        end

        cluster['dependencies'] << genAdminFirewallRuleset(vpc: cluster['vpc'], region: cluster['region'], cloud: cluster['cloud'])
      }

      alarms.each { |alarm|
        alarm['region'] = config['region'] if alarm['region'].nil?
        alarm["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("Alarm")
        alarm["dependencies"] = [] if alarm["dependencies"].nil?

        if alarm["dimensions"]
          alarm["dimensions"].each{ |dimension|
            if dimension["cloud_class"].nil?
              MU.log "You must specify 'cloud_class'", MU::ERR
              ok = false
            end

            alarm["namespace"] = 
              if dimension["cloud_class"] == "InstanceId"
                "AWS/EC2"
              elsif dimension["cloud_class"] == "DBInstanceIdentifier"
                "AWS/RDS"
              elsif dimension["cloud_class"] == "LoadBalancerName"
                "AWS/ELB"
              elsif dimension["cloud_class"] == "CacheClusterId"
                "AWS/ElastiCache"
              elsif dimension["cloud_class"] == "VolumeId"
                "AWS/EBS"
              elsif dimension["cloud_class"] == "BucketName"
                "AWS/S3"
              elsif dimension["cloud_class"] == "TopicName"
                "AWS/SNS"
              end
          }
        end

        ok = false unless validate_alarm_config(alarm)
      }

      logs.each { |log_rec|
        log_rec['region'] = config['region'] if log_rec['region'].nil?
        log_rec["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("Log")
        log_rec["dependencies"] = [] if log_rec["dependencies"].nil?
        
        if log_rec["filters"] && !log_rec["filters"].empty?
          log_rec["filters"].each{ |filter|
            if filter["namespace"].start_with?("AWS/")
              MU.log "'namespace' can't be under the 'AWS/' namespace", MU::ERR
              ok = false
            end
          }
        end
      }

      servers.each { |server|
        if server_names.include?(server['name'])
          MU.log "Can't use name #{server['name']} more than once in servers/server_pools"
          ok = false
        end
        server_names << server['name']
        server["#MU_CLOUDCLASS"] = Object.const_get("MU").const_get("Cloud").const_get("Server")
        server["#MU_GROOMER"] = MU::Groomer.loadGroomer(server['groomer'])
        server['region'] = config['region'] if server['region'].nil?
        server["dependencies"] = Array.new if server["dependencies"].nil?
        if !server['generate_iam_role']
          if !server['iam_role']
            MU.log "Must set iam_role if generate_iam_role set to false", MU::ERR
            ok = false
          end
          if !server['iam_policies'].nil? and server['iam_policies'].size > 0
            MU.log "Cannot mix iam_policies with generate_iam_role set to false", MU::ERR
            ok = false
          end
        end
        if !server['create_image'].nil?
          if server['create_image'].has_key?('copy_to_regions') and
              (server['create_image']['copy_to_regions'].nil? or
                  server['create_image']['copy_to_regions'].include?("#ALL") or
                  server['create_image']['copy_to_regions'].size == 0
              )
            server['create_image']['copy_to_regions'] = MU::Cloud::AWS.listRegions
          end
        end
        if server['ami_id'].nil?
          if MU::Config.amazon_images.has_key?(server['platform']) and
              MU::Config.amazon_images[server['platform']].has_key?(server['region'])
            server['ami_id'] = MU::Config.amazon_images[server['platform']][server['region']]
          else
            MU.log "No AMI specified for #{server['name']} and no default available for platform #{server['platform']} in region #{server['region']}", MU::ERR, details: server
            ok = false
          end
        end

        if server["alarms"] && !server["alarms"].empty?
          server["alarms"].each { |alarm|
            alarm["namespace"] = "AWS/EC2" if alarm["namespace"].nil?
            ok = false unless validate_alarm_config(alarm)
          }
        end

        server['skipinitialupdates'] = true if @skipinitialupdates
        server['vault_access'] = [] if server['vault_access'].nil?
        server['vault_access'] << {"vault" => "splunk", "item" => "admin_user"}
        ok = false if !check_vault_refs(server)

        if !server['ingress_rules'].nil?
          fwname = "server"+server['name']
          firewall_rule_names << fwname
          acl = {"name" => fwname, "rules" => server['ingress_rules'], "region" => server['region']}
          acl["vpc"] = server['vpc'].dup if !server['vpc'].nil?
          firewall_rules << resolveFirewall.call(acl)
          server["add_firewall_rules"] = [] if server["add_firewall_rules"].nil?
          server["add_firewall_rules"] << {"rule_name" => fwname}
        end

        if server["collection"] != nil
          server["dependencies"] << {
              "type" => "collection",
              "name" => server["collection"]
          }
        end

        if !server["vpc"].nil?
          server['vpc']['region'] = server['region'] if server['vpc']['region'].nil?
          server['vpc']['cloud'] = server['cloud'] if server['vpc']['cloud'].nil?
          # If we're using a local VPC in this deploy, set it as a dependency and get the subnets right
          if !server["vpc"]["vpc_name"].nil? and vpc_names.include?(server["vpc"]["vpc_name"]) and server["vpc"]["deploy_id"].nil?
            server["dependencies"] << {
                "type" => "vpc",
                "name" => server["vpc"]["vpc_name"]
            }

            if server["vpc"]["subnet_name"].nil? and server["vpc"]["subnet_id"].nil? and server["vpc"]["subnet_pref"].nil?
              MU.log "A server VPC block must specify a target subnet", MU::ERR
              ok = false
            end

            if !server["vpc"]["subnet_name"].nil? and nat_routes.has_key?(server["vpc"]["subnet_name"])
              server["dependencies"] << {
                  "type" => "server",
                  "name" => nat_routes[server["vpc"]["subnet_name"]],
                  "phase" => "groom"
              }
            end
            if !processVPCReference(server["vpc"],
                                    "server #{server['name']}",
                                    dflt_region: config['region'],
                                    is_sibling: true,
                                    sibling_vpcs: vpcs)
              ok = false
            end

          else
            # If we're using a VPC from somewhere else, make sure the flippin'
            # thing exists, and also fetch its id now so later search routines
            # don't have to work so hard.
            if !processVPCReference(server["vpc"], "server #{server['name']}", dflt_region: config['region'])
              ok = false
            end
          end
        end

        if !server["add_firewall_rules"].nil?
          server["add_firewall_rules"].each { |acl_include|
            if firewall_rule_names.include?(acl_include["rule_name"])
              server["dependencies"] << {
                  "type" => "firewall_rule",
                  "name" => acl_include["rule_name"]
              }
            end
          }
        end
        if !server["loadbalancers"].nil?
          server["loadbalancers"].each { |lb|
            if lb["concurrent_load_balancer"] != nil
              server["dependencies"] << {
                  "type" => "loadbalancer",
                  "name" => lb["concurrent_load_balancer"]
              }
            end
          }
        end
        server['dependencies'] << genAdminFirewallRuleset(vpc: server['vpc'], region: server['region'], cloud: server['cloud'])
        server["dependencies"].uniq!
      }

      @admin_firewall_rules.each { |acl|
        firewall_rules << resolveFirewall.call(acl)
      }

      config['firewall_rules'] = firewall_rules
      ok = false if !MU::Config.check_dependencies(config)

      # TODO enforce uniqueness of resource names
      raise ValidationError if !ok
    end


    def self.printSchema(dummy_kitten_class, class_hierarchy, schema, in_array = false, required = false)
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

            printme << self.printSchema(dummy_kitten_class, class_hierarchy+ [name], prop, false, req)
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
        docstring = docstring + "# **REQUIRED.**\n" if required
        docstring = docstring + "# #{schema['description'].gsub(/\n/, "\n#")}\n" if !schema['description'].nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "# @see #{class_hierarchy.join("::")}\n"
        docstring = docstring + "attr_accessor :#{name}"
        return docstring

      elsif schema["type"] == "array"
        return self.printSchema(dummy_kitten_class, class_hierarchy, schema['items'], true, required)
      else
        name = class_hierarchy.last
        if schema['type'].nil?
          MU.log "Couldn't determine schema type in #{class_hierarchy}", MU::WARN, details: schema
          return nil
        end
        if in_array
          type = "Array<#{schema['type'].capitalize}>"
        else
          type = schema['type'].capitalize
        end
        docstring = "\n"
        docstring = docstring + "# **REQUIRED.**\n" if required and schema['default'].nil?
        docstring = docstring + "# Default: `#{schema['default']}`\n" if !schema['default'].nil?
        if !schema['enum'].nil?
          docstring = docstring + "# Must be one of: `#{schema['enum'].join(', ')}.`\n"
        elsif !schema['pattern'].nil?
          # XXX unquoted regex chars confuse the hell out of YARD. How do we
          # quote {}[] etc in YARD-speak?
          docstring = docstring + "# Must match pattern `#{schema['pattern'].gsub(/\n/, "\n#")}`.\n"
        end
        docstring = docstring + "# #{schema['description'].gsub(/\n/, "\n#")}\n" if !schema['description'].nil?
        docstring = docstring + "#\n"
        docstring = docstring + "# @return [#{type}]\n"
        docstring = docstring + "attr_accessor :#{name}"

        return docstring
      end

      return nil
    end

    # There's a small amount of variation in the way various resources need to
    # refer to VPCs, so let's wrap them all in a method that'll handle the
    # wiggling.
    NO_SUBNETS = 0.freeze
    ONE_SUBNET = 1.freeze
    MANY_SUBNETS = 2.freeze
    NAT_OPTS = true.freeze
    NO_NAT_OPTS = false.freeze

    def self.vpc_reference_primitive(subnets = MANY_SUBNETS, nat_opts = NAT_OPTS, subnet_pref = nil)
      vpc_ref_schema = {
          "type" => "object",
          "description" => "Deploy, attach, allow access from, or peer this resource with a VPC of VPCs.",
          "minProperties" => 1,
          "additionalProperties" => false,
          "properties" => {
              "vpc_id" => {"type" => "string"},
              "vpc_name" => {"type" => "string"},
              "region" => @region_primitive,
              "cloud" => @cloud_primitive,
              "tag" => {
                  "type" => "string",
                  "description" => "Identify this VPC by a tag (key=value). Note that this tag must not match more than one resource.",
                  "pattern" => "^[^=]+=.+"
              },
              "deploy_id" => {
                  "type" => "string",
                  "description" => "Look for a VPC fitting this description in another Mu deployment with this id.",
              }
          }
      }

      if nat_opts
        vpc_ref_schema["properties"].merge!(
            {
                "nat_host_name" => {"type" => "string"},
                "nat_host_id" => {"type" => "string"},
                "nat_host_ip" => {
                    "type" => "string",
                    "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
                },
                "nat_ssh_user" => {
                    "type" => "string",
                    "default" => "root",
                },
                "nat_ssh_key" => {
                    "type" => "string",
                    "description" => "An alternate SSH private key for access to the NAT. We'll expect to find this in ~/.ssh along with the regular keys.",
                },
                "nat_host_tag" => {
                    "type" => "string",
                    "description" => "Identify a NAT host by a tag (key=value). Note that this tag must not match more than one server.",
                    "pattern" => "^[^=]+=.+"
                }
            }
        )
      end

      if subnets > 0
        vpc_ref_schema["properties"]["subnet_pref"] = {
            "type" => "string",
            "default" => subnet_pref,
            "description" => "When auto-discovering VPC resources, this specifies whether to prefer subnets with or without public internet routes.",
        }

        if subnets == ONE_SUBNET
          vpc_ref_schema["properties"]["subnet_pref"]["enum"] = ["public", "private", "any"]
        elsif subnets == MANY_SUBNETS
          vpc_ref_schema["properties"]["subnet_pref"]["enum"] = ["public", "private", "any", "all", "all_public", "all_private"]
        else
          vpc_ref_schema["properties"]["subnet_pref"]["enum"] = ["public", "private", "any", "all_public", "all_private", "all"]
        end
      end

      if subnets == ONE_SUBNET or subnets == (ONE_SUBNET+MANY_SUBNETS)
        vpc_ref_schema["properties"]["subnet_name"] = {"type" => "string"}
        vpc_ref_schema["properties"]["subnet_id"] = {"type" => "string"}
      end
      if subnets == MANY_SUBNETS or subnets == (ONE_SUBNET+MANY_SUBNETS)
        vpc_ref_schema["properties"]["subnets"] = {
            "type" => "array",
            "items" => {
                "type" => "object",
                "description" => "The subnets to which to attach this resource. Will default to all subnets in this VPC if not specified.",
                "additionalProperties" => false,
                "properties" => {
                    "subnet_name" => {"type" => "string"},
                    "subnet_id" => {"type" => "string"},
                    "tag" => {
                        "type" => "string",
                        "description" => "Identify this subnet by a tag (key=value). Note that this tag must not match more than one resource.",
                        "pattern" => "^[^=]+=.+"
                    }
                }
            }
        }
        if subnets == (ONE_SUBNET+MANY_SUBNETS)
          vpc_ref_schema["properties"]["subnets"]["items"]["description"] = "Extra subnets to which to attach this {MU::Cloud::AWS::Server}. Extra network interfaces will be created to accomodate these attachments."
        end
      end

      return vpc_ref_schema
    end

    @database_ref_primitive = {
        "type" => "object",
        "description" => "Incorporate a database object",
        "minProperties" => 1,
        "additionalProperties" => false,
        "properties" => {
            "db_id" => {"type" => "string"},
            "db_name" => {"type" => "string"},
            "region" => @region_primitive,
            "cloud" => @cloud_primitive,
            "tag" => {
                "type" => "string",
                "description" => "Identify this Database by a tag (key=value). Note that this tag must not match more than one resource.",
                "pattern" => "^[^=]+=.+"
            },
            "deploy_id" => {
                "type" => "string",
                "description" => "Look for a Database fitting this description in another Mu deployment with this id.",
            }
        }
    }


    #		@route_table_reference_primitive = {
    #			"type" => "object",
    #			"description" => "Deploy, attach, or peer this resource with a VPC.",
    #			"minProperties" => 1,
    #			"additionalProperties" => false,
    #			"properties" => {
    #				"vpc_id" => { "type" => "string" },
    #				"vpc_name" => { "type" => "string" },
    #				"tag" => {
    #					"type" => "string",
    #					"description" => "Identify this VPC by a tag (key=value). Note that this tag must not match more than one resource.",
    #					"pattern" => "^[^=]+=.+"
    #				},
    #				"deploy_id" => {
    #					"type" => "string",
    #					"description" => "Look for a VPC fitting this description in another Mu deployment with this id.",
    #				}
    #			}
    #		}


    @region_primitive = {
        "type" => "string",
        "enum" => MU::Cloud::AWS.listRegions
    }

    @cloud_primitive = {
        "type" => "string",
        "default" => MU::Config.defaultCloud,
        "enum" => MU::Cloud.supportedClouds
    }

    @dependencies_primitive = {
        "type" => "array",
        "items" => {
            "type" => "object",
            "description" => "Declare other server or database objects which this server requires. This server will wait to finish bootstrapping until those dependent resources become available.",
            "required" => ["name", "type"],
            "additionalProperties" => false,
            "properties" => {
                "name" => {"type" => "string"},
                "type" => {
                    "type" => "string",
                    "enum" => ["server", "database", "server_pool", "loadbalancer", "collection", "firewall_rule", "vpc", "dnszone", "cache_cluster"]
                },
                "phase" => {
                    "type" => "string",
                    "description" => "Which part of the creation process of the resource we depend on should we wait for before starting our own creation? Defaults are usually sensible, but sometimes you want, say, a Server to wait on another Server to be completely ready (through its groom phase) before starting up.",
                    "enum" => ["create", "groom"]
                }
            }
        }
    }

    @tags_primitive = {
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

    @cidr_pattern = "^\\d+\\.\\d+\\.\\d+\\.\\d+\/[0-9]{1,2}$"
    @cidr_description = "CIDR-formatted IP block, e.g. 1.2.3.4/32"
    @cidr_primitive = {
        "type" => "string",
        "pattern" => @cidr_pattern,
        "description" => @cidr_description
    }

    @route_primitive = {
        "type" => "object",
        "description" => "Define a network route, typically for use inside a VPC.",
        "properties" => {
            "destination_network" => {
                "type" => "string",
                "pattern" => @cidr_pattern,
                "description" => @cidr_description,
                "default" => "0.0.0.0/0"
            },
            "peer_id" => {
                "type" => "string",
                "description" => "The ID of a VPC peering connection to use as a gateway"
            },
            "gateway" => {
                "type" => "string",
                "description" => "The ID of a VPN or Internet gateway attached to your VPC. You must provide either gateway or NAT host, but not both. #INTERNET will refer to this VPC's default internet gateway, if one exists. #NAT will refer to a this VPC's NAT gwateway",
                "default" => "#INTERNET"
            },
            "nat_host_id" => {
                "type" => "string",
                "description" => "The instance id of a NAT host in this VPN."
            },
            "nat_host_name" => {
                "type" => "string",
                "description" => "The MU resource name or Name tag of a NAT host in this VPN."
            },
            "interface" => {
                "type" => "string",
                "description" => "A network interface over which to route."
            }
        }
    }

    @flowlogs_primitive = {
      "traffic_type_to_log" => {
        "type" => "string",
        "description" => "The class of traffic to log - accepted traffic, rejected traffic or all traffic.",
        "enum" => ["accept", "reject", "all"],
        "default" => "all"
      },
      "log_group_name" => {
        "type" => "string",
        "description" => "An existing CloudWachLogs log group the traffic will be logged to. If not provided, a new one will be created"
      },
      "enable_traffic_logging" => {
        "type" => "boolean",
        "description" => "If traffic logging is enabled or disabled. Will be enabled on all subnets and network interfaces if set to true on a VPC",
        "default" => false
      }
      }

    @vpc_primitive = {
        "type" => "object",
        "required" => ["name"],
        "additionalProperties" => false,
        "description" => "Create Virtual Private Clouds with custom public or private subnets.",
        "properties" => {
            "name" => {"type" => "string"},
            "cloud" => @cloud_primitive,
            "ip_block" => {
                "type" => "string",
                "pattern" => @cidr_pattern,
                "description" => @cidr_description,
                "default" => "10.0.0.0/16"
            },
            "tags" => @tags_primitive,
            "create_internet_gateway" => {
                "type" => "boolean",
                "default" => true
            },
            "create_nat_gateway" => {
                "type" => "boolean",
                "description" => "If set to 'true' will create a NAT gateway to enable traffic in private subnets to be routed to the internet.",
                "default" => false
            },
            "enable_dns_support" => {
                "type" => "boolean",
                "default" => true
            },
            "endpoint_policy" => {
                "type" => "array",
                "items" => {
                    "description" => "Amazon-compatible endpoint policy that controls access to the endpoint by other resources in the VPC. If not provided Amazon will create a default policy that provides full access.",
                    "type" => "object"
                }
            },
            "endpoint" => {
                "type" => "string",
                "description" => "An Amazon service specific endpoint that resources within a VPC can route to without going through a NAT or an internet gateway. Currently only S3 is supported. an example S3 endpoint in the us-east-1 region: com.amazonaws.us-east-1.s3."
            },
            "enable_dns_hostnames" => {
                "type" => "boolean",
                "default" => true
            },
            "nat_gateway_multi_az" => {
              "type" => "boolean",
              "description" => "If set to 'true' will create a separate NAT gateway in each availability zone and configure subnet route tables appropriately",
              "default" => false
            },
            "dependencies" => @dependencies_primitive,
            "auto_accept_peers" => {
                "type" => "boolean",
                "description" => "Peering connections requested to this VPC by other deployments on the same Mu master will be automatically accepted.",
                "default" => true
            },
            "peers" => {
                "type" => "array",
                "description" => "One or more other VPCs with which to attempt to create a peering connection.",
                "items" => {
                    "type" => "object",
                    "required" => ["vpc"],
                    "description" => "One or more other VPCs with which to attempt to create a peering connection.",
                    "properties" => {
                        "account" => {
                            "type" => "string",
                            "description" => "The AWS account which owns the target VPC."
                        },
                        "vpc" => vpc_reference_primitive(MANY_SUBNETS, NO_NAT_OPTS, "all")
                        #							"route_tables" => {
                        #								"type" => "array",
                        #								"items" => {
                        #									"type" => "string",
                        #									"description" => "The name of a route to which to add a route for this peering connection. If none are specified, all available route tables will have approprite routes added."
                        #								}
                        #							}
                    }
                }
            },
            "route_tables" => {
                "type" => "array",
                "items" => {
                    "type" => "object",
                    "required" => ["name", "routes"],
                    "description" => "A table of route entries, typically for use inside a VPC.",
                    "properties" => {
                        "name" => {"type" => "string"},
                        "routes" => {
                            "type" => "array",
                            "items" => @route_primitive
                        }
                    }
                }
            },
            "subnets" => {
                "type" => "array",
                "items" => {
                    "type" => "object",
                    "required" => ["name", "ip_block"],
                    "description" => "A list of subnets",
                    "properties" => {
                        "name" => {"type" => "string"},
                        "ip_block" => @cidr_primitive,
                        # XXX what does the API do if we don't set this? pick one at random?
                        "availability_zone" => {"type" => "string"},
                        "route_table" => {"type" => "string"},
                        "map_public_ips" => {
                            "type" => "boolean",
                            "description" => "If the cloud provider's instances should automatically be assigned publicly routable addresses.",
                            "default" => false
                        }
                    }
                }
            },
            "dhcp" => {
                "type" => "object",
                "description" => "Alternate DHCP behavior for nodes in this VPC",
                "additionalProperties" => false,
                "properties" => {
                    "dns_servers" => {
                        "type" => "array",
                        "minItems" => 1,
                        "maxItems" => 4,
                        "items" => {
                            "type" => "string",
                            "description" => "The IP address of up to four DNS servers",
                            "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
                        }
                    },
                    "ntp_servers" => {
                        "type" => "array",
                        "minItems" => 1,
                        "maxItems" => 4,
                        "items" => {
                            "type" => "string",
                            "description" => "The IP address of up to four NTP servers",
                            "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
                        }
                    },
                    "netbios_servers" => {
                        "type" => "array",
                        "minItems" => 1,
                        "maxItems" => 4,
                        "items" => {
                            "type" => "string",
                            "description" => "The IP address of up to four NetBIOS servers",
                            "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
                        }
                    },
                    "netbios_type" => {
                        "type" => "integer",
                        "enum" => [1, 2, 4, 8],
                        "default" => 2
                    },
                    "domains" => {
                        "type" => "array",
                        "minItems" => 1,
                        "items" => {
                            "type" => "string",
                            "description" => "If you're using AmazonProvidedDNS in us-east-1, specify ec2.internal. If you're using AmazonProvidedDNS in another region, specify region.compute.internal (for example, ap-northeast-1.compute.internal). Otherwise, specify a domain name (for example, MyCompany.com)."
                        }
                    }
                }
            }
        }
    }

    @vpc_primitive["properties"].merge!(@flowlogs_primitive)
    @vpc_primitive["properties"]["subnets"]["items"]["properties"].merge!(@flowlogs_primitive)

    @ec2_size_primitive = {
        # XXX maybe we shouldn't validate this, but it makes a good example
        "pattern" => "^(t|m|c|i|g|r|hi|hs|cr|cg|cc){1,2}[0-9]\\.(nano|micro|small|medium|[248]?x?large)$",
        "description" => "The Amazon EC2 instance type to use when creating this server.",
        "type" => "string"
    }
    @eleasticache_size_primitive = {
        "pattern" => "^cache\.(t|m|c|i|g|hi|hs|cr|cg|cc){1,2}[0-9]\\.(micro|small|medium|[248]?x?large)$",
        "type" => "string",
        "description" => "The Amazon EleastiCache instance type to use when creating this cache cluster.",
    }
    @rds_size_primitive = {
        "pattern" => "^db\.(t|m|c|i|g|r|hi|hs|cr|cg|cc){1,2}[0-9]\\.(micro|small|medium|[248]?x?large)$",
        "type" => "string",
        "description" => "The Amazon RDS instance type to use when creating this database instance.",
    }

    @rds_parameters_primitive = {
        "type" => "array",
        "minItems" => 1,
        "items" => {
            "description" => "The database parameter group parameter to change and when to apply the change.",
            "type" => "object",
            "title" => "Database Parameter",
            "required" => ["name", "value"],
            "additionalProperties" => false,
            "properties" => {
                "name" => {
                    "type" => "string"
                },
                "value" => {
                    "type" => "string"
                },
                "apply_method" => {
                    "enum" => ["pending-reboot", "immediate"],
                    "default" => "immediate",
                    "type" => "string"
                }
            }
        }
    }

    @eleasticache_parameters_primitive = {
        "type" => "array",
        "minItems" => 1,
        "items" => {
            "description" => "The cache cluster parameter group parameter to change and when to apply the change.",
            "type" => "object",
            "title" => "Cache Cluster Parameter",
            "required" => ["name", "value"],
            "additionalProperties" => false,
            "properties" => {
                "name" => {
                    "type" => "string"
                },
                "value" => {
                    "type" => "string"
                }
            }
        }
    }

    @firewall_ruleset_rule_primitive = {
        "type" => "object",
        "description" => "Network ingress and/or egress rules.",
        "additionalProperties" => false,
        "properties" => {
            "port_range" => {"type" => "string"},
            "port" => {"type" => "integer"},
            "proto" => {
                "enum" => ["udp", "tcp", "icmp"],
                "default" => "tcp",
                "type" => "string"
            },
            "ingress" => {
                "type" => "boolean",
                "default" => true
            },
            "egress" => {
                "type" => "boolean",
                "default" => false
            },
            "hosts" => {
                "type" => "array",
                "items" => @cidr_primitive
            },
            "sgs" => {
                "type" => "array",
                "items" => {
                    "type" => "string",
                    "description" => "Other AWS Security Groups to add to this one"
                }
            },
            "lbs" => {
                "type" => "array",
                "items" => {
                    "type" => "string",
                    "description" => "The name of a Load Balancer to allow in (via its IP)"
                }
            }
        }
    }


    @firewall_ruleset_primitive = {
        "type" => "object",
        "required" => ["name"],
        "additionalProperties" => false,
        "description" => "Create network-level access controls.",
        "properties" => {
            "name" => {"type" => "string"},
            "cloud" => @cloud_primitive,
            "vpc_name" => {
                "type" => "string",
                "description" => "Backwards-compatibility means of identifying a VPC; see {MU::Config::BasketofKittens::firewall_rules::vpc}"
            },
            "vpc_id" => {
                "type" => "string",
                "description" => "Backwards-compatibility means of identifying a VPC; see {MU::Config::BasketofKittens::firewall_rules::vpc}"
            },
            "vpc" => vpc_reference_primitive(NO_SUBNETS, NO_NAT_OPTS),
            "tags" => @tags_primitive,
            "dependencies" => @dependencies_primitive,
            "self_referencing" => {
                "type" => "boolean",
                "default" => false
            },
            "rules" => {
                "type" => "array",
                "items" => @firewall_ruleset_rule_primitive
            }
        }
    }

    @additional_firewall_rules = {
        "type" => "array",
        "items" => {
            "type" => "object",
            "additionalProperties" => false,
            "description" => "Apply one or more network rulesets, defined in this stack or pre-existing, to this resource. Note that if you add a pre-existing ACL to your resource, they must be compatible (e.g. if using VPCs, they must reside in the same VPC).",
            "minProperties" => 1,
            "properties" => {
                "rule_id" => {"type" => "string"},
                "rule_name" => {"type" => "string"}
            }
        }
    }

    @storage_primitive = {
        "type" => "array",
        "items" => {
            "type" => "object",
            "description" => "Creates and attaches an EBS volume to this instance.",
            "required" => ["size"],
            "additionalProperties" => false,
            "properties" => {
                "size" => {
                    "type" => "integer",
                    "description" => "Size of this EBS volume (GB)",
                },
                "iops" => {
                    "type" => "integer",
                    "description" => "The amount of IOPS to allocate to Provisioned IOPS (io1) volumes.",
                },
                "device" => {
                    "type" => "string",
                    "description" => "Map this volume to a specific OS-level device (e.g. /dev/sdg)",
                },
                "virtual_name" => {
                    "type" => "string",
                },
                "snapshot_id" => {
                    "type" => "string",
                },
                "delete_on_termination" => {
                    "type" => "boolean",
                    "default" => true
                },
                "no_device" => {
                    "type" => "string",
                    "description" => "Do not share this device with the OS"
                },
                "encrypted" => {
                    "type" => "boolean",
                    "default" => false
                },
                "volume_type" => {
                    "enum" => ["standard", "io1", "gp2"],
                    "type" => "string",
                    "default" => "gp2"
                }
            }
        }
    }

    # We want to have a default email to send SNS notifications
    sns_notification_email = 
      if MU.chef_user == "mu"
        ENV['MU_ADMIN_EMAIL']
      else
        MU.userEmail
      end

    @alarm_common_properties = {
        "name" => {
            "type" => "string"
        },
        "ok_actions" => {
            "type" => "array",
            "minItems" => 1,
            "description" => "What action(s) to take when alarm state transitions to 'OK'.",
            "items" => {
                "type" => "String"
            }
        },
        "alarm_actions" => {
            "type" => "array",
            "minItems" => 1,
            "description" => "What action(s) to take when alarm state transitions to 'ALARM'.",
            "items" => {
                "type" => "String"
            }
        },
        "no_data_actions" => {
            "type" => "array",
            "minItems" => 1,
            "description" => "What action(s) to take when alarm state transitions to 'INSUFFICIENT'.",
            "items" => {
                "type" => "String"
            }
        },
        "metric_name" => {
            "type" => "string",
            "description" => "The name of the attribute to monitor eg. CPUUtilization."
        },
        "namespace" => {
            "type" => "string",
            "description" => "The name of container 'metric_name' belongs to eg. 'AWS/EC2'"
        },
        "statistic" => {
            "type" => "string",
            "description" => "",
            "enum" => ["SampleCount", "Average", "Sum", "Minimum", "Maximum"]
        },
        "dimensions" => {
            "type" => "array",
            "description" => "What to monitor",
            "minItems" => 1,
            "items" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "What to monitor",
                "properties" => {
                    "cloud_class" => {
                        "type" => "string",
                        "description" => "eg InstanceId, DBInstanceIdentifier",
                    },
                    "cloud_id" => {
                        "type" => "string",
                        "description" => "The cloud identifier of the resource the alarm is being created for. eg - i-d96eca0d. Must use either 'cloud_id' OR 'mu_name' AND 'deploy_id'"
                    },
                    "mu_name" => {
                        "type" => "string",
                        "description" => "Should also include 'deploy_id' so we will be able to identifiy a sinlge resource. Use either 'cloud_id' OR 'mu_name' and 'deploy_id'"
                    },
                    "deploy_id" => {
                        "type" => "string",
                        "description" => "Should also include 'mu_name' so we will be able to identifiy a sinlge resource. Use either 'cloud_id' OR 'mu_name' and 'deploy_id'"
                    }
                }
            }  
        },
        "period" => {
            "type" => "integer",
            "description" => "The time, in seconds the 'statistic' is checked/tested. Must be multiples of 60"
        },
        "unit" => {
            "type" => "string",
            "description" => "Associated with the 'metric'",
            "enum" => ["Seconds", "Microseconds", "Milliseconds", "Bytes", "Kilobytes", "Megabytes", "Gigabytes", "Terabytes", "Bits", "Kilobits", "Megabits", "Gigabits", "Terabits", "Percent", "Count", "Bytes/Second", 
                                "Kilobytes/Second", "Megabytes/Second", "Gigabytes/Second", "Terabytes/Second", "Bits/Second", "Kilobits/Second", "Megabits/Second", "Gigabits/Second", "Terabits/Second", "Count/Second", "nil"]
        },
        "evaluation_periods" => {
            "type" => "integer",
            "description" => "The number of times to repeat the 'period' before changing the state of an alarm. eg form 'OK' to 'ALARM' state"
        },
        "threshold" => {
        # TO DO: This should be a float
            "type" => "integer",
            "description" => "The value the 'statistic' is compared to and action (eg 'alarm_actions') will be invoked "
        },
        "comparison_operator" => {
            "type" => "string",
            "description" => "The arithmetic operation to use when comparing 'statistic' and 'threshold'. The 'statistic' value is used as the first operand",
            "enum" => ["GreaterThanOrEqualToThreshold", "GreaterThanThreshold", "LessThanThreshold", "LessThanOrEqualToThreshold"]
        },
        # TO DO: Separate all of these to an SNS primitive
        "enable_notifications" => {
            "type" => "boolean",
            "description" => "Rather to send notifications when the alarm state changes"
        },
        "notification_group" => {
            "type" => "string",
            "description" => "The name of the notification group. Will be created if it doesn't exist. We use / create a default one if not specified. NOTE: because we can't confirm subscription to a group programmatically, you should use an existing group",
            "default" => "mu-default"
        },
        "notification_type" => {
            "type" => "string",
            "description" => "What type of notification endpoint will the notification be sent to. defaults to 'email'",
            "enum" => ["http", "https", "email", "email-json", "sms", "sqs", "application"],
            "default" => "email"
        },
        "notification_endpoint" => {
            "type" => "string",
            "description" => "The endpoint the notification will be sent to. eg. if notification_type is 'email'/'email-json' the endpoint will be the email address. A confirmation email will be sent to this email address if a new notification_group is created, if not specified and notification_type is set to 'email' we will use the mu-master email address",
            "default_if" => [
                {
                    "key_is" => "notification_type",
                    "value_is" => "email",
                    "set" => sns_notification_email
                },
                {
                    "key_is" => "notification_type",
                    "value_is" => "email-json",
                    "set" => sns_notification_email
                }
            ]              
        }
    }

    @alarm_primitive = {
        "type" => "object",
        "title" => "CloudWatch Monitoring",
        "additionalProperties" => false,
        "description" => "Create Amazon CloudWatch alarms.",
        "properties" => {
          "cloud" => @cloud_primitive,
          "region" => @region_primitive,
          "dependencies" => @dependencies_primitive
        }
    }
    @alarm_primitive["properties"].merge!(@alarm_common_properties)

    @alarm_common_primitive = {
        "type" => "array",
        "minItems" => 1,
        "items" => {
            "description" => "Create a CloudWatch Alarm.",
            "type" => "object",
            "title" => "CloudWatch Alarm Parameters",
            "required" => ["name", "metric_name", "statistic", "period", "evaluation_periods", "threshold", "comparison_operator"],
            "additionalProperties" => false,
            "properties" => {
            }
        }
    }
    @alarm_common_primitive["items"]["properties"].merge!(@alarm_common_properties)

    @cloudwatchlogs_filter_primitive = {
      "type" => "array",
      "minItems" => 1,
      "items" => {
        "description" => "Create a filter on a CloudWachLogs log group.",
        "type" => "object",
        "title" => "CloudWatchLogs filter Parameters",
        "required" => ["name", "search_pattern", "metric_name", "namespace", "value"],
        "additionalProperties" => false,
        "properties" => {
          "name" => {
              "type" => "string"
          },
          "search_pattern" => {
              "type" => "string",
              "description" => "A search pattern that will match values in the log"
          },
          "metric_name" => {
              "type" => "string",
              "description" => "A descriptive and easy to find name for the metric. This can be used to create Alarm(s)"
          },
          "namespace" => {
              "type" => "string",
              "description" => "A new or existing name space to add the metric to. Use the same namespace for all filters/metrics that are logically grouped together. Will be used to to create Alarm(s)"
          },
          "value" => {
              "type" => "string",
              "description" => ""
          }
        }
      }
    }

    @log_primitive = {
      "type" => "object",
      "title" => "CloudWatch Logs",
      "additionalProperties" => false,
      "description" => "Log events using CloudWatch Logs.",
      "properties" => {
        "name" => {
          "type" => "string"
        },
        "cloud" => @cloud_primitive,
        "region" => @region_primitive,
        "dependencies" => @dependencies_primitive,
        "retention_period" => {
          "type" => "integer",
          "description" => "The number of days to keep log events in the log group before deleting them.",
          "default" => 14,
          "enum" => [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653]
        },
        "enable_cloudtrail_logging"=> {
          "type" => "boolean",
          "default" => false
        },
        "filters" => @cloudwatchlogs_filter_primitive
      }
    }

    @cloudformation_primitive = {
        "type" => "object",
        "title" => "cloudformation",
        "required" => ["name", "on_failure"],
        "additionalProperties" => false,
        "description" => "Create an Amazon CloudFormation stack.",
        "properties" => {
            "name" => {"type" => "string"},
            "parameters" => {
                "type" => "array",
                "items" => {
                    "type" => "object",
                    "description" => "set cloudformation template parameter",
                    "required" => ["parameter_key", "parameter_value"],
                    "additionalProperties" => false,
                    "properties" => {
                        "parameter_key" => {"type" => "string"},
                        "parameter_value" => {"type" => "string"}
                    }
                }
            },
            "pass_deploy_key_as" => {
                "type" => "string",
                "description" => "Pass in the deploy key for this stack as a CloudFormation parameter. Set this to the CloudFormation parameter name.",
            },
            "on_failure" => {
                "type" => "string",
                "enum" => ["DO_NOTHING", "ROLLBACK", "DELETE"]
            },
            "template_file" => {"type" => "string"},
            "time" => {"type" => "string"},
            "template_url" => {
                "type" => "string",
                "pattern" => "^#{URI::regexp(%w(http https))}$"
            },
            "creation_style" => {
                "type" => "string",
                "enum" => ["existing", "new"]
            }
        }
    }

    @userdata_primitive = {
        "type" => "object",
        "description" => "A script to be run during the bootstrap process. Typically used to preconfigure Windows instances.",
        "required" => ["path"],
        "additionalProperties" => false,
        "properties" => {
            "use_erb" => {
                "type" => "boolean",
                "default" => true,
                "description" => "Assume that this script is an ERB template and parse it as one before passing to the instance."
            },
            "path" => {
                "type" => "string",
                "description" => "A local path or URL to a file which will be loaded and passed to the instance. Relative paths will be resolved from the current working directory of the deploy tool when invoked."
            }
        }
    }

    @static_ip_primitive = {
        "type" => "object",
        "additionalProperties" => false,
        "minProperties" => 1,
        "description" => "Assign a specific IP to this instance once it's ready.",
        "properties" => {
            "ip" => {
                "type" => "string",
                "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$",
            },
            "assign_ip" => {
                "type" => "boolean",
                "default" => true
            }
        }
    }

    @loadbalancer_reference_primitive = {
        "type" => "array",
        "minItems" => 1,
        "items" => {
            "type" => "object",
            "minProperties" => 1,
            "maxProperties" => 1,
            "additionalProperties" => false,
            "description" => "One or more Load Balancers with which this instance should register.",
            "properties" => {
                "concurrent_load_balancer" => {
                    "type" => "string",
                    "description" => "The name of a MU loadbalancer object, which should also defined in this stack. This will be added as a dependency."
                },
                "existing_load_balancer" => {
                    "type" => "string",
                    "description" => "The DNS name of an existing Elastic Load Balancer. Must be in the same region as this deployment."
                }
            }
        }
    }

    def self.dns_records_primitive(need_target: true, default_type: nil, need_zone: false)
      dns_records_primitive = {
          "type" => "array",
          "maxItems" => 100,
          "items" => {
              "type" => "object",
              "required" => ["target", "type"],
              "additionalProperties" => false,
              "description" => "DNS records to create. If specified inside another resource (e.g. {MU::Config::BasketofKittens::servers}, {MU::Config::BasketofKittens::loadbalancers}, or {MU::Config::BasketofKittens::databases}), the record(s) will automatically target that resource.",
              "properties" => {
                  "override_existing" => {
                      "type" => "boolean",
                      "description" => "If true, this record will overwrite any existing record of the same name and type.",
                      "default" => false
                  },
                  "type" => {
                      "type" => "string",
                      "description" => "The class of DNS record to create. The R53ALIAS type is not traditional DNS, but instead refers to AWS Route53's alias functionality. An R53ALIAS is only valid if the target is an Elastic LoadBalancer, CloudFront, S3 bucket (configured as a public web server), or another record in the same Route53 hosted zone.",
                      "enum" => ["SOA", "A", "TXT", "NS", "CNAME", "MX", "PTR", "SRV", "SPF", "AAAA", "R53ALIAS"]
                  },
                  "alias_zone" => {
                      "type" => "string",
                      "description" => "If using a type of R53ALIAS, this is the hosted zone ID of the target. Defaults to the zone to which this record is being added."
                  },
                  "deploy_id" => {
                    "type" => "string",
                    "description" => "Look for a resource in another Mu deployment with this id. Requires mu_type",
                  },
                  "mu_type" => {
                    "type" => "string",
                    "description" => "The Mu resource type to search the deployment for.",
                      "enum" => ["loadbalancer", "server", "database", "cache_cluster"]
                  },
                  "target_type" => {
                      "description" => "If the target is a public or a private resource. This only applies to servers/server_pools when using automatic DNS registration. If set to public but the target only has a private address, the private address will be used",
                      "type" => "string",
                      "enum" => ["public", "private"]
                  },
                  "weight" => {
                      "type" => "integer",
                      "description" => "Set the proportion of traffic directed to this target, based on the relative weight of other records with the same DNS name and type."
                  },
                  "region" => {
                      "type" => "string",
                      "enum" => MU::Cloud::AWS.listRegions,
                      "description" => "Set preferred region for latency-based routing."
                  },
                  "failover" => {
                      "type" => "string",
                      "description" => "Failover classification",
                      "enum" => ["PRIMARY", "SECONDARY"]
                  },
                  "ttl" => {
                      "type" => "integer",
                      "description" => "DNS time-to-live value for query caching.",
                      "default" => 7200
                  },
                  "target" => {
                      "type" => "string",
                      "description" => "The value of this record. Must be valid for the 'type' field, e.g. A records must point to an IP address. If creating a record for an existing deployment, specify the mu_name of the resource, you must also specifiy deploy_id and mu_type",
                  },
                  "name" => {
                      "description" => "Name of the record to create. If not specified, will default to the Mu resource name.",
                      "type" => "string",
                      "pattern" => "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
                  },
                  "append_environment_name" => {
                      "description" => "If to append the environment name (eg mydnsname.dev.mudomain.com). to the DNS name",
                      "type" => "boolean",
                      "default" => false
                  },
                  "geo_location" => {
                      "type" => "object",
                      "description" => "Set location for location-based routing.",
                      "additionalProperties" => false,
                      "properties" => {
                          "continent_code" => {
                              "type" => "string",
                              "description" => "The code for a continent geo location. Note: only continent locations have a continent code. Specifying continent_code with either country_code or subdivision_code returns an InvalidInput error.",
                              "enum" => ["AF", "AN", "AS", "EU", "OC", "NA", "SA"]
                          },
                          "country_code" => {
                              "type" => "string",
                              "description" => "The code for a country geo location. The default location uses '' for the country code and will match all locations that are not matched by a geo location. All other country codes follow the ISO 3166 two-character code."
                          },
                          "subdivision_code" => {
                              "type" => "string",
                              "description" => "The code for a country's subdivision (e.g., a province of Canada). A subdivision code is only valid with the appropriate country code. Specifying subdivision_code without country_code returns an InvalidInput error."
                          }
                      }
                  },
                  "healthcheck" => {
                      "type" => "object",
                      "required" => ["method"],
                      "description" => "Check used to determine instance health for failover routing.",
                      "additionalProperties" => false,
                      "properties" => {
                          "method" => {
                              "type" => "string",
                              "description" => "The health check method to use",
                              "enum" => ["HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH", "TCP"]
                          },
                          "port" => {
                              "type" => "integer",
                              "description" => "Port on which this health check should expect to find a working service.  For HTTP and HTTP_STR_MATCH this defaults to 80 if the port is not specified. For HTTPS and HTTPS_STR_MATCH this defaults to 443 if the port is not specified.",
                          },
                          "path" => {
                              "type" => "string",
                              "description" => "Path to check for HTTP-based health checks."
                          },
                          "search_string" => {
                              "type" => "string",
                              "description" => "Path to check for STR_MATCH-based health checks."
                          },
                          "check_interval" => {
                              "type" => "integer",
                              "description" => "The frequency of health checks.",
                              "default" => 30,
                              "enum" => [10, 30]
                          },
                          "failure_threshold" => {
                              "type" => "integer",
                              "description" => "The number of failed health checks before we consider this entry in failure.",
                              "default" => 2,
                              "pattern" => "^[01]?\\d$"
                          }
                      }
                  }
              }
          }
      }

      if !need_target
        dns_records_primitive["items"]["required"].delete("target")
        dns_records_primitive["items"]["properties"].delete("target")
      end

      if need_zone
        dns_records_primitive["items"]["required"] << "zone"
        dns_records_primitive["items"]["properties"]["zone"] = {
            "type" => "object",
            "additionalProperties" => false,
            "minProperties" => 1,
            "description" => "The zone to which to add this record, either as a domain name or as a Route53 zone identifier.",
            "properties" => {
                "name" => {
                    "type" => "string",
                    "description" => "The domain name of the DNS zone to which to add this record."
                },
                "id" => {
                    "type" => "string",
                    "description" => "The Route53 identifier of the zone to which to add this record."
                }
            }
        }
      end

      if !default_type.nil?
        dns_records_primitive["items"]["properties"]["type"]["default"] = default_type
        dns_records_primitive["items"]["required"].delete("type")
      end

      return dns_records_primitive
    end


    # properties common to both server and server_pool resources
    @server_common_properties = {
        "name" => {"type" => "string"},
        "region" => @region_primitive,
        "cloud" => @cloud_primitive,
        "async_groom" => {
            "type" => "boolean",
            "default" => false,
            "description" => "Bootstrap asynchronously via the Momma Cat daemon instead of during the main deployment process"
        },
        "groomer" => {
            "type" => "string",
            "default" => MU::Config.defaultGroomer,
            "enum" => MU.supportedGroomers
        },
        "tags" => @tags_primitive,
        "alarms" => @alarm_common_primitive,
        "active_directory" => {
            "type" => "object",
            "additionalProperties" => false,
            "required" => ["domain_name", "short_domain_name", "domain_controllers", "domain_join_vault", "domain_admin_vault"],
            "description" => "Integrate this node into an Active Directory domain. On Linux, will configure Winbind and PAM for system-level AD authentication.",
            "properties" => {
                "domain_name" => {
                    "type" => "string",
                    "description" => "The full name Active Directory domain to join"
                },
                "short_domain_name" => {
                    "type" => "string",
                    "description" => "The short (NetBIOS) Active Directory domain to join"
                },
                "domain_controllers" => {
                    "type" => "array",
                    "minItems" => 1,
                    "items" => {
                        "type" => "string",
                        "description" => "IP address of a domain controller"
                    }
                },
                "domain_controller_hostname" => {
                    "type" => "string",
                    "description" => "A custom hostname for your domain controller. mu_windows_name will be used if not specified. Do not specify when joining a Domain-Node"
                },
                "domain_operation" => {
                    "type" => "string",
                    "default" => "join",
                    "enum" => ["join", "create", "add_controller"],
                    "description" => "Rather to join, create or add a Domain Controller"
                },
                "node_type" => {
                    "type" => "string",
                    "enum" => ["domain_node", "domain_controller"],
                    "description" => "If the node will be a domain controller or a domain node",
                    "default" => "domain_node",
                    "default_if" => [
                        {
                            "key_is" => "domain_operation",
                            "value_is" => "create",
                            "set" => "domain_controller"
                        },
                        {
                            "key_is" => "domain_operation",
                            "value_is" => "add_controller",
                            "set" => "domain_controller"
                        },
                        {
                            "key_is" => "domain_operation",
                            "value_is" => "join",
                            "set" => "domain_node"
                        }
                    ]
                },
                "computer_ou" => {
                    "type" => "string",
                    "description" => "The OU to which to add this computer when joining the domain."
                },
                "domain_join_vault" => {
                    "type" => "object",
                    "additionalProperties" => false,
                    "description" => "Vault used to store the credentials for the domain join user",
                    "properties" => {
                        "vault" => {
                            "type" => "string",
                            "default" => "active_directory",
                            "description" => "The vault where these credentials reside"
                        },
                        "item" => {
                            "type" => "string",
                            "default" => "join_domain",
                            "description" => "The vault item where these credentials reside"
                        },
                        "password_field" => {
                            "type" => "string",
                            "default" => "password",
                            "description" => "The field within the Vault item where the password for these credentials resides"
                        },
                        "username_field" => {
                            "type" => "string",
                            "default" => "username",
                            "description" => "The field where the user name for these credentials resides"
                        }
                    }
                },
                "domain_admin_vault" => {
                    "type" => "object",
                    "additionalProperties" => false,
                    "description" => "Vault used to store the credentials for the domain admin user",
                    "properties" => {
                        "vault" => {
                            "type" => "string",
                            "default" => "active_directory",
                            "description" => "The vault where these credentials reside"
                        },
                        "item" => {
                            "type" => "string",
                            "default" => "domain_admin",
                            "description" => "The vault item where these credentials reside"
                        },
                        "password_field" => {
                            "type" => "string",
                            "default" => "password",
                            "description" => "The field within the Vault item where the password for these credentials resides"
                        },
                        "username_field" => {
                            "type" => "string",
                            "default" => "username",
                            "description" => "The field where the user name for these credentials resides"
                        }
                    }
                }
            }
        },
        "add_private_ips" => {
            "type" => "integer",
            "description" => "Assign extra private IP addresses to this server."
        },
        "skipinitialupdates" => {
            "type" => "boolean",
            "description" => "Node bootstrapping normally runs an internal recipe that does a full system update. This is very slow for testing, so let's have an option to disable it.",
            "default" => false
        },
        "sync_siblings" => {
            "type" => "boolean",
            "description" => "If true, chef-client will automatically re-run on nodes of the same type when this instance has finished grooming. Use, for example, to add new members to a database cluster in an autoscale group by sharing data in Chef's node structures.",
            "default" => false
        },
        "dns_sync_wait" => {
            "type" => "boolean",
            "description" => "Wait for DNS record to propagate in DNS Zone.",
            "default" => true,
        },
        "loadbalancers" => @loadbalancer_reference_primitive,
        "dependencies" => @dependencies_primitive,
        "add_firewall_rules" => @additional_firewall_rules,
        "static_ip" => @static_ip_primitive,
        "src_dst_check" => {
            "type" => "boolean",
            "description" => "Turn off network-level routing paranoia. Set this false to make a NAT do its thing.",
            "default" => true
        },
        "associate_public_ip" => {
            "type" => "boolean",
            "default" => false,
            "description" => "Associate public IP address?"
        },
        "userdata_script" => @userdata_primitive,
        "windows_admin_username" => {
            "type" => "string",
            "default" => "Administrator",
            "description" => "Use an alternate Windows account for Administrator functions. Will change the name of the Administrator account, if it has not already been done."
        },
        "windows_auth_vault" => {
            "type" => "object",
            "additionalProperties" => false,
            "required" => ["vault", "item"],
            "description" => "Set Windows nodes' local administrator password to a value specified in a Chef Vault.",
            "properties" => {
                "vault" => {
                    "type" => "string",
                    "default" => "windows",
                    "description" => "The vault where these credentials reside"
                },
                "item" => {
                    "type" => "string",
                    "default" => "credentials",
                    "description" => "The vault item where these credentials reside"
                },
                "password_field" => {
                    "type" => "string",
                    "default" => "password",
                    "description" => "The field within the Vault item where the password for Windows local Administrator user is stored"
                },
                "ec2config_password_field" => {
                    "type" => "string",
                    "default" => "ec2config_password",
                    "description" => "The field within the Vault item where the password for the EC2config service user is stored"
                },
                "sshd_password_field" => {
                    "type" => "string",
                    "default" => "sshd_password",
                    "description" => "The field within the Vault item where the password for the Cygwin/SSH service user is stored"
                }
            }
        },
        "ssh_user" => {
            "type" => "string",
            "default" => "root",
            "default_if" => [
                {
                    "key_is" => "platform",
                    "value_is" => "windows",
                    "set" => "Administrator"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "win2k12",
                    "set" => "Administrator"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "win2k12r2",
                    "set" => "Administrator"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "ubuntu",
                    "set" => "ubuntu"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "ubuntu14",
                    "set" => "ubuntu"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "centos7",
                    "set" => "centos"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "rhel7",
                    "set" => "ec2-user"
                },
                {
                    "key_is" => "platform",
                    "value_is" => "rhel71",
                    "set" => "ec2-user"
                }
            ]
        },
        "use_cloud_provider_windows_password" => {
            "type" => "boolean",
            "default" => true
        },
        "platform" => {
            "type" => "string",
            "default" => "linux",
            "enum" => ["linux", "windows", "centos", "ubuntu", "centos6", "ubuntu14", "win2k12", "win2k12r2", "centos7", "rhel7", "rhel71"],
            "description" => "Helps select default AMIs, and enables correct grooming behavior based on operating system type.",
        },
        "run_list" => {
            "type" => "array",
            "items" => {
                "type" => "string",
                "description" => "Chef run list entry, e.g. role[rolename] or recipe[recipename]."
            }
        },
        "ingress_rules" => {
            "type" => "array",
            "items" => @firewall_ruleset_rule_primitive
        },
        # This is a free-form means to pass stuff to the mu-tools Chef cookbook
        "application_attributes" => {
            "type" => "object",
            "description" => "Chef Node structure artifact for mu-tools cookbook.",
        },
        # Objects here will be stored in this node's Chef Vault
        "secrets" => {
            "type" => "object",
            "description" => "JSON artifact to be stored in Chef Vault for this node. Note that these values will still be stored in plain text local to the MU server, but only accessible to nodes via Vault."
        },
        # This node will be granted access to the following Vault items.
        "vault_access" => {
            "type" => "array",
            "minItems" => 1,
            "items" => {
                "description" => "Chef Vault items to which this node should be granted access.",
                "type" => "object",
                "title" => "vault_access",
                "required" => ["vault", "item"],
                "additionalProperties" => false,
                "properties" => {
                    "vault" => {
                        "type" => "string",
                        "description" => "The Vault to which this node should be granted access."
                    },
                    "item" => {
                        "type" => "string",
                        "description" => "The item within the Vault to which this node should be granted access."
                    }
                }
            }
        }
    }

    @server_primitive = {
        "type" => "object",
        "title" => "server",
        "required" => ["name", "size", "cloud"],
        "additionalProperties" => false,
        "description" => "Create individual server instances.",
        "properties" => {
            "dns_records" => dns_records_primitive(need_target: false, default_type: "A", need_zone: true),
            "create_image" => {
                "type" => "object",
                "title" => "create_image",
                "required" => ["image_then_destroy", "image_exclude_storage", "public"],
                "additionalProperties" => false,
                "description" => "Create a reusable image of this server once it is complete.",
                "properties" => {
                    "public" => {
                        "type" => "boolean",
                        "description" => "Make the image public once it's complete",
                        "default" => false
                    },
                    "image_then_destroy" => {
                        "type" => "boolean",
                        "description" => "Destroy the source server after creating the reusable image(s).",
                        "default" => false
                    },
                    "image_exclude_storage" => {
                        "type" => "boolean",
                        "description" => "When creating an image of this server, exclude the block device mappings of the source server.",
                        "default" => false
                    },
                    "copy_to_regions" => {
                        "type" => "array",
                        "description" => "Replicate the AMI to regions other than the source server's.",
                        "items" => {
                            "type" => "String",
                            "description" => "Regions in which to place more copies of this image. If none are specified, or if the keyword #ALL is specified, will place in all available regions."
                        }
                    }
                }
            },
            "vpc" => vpc_reference_primitive(ONE_SUBNET+MANY_SUBNETS, NAT_OPTS, "public"),
            "monitoring" => {
                "type" => "boolean",
                "default" => true,
                "description" => "Enable detailed instance monitoring.",
            },
            "private_ip" => {
                "type" => "string",
                "description" => "Request a specific private IP address for this instance.",
                "pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
            },
            "ami_id" => {
                "type" => "string",
                "description" => "The Amazon EC2 AMI on which to base this instance. Will use the default appropriate for the platform, if not specified.",
            },
            "size" => @ec2_size_primitive,
            "storage" => @storage_primitive,
            "generate_iam_role" => {
                "type" => "boolean",
                "default" => true,
                "description" => "Generate a unique IAM profile for this Server or ServerPool.",
            },
            "iam_role" => {
                "type" => "string",
                "description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile. If generate_iam_role is false, will simple use this profile.",
            },
            "iam_policies" => {
                "type" => "array",
                "items" => {
                    "description" => "Amazon-compatible role policies which will be merged into this node's own instance profile.  Not valid with generate_iam_role set to false. Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
                    "type" => "object"
                }
            }
        }
    }
    @server_primitive["properties"].merge!(@server_common_properties)

    @database_primitive = {
        "type" => "object",
        "title" => "database",
        "description" => "Create a dedicated database server.",
        "required" => ["name", "engine", "size", "cloud"],
        "additionalProperties" => false,
        "properties" => {
            "cloud" => @cloud_primitive,
            "groomer" => {
                "type" => "string",
                "default" => MU::Config.defaultGroomer,
                "enum" => MU.supportedGroomers
            },
            "name" => {"type" => "string"},
            "region" => @region_primitive,
            "db_family" => {"type" => "string"},
            "tags" => @tags_primitive,
            "alarms" => @alarm_common_primitive,
            "engine_version" => {"type" => "string"},
            "add_firewall_rules" => @additional_firewall_rules,
            "read_replica_of" => @database_ref_primitive,
            "ingress_rules" => {
                "type" => "array",
                "items" => @firewall_ruleset_rule_primitive
            },
            "engine" => {
                "enum" => ["mysql", "postgres", "oracle-se1", "oracle-se", "oracle-ee", "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web", "aurora"],
                "type" => "string"
            },
            "dns_records" => dns_records_primitive(need_target: false, default_type: "CNAME", need_zone: true),
            "dns_sync_wait" => {
                "type" => "boolean",
                "description" => "Wait for DNS record to propagate in DNS Zone.",
                "default" => true
            },
            "dependencies" => @dependencies_primitive,
            "size" => @rds_size_primitive,
            "storage" => {
                "type" => "integer",
                "description" => "Storage space for this database instance (GB)."
            },
            "storage_type" => {
                "enum" => ["standard", "gp2", "io1"],
                "type" => "string",
                "default" => "gp2"
            },
            "run_sql_on_deploy" => {
                "type" => "array",
                "minItems" => 1,
                "items" => {
                    "description" => "Arbitrary SQL commands to run after the database is fully configred (PostgreSQL databases only).",
                    "type" => "string"
                }
            },
            "port" => {"type" => "integer"},
            "vpc" => vpc_reference_primitive(MANY_SUBNETS, NAT_OPTS, "all_public"),
            "publicly_accessible" => {
                "type" => "boolean",
                "default" => true
            },
            "multi_az_on_create" => {
                "type" => "boolean",
                "description" => "Enable high availability when the database instance is created",
                "default" => false
            },
            "multi_az_on_deploy" => {
                "type" => "boolean",
                "description" => "Enable high availability after the database instance is created. This may make deployments based on creation_style other then 'new' faster.",
                "default" => false
            },
            "backup_retention_period" => {
                "type" => "integer",
                "default" => 1,
                "description" => "The number of days to retain an automatic database snapshot. If set to 0 and deployment is multi-az will be overridden to 35"
            },
            "preferred_backup_window" => {
                "type" => "string",
                "default" => "05:00-05:30",
                "description" => "The preferred time range to perform automatic database backups."
            },
            "preferred_maintenance_window " => {
                "type" => "string",
                "description" => "The preferred data/time range to perform database maintenance."
            },
            "iops" => {
                "type" => "integer",
                "description" => "The amount of IOPS to allocate to Provisioned IOPS (io1) volumes. Increments of 1,000"
            },
            "auto_minor_version_upgrade" => {
                "type" => "boolean",
                "default" => true
            },
            "allow_major_version_upgrade" => {
                "type" => "boolean",
                "default" => false
            },
            "storage_encrypted" => {
                "type" => "boolean",
                "default" => false
            },
            "creation_style" => {
                "type" => "string",
                "enum" => ["existing", "new", "new_snapshot", "existing_snapshot", "point_in_time"],
                "description" => "'new' - create a pristine database instances; 'existing' - use an existing database instance; 'new_snapshot' - create a snapshot of an existing database, and create a new one from that snapshot; 'existing_snapshot' - create database from an existing snapshot.; 'point_in_time' - create database from point in time backup of an existing database",
                "default" => "new"
            },
            "license_model" => {
                "type" => "string",
                "enum" => ["license-included", "bring-your-own-license", "general-public-license", "postgresql-license"],
                "default" => "license-included"
            },
            "identifier" => {
                "type" => "string",
                "description" => "For any creation_style other than 'new' this parameter identifies the database to use. In the case of new_snapshot or point_in_time this is the identifier of an existing database instance; in the case of existing_snapshot this is the identifier of the snapshot."
            },
            "master_user" => {
                "type" => "string",
                "description" => "Set master user name for this database instance; if not specified a random username will be generated"
            },
            "restore_time" => {
              "type" => "string",
              "description" => "Must either be set to 'latest' or date/time value in the following format: 2015-09-12T22:30:00Z. Applies only to point_in_time creation_style"
            },
            "create_read_replica" => {
                "type" => "boolean",
                "default" => false
            },
            "cluster_node_count" => {
              "type" => "integer",
              "description" => "The number of database instances to add to a database cluster. This only applies to aurora",
              "default_if" => [
                {
                  "key_is" => "engine",
                  "value_is" => "aurora",
                  "set" => 1
                }
              ]
            },
            "create_cluster" => {
              "type" => "boolean",
                "description" => "Rather to create a database cluster. This only applies to aurora",
                "default_if" => [
                  {
                    "key_is" => "engine",
                    "value_is" => "aurora",
                    "set" => true
                  }
                ]
            },
            "db_parameter_group_parameters" => @rds_parameters_primitive,
            "cluster_parameter_group_parameters" => @rds_parameters_primitive,
            "parameter_group_family" => {
                "type" => "String",
                "enum" => ["postgres9.4", "postgres9.3", "mysql5.1", "mysql5.5", "mysql5.6", "oracle-ee-11.2", "oracle-ee-12.1", "oracle-se-11.2", "oracle-se-12.1", "oracle-se1-11.2", "oracle-se1-12.1",
                                   "aurora5.6", "sqlserver-ee-10.5", "sqlserver-ee-11.0", "sqlserver-ex-10.5", "sqlserver-ex-11.0", "sqlserver-se-10.5", "sqlserver-se-11.0", "sqlserver-web-10.5", "sqlserver-web-11.0"],
                "description" => "The database family to create the DB Parameter Group for. The family type must be the same type as the database major version - eg if you set engine_version to 9.4.4 the db_family must be set to postgres9.4."
            },
            "auth_vault" => {
                "type" => "object",
                "additionalProperties" => false,
                "required" => ["vault", "item"],
                "description" => "The vault storing the password of the database master user. a random password will be generated if not specified.",
                "properties" => {
                    "vault" => {
                        "type" => "string",
                        "default" => "database",
                        "description" => "The vault where these credentials reside"
                    },
                    "item" => {
                        "type" => "string",
                        "default" => "credentials",
                        "description" => "The vault item where these credentials reside"
                    },
                    "password_field" => {
                        "type" => "string",
                        "default" => "password",
                        "description" => "The field within the Vault item where the password for database master user is stored"
                    }
                }
            }
        }
    }

    @cache_cluster_primitive = {
        "type" => "object",
        "title" => "Cache Cluster",
        "description" => "Create cache cluster(s).",
        "required" => ["name", "engine", "size", "cloud"],
        "additionalProperties" => false,
        "properties" => {
            "cloud" => @cloud_primitive,
            "name" => {"type" => "string"},
            "region" => @region_primitive,
            "tags" => @tags_primitive,
            "engine_version" => {"type" => "string"},
            "node_count" => {
              "type" => "integer",
                "description" => "The number of cache nodes in a cache cluster (memcached), or the number of cache clusters in a cache group (redis)",
                "default" => 1
            },
            "add_firewall_rules" => @additional_firewall_rules,
            "engine" => {
                "enum" => ["memcached", "redis"],
                "type" => "string",
                "default" => "redis"
            },
            "dns_records" => dns_records_primitive(need_target: false, default_type: "CNAME", need_zone: true),
            "dns_sync_wait" => {
                "type" => "boolean",
                "description" => "Wait for DNS record to propagate in DNS Zone.",
                "default" => true
            },
            "alarms" => @alarm_common_primitive,
            "dependencies" => @dependencies_primitive,
            "size" => @eleasticache_size_primitive,
            "port" => {
                "type" => "integer",
                "default" => 6379,
                "default_if" => [
                    {
                        "key_is" => "engine",
                        "value_is" => "memcached",
                        "set" => 11211
                    },
                    {
                      "key_is" => "engine",
                        "value_is" => "redis",
                        "set" => 6379
                    }
                ]
            },
            "vpc" => vpc_reference_primitive(MANY_SUBNETS, NAT_OPTS, "all_public"),
            "multi_az" => {
                "type" => "boolean",
                "description" => "Rather to deploy the cache cluster/cache group in Multi AZ or Single AZ",
                "default" => false
            },
            "snapshot_arn" => {
                "type" => "string",
                "description" => "The ARN (Resource Name) of the redis backup stored in S3. Applies only to redis"
            },
            "snapshot_retention_limit" => {
                "type" => "integer",
                "description" => "The number of days to retain an automatic cache cluster snapshot. Applies only to redis"
            },
            "snapshot_window" => {
                "type" => "string",
                "description" => "The preferred time range to perform automatic cache cluster backups. Time is in UTC. Applies only to redis. Window must be at least 60 minutes long - 05:00-06:00."
            },
            "preferred_maintenance_window" => {
                "type" => "string",
                "description" => "The preferred data/time range to perform cache cluster maintenance. Window must be at least 60 minutes long - sun:06:00-sun:07:00. "
            },
            "auto_minor_version_upgrade" => {
                "type" => "boolean",
                "default" => true
            },
            "creation_style" => {
                "type" => "string",
                "enum" => ["new", "new_snapshot", "existing_snapshot"],
                "description" => "'new' - create a new cache cluster; 'new_snapshot' - create a snapshot of of an exisiting cache cluster, and build a new cache cluster from that snapshot; 'existing_snapshot' - create a cache cluster from an existing snapshot.",
                "default" => "new"
            },
            "identifier" => {
                "type" => "string",
                "description" => "For any creation_style other than 'new' this parameter identifies the cache cluster to use. In the case of new_snapshot it will create a snapshot from that cache cluster first; in the case of existing_snapshot, it will use the latest avaliable snapshot."
            },
            "notification_arn" => {
                "type" => "string",
                "description" => "The AWS resource name of the AWS SNS notification topic notifications will be sent to.",
            },
            "parameter_group_parameters" => @eleasticache_parameters_primitive,
            "parameter_group_family" => {
                "type" => "String",
                "enum" => ["memcached1.4", "redis2.6", "redis2.8"],
                "description" => "The cache cluster family to create the Parameter Group for. The family type must be the same type as the cache cluster major version - eg if you set engine_version to 2.6 this parameter must be set to redis2.6."
            }
        }
    }

    @loadbalancer_primitive = {
        "type" => "object",
        "title" => "loadbalancer",
        "description" => "Create Load Balancers",
        "additionalProperties" => false,
        "required" => ["name", "listeners", "cloud"],
        "properties" => {
            "name" => {
                "type" => "string",
                "description" => "Note that Amazon Elastic Load Balancer names must be relatively short. Brevity is recommended here."
            },
            "tags" => @tags_primitive,
            "add_firewall_rules" => @additional_firewall_rules,
            "dns_records" => dns_records_primitive(need_target: false, default_type: "R53ALIAS", need_zone: true),
            "dns_sync_wait" => {
                "type" => "boolean",
                "description" => "Wait for DNS record to propagate in DNS Zone.",
                "default" => true,
            },
            "alarms" => @alarm_common_primitive,
            "ingress_rules" => {
                "type" => "array",
                "items" => @firewall_ruleset_rule_primitive
            },
            "region" => @region_primitive,
            "cloud" => @cloud_primitive,
            "cross_zone_unstickiness" => {
                "type" => "boolean",
                "default" => false
            },
            "idle_timeout" => {
                "type" => "integer",
                "description" => "Specifies the time (in seconds) the connection is allowed to be idle (no data has been sent over the connection) before it is closed by the load balancer.",
                "default" => 60
            },
            "lb_cookie_stickiness_policy" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "Creates a cookie to tie client sessions to back-end servers. Only valid with HTTP/HTTPS listeners.",
                "required" => ["name"],
                "properties" => {
                    "name" => {
                        "type" => "string",
                        "description" => "The name of this policy.",
                        "pattern" => "^([a-zA-Z0-9\\-]+)$"
                    },
                    "timeout" => {
                        "type" => "integer",
                        "description" => "The time period in seconds after which the cookie should be considered stale. Not specifying this parameter indicates that the sticky session will last for the duration of the browser session."
                    }
                }
            },
            "app_cookie_stickiness_policy" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "Use an application cookie to tie client sessions to back-end servers. Only valid with HTTP/HTTPS listeners.",
                "required" => ["name", "cookie"],
                "properties" => {
                    "name" => {
                        "type" => "string",
                        "description" => "The name of this policy.",
                        "pattern" => "^([a-zA-Z0-9\\-]+)$"
                    },
                    "cookie" => {
                        "type" => "string",
                        "description" => "The name of an application cookie to use for session tracking."
                    }
                }
            },
            "connection_draining_timeout" => {
                "type" => "integer",
                "description" => "Permits the load balancer to complete connections to unhealthy backend instances before retiring them fully. Timeout is in seconds; set to -1 to disable.",
                "default" => -1
            },
            "private" => {
                "type" => "boolean",
                "default" => false,
                "description" => "Set to true if this ELB should only be assigned a private IP address (no public interface)."
            },
            "dependencies" => @dependencies_primitive,
            "vpc" => vpc_reference_primitive(MANY_SUBNETS, NO_NAT_OPTS, "all_public"),
            "zones" => {
                "type" => "array",
                "minItems" => 1,
                "description" => "Availability Zones in which this Load Balancer can operate. Specified Availability Zones must be in the same EC2 Region as the load balancer. Traffic will be equally distributed across all zones. If no zones are specified, we'll use all zones in the current region.",
                "items" => {
                    "type" => "string"
                }
            },
            "access_log" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "Access logging for Load Balancer requests.",
                "required" => ["enabled", "s3_bucket_name"],
                "properties" => {
                    "enabled" => {
                        "type" => "boolean",
                        "description" => "Toggle access log publishing.",
                        "default" => false
                    },
                    "s3_bucket_name" => {
                        "type" => "string",
                        "description" => "The Amazon S3 bucket to which to publish access logs."
                    },
                    "s3_bucket_prefix" => {
                        "type" => "string",
                        "default" => "",
                        "description" => "The path within the S3 bucket to which to publish the logs."
                    },
                    "emit_interval" => {
                        "type" => "integer",
                        "description" => "How frequently to publish access logs.",
                        "enum" => [5, 60],
                        "default" => 60
                    }
                }
            },
            "healthcheck" => {
                "type" => "object",
                "additionalProperties" => false,
                "description" => "The method used by a Load Balancer to check the health of its client nodes.",
                "required" => ["target"],
                "properties" => {
                    "target" => {
                        "type" => "String",
                        "pattern" => "^(TCP:\\d+|SSL:\\d+|HTTP:\\d+\\/.*|HTTPS:\\d+\\/.*)$",
                        "description" => 'Specifies the instance being checked. The protocol is either TCP, HTTP, HTTPS, or SSL. The range of valid ports is one (1) through 65535.

							TCP is the default, specified as a TCP: port pair, for example "TCP:5000". In this case a healthcheck simply attempts to open a TCP connection to the instance on the specified port. Failure to connect within the configured timeout is considered unhealthy.

							SSL is also specified as SSL: port pair, for example, SSL:5000.

							For HTTP or HTTPS protocol, the situation is different. You have to include a ping path in the string. HTTP is specified as a HTTP:port;/;PathToPing; grouping, for example "HTTP:80/weather/us/wa/seattle". In this case, a HTTP GET request is issued to the instance on the given port and path. Any answer other than "200 OK" within the timeout period is considered unhealthy.

							The total length of the HTTP ping target needs to be 1024 16-bit Unicode characters or less.'
                    },
                    "timeout" => {
                        "type" => "integer",
                        "default" => 5
                    },
                    "interval" => {
                        "type" => "integer",
                        "default" => 30
                    },
                    "unhealthy_threshold" => {
                        "type" => "integer",
                        "default" => 2
                    },
                    "healthy_threshold" => {
                        "type" => "integer",
                        "default" => 10
                    }
                }
            },
            "listeners" => {
                "type" => "array",
                "items" => {
                    "type" => "object",
                    "required" => ["lb_protocol", "lb_port", "instance_protocol", "instance_port"],
                    "additionalProperties" => false,
                    "description" => "A list of port/protocols which this Load Balancer should answer.",
                    "properties" => {
                        "lb_port" => {
                            "type" => "integer",
                            "description" => "Specifies the external load balancer port number. This property cannot be modified for the life of the load balancer."
                        },
                        "instance_port" => {
                            "type" => "integer",
                            "description" => "Specifies the TCP port on which the instance server is listening. This property cannot be modified for the life of the load balancer."
                        },
                        "lb_protocol" => {
                            "type" => "string",
                            "enum" => ["HTTP", "HTTPS", "TCP", "SSL"],
                            "description" => "Specifies the load balancer transport protocol to use for routing - HTTP, HTTPS, TCP or SSL. This property cannot be modified for the life of the load balancer."
                        },
                        "instance_protocol" => {
                            "type" => "string",
                            "enum" => ["HTTP", "HTTPS", "TCP", "SSL"],
                            "description" => "Specifies the protocol to use for routing traffic to back-end instances - HTTP, HTTPS, TCP, or SSL. This property cannot be modified for the life of the load balancer.
	
								If the front-end protocol is HTTP or HTTPS, InstanceProtocol has to be at the same protocol layer, i.e., HTTP or HTTPS. Likewise, if the front-end protocol is TCP or SSL, InstanceProtocol has to be TCP or SSL."
                        },
                        "ssl_certificate_name" => {
                            "type" => "string",
                            "description" => "The name of a server certificate."
                        },
                        "ssl_certificate_id" => {
                            "type" => "string",
                            "description" => "The ARN string of a server certificate."
                        }
                    }
                }
            }
        }
    }

    @dns_zones_primitive = {
        "type" => "object",
        "additionalProperties" => false,
        "description" => "Create a DNS zone in Route 53.",
        "required" => ["name", "cloud"],
        "properties" => {
            "cloud" => @cloud_primitive,
            "name" => {
                "type" => "string",
                "description" => "The domain name to create. Must comply with RFC 1123",
                "pattern" => "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
            },
            "private" => {
                "type" => "boolean",
                "default" => true,
                "description" => "Create as a private internal domain, not publicly resolvable."
            },
            "all_account_vpcs" => {
                "type" => "boolean",
                "default" => true,
                "description" => "If this zone is private, make sure it is resolvable from all VPCs in this account. Will supercede the list in {MU::Config::BasketofKittens::dnszones.vpcs} for VPCs in this account."
            },
            "records" => dns_records_primitive(),
            "dependencies" => @dependencies_primitive,
            "vpcs" => {
                "type" => "array",
                "items" => vpc_reference_primitive(NO_SUBNETS, NO_NAT_OPTS)
            }
        }
    }

    @server_pool_primitive = {
        "type" => "object",
        "additionalProperties" => false,
        "description" => "Create scalable pools of identical servers.",
        "required" => ["name", "min_size", "max_size", "basis", "cloud"],
        "properties" => {
            "dns_records" => dns_records_primitive(need_target: false, default_type: "A", need_zone: true),
            "wait_for_nodes" => {
                "type" => "integer",
                "description" => "Use this parameter to force a certain number of nodes to come up and be fully bootstrapped before the rest of the pool is initialized.",
                "default" => 0,
            },
            "vpc" => vpc_reference_primitive(MANY_SUBNETS, NAT_OPTS, "all_private"),
            "min_size" => {"type" => "integer"},
            "max_size" => {"type" => "integer"},
            "tags" => @tags_primitive,
            "desired_capacity" => {
                "type" => "integer",
                "description" => "The number of Amazon EC2 instances that should be running in the group. Should be between min_size and max_size."
            },
            "default_cooldown" => {
                "type" => "integer",
                "default" => 300
            },
            "health_check_type" => {
                "type" => "string",
                "enum" => ["EC2", "ELB"],
                "default" => "EC2",
            },
            "health_check_grace_period" => {
                "type" => "integer",
                "default" => 0
            },
            "vpc_zone_identifier" => {
                "type" => "string",
                "description" => "A comma-separated list of subnet identifiers of Amazon Virtual Private Clouds (Amazon VPCs).

					If you specify subnets and Availability Zones with this call, ensure that the subnets' Availability Zones match the Availability Zones specified."
            },
            "scaling_policies" => {
                "type" => "array",
                "minItems" => 1,
                "items" => {
                    "type" => "object",
                    "required" => ["name", "type"],
                    "additionalProperties" => false,
                    "description" => "A custom AWS Autoscale scaling policy for this pool.",
                    "properties" => {
                        "name" => {
                            "type" => "string"
                        },
                        "alarms" => @alarm_common_primitive,
                        "type" => {
                            "type" => "string",
                            "enum" => ["ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"],
                            "description" => "Specifies whether 'adjustment' is an absolute number or a percentage of the current capacity. Valid values are ChangeInCapacity, ExactCapacity, and PercentChangeInCapacity."
                        },
                        "adjustment" => {
                            "type" => "integer",
                            "description" => "The number of instances by which to scale. 'type' determines the interpretation of this number (e.g., as an absolute number or as a percentage of the existing Auto Scaling group size). A positive increment adds to the current capacity and a negative value removes from the current capacity. Used only when policy_type is set to 'SimpleScaling'"
                        },
                        "cooldown" => {
                            "type" => "integer",
                            "default" => 1,
                            "description" => "The amount of time, in seconds, after a scaling activity completes and before the next scaling activity can start."
                        },
                        "min_adjustment_magnitude" => {
                            "type" => "integer",
                            "description" => "Used when 'type' is set to 'PercentChangeInCapacity', the scaling policy changes the DesiredCapacity of the Auto Scaling group by at least the number of instances specified in the value."
                        },
                        "policy_type" => {
                          "type" => "string",
                          "enum" => ["SimpleScaling", "StepScaling"],
                          "description" => "'StepScaling' will add capacity based on the magnitude of the alarm breach, 'SimpleScaling' will add capacity based on the 'adjustment' value provided. Defaults to 'SimpleScaling'.",
                          "default" => "SimpleScaling"
                        },
                        "metric_aggregation_type" => {
                          "type" => "string",
                          "enum" => ["Minimum", "Maximum", "Average"],
                          "description" => "Defaults to 'Average' if not specified. Required when policy_type is set to 'StepScaling'",
                          "default" => "Average"
                        },
                        "step_adjustments" => {
                          "type" => "array",
                          "minItems" => 1,
                          "items" => {
                            "type" => "object",
                            "title" => "admin",
                            "description" => "Requires policy_type 'StepScaling'",
                            "required" => ["adjustment"],
                            "additionalProperties" => false,
                            "properties" => {
                              "adjustment" => {
                                  "type" => "integer",
                                  "description" => "The number of instances by which to scale at this specific step. Postive value when adding capacity, negative value when removing capacity"
                              },
                              "lower_bound" => {
                                  "type" => "integer",
                                  "description" => "The lower bound value in percentage points above/below the alarm threshold at which to add/remove capacity for this step. Positive value when adding capacity and negative when removing capacity. If this is the first step and capacity is being added this value will most likely be 0"
                              },
                              "upper_bound" => {
                                  "type" => "integer",
                                  "description" => "The upper bound value in percentage points above/below the alarm threshold at which to add/remove capacity for this step. Positive value when adding capacity and negative when removing capacity. If this is the first step and capacity is being removed this value will most likely be 0"
                              }
                            }
                          }
                        },
                        "estimated_instance_warmup" => {
                          "type" => "integer",
                          "description" => "Required when policy_type is set to 'StepScaling'"
                        }
                    }
                }
            },
            "termination_policies" => {
                "type" => "array",
                "minItems" => 1,
                "items" => {
                    "type" => "String",
                    "default" => "Default",
                    "enum" => ["Default", "OldestInstance", "NewestInstance", "OldestLaunchConfiguration", "ClosestToNextInstanceHour"]
                }
            },
            #XXX this needs its own primitive and discovery mechanism
            "zones" => {
                "type" => "array",
                "minItems" => 1,
                "items" => {
                    "type" => "string",
                }
            },
            "basis" => {
                "type" => "object",
                "minProperties" => 1,
                "maxProperties" => 1,
                "additionalProperties" => false,
                "description" => "The baseline for new servers created within this Autoscale Group.",
                "properties" => {
                    "instance_id" => {
                        "type" => "string",
                        "description" => "The AWS instance ID of an existing instance to use as the base image for this Autoscale Group.",
                    },
                    "server" => {
                        "type" => "string",
                        "description" => "Build a server defined elsewhere in this stack, then use it as the base image for this Autoscale Group.",
                    },
                    "launch_config" => {
                        "type" => "object",
                        "required" => ["name", "size"],
                        "minProperties" => 3,
                        "additionalProperties" => false,
                        "description" => "An Amazon Launch Config for an Autoscale Group.",
                        "properties" => {
                            "name" => {"type" => "string"},
                            "instance_id" => {
                                "type" => "string",
                                "description" => "The AWS instance ID of an existing instance to use as the base image in this Launch Config.",
                            },
                            "storage" => @storage_primitive,
                            "server" => {
                                "type" => "string",
                                "description" => "Build a server defined elsewhere in this stack, create an AMI from it, then use it as the base image in this Launch Config.",
                            },
                            "ami_id" => {
                                "type" => "string",
                                "description" => "The Amazon EC2 AMI to use as the base image in this Launch Config. Will use the default for platform if not specified.",
                            },
                            "monitoring" => {
                                "type" => "boolean",
                                "default" => true,
                                "description" => "Enable instance monitoring?",
                            },
                            "ebs_optimized" => {
                                "type" => "boolean",
                                "default" => false,
                                "description" => "EBS optimized?",
                            },
                            "iam_role" => {
                                "type" => "string",
                                "description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile. If generate_iam_role is false, will simple use this profile.",
                            },
                            "generate_iam_role" => {
                                "type" => "boolean",
                                "default" => true,
                                "description" => "Generate a unique IAM profile for this Server or ServerPool.",
                            },
                            "iam_policies" => {
                                "type" => "array",
                                "items" => {
                                    "description" => "Amazon-compatible role policies which will be merged into this node's own instance profile.  Not valid with generate_iam_role set to false. Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
                                    "type" => "object"
                                }
                            },
                            "spot_price" => {
                                "type" => "string",
                            },
                            "kernel_id" => {
                                "type" => "string",
                                "description" => "Kernel to use with servers created from this Launch Configuration.",
                            },
                            "ramdisk_id" => {
                                "type" => "string",
                                "description" => "Kernel to use with servers created from this Launch Configuration.",
                            },
                            "size" => @ec2_size_primitive
                        }
                    }
                }
            }
        }
    }
    @server_pool_primitive["properties"].merge!(@server_common_properties)

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
            "region" => @region_primitive,
            # TODO availability zones (or an array thereof) 

            "loadbalancers" => {
                "type" => "array",
                "items" => @loadbalancer_primitive
            },
            "server_pools" => {
                "type" => "array",
                "items" => @server_pool_primitive
            },
            "cache_clusters" => {
                "type" => "array",
                "items" => @cache_cluster_primitive
            },
            "alarms" => {
                "type" => "array",
                "items" => @alarm_primitive
            },
            "logs" => {
                "type" => "array",
                "items" => @log_primitive
            },
            "dnszones" => {
                "type" => "array",
                "items" => @dns_zones_primitive
            },
            "databases" => {
                "type" => "array",
                "items" => @database_primitive
            },
            "servers" => {
                "type" => "array",
                "items" => @server_primitive
            },
            "firewall_rules" => {
                "type" => "array",
                "items" => @firewall_ruleset_primitive
            },
            "collections" => {
                "type" => "array",
                "items" => @cloudformation_primitive
            },
            "vpcs" => {
                "type" => "array",
                "items" => @vpc_primitive
            },
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


  end #class
end #module
