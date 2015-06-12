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
gem "chef"
autoload :Chef, 'chef'
gem "knife-windows"
gem "chef-vault"
autoload :Chef, 'chef-vault'
autoload :ChefVault, 'chef-vault'

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
			@@amazon_images.merge!(custom){ |key, oldval, newval|
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
		
		rcfile = nil
		home = Etc.getpwuid(Process.uid).dir
		if ENV.include?('MU_INSTALLDIR') and File.readable?(ENV['MU_INSTALLDIR']+"/etc/mu.rc")
			rcfile = ENV['MU_INSTALLDIR']+"/etc/mu.rc"
		elsif File.readable?("/opt/mu/etc/mu.rc")
			rcfile = "/opt/mu/etc/mu.rc"
		elsif File.readable?("#{home}/.murc")
			rcfile = "#{home}/.murc"
		end
		MU.log "MU::Config loading #{rcfile}", MU::DEBUG
		File.readlines(rcfile).each {|line|
			line.strip!
			name, value = line.split(/=/, 2)
			name.sub!(/^export /, "")
			if !value.nil? and !value.empty?
				value.gsub!(/(^"|"$)/, "")
				if !value.match(/\$/)
					@mu_env_vars = "#{@mu_env_vars} #{name}=\"#{value}\""
				end
			end
		}

		# The invocation to Chef's knife utility. We want full paths and clean
		# environments when running external commands.
		@knife = "cd #{MU.myRoot} && env -i HOME=#{home} #{@mu_env_vars} PATH=/opt/chef/embedded/bin:/usr/bin:/usr/sbin knife"
		# The canonical path to invoke Chef's *knife* utility with a clean environment.
		# @return [String]
		def self.knife; @knife;end
		attr_reader :knife

		@vault_opts = "--mode client -u #{MU.chef_user} -F json"
		# The canonical set of arguments for most `knife vault` commands
		# @return [String]
		def self.vault_opts; @vault_opts;end
		attr_reader :vault_opts

		@chefclient = "env -i HOME=#{home} #{@mu_env_vars} PATH=/opt/chef/embedded/bin:/usr/bin:/usr/sbin chef-client"
		# The canonical path to invoke Chef's *chef-client* utility with a clean environment.
		# @return [String]
		def self.chefclient; @chefclient;end
		attr_reader :chefclient


		# Load a configuration file ("Basket of Kittens").
		# @param path [String]: The path to the master config file to load. Note that this can include other configuration files via ERB.
		# @param skipinitialupdates [Boolean]: Whether to forcibly apply the *skipinitialupdates* flag to nodes created by this configuration.
		# @param params [Hash]: Optional name-value parameter pairs, which will be passed to our configuration files as ERB variables.
		# @return [Hash]: The complete validated configuration for a deployment.
	  def initialize(path, skipinitialupdates = false, params: params = Hash.new)
			$myPublicIp = MU.getAWSMetaData("public-ipv4")
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
					@config['admins'] = [ { "name" => "Mu Administrator", "email" => ENV['MU_ADMIN_EMAIL'] } ]
				else
					@config['admins'] = [ { "name" => MU.userName, "email" => MU.userEmail } ]
				end
			end
			MU::Config.set_defaults(@config, MU::Config.schema)
			MU::Config.validate(@config)

			return @config.freeze
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
				conf.each_pair {|key, val|
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
			config.each {|type|
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
			ok = true

			muVPC = MU.resourceClass(vpc_block['cloud'], "VPC")
			muServer = MU.resourceClass(vpc_block['cloud'], "Server")

			if vpc_block['region'].nil? or 
				vpc_block['region'] = dflt_region
			end

			# First, dig up the enclosing VPC 
			tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !vpc_block['tag'].nil?

			if !is_sibling
				begin
					ext_vpc, name = muVPC.find(
						id: vpc_block["vpc_id"],
						name: vpc_block["vpc_name"],
						deploy_id: vpc_block["deploy_id"],
						tag_key: tag_key,
						tag_value: tag_value,
						region: vpc_block["region"]
					)
				ensure
					if !ext_vpc
						MU.log "Couldn't resolve VPC reference to a live VPC in #{parent_name}", MU::ERR, details: vpc_block
						return false
					elsif !vpc_block["vpc_id"]
						MU.log "Resolved VPC to #{ext_vpc.vpc_id} in #{parent_name}", MU::DEBUG, details: vpc_block
						vpc_block["vpc_id"] = ext_vpc.vpc_id
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

					ext_nat, name = muServer.find(
						id: vpc_block["nat_host_id"],
						name: vpc_block["nat_host_name"],
						deploy_id: vpc_block["deploy_id"],
						tag_key: nat_tag_key,
						tag_value: nat_tag_value,
						ip: vpc_block['nat_host_ip'],
						region: vpc_block['region']
					)
					if !ext_nat
						if vpc_block["nat_host_id"].nil? and nat_tag_key.nil? and vpc_block['nat_host_ip'].nil? and vpc_block["deploy_id"].nil?
							MU.log "Couldn't resolve NAT host to a live instance in #{parent_name}.", MU::DEBUG, details: vpc_block
						else
							MU.log "Couldn't resolve NAT host to a live instance in #{parent_name}", MU::ERR, details: vpc_block
							return false
						end
					elsif !vpc_block["nat_host_id"]
						MU.log "Resolved NAT host to #{ext_nat.instance_id} in #{parent_name}", MU::DEBUG, details: vpc_block
						vpc_block["nat_host_id"] = ext_nat.instance_id
						vpc_block.delete('nat_host_name')
						vpc_block.delete('nat_host_ip')
						vpc_block.delete('nat_host_tag')
					end
				end

				# Some resources specify multiple subnets...
				if vpc_block['subnets'] 
					vpc_block['subnets'].each { |subnet|
						subnet["deploy_id"] = vpc_block["deploy_id"] if !subnet['deploy_id'] and vpc_block["deploy_id"]
						tag_key, tag_value = vpc_block['tag'].split(/=/, 2) if !subnet['tag'].nil?
						ext_subnet = muVPC.findSubnet(
							id: subnet['subnet_id'],
							name: subnet['subnet_name'],
							deploy_id: subnet["deploy_id"],
							vpc_id: vpc_block["vpc_id"],
							tag_key: tag_key,
							tag_value: tag_value,
							region: vpc_block['region']
						)
						if !ext_subnet
							ok = false
							MU.log "Couldn't resolve subnet reference in #{parent_name} to a live subnet", MU::ERR, details: subnet
						elsif !subnet['subnet_id']
							subnet['subnet_id'] = ext_subnet.subnet_id
							subnet.delete('deploy_id')
							subnet.delete('subnet_name')
							subnet.delete('tag')
							MU.log "Resolved subnet reference in #{parent_name} to #{ext_subnet.subnet_id}", MU::DEBUG, details: subnet
						end
					}
				# ...others single subnets
				elsif (vpc_block['subnet_name'] or vpc_block['subnet_id']) 
					ext_subnet = muVPC.findSubnet(
						id: vpc_block['subnet_id'],
						name: vpc_block['subnet_name'],
						deploy_id: vpc_block["deploy_id"],
						vpc_id: vpc_block["vpc_id"],
						tag_key: tag_key,
						tag_value: tag_value,
						region: vpc_block['region']
					)
					if !ext_subnet
						ok = false
						MU.log "Couldn't resolve subnet reference in #{parent_name} to a live subnet", MU::ERR, details: subnet
					elsif !vpc_block['subnet_id']
						vpc_block['subnet_id'] = ext_subnet.subnet_id
						vpc_block.delete('subnet_name')
						MU.log "Resolved subnet reference in #{parent_name} to #{ext_subnet.subnet_id}", MU::DEBUG, details: vpc_block
					end
				end
			end #the !is_sibling processing for vpc's outside the deploy

			# ...and other times we get to pick - deal with subnet_pref but do not override a subnet name or ID
			honor_subnet_prefs=true 
			if vpc_block['subnets']
				vpc_block['subnets'].each {|subnet|
					if subnet['subnet_id'] or subnet['subnet_name']
						honor_subnet_prefs=false
					end
				} 
			elsif (vpc_block['subnet_name'] or vpc_block['subnet_id']) 
				honor_subnet_prefs=false
			end


			if vpc_block['subnet_pref'] and honor_subnet_prefs
				private_subnets = []
				public_subnets = []
				nat_routes = {}
				subnet_ptr = "subnet_id"
				if !is_sibling
					muVPC.listSubnets(vpc_id: vpc_block["vpc_id"], region: vpc_block['region']).each { |subnet|
						if muVPC.isSubnetPrivate?(subnet, region: vpc_block['region'])
							private_subnets << subnet
						else
							public_subnets << subnet
						end
					}
				else
					sibling_vpcs.each { |ext_vpc|
						if ext_vpc['name'] == vpc_block['vpc_name']
							subnet_ptr = "subnet_name"
							ext_vpc['subnets'].each { |subnet|
								if subnet['is_public']
									public_subnets << subnet['name']
								else
									private_subnets << subnet['name']
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
					vpc_block[subnet_ptr] = public_subnets[rand(public_subnets.length)]
				when "private"
					vpc_block[subnet_ptr] = private_subnets[rand(private_subnets.length)]
					if !is_sibling
						vpc_block['nat_host_id'] = muVPC.getDefaultRoute(vpc_block[subnet_ptr], region: vpc_block['region'])
					elsif nat_routes.has_key?(vpc_block[subnet_ptr])
						vpc_block['nat_host_name'] == nat_routes[vpc_block[subnet_ptr]]
					end
				when "any"
					vpc_block[subnet_ptr] = public_subnets.concat(private_subnets)[rand(public_subnets.length+private_subnets.length)]
				when "all"
					vpc_block['subnets'] = []
					public_subnets.each { |subnet|
						vpc_block['subnets'] << { subnet_ptr => subnet }
					}
					private_subnets.each { |subnet|
					vpc_block['subnets'] << { subnet_ptr => subnet }
					}
				when "all_public"
					vpc_block['subnets'] = []
					public_subnets.each { |subnet|
						vpc_block['subnets'] << { subnet_ptr => subnet }
					}
				when "all_private"
					vpc_block['subnets'] = []
					private_subnets.each { |subnet|
						vpc_block['subnets'] << { subnet_ptr => subnet }
						if !is_sibling and vpc_block['nat_host_id'].nil?
							vpc_block['nat_host_id'] = muVPC.getDefaultRoute(subnet, region: vpc_block['region'])
						elsif nat_routes.has_key?(subnet) and vpc_block['nat_host_name'].nil?
							vpc_block['nat_host_name'] == nat_routes[subnet]
						end
					}
				end
			end

			if ok
				vpc_block.delete('deploy_id')
				vpc_block.delete('nat_host_id') if vpc_block.has_key?('nat_host_id') and !vpc_block['nat_host_id'].match(/^i-/)
				vpc_block.delete('vpc_name') if vpc_block.has_key?('vpc_id')
				vpc_block.delete('deploy_id')
				vpc_block.delete('tag')
				MU.log "Resolved VPC resources for #{parent_name}", MU::NOTICE, details: vpc_block
			end

			return ok
		end

		# Verify that a server or server_pool has a valid AD config referencing
		# valid Vaults for credentials.
		def self.check_vault_refs(server)
			ok = true
			server['vault_access'] = [] if server['vault_access'].nil?
			if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
				Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
			end

			begin
				if !server['active_directory'].nil?
					server['vault_access'] << {
						"vault" => server['active_directory']['auth_vault'],
						"item" => server['active_directory']['auth_item']
					}
					item = ChefVault::Item.load(server['active_directory']['auth_vault'], server['active_directory']['auth_item'])
					["auth_username_field", "auth_password_field"].each { |field|
						if !item.has_key?(server['active_directory'][field])
							ok = false
							MU.log "I don't see a value named #{field} in Chef Vault #{server['active_directory']['auth_vault']}:#{server['active_directory']['auth_item']}", MU::ERR
						end
					}
				end
				if !server['windows_admin_password'].nil?
					server['vault_access'] << {
						"vault" => server['windows_admin_password']['vault'],
						"item" => server['windows_admin_password']['item']
					}
					item = ChefVault::Item.load(server['windows_admin_password']['vault'], server['windows_admin_password']['item'])
					if !item.has_key?(server['windows_admin_password']['password_field'])
						ok = false
						MU.log "I don't see a value named #{server['windows_admin_password']['password_field']} in Chef Vault #{server['windows_admin_password']['vault']}:#{server['windows_admin_password']['item']}", MU::ERR
					end
				end
				# Check all of the non-special ones while we're at it
				server['vault_access'].each { |v|
					item = ChefVault::Item.load(v['vault'], v['item'])
				}
			rescue ChefVault::Exceptions::KeysNotFound => e
				MU.log "Can't load a Chef Vault I was configured to use. Does it exist?", MU::ERR, details: e.inspect
				ok = false
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
			loadbalancers = config['loadbalancers']
			cloudformation_stacks = config['cloudformation_stacks']
			firewall_rules = config['firewall_rules']
			dnszones = config['dnszones']
			vpcs = config['vpcs']

			databases = Array.new if databases.nil?
			servers = Array.new if servers.nil?
			server_pools = Array.new if server_pools.nil?
			loadbalancers = Array.new if loadbalancers.nil?
			cloudformation_stacks = Array.new if cloudformation_stacks.nil?
			firewall_rules = Array.new if firewall_rules.nil?
			vpcs = Array.new if vpcs.nil?
			dnszones = Array.new if dnszones.nil?

			if databases.size < 1 and servers.size < 1 and server_pools.size < 1 and loadbalancers.size < 1 and cloudformation_stacks.size < 1 and firewall_rules.size < 1 and vpcs.size < 1 and dnszones.size < 1
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
				vpc["#MU_CLASS"] = MU.resourceClass(server['cloud'], "VPC")
				vpc['region'] = config['region'] if vpc['region'].nil?
				vpc["dependencies"] = Array.new if vpc["dependencies"].nil?
				subnet_routes = Hash.new
				public_routes = Array.new
				vpc['subnets'].each { |subnet|
					subnet_routes[subnet['route_table']] = Array.new if subnet_routes[subnet['route_table']].nil?
					subnet_routes[subnet['route_table']] << subnet['name']
				}
				vpc['route_tables'].each { |table|
					table['routes'].each { |route|
						if (!route['nat_host_name'].nil? or !route['nat_host_id'].nil?)
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
						if route['gateway'] == '#INTERNET'
							vpc['subnets'].each { |subnet|
								if table['name'] == subnet['route_table']
									subnet['is_public'] = true
								end
								if !nat_routes[subnet['name']].nil?
									subnet['nat_host_name'] = nat_routes[subnet['name']]
								end
							}
						end
					}
				}
				vpc_names << vpc['name']
			}

			# Now go back through and identify peering connections involving any of
			# the VPCs we've declared. XXX Note that it's real easy to create a
			# circular dependency here. Ugh.
			vpcs.each { |vpc|
				if !vpc["peers"].nil?
					vpc["peers"].each { |peer|
						peer['region'] = config['region'] if peer['region'].nil?
						peer['cloud'] = vpc['cloud'] if vpc['cloud'].nil?
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
				zone["#MU_CLASS"] = MU.resourceClass(server['cloud'], "DNSZone")
				zone['region'] = config['region'] if zone['region'].nil?
				ext_zone, ext_name = MU::AWS::DNSZone.find(name: zone['name'])

				if !ext_zone.nil?
					MU.log "DNS zone #{zone['name']} already exists", MU::ERR
					ok = false
				end
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

			firewall_rules.each { |acl|
				firewall_rule_names << acl['name']
				acl['region'] = config['region'] if acl['region'].nil?
				acl["dependencies"] = Array.new if acl["dependencies"].nil?
				acl["#MU_CLASS"] = Object.const_get("MU::#{server['cloud']}::FirewallRule")

				if !acl["vpc_name"].nil? or !acl["vpc_id"].nil?
					acl['vpc'] = Hash.new
					acl['vpc']['vpc_id'] = acl["vpc_id"] if !acl["vpc_id"].nil?
					acl['vpc']['vpc_name'] = acl["vpc_name"] if !acl["vpc_name"].nil?
				end
				if !acl["vpc"].nil?
					acl['vpc']['region'] = config['region'] if acl['vpc']['region'].nil?
					acl["vpc"]['#CLOUD'] = acl['#MU_CLASS']
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
							end
						}
					end
					if !rule['lbs'].nil?
						rule['lbs'].each { |lb_name|
							loadbalancers.each { |lb|
								if lb['name'] == lb_name
									acl["dependencies"] << {
										"type" => "loadbalancer",
										"name" => lb_name
									}
								end
							}
						}
					end
				}
				acl['dependencies'].uniq!
			}


			loadbalancers.each { |lb|
				lb['region'] = config['region'] if lb['region'].nil?
				lb["dependencies"] = Array.new if lb["dependencies"].nil?
				lb["#MU_CLASS"] = MU.resourceClass(server['cloud'], "LoadBalancer")
				if !lb["vpc"].nil?
					lb['vpc']['region'] = lb['region'] if lb['vpc']['region'].nil?
					lb["vpc"]['#MU_CLASS'] = lb['#MU_CLASS']
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
							resp = MU::AWS.iam.get_server_certificate(server_certificate_name: listener["ssl_certificate_name"])
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
			}

			cloudformation_stacks.each { |stack|
				stack['region'] = config['region'] if stack['region'].nil?
				stack["#MU_CLASS"] = MU.resourceClass(server['cloud'], "CloudFormation")
			}

			server_pools.each { |asg|
				if server_names.include?(asg['name'])
					MU.log "Can't use name #{asg['name']} more than once in servers/server_pools"
					ok = false
				end
				server_names << asg['name']
				asg['region'] = config['region'] if asg['region'].nil?
				asg["dependencies"] = Array.new if asg["dependencies"].nil?
				asg["#MU_CLASS"] = MU.resourceClass(server['cloud'], "ServerPool")
				asg["#MU_GROOMER"] = MU.loadGroomer(asg['groomer'])
				asg['skipinitialupdates'] = true if @skipinitialupdates
				if asg["basis"]["server"] != nil
					asg["dependencies"] << { "type" => "server", "name" => asg["basis"]["server"] }
				end
				if !asg['static_ip'].nil? and !asg['ip'].nil?
					ok = false
					MU.log "Server Pools cannot assign specific static IPs.", MU::ERR
				end
				asg['vault_access'] = [] if asg['vault_access'].nil?
				asg['vault_access'] << { "vault" => "splunk", "item" => "admin_user" }
				ok = false if !check_vault_refs(asg)
				if asg["basis"]["launch_config"] != nil
					launch = asg["basis"]["launch_config"]
					if launch["server"].nil? and launch["instance_id"].nil? and launch["ami_id"].nil?
						if MU::Config.amazon_images.has_key?(asg['platform']) and
							 MU::Config.amazon_images[asg['platform']].has_key?(asg['region'])
							launch['ami_id'] = MU::Config.amazon_images[asg['platform']][asg['region']]
						else
							ok = false
							MU.log "One of the following MUST be specified for launch_config: server, ami_id, instance_id.", MU::ERR
						end
					end
					if launch["server"] != nil
						asg["dependencies"] << { "type" => "server", "name" => launch["server"] }
						servers.each { |server|
							if server["name"] == launch["server"]
								server["create_ami"] = true
							end
						}
					end
				end
				if asg["region"].nil? and asg["zones"].nil? and asg["vpc_zone_identifier"].nil? and asg["vpc"].nil?
					ok = false
					MU.log "One of the following MUST be specified for Server Pools: region, zones, vpc_zone_identifier, vpc.", MU::ERR
				end
				if !asg["scaling_policies"].nil?
					asg["scaling_policies"].each { |policy|
						if policy['type'] != "PercentChangeInCapacity" and !policy['min_adjustment_step'].nil?
							MU.log "Cannot specify scaling policy min_adjustment_step if type is not PercentChangeInCapacity", MU::ERR
							ok = false
						end
					}
				end
# TODO make sure any load balancer we ask for has the same VPC configured
				if !asg["loadbalancers"].nil?
					asg["loadbalancers"].each { |lb|
						if lb["concurrent_load_balancer"] != nil
							asg["dependencies"] << {
								"type" => "loadbalancer",
								"name" => lb["concurrent_load_balancer"]
							}
						end
					}
				end
				if !asg["vpc"].nil?
					asg['vpc']['region'] = asg['region'] if asg['vpc']['region'].nil?
					asg["vpc"]['cloud'] = asg['cloud']
					# If we're using a VPC in this deploy, set it as a dependency
					if !asg["vpc"]["vpc_name"].nil? and vpc_names.include?(asg["vpc"]["vpc_name"]) and asg["vpc"]["deploy_id"].nil?
						asg["dependencies"] << {
							"type" => "vpc",
							"name" => asg["vpc"]["vpc_name"]
						}
						if !asg["vpc"]["subnet_name"].nil? and nat_routes.has_key?(asg["vpc"]["subnet_name"])
							asg["dependencies"] << {
								"type" => "asg",
								"name" => nat_routes[subnet["subnet_name"]],
								"phase" => "groom"
							}
						end
						if !processVPCReference(asg["vpc"],
																		"server_pool #{asg['name']}",
																		dflt_region: config['region'],
																		is_sibling: true,
																		sibling_vpcs: vpcs)
							ok = false
						end
					else
						# If we're using a VPC from somewhere else, make sure the flippin'
						# thing exists, and also fetch its id now so later search routines
						# don't have to work so hard.
						if !processVPCReference(asg["vpc"], "server_pool #{asg['name']}", dflt_region: config['region'])
							ok = false
						end
					end
				end
				asg["dependencies"].uniq!
				if !asg["add_firewall_rules"].nil?
					asg["add_firewall_rules"].each { |acl_include|
						if firewall_rule_names.include?(acl_include["rule_name"])
							asg["dependencies"] << {
								"type" => "firewall_rule",
								"name" => acl_include["rule_name"]
							}
						end
					}
				end
			}

			databases.each { |db|
				db['region'] = config['region'] if db['region'].nil?
				db["dependencies"] = Array.new if db["dependencies"].nil?
				db["#MU_CLASS"] = MU.resourceClass(server['cloud'], "Database")
				if db['cloudformation_stack'] != nil
					# XXX don't do this if 'true' was explicitly asked for (as distinct
					# from default)
					db['publicly_accessible'] = false
				end
				if !db['password'].nil? and ( db['password'].length < 8 or db['password'].match(/[\/\\@\s]/) )
					MU.log "Database password '#{db['password']}' doesn't meet RDS requirements. Must be > 8 chars and have only ASCII characters other than /, @, \", or [space].", MU::ERR
					ok = false
				end
				if db["multi_az_on_create"] and db["multi_az_on_deploy"]
					MU.log "Both of multi_az_on_create and multi_az_on_deploy cannot be true", MU::ERR
					ok = false
				end

				# Adding rules for Database instance storage. This varies depending on storage type and database type. 
				if db["storage_type"] == "standard" or db["storage_type"] == "gp2"
					if db["engine"] == "postgres" or db["engine"] == "mysql"
						if !(5..3072).include? db["storage"]
							MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 5 to 3072 GB for #{db["storage_type"]} volume types", MU::ERR
							ok = false
						end
					elsif %w{oracle-se1 oracle-se oracle-ee}.include? db["engine"]
						if !(10..3072).include? db["storage"]
							MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 10 to 3072 GB for #{db["storage_type"]} volume types", MU::ERR
							ok = false
						end
					elsif %w{sqlserver-ex sqlserver-web}.include? db["engine"]
						if !(20..1024).include? db["storage"]
							MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 20 to 1024 GB for #{db["storage_type"]} volume types", MU::ERR
							ok = false
						end					
					elsif %w{sqlserver-ee sqlserver-se}.include? db["engine"]
						if !(200..1024).include? db["storage"]
							MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 200 to 1024 GB for #{db["storage_type"]} volume types", MU::ERR
							ok = false
						end
					end
				elsif db["storage_type"] == "io1"
					if %w{postgres mysql oracle-se1 oracle-se oracle-ee}.include? db["engine"]
						if !(100..3072).include? db["storage"]
							MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 100 to 3072 GB for #{db["storage_type"]} volume types", MU::ERR
							ok = false
						end
					elsif %w{sqlserver-ex sqlserver-web}.include? db["engine"]
						if !(100..1000).step(100).include? db["storage"]
							MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 100 to 1000 GB  with 100 GB increments for #{db["storage_type"]} volume types", MU::ERR
							ok = false
						end
					elsif %w{sqlserver-ee sqlserver-se}.include? db["engine"]
						if !(200..1000).step(100).include? db["storage"]
							MU.log "Database storage size is set to #{db["storage"]}. #{db["engine"]} only supports storage sizes between 100 to 1000 GB  with 100 GB increments for #{db["storage_type"]} volume types", MU::ERR
							ok = false
						end
					end
				end

				if db["read_replica"]
					if db["engine"] != "postgres" and db["engine"] != "mysql"
						MU.log "Read replica(s) database instances only supported for postgres and mysql. #{db["engine"]} not supported.", MU::ERR
						ok = false
					end
				end
				
				if db["engine"] == "postgres"
					db["license_model"] = "postgresql-license"
				elsif db["engine"] == "mysql"
					db["license_model"] = "general-public-license"
				end

				if (db["creation_style"] == "new" or
						db["creation_style"] == "new_snapshot" or
						db["creation_style"] == "existing_snapshot") and
						db["size"].nil?
					MU.log "You must specify 'size' when creating a new database or a database from a snapshot.", MU::ERR
					ok = false
				end
				if db["creation_style"] == "new" and db["storage"].nil?
					MU.log "You must specify 'storage' when creating a new database.", MU::ERR
					ok = false
				end

				if db["creation_style"] == "existing" or db["creation_style"] == "new_snapshot" or db["creation_style"] == "existing_snapshot"
					if db["identifier"].nil?
						ok = false
						MU.log "Using existing database (or snapshot thereof), but no identifier given", MU::ERR
					end
					# XXX be nice to tell users that these parameters are invalid here,
					# but only if they specified them.
					### Moving this back to MU::AWS::Database 
					# db.delete("storage_encrypted")
					# db.delete("preferred_backup_window")
					# db.delete("backup_retention_period")
				end

				if !db["run_sql_on_deploy"].nil? and (db["engine"] != "postgres" and db["engine"] != "mysql")
					ok = false
					MU.log "Running SQL on deploy is only supported for postgres and mysql databases", MU::ERR
				end

				if db["cloudformation_stack"] != nil
					db["dependencies"] << {
						"type" => "cloudformation_stack",
						"name" => db["cloudformation_stack"]
					}
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
							MU.log "publicly_accessible must be set to true when deploying into public subnets.", MU::ERR
							ok = false
						elsif db["vpc"]["subnet_pref"] == "all_private" and db['publicly_accessible']
							MU.log "publicly_accessible must be set to false when deploying into private subnets.", MU::ERR
							ok = false
						end
					end

					db['vpc']['region'] = db['region'] if db['vpc']['region'].nil?
					db["vpc"]['cloud'] = db['cloud']
					# If we're using a VPC in this deploy, set it as a dependency
					if !db["vpc"]["vpc_name"].nil? and vpc_names.include?(db["vpc"]["vpc_name"]) and db["vpc"]["deploy_id"].nil?
						db["dependencies"] << {
							"type" => "vpc",
							"name" => db["vpc"]["vpc_name"]
						}

						if !processVPCReference(db["vpc"],
																		"database #{db['name']}",
																		dflt_region: config['region'],
																		is_sibling: true,
																		sibling_vpcs: vpcs)
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

			}

			servers.each { |server|
				if server_names.include?(server['name'])
					MU.log "Can't use name #{server['name']} more than once in servers/server_pools"
					ok = false
				end
				server_names << server['name']
				server["#MU_CLASS"] = MU.resourceClass(server['cloud'], "Server")
				server["#MU_GROOMER"] = MU.loadGroomer(server['groomer'])
				server['region'] = config['region'] if server['region'].nil?
				server["dependencies"] = Array.new if server["dependencies"].nil?
				server['create_ami'] = true if server['image_then_destroy']
				if server['ami_id'].nil?
					if MU::Config.amazon_images.has_key?(server['platform']) and
						 MU::Config.amazon_images[server['platform']].has_key?(server['region'])
						server['ami_id'] = MU::Config.amazon_images[server['platform']][server['region']]
					else
						MU.log "No AMI specified for #{server['name']} and no default available for platform #{server['platform']} in region #{server['region']}", MU::ERR, details: server
						ok = false
					end
				end

				server['skipinitialupdates'] = true if @skipinitialupdates
				server['vault_access'] = [] if server['vault_access'].nil?
				server['vault_access'] << { "vault" => "splunk", "item" => "admin_user" }
				ok = false if !check_vault_refs(server)

				if server['ingress_rules'] != nil
					server['ingress_rules'].each {|rule|
						if rule['port'].nil? and rule['port_range'].nil? and rule['proto'] != "icmp"
							MU.log "Non-ICMP ingress rules must specify a port or port range", MU::ERR
							ok = false
						end
						if (rule['hosts'].nil? or rule['hosts'].size == 0) and (rule['sgs'].nil? or rule['sgs'].size == 0) and (rule['lbs'].nil? or rule['lbs'].size == 0)
							MU.log "Ingress/egress rules must specify hosts, security groups, or load balancers to which to grant access", MU::ERR
							ok = false
						end
					}
				end


				if server["cloudformation_stack"] != nil
					server["dependencies"] << {
						"type" => "cloudformation_stack",
						"name" => server["cloudformation_stack"]
					}
				end

				if !server["vpc"].nil?
					server['vpc']['region'] = server['region'] if server['vpc']['region'].nil?
					server['vpc']['cloud'] = server['cloud'] if server['vpc']['cloud'].nil?
					server["vpc"]['#MU_CLASS'] = server['#MU_CLASS']
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
						acl_include['#MU_CLASS'] = server['#MU_CLASS']
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
						lb['#MU_CLASS'] = server['#MU_CLASS']
						if lb["concurrent_load_balancer"] != nil
							server["dependencies"] << {
								"type" => "loadbalancer",
								"name" => lb["concurrent_load_balancer"]
							}
						end
					}
				end
				server["dependencies"].uniq!
			}

			ok = false if !MU::Config.check_dependencies(config)

# TODO enforce uniqueness of resource names
			raise ValidationError if !ok
		end


		def self.printSchema(dummy_kitten_class, class_hierarchy, schema, in_array = false, required = false)
			if schema["type"] == "object"
				printme = Array.new
				if !schema["properties"].nil?
					# order sub-elements by whether they're required, so we can use YARD's
					# grouping tags on them
					if !schema["required"].nil? and schema["required"].size > 0
						prop_list = schema["properties"].keys.sort_by {|name|
							schema["required"].include?(name)	? 0 : 1
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
					"vpc_id" => { "type" => "string" },
					"vpc_name" => { "type" => "string" },
					"region" => @region_primitive,
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
						"nat_host_name" => { "type" => "string" },
						"nat_host_id" => { "type" => "string" },
						"nat_host_ip" => {
							"type" => "string",
							"pattern" => "^\\d+\\.\\d+\\.\\d+\\.\\d+$"
						},
						"nat_ssh_user" => {
							"type" => "string",
							"default" => "root",
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
				vpc_ref_schema["properties"]["subnet_name"] = { "type" => "string" }
				vpc_ref_schema["properties"]["subnet_id"] = { "type" => "string" }
			end
			if subnets == MANY_SUBNETS or subnets == (ONE_SUBNET+MANY_SUBNETS)
				vpc_ref_schema["properties"]["subnets"] = {
					"type"=> "array",
					"items" => {
						"type" => "object",
						"description" => "The subnets to which to attach this resource. Will default to all subnets in this VPC if not specified.",
						"additionalProperties" => false,
						"properties" => {
							"subnet_name" => { "type" => "string" },
							"subnet_id" => { "type" => "string" },
							"tag" => {
								"type" => "string",
								"description" => "Identify this subnet by a tag (key=value). Note that this tag must not match more than one resource.",
								"pattern" => "^[^=]+=.+"
							}
						}
					}
				}
				if subnets == (ONE_SUBNET+MANY_SUBNETS)
					vpc_ref_schema["properties"]["subnets"]["items"]["description"] = "Extra subnets to which to attach this {MU::AWS::Server}. Extra network interfaces will be created to accomodate these attachments."
				end
			end
			
			return vpc_ref_schema
		end

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
			"enum" => MU::AWS.listRegions
		}

		@cloud_primitive = {
			"type" => "string",
			"default" => MU::Config.defaultCloud,
			"enum" => MU.supportedClouds
		}


		@dependencies_primitive = {
			"type" => "array",
			"items" => {
				"type" => "object",
				"description" => "Declare other server or database objects which this server requires. This server will wait to finish bootstrapping until those dependent resources become available.",
				"required" => ["name", "type"],
				"additionalProperties" => false,
				"properties" => {
					"name" => { "type" => "string" },
					"type" => {
						"type" => "string",
						"enum" => ["server", "database", "server_pool", "loadbalancer", "cloudformation_stack", "firewall_rule", "vpc", "dnszone"]
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
					"description" => "The ID of a VPN or Internet gateway attached to your VPC. You must provide either gateway or NAT host, but not both. #INTERNET will refer to this VPN's default internet gateway, if one exists.",
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

		@vpc_primitive = {
			"type" => "object",
			"required" => ["name"],
			"additionalProperties" => false,
			"description" => "Create Virtual Private Clouds with custom public or private subnets.",
			"properties" => {
				"name" => { "type" => "string" },
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
				"enable_dns_support" => {
					"type" => "boolean",
					"default" => true
				},
				"enable_dns_hostnames" => {
					"type" => "boolean",
					"default" => true
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
							"name" => { "type" => "string" },
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
							"name" => { "type" => "string" },
							"ip_block" => @cidr_primitive,
							# XXX what does the API do if we don't set this? pick one at random?
							"availability_zone" => { "type" => "string" },
							"route_table" => { "type" => "string" },
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

		@ec2_size_primitive = {
			# XXX maybe we shouldn't validate this, but it makes a good example
			"pattern" => "^(t|m|c|i|g|r|hi|hs|cr|cg|cc){1,2}[0-9]\\.(micro|small|medium|[248]?x?large)$",
			"description" => "The Amazon EC2 instance type to use when creating this server.",
			"type" => "string"
		}
		@rds_size_primitive = {
			"pattern" => "^db\.(t|m|c|i|g|hi|hs|cr|cg|cc){1,2}[0-9]\\.(micro|small|medium|[248]?x?large)$",
			"type" => "string",
			"description" => "The Amazon RDS instance type to use when creating this database instance.",
		}

		@firewall_ruleset_rule_primitive = {
			"type" => "object",
			"description" => "Network ingress and/or egress rules.",
			"additionalProperties" => false,
			"properties" => {
				"port_range" => { "type" => "string" },
				"port" => { "type" => "integer" },
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
				"name" => { "type" => "string" },
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
					"rule_id" => { "type" => "string" },
					"rule_name" => { "type" => "string" }
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

		@cloudformation_primitive = {
			"type" => "object",
			"title" => "cloudformation",
			"required" => ["name", "on_failure"],
			"additionalProperties" => false,
			"description" => "Create an Amazon CloudFormation stack.",
			"properties" => {
				"name" => { "type" => "string" },
				"parameters"=>{
					"type"=> "array",
					"items" => {
						"type" => "object",
						"description" => "set cloudformation template parameter",
						"required" => ["parameter_key","parameter_value"],
						"additionalProperties" => false,
						"properties" => {
							"parameter_key" => { "type" => "string" },
							"parameter_value" => { "type" => "string" }
						}
					}
				},
				"pass_deploy_key_as"=> {
					"type" => "string",
					"description" => "Pass in the deploy key for this stack as a CloudFormation parameter. Set this to the CloudFormation parameter name.",
				},
				"on_failure"=> {
					"type" => "string",
					"enum" => ["DO_NOTHING","ROLLBACK","DELETE"]
				},
				"template_file" => { "type" => "string"},
				"time" =>{ "type" => "string" },
				"template_url" => {
					"type" => "string" ,
					"pattern" => "^#{URI::regexp(%w(http https))}$"
				},
				"creation_style"=> { 
					"type" => "string",
					"enum" => ["existing","new"]
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
					"concurrent_load_balancer"=> {
						"type" => "string",
						"description" => "The name of a MU loadbalancer object, which should also defined in this stack. This will be added as a dependency."
					},
					"existing_load_balancer"=> {
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
						"weight" => {
							"type" => "integer",
							"description" => "Set the proportion of traffic directed to this target, based on the relative weight of other records with the same DNS name and type."
						},
						"region" => {
							"type" => "string",
							"enum" => MU::AWS.listRegions,
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
							"description" => "The value of this record. Must be valid for the 'type' field, e.g. A records must point to an IP address.",
						},
						"name" => {
							"description" => "Name of the record to create. If not specified, will default to the Mu resource name.",
							"type" => "string",
							"pattern" => "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
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
			"name" => { "type" => "string" },
			"region" => @region_primitive,
			"cloud" => @cloud_primitive,
			"groomer" => {
				"type" => "string",
				"default" => MU::Config.defaultGroomer,
				"enum" => MU.supportedGroomers
			},
			"tags" => @tags_primitive,
			"active_directory" => {
				"type" => "object",
				"additionalProperties" => false,
				"required" => ["domain_name", "short_domain_name", "domain_controllers"],
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
					"computer_ou" => {
						"type" => "string",
						"description" => "The OU to which to add this computer when joining the domain."
					},
					"auth_vault" => {
						"type" => "string",
						"default" => "active_directory",
						"description" => "The vault where these credentials reside"
					},
					"auth_item" => {
						"type" => "string",
						"default" => "join_domain",
						"description" => "The vault item where these credentials reside"
					},
					"auth_username_field" => {
						"type" => "string",
						"default" => "username",
						"description" => "The field where the username for these credentials resides"
					},
					"auth_password_field" => {
						"type" => "string",
						"default" => "password",
						"description" => "The field where the password for these credentials resides"
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
			"dns_sync_wait"=> {
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
			"windows_admin_password" => {
				"type" => "object",
				"additionalProperties" => false,
				"description" => "Set Windows nodes' local administrator password to a value specified in a Chef Vault.",
				"properties" => {
					"vault" => {
						"type" => "string",
						"default" => "windows",
						"description" => "The vault where these credentials reside"
					},
					"item" => {
						"type" => "string",
						"default" => "administrator",
						"description" => "The vault item where these credentials reside"
					},
					"password_field" => {
						"type" => "string",
						"default" => "password",
						"description" => "The field within the Vault item where the password for these credentials resides"
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
					}
				]
			},
			"never_generate_admin_password" => {
				"type" => "boolean",
				"default" => false
			},
			"platform" => {
				"type" => "string",
				"default" => "linux",
				"enum" => ["linux", "windows", "centos", "ubuntu", "centos6", "ubuntu14", "win2k12", "win2k12r2", "centos7"],
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
				"create_ami" => {
					"type" => "boolean",
					"description" => "Create an EC2 AMI of this server once it is complete.",
					"default" => false
				},
				"vpc" => vpc_reference_primitive(ONE_SUBNET+MANY_SUBNETS, NAT_OPTS, "public"),
				"image_then_destroy" => {
					"type" => "boolean",
					"description" => "Create an EC2 AMI of this server once it is complete, then destroy this server.",
					"default" => false
				},
				"image_exclude_storage" => {
					"type" => "boolean",
					"description" => "When creating an image of this server, exclude block device mappings.",
					"default" => false
				},
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
				"iam_role" => {
					"type" => "string",
					"description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile.",
				},
				"iam_policies" => {
					"type" => "array",
					"items" => {
						"description" => "Amazon-compatible role policies which will be merged into this node's own instance profile.  Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
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
				"name" => { "type" => "string" },
				"region" => @region_primitive,
				"db_family" => { "type" => "string" },
				"tags" => @tags_primitive,
				"engine_version" => { "type" => "string" },
				"add_firewall_rules" => @additional_firewall_rules,
				"engine" => {
					"enum" => ["mysql", "postgres", "oracle-se1", "oracle-se", "oracle-ee", "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web" ],
					"type" => "string",
				},
				"dns_records" => dns_records_primitive(need_target: false, default_type: "CNAME", need_zone: true),
				"dns_sync_wait"=> {
					"type" => "boolean",
					"description" => "Wait for DNS record to propagate in DNS Zone.",
					"default" => true,
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
				"port" => { "type" => "integer" },
				"vpc" => vpc_reference_primitive(MANY_SUBNETS, NAT_OPTS, "all_public"),
				"publicly_accessible"=> {
					"type" => "boolean",
					"default" => true,
				}, 
				"multi_az_on_create"=> {
					"type" => "boolean",
					"default" => false
				},
				"multi_az_on_deploy"=> {
					"type" => "boolean",
					"default" => true,
					"default_if" => [
						{
							"creation_style" => "existing",
							"set" => false
						}
					]
				},
				"backup_retention_period"=> {
					"type" => "integer",
					"default" => 1,
					"description" => "The number of days to retain an automatic database snapshot. If set to 0 and deployment is multi-az will be overridden to 35",
				},
				"preferred_backup_window"=> {
					"type" => "string",
					"default" => "05:00-05:30",
					"description" => "The preferred time range to perform automatic database backups.",
				},
				"preferred_maintenance_window "=> {
					"type" => "string",
					"description" => "The preferred data/time range to perform database maintenance.",
				},
				"iops"=> {
					"type" => "integer",
					"description" => "The amount of IOPS to allocate to Provisioned IOPS (io1) volumes. Increments of 1,000",
				},
				"auto_minor_version_upgrade"=> { 
					"type" => "boolean",
					"default" => true
				},
				"allow_major_version_upgrade"=> { 
					"type" => "boolean",
					"default" => false
				},
				"storage_encrypted"=> {
					"type" => "boolean",
					"default" => false
				},
				"creation_style"=> {
					"type" => "string",
					"enum" => ["existing","new","new_snapshot","existing_snapshot"],
					"description" => "'new' - create a pristine database instances; 'existing' - use an already-extant database instance; 'new_snapshot' - create a snapshot of an already-extant database, and build a new one from that snapshot; 'existing_snapshot' - create database from an existing snapshot.",
					"default" => "new"
				},
				"license_model"=> {
					"type" => "string",
					"enum" => ["license-included","bring-your-own-license","general-public-license", "postgresql-license"],
					"default" => "license-included"
				},
				"identifier" => {
					"type" => "string",
					"description" => "For any creation_style other than 'new' this parameter identifies the database to use. In the case of new_snapshot it will create a snapshot from that database first; in the case of existing_snapshot, it will use the latest avaliable snapshot.",
				},
				"password" => {
					"type" => "string",
					"description" => "Set master password to this; if not specified, a random string will be generated. If you are creating from a snapshot, or using an existing database, you will almost certainly want to set this."
				},
				"read_replica" => {
					"type" => "object",
					"additionalProperties" => false,
					"required" => ["name"],
					"description" => "Create a read replica database server.",
					"properties" => {
						"name" => { "type" => "string" },
						"tags" => @tags_primitive,
						"dns_records" => dns_records_primitive(need_target: false, default_type: "CNAME", need_zone: true),
						"dns_sync_wait"=> {
							"type" => "boolean",
							"description" => "Wait for DNS record to propagate in DNS Zone.",
							"default" => true,
						},
						"dependencies" => @dependencies_primitive,
						"size" => @rds_size_primitive,
						"storage_type" => {
							"enum" => ["standard", "gp2", "io1"],
							"type" => "string",
							"default" => "gp2"
						},
						"port" => { "type" => "integer" },
						"vpc" => vpc_reference_primitive(MANY_SUBNETS, NAT_OPTS, "all_public"),
						"publicly_accessible"=> {
							"type" => "boolean",
							"default" => true,
						},
						"iops"=> {
							"type" => "integer",
							"description" => "The amount of IOPS to allocate to Provisioned IOPS (io1) volumes. Increments of 1,000",
						},
						"auto_minor_version_upgrade"=> { 
							"type" => "boolean",
							"default" => true
						},
						"identifier" => {
							"type" => "string",
						},
						"source_identifier" => {
							"type" => "string",
						},
					}
				},
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
				"dns_sync_wait"=> {
					"type" => "boolean",
					"description" => "Wait for DNS record to propagate in DNS Zone.",
					"default" => true,
				},
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
							"description" => "The name of this policy."
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
							"description" => "The name of this policy."
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
				"min_size" => { "type" => "integer" },
				"max_size" => { "type" => "integer" },
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
						"required" => ["name", "type", "adjustment"],
						"additionalProperties" => false,
						"description" => "A custom AWS Autoscale scaling policy for this pool.",
						"properties" => {
							"name" => {
								"type" => "string"
							},
# XXX "alarm" - need some kind of reference capability to a CloudWatch alarm
							"type" => {
								"type" => "string",
								"enum" => ["ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"],
								"description" => "Specifies whether 'adjustment' is an absolute number or a percentage of the current capacity. Valid values are ChangeInCapacity, ExactCapacity, and PercentChangeInCapacity."
							},
							"adjustment" => {
								"type" => "integer",
								"description" => "The number of instances by which to scale. 'type' determines the interpretation of this number (e.g., as an absolute number or as a percentage of the existing Auto Scaling group size). A positive increment adds to the current capacity and a negative value removes from the current capacity."
							},
							"cooldown" => {
								"type" => "integer",
								"default" => 1,
								"description" => "The amount of time, in seconds, after a scaling activity completes and before the next scaling activity can start."
							},
							"min_adjustment_step" => {
								"type" => "integer",
								"description" => "Used with 'type' with the value PercentChangeInCapacity, the scaling policy changes the DesiredCapacity of the Auto Scaling group by at least the number of instances specified in the value."
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
								"name" => { "type" => "string" },
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
									"description" => "An Amazon IAM instance profile, from which to harvest role policies to merge into this node's own instance profile.",
								},
								"iam_policies" => {
									"type" => "array",
									"items" => {
										"description" => "Amazon-comptabible role policies which will be merged into this node's own instance profile. Our parser expects the role policy document to me embedded under a named container, e.g. { 'name_of_policy':'{ <policy document> } }",
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
				"cloudformation_stacks" => {
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
							"name" => { "type" => "string" },
							"email" => { "type" => "string" },
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
