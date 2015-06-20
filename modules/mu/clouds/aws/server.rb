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

require 'net/ssh'
require 'net/ssh/multi'
require 'net/ssh/proxy/command'
autoload :OpenStruct, "ostruct"
autoload :Timeout, "timeout"
autoload :ERB, "erb"
autoload :Base64, "base64"
require 'open-uri'

module MU
class Cloud
	class AWS

		# A server as configured in {MU::Config::BasketofKittens::servers}
		class Server < MU::Cloud::Server
			# An exception denoting an expected, temporary connection failure to a
			# bootstrapping instance, e.g. for Windows instances that must reboot in
			# mid-installation.
			class BootstrapTempFail < MuNonFatal; end

			# Whether {MU::Deploy} should hold creation of other resources which depend on this resource until the latter has been created.
			def deps_wait_on_my_creation; false.freeze end
			# Whether {MU::Deploy} should hold creation of this resource until resources on which it depends have been fully created and deployed.
			def waits_on_parent_completion; false.freeze end

			# @return [Mutex]
			def self.userdata_mutex
				@userdata_mutex ||= Mutex.new
			end

			# A list of block device names to use if we get a storage block that
			# doesn't declare one explicitly.
			# This probably fails on some AMIs. It's crude.
			@disk_devices = [
				"/dev/sdf",
				"/dev/sdg",
				"/dev/sdh",
				"/dev/sdi",
				"/dev/sdj",
				"/dev/sdk",
				"/dev/sdl",
				"/dev/sdm",
				"/dev/sdn"
			]
			# List of standard disk device names to present to instances.
			# @return [Array<String>]
			def self.disk_devices
				@disk_devices
			end

			# See that we get our ephemeral storage devices with AMIs that don't do it
			# for us
			@ephemeral_mappings = [
				{
					:device_name => "/dev/sdr",
					:virtual_name => "ephemeral0"
				},
				{
					:device_name => "/dev/sds",
					:virtual_name => "ephemeral1"
				},
				{
					:device_name => "/dev/sdt",
					:virtual_name => "ephemeral2"
				},
				{
					:device_name => "/dev/sdu",
					:virtual_name => "ephemeral3"
				}
			]
			# Ephemeral storage device mappings. Useful for AMIs that don't do this
			# for us.
			# @return [Hash]
			def self.ephemeral_mappings
				@ephemeral_mappings
			end

			attr_reader :mu_name
			attr_reader :cloud_id
			attr_reader :config
			attr_reader :deploy

			# @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
			# @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::servers}
			def initialize(mommacat: mommacat, kitten_cfg: kitten_cfg, mu_name: mu_name)
				@deploy = mommacat
				@config = kitten_cfg

				if !mu_name.nil?
					@mu_name = mu_name
					@config['mu_name'] = mu_name
				else
					@mu_name = MU::MommaCat.getResourceName(@config['name'])
					@config['mu_name'] = @mu_name

					if %w{win2k12r2 win2k12 windows}.include?(@config['platform']) or
						 !@config['active_directory'].nil?
						@config['mu_windows_name'] = MU::MommaCat.getResourceName(@config['name'], max_length: 15, need_unique_string: true)
						if !@config['never_generate_admin_password'] and !@config['windows_admin_password']
							@config['winpass'] = MU::Cloud::AWS::Server.generateWindowsAdminPassword
							MU.log "I generated a Windows admin password for #{@mu_name}. It is: #{@config['winpass']}"
						end
					end

					@config['instance_secret'] = Password.random(50)
				end

				@userdata = MU::Cloud::AWS::Server.fetchUserdata(
					platform: @config["platform"],
					template_variables: {
						"deployKey" => Base64.urlsafe_encode64(@deploy.public_key),
						"deploySSHKey" => @deploy.ssh_public_key,
						"muID" => MU.mu_id,
						"muUser" => MU.chef_user,
						"publicIP" => MU.mu_public_ip,
						"skipApplyUpdates" => @config['skipinitialupdates'],
						"windowsAdminName" => @config['windows_admin_username'],
						"resourceName" => @config["name"],
						"resourceType" => "server"
					},
					custom_append: @config['userdata_script']
				)

				@groomer = MU::Groomer.new(self)
				@disk_devices = MU::Cloud::AWS::Server.disk_devices
				@ephemeral_mappings = MU::Cloud::AWS::Server.ephemeral_mappings
			end

			# Fetch our baseline userdata argument (read: "script that runs on first
			# boot") for a given platform.
			# *XXX* both the eval() and the blind File.read() based on the platform
			# variable are dangerous without cleaning. Clean them.
			# @param platform [String]: The target OS.
			# @param template_variables [Hash]: A list of variable substitutions to pass as globals to the ERB parser when loading the userdata script.
			# @param custom_append [String]: Arbitrary extra code to append to our default userdata behavior.
			# @return [String]
			def self.fetchUserdata(
															platform: platform = "linux",
															template_variables: template_variables = Hash.new,
															custom_append: custom_append = nil
														)
				userdata_mutex.synchronize {
					if template_variables.nil? or !template_variables.is_a?(Hash)
						raise MuError, "My second argument should be a hash of variables to pass into ERB templates"
					end
					$mu = OpenStruct.new(template_variables)
					userdata_dir = File.expand_path(MU.myRoot+"/modules/mu/userdata")
					platform = "linux" if %w{centos centos6 centos7 ubuntu ubuntu14}.include? platform
					platform = "windows" if %w{win2k12r2 win2k12}.include? platform
					erbfile = "#{userdata_dir}/#{platform}.erb"
					if !File.exist?(erbfile)
						MU.log "No such userdata template '#{erbfile}'", MU::WARN
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
					if !custom_append.nil?
						if custom_append['path'].nil?
							raise MuError, "Got a custom userdata script argument, but no ['path'] component"
						end
						erbfile = File.read(custom_append['path'])
						MU.log "Loaded userdata script from #{custom_append['path']}"
						if custom_append['use_erb']
							begin
								erb = ERB.new(erbfile, 1)
								script = script+"\n"+erb.result
							rescue NameError => e
								raise MuError, "Error parsing userdata script #{erbfile} as an ERB template: #{e.inspect}"
							end
							MU.log "Parsed #{custom_append['path']} as ERB", MU::DEBUG, details: script
						else
							script = script+"\n"+erb.result
							MU.log "Parsed #{custom_append['path']} as flat file", MU::DEBUG, details: script
						end
					end
					return script
				}
			end

			# Find volumes attached to a given instance id and tag them. If no arguments
			# besides the instance id are provided, it will add our special MU-ID
			# tag. Can also be used to do things like set the resource's name, if you
			# leverage the other arguments.
			# @param instance_id [String]: The cloud provider's identifier for the parent instance of this volume.
			# @param device [String]: The OS-level device name of the volume.
			# @param tag_name [String]: The name of the tag to attach.
			# @param tag_value [String]: The value of the tag to attach.
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.tagVolumes(instance_id, device=nil, tag_name="MU-ID", tag_value=MU.mu_id, region: MU.curRegion)
			  MU::Cloud::AWS.ec2(region).describe_volumes(filters: [name: "attachment.instance-id", values: [instance_id]]).each { |vol|
			    vol.volumes.each { |volume|
						volume.attachments.each { |attachment|
							vol_parent = attachment.instance_id
							vol_id = attachment.volume_id
							vol_dev = attachment.device
							if vol_parent == instance_id and (vol_dev == device or device.nil?) 
								MU::MommaCat.createTag(vol_id, tag_name, tag_value, region: region)
								break
							end
						}
					}
				}
			end
			
			# Called automatically by {MU::Deploy#createResources}
			def create
				begin
					done = false
					instance = createEc2Instance

					@config["instance_id"] = instance.instance_id
					MU.mommacat.saveSecret(@config["instance_id"], @config['instance_secret'], "instance_secret")
					@config.delete("instance_secret")
					if !@config['winpass'].nil?
						MU.mommacat.saveSecret(@config["instance_id"], @config['winpass'], "windows_password")
						@config.delete("winpass")
					end
					if !@config['async_groom']
						sleep 5
						MU::MommaCat.lock(instance.instance_id+"-create")
						if !postBoot
							MU.log "#{@config['name']} is already being groomed, skipping", MU::NOTICE
						else
							MU.log "Node creation complete for #{@config['name']}"
						end
						MU::MommaCat.unlock(instance.instance_id+"-create")
					else
						MU::MommaCat.createStandardTags(instance.instance_id, region: @config['region'])
					  MU::MommaCat.createTag(instance.instance_id,"Name",MU::MommaCat.getResourceName(@config['name']), region: @config['region'])
					end
					done = true
				rescue Exception => e
					if !instance.nil? and !done
						MU.log "Aborted before I could finish setting up #{@config['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
						MU::MommaCat.unlockAll
						if !@deploy.nocleanup
							parent_thread_id = Thread.current.object_id
							Thread.new {
								MU.dupGlobals(parent_thread_id)
								MU::Cloud::AWS::Server.removeIAMProfile(@config['name'])
								MU::Cloud::AWS::Server.cleanup(noop: false, ignoremaster: false, skipsnapshots: true)
							}
						end
					end
					raise e
				end

				return @config
			end

			# Remove the automatically generated IAM Profile for a given class of
			# server.
			# @param name [String]: The name field of the {MU::Cloud::AWS::Server} or {MU::Cloud::AWS::ServerPool} resource's IAM profile to remove.
			# @return [void]
			def self.removeIAMProfile(name)
				rolename = MU::MommaCat.getResourceName(name)
				MU.log "Removing IAM role and policies for '#{name}' nodes"
				begin
					MU::Cloud::AWS.iam.remove_role_from_instance_profile(
						instance_profile_name: rolename,
						role_name: rolename
					)
				rescue Aws::IAM::Errors::NoSuchEntity => e
					MU.log "Cleaning up IAM role #{rolename}: #{e.inspect}", MU::DEBUG
				end
				begin
					MU::Cloud::AWS.iam.delete_instance_profile(instance_profile_name: rolename)
				rescue Aws::IAM::Errors::NoSuchEntity => e
					MU.log "Cleaning up IAM role #{rolename}: #{e.inspect}", MU::DEBUG
				end
				begin
					policies = MU::Cloud::AWS.iam.list_role_policies(role_name: rolename).policy_names
					policies.each { |policy|
						MU::Cloud::AWS.iam.delete_role_policy(role_name: rolename, policy_name: policy)
					}
				rescue Aws::IAM::Errors::NoSuchEntity => e
					MU.log "Cleaning up IAM role #{rolename}: #{e.inspect}", MU::DEBUG
				end
				begin
					MU::Cloud::AWS.iam.delete_role(role_name: rolename)
				rescue Aws::IAM::Errors::NoSuchEntity => e
					MU.log "Cleaning up IAM role #{rolename}: #{e.inspect}", MU::DEBUG
				end
			end

			# Create an Amazon IAM instance profile. One of these should get created
			# for each class of instance (each {MU::Cloud::AWS::Server} or {MU::Cloud::AWS::ServerPool}),
			# and will include both baseline Mu policies and whatever other policies
			# are requested.
			# @param name [String]: The name field of the {MU::Cloud::AWS::Server} or {MU::Cloud::AWS::ServerPool} resource's IAM profile to create.
			# @return [String]: The name of the instance profile.
			def self.createIAMProfile(name, base_profile: nil, extra_policies: nil)
				rolename = MU::MommaCat.getResourceName(name, max_length: 64)
				MU.log "Creating IAM role and policies for '#{name}' nodes"
				policies = Hash.new
				policies['Mu_Bootstrap_Secret'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::'+MU.adminBucketName+'/'+"#{MU.mu_id}-secret"+'"}]}'
				policies['Mu_Volume_Management'] ='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:CreateTags","ec2:CreateVolume","ec2:AttachVolume","ec2:DescribeInstanceAttribute","ec2:DescribeVolumeAttribute","ec2:DescribeVolumeStatus","ec2:DescribeVolumes"],"Resource":"*"}]}'

				if base_profile
					MU.log "Incorporating policies from existing IAM profile '#{base_profile}'"
					resp = MU::Cloud::AWS.iam.get_instance_profile(instance_profile_name: base_profile)
					resp.instance_profile.roles.each { |baserole|
						role_policies = MU::Cloud::AWS.iam.list_role_policies(role_name: baserole.role_name).policy_names
						role_policies.each { |name|
							resp = MU::Cloud::AWS.iam.get_role_policy(
								role_name: baserole.role_name,
								policy_name: name
							)
							policies[name] = URI.unescape(resp.policy_document)
						}
					}
				end
				if extra_policies
					MU.log "Incorporating other specified policies", details: extra_policies
					extra_policies.each { |policy_set|
						policy_set.each_pair { |name, policy|
							if policies.has_key?(name)
								MU.log "Attempt to add duplicate node policy '#{name}' to '#{rolename}'", MU::WARN, details: policy
								next
							end
							policies[name] = JSON.generate(policy)
						}
					}
				end
				resp = MU::Cloud::AWS.iam.create_role(
					role_name: rolename,
					assume_role_policy_document: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}'
				)
				begin
					name=doc=nil
					policies.each_pair { |name, doc|
						MU.log "Merging policy #{name} into #{rolename}", MU::NOTICE, details: doc
						MU::Cloud::AWS.iam.put_role_policy(
							role_name: rolename,
							policy_name: name,
							policy_document: doc
						)
					}
				rescue Aws::IAM::Errors::MalformedPolicyDocument => e
					MU.log "Malformed policy when creating IAM Role #{rolename}: #{e.inspect}", MU::ERR
					raise MuError, "Malformed policy when creating IAM Role #{rolename}: #{e.inspect}"
				end
				MU::Cloud::AWS.iam.create_instance_profile(
					instance_profile_name: rolename
				)
				MU::Cloud::AWS.iam.add_role_to_instance_profile(
					instance_profile_name: rolename,
					role_name: rolename
				)

				return rolename
			end
			
			# Create an Amazon EC2 instance.
			def createEc2Instance
			  name = @config["name"]
			  node = @config['mu_name']
				@config['iam_role'] = MU::Cloud::AWS::Server.createIAMProfile("Server-"+name, base_profile: @config['iam_role'], extra_policies: @config['iam_policies'])
				@config['iam_role'] = @config['iam_role']

			  instance_descriptor = {
			    :image_id => @config["ami_id"],
			    :key_name => @deploy.ssh_key_name,
			    :instance_type => @config["size"],
			    :disable_api_termination => true,
			    :min_count => 1,
			    :max_count => 1,
					:network_interfaces => [
						{
							:associate_public_ip_address => name["associate_public_ip"]
						}
					]
			  }
				
				if !@config['private_ip'].nil?
					instance_descriptor[:private_ip_address] = @config['private_ip']
				end

				vpc_id=subnet_id=nat_host_name=nat_ssh_user = nil
				subnet_retries = 0
				if !@config["vpc"].nil?
					begin
						vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::Cloud::AWS::VPC.parseVPC(@config['vpc'])
					rescue Aws::EC2::Errors::ServiceError => e
						MU.log e.message, MU::ERR, details: @config
						if subnet_retries < 5
						  subnet_retries = subnet_retries + 1
						  sleep 15
						  retry
						end
						raise MuError, e.inspect
					end
					subnet_id = subnet_ids.first
					if subnet_id.nil? or subnet_id.empty?
						raise MuError, "Got null Subnet id out of #{@config['vpc']}"
					end

					MU.log "Deploying #{node} into VPC #{vpc_id} Subnet #{subnet_id}"

					if !@config["vpc"]["nat_host_name"].nil? or !@config["vpc"]["nat_host_id"].nil?
						admin_sg = MU::Cloud::AWS::Server.punchAdminNAT(@config, node)
					else
						admin_sg = MU::Cloud::AWS::FirewallRule.setAdminSG(vpc_id: vpc_id, region: @config['region'])
					end

					instance_descriptor[:subnet_id] = subnet_id
					node_sg = MU::Cloud::AWS::FirewallRule.createEc2SG(
							@config["name"].upcase,
							@config["ingress_rules"],
							description: "SG holes for #{node}",
							vpc_id: vpc_id,
							region: @config['region']
					)
				else
					admin_sg = MU::Cloud::AWS::FirewallRule.setAdminSG(region: @config['region'])
					node_sg = MU::Cloud::AWS::FirewallRule.createEc2SG(
							@config["name"].upcase,
							@config["ingress_rules"],
							description: "SG holes for #{node}",
							region: @config['region']
					)
				end
				security_groups = Array.new
				security_groups << admin_sg
				security_groups << node_sg
				if !@config["add_firewall_rules"].nil?
					@config["add_firewall_rules"].each { |acl|
						sg = MU::Cloud::FirewallRule.find(sg_id: acl["rule_id"], name: acl["rule_name"], region: @config['region'])
						if sg.nil?
							raise MuError, "Couldn't find dependent security group #{acl} for server #{node}"
						end
						security_groups << sg.group_id
					}
				end

				instance_descriptor[:security_group_ids] = security_groups

			  if !@userdata.nil? and !@userdata.empty?
			    instance_descriptor[:user_data] =  Base64.encode64(@userdata)
			  end

			  if !@config["iam_role"].nil?
			    instance_descriptor[:iam_instance_profile] = { name: @config["iam_role"]}
			  end

				configured_storage = Array.new
				if @config["storage"]
					@config["storage"].each { |vol|
						configured_storage << MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
					}
				end
			
				MU::Cloud::AWS::Server.waitForAMI(@config["ami_id"], region: @config['region'])

				instance_descriptor[:block_device_mappings] = configured_storage
				instance_descriptor[:block_device_mappings].concat(@ephemeral_mappings)

				instance_descriptor[:monitoring] = { enabled: @config['monitoring'] }

				MU.log "Creating EC2 instance #{node}"
				MU.log "Instance details for #{node}: #{instance_descriptor}", MU::DEBUG
#				if instance_descriptor[:block_device_mappings].empty?
#					instance_descriptor.delete(:block_device_mappings)
#				end
#pp instance_descriptor[:block_device_mappings]
				retries = 0
				begin
					response = MU::Cloud::AWS.ec2(@config['region']).run_instances(instance_descriptor)
				rescue Aws::EC2::Errors::InvalidGroupNotFound, Aws::EC2::Errors::InvalidSubnetIDNotFound, Aws::EC2::Errors::InvalidParameterValue => e
					if retries < 10
						if retries > 7
							MU.log "Seeing #{e.inspect} while trying to launch #{node}, retrying a few more times...", MU::WARN, details: instance_descriptor
						end
						sleep 10
						retries = retries + 1
						retry
					else
						raise MuError, e.inspect
					end
				end

				instance = response.instances.first
				MU.log "#{node} (#{instance.instance_id}) coming online"


				return instance

			end

			# Figure out what's needed to SSH into this server.
			# @return [Array<String>]: nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name
			def getSSHConfig
				ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
				return nil if @config.nil? or @deploy.nil?

				nat_ssh_key = nat_ssh_user = nat_ssh_host = nil
				if !@config["vpc"].nil? and !MU::Cloud::AWS::VPC.haveRouteToInstance?(@config['instance_id'])
					if !@config["vpc"]["nat_host_name"].nil? or
						 !@config["vpc"]["nat_host_id"].nil?
						nat_ssh_user = @config["vpc"]["nat_ssh_user"]
						nat_instance, mu_name = MU::Cloud::Server.find(
							id: @config["vpc"]["nat_host_id"],
							name: @config["vpc"]["nat_host_name"],
							region: @config['region']
						)
						if nat_instance.nil?
							MU.log "#{@config["name"]} (#{MU.mu_id}) is configured to use #{@config['vpc']} but I can't find a running instance matching nat_host_id or nat_host_name", MU::ERR, details: caller
							raise MuError, "#{@config["name"]} (#{MU.mu_id}) is @configured to use #{@config['vpc']} but I can't find a running instance matching nat_host_id or nat_host_name"
						end
						nat_ssh_key = nat_instance.key_name
						nat_ssh_host = nat_instance.public_ip_address
						found_servers = MU::MommaCat.getResourceDeployStruct(MU::Cloud::Server.cfg_plural, name: mu_name)
						if !found_servers.nil? and found_servers.is_a?(Hash)
							if found_servers.values.first['instance_id'] == nat_instance.instance_id
								dns_name = MU::Cloud::DNSZone.genericMuDNSEntry(found_servers.keys.first, nat_ssh_host, MU::Cloud::Server, noop: true, sync_wait: @config['dns_sync_wait'])
							end
						end
						nat_ssh_host = dns_name if !dns_name.nil?
						if nat_ssh_user.nil? and !nat_ssh_host.nil?
							MU.log "#{@config["name"]} (#{MU.mu_id}) is configured to use #{@config['vpc']} NAT #{nat_ssh_host}, but username isn't specified. Guessing root.", MU::ERR, details: caller
							nat_ssh_user = "root"
						end
					end
				end

				if @config['canonical_ip'].nil?
					instance, mu_name = MU::Cloud::Server.find(id: @config['instance_id'], region: @config['region'])
					canonical_ip = instance.public_ip_address
					canonical_ip = instance.private_ip_address if !canonical_ip
					@config['canonical_ip'] = canonical_ip
				end
				if @config['ssh_user'].nil?
					if %w{win2k12r2 win2k12 windows}.include?(@server['platform'])
						@config['ssh_user'] = "Administrator"
					else
						@config['ssh_user'] = "root"
					end
				end

				return [nat_ssh_key, nat_ssh_user, nat_ssh_host, @config['canonical_ip'], @config['ssh_user'], @deploy.ssh_key_name]

			end

			# Basic setup tasks performed on a new node during its first initial ssh
			# connection. Most of this is terrible Windows glue.
			# @param ssh [Net::SSH::Connection::Session]: The active SSH session to the new node.
			# @param server [Hash]: A server's configuration block as defined in {MU::Config::BasketofKittens::servers}
			def self.initialSSHTasks(ssh, server)
				chef_cleanup = %q{test -f /opt/mu_installed_chef || ( rm -rf /var/chef/ /etc/chef /opt/chef/ /usr/bin/chef-* ; touch /opt/mu_installed_chef )}
				win_env_fix = %q{echo 'export PATH="$PATH:/cygdrive/c/opscode/chef/embedded/bin"' > "$HOME/chef-client"; echo 'prev_dir="`pwd`"; for __dir in /proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Session\ Manager/Environment;do cd "$__dir"; for __var in `ls * | grep -v TEMP | grep -v TMP`;do __var=`echo $__var | tr "[a-z]" "[A-Z]"`; test -z "${!__var}" && export $__var="`cat $__var`" >/dev/null 2>&1; done; done; cd "$prev_dir"; /cygdrive/c/opscode/chef/bin/chef-client.bat $@' >> "$HOME/chef-client"; chmod 700 "$HOME/chef-client"; ( grep "^alias chef-client=" "$HOME/.bashrc" || echo 'alias chef-client="$HOME/chef-client"' >> "$HOME/.bashrc" ) ; ( grep "^alias mu-groom=" "$HOME/.bashrc" || echo 'alias mu-groom="powershell -File \"c:/Program Files/Amazon/Ec2ConfigService/Scripts/UserScript.ps1\""' >> "$HOME/.bashrc" )}
				win_set_pw = nil
				if !server['windows_admin_password'].nil?
					field = server["windows_admin_password"]["password_field"]
					pw = ChefVault::Item.load(
						server['windows_admin_password']['vault'],
						server['windows_admin_password']['item']
					)[field]
					win_set_pw = %Q{powershell -Command "&{ (([adsi]('WinNT://./#{server["windows_admin_username"]}, user')).psbase.invoke('SetPassword', '#{pw}'))}"}
				else
					begin
						winpass = MU.mommacat.fetchSecret(server["instance_id"], "winpass", quiet: true)
						win_set_pw = %Q{powershell -Command "&{ (([adsi]('WinNT://./#{server['windows_admin_username']}, user')).psbase.invoke('SetPassword', '#{winpass}'))}"} if !winpass.nil?
					rescue MU::MommaCat::SecretError
						# This is ok
					end
				end

				win_installer_check = %q{ls /proc/registry/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Installer/}
				win_set_hostname = %Q{powershell -Command "& {Rename-Computer -NewName "#{server['mu_windows_name']}" -Force -PassThru -Restart}"}
				# We sometimes get a machine that's already been integrated into AD, and
				# thus needs domain creds to rename. Use 'em if we have 'em.
				win_set_hostname_ad = nil
				if !server['active_directory'].nil?
					item = ChefVault::Item.load(
						server['active_directory']['auth_vault'],
						server['active_directory']['auth_item']
					)
					ad_user = item[server['active_directory']['auth_username_field']]
					ad_pwd = item[server['active_directory']['auth_password_field']]
					win_set_hostname_ad = %Q{powershell -Command "& {Rename-Computer -NewName "#{server['mu_windows_name']}" -Force -PassThru -Restart -DomainCredential(New-Object System.Management.Automation.PSCredential('femadata\\#{ad_user}', (ConvertTo-SecureString '#{ad_pwd}' -AsPlainText -Force)))}"}
				end

				begin
					if !server['set_windows_pass'] and !win_set_pw.nil?
						MU.log "Setting Windows password for user #{server['windows_admin_username']}", MU::NOTICE
						ssh.exec!(win_set_pw)
MU.log win_set_pw, MU::ERR
						server['set_windows_pass'] = true
					end
					if !server['cleaned_chef']
						MU.log "Expunging pre-existing Chef install, if we didn't create it", MU::NOTICE
						ssh.exec!(chef_cleanup)
						server['cleaned_chef'] = true
					end
					if %w{win2k12r2 win2k12 windows}.include? server['platform']
						output = ssh.exec!(win_env_fix)
						output = ssh.exec!(win_installer_check)
						if output.match(/InProgress/)
							raise BootstrapTempFail, "Windows Installer service is still doing something, need to wait"
						end
						if !server['hostname_set'] and !server['mu_windows_name'].nil?
							# XXX need a better guard here, this pops off every time
							ssh.exec!(win_set_hostname)
							ssh.exec!(win_set_hostname_ad) if !win_set_hostname_ad.nil?
							server['hostname_set'] = true
							raise BootstrapTempFail, "Setting hostname to #{server['mu_windows_name']}, possibly rebooting"
						end
					end
				rescue RuntimeError => e
					raise BootstrapTempFail, "Got #{e.inspect} performing initial SSH connect tasks, will try again"
				end
			end

			
			# Apply tags, bootstrap our configuration management, and other
			# administravia for a new instance.
			def postBoot
				node, config, deploydata, instance = describe(@config['instance_id'], @config['mu_name'])

				return false if !MU::MommaCat.lock(instance.instance_id+"-orchestrate", true)
				return false if !MU::MommaCat.lock(instance.instance_id+"-groom", true)

				MU::MommaCat.createStandardTags(instance.instance_id, region: @config['region'])
			  MU::MommaCat.createTag(instance.instance_id, "Name", node, region: @config['region'])
				if !@config['tags'].nil?
					@config['tags'].each { |tag|
						MU::MommaCat.createTag(instance.instance_id, tag['key'], tag['value'], region: @config['region'])
					}
				end
				MU.log "Tagged #{node} (#{instance.instance_id}) with MU-ID=#{MU.mu_id}", MU::DEBUG

				retries = 0
				id = instance.instance_id
				begin
					if instance.nil? or instance.state.name != "running"
						if !instance.nil? and instance.state.name == "terminated"
							retries = 30
							raise MuError, "#{id} appears to have been terminated mid-bootstrap!"
						end
						if retries % 3 == 0
							MU.log "Waiting for EC2 instance #{node} to be ready...", MU::NOTICE
						end
						sleep 20
						instance, mu_name = MU::Cloud::Server.find(id: id, region: @config['region'])
					end
				rescue Aws::EC2::Errors::ServiceError => e
					if retries < 30
						MU.log "Got #{e.inspect} during initial instance creation of #{id}, retrying...", MU::NOTICE, details: instance
						retries = retries + 1
						sleep 5
						retry
					else
						raise MuError, "Too many retries creating #{node} (#{e.inspect})"
					end
				end while instance.nil? or (instance.state.name != "running" and retries < 30)

				admin_sg = MU::Cloud::AWS::Server.punchAdminNAT(@config, node)

				# Unless we're planning on associating a different IP later, set up a 
				# DNS entry for this thing and let it sync in the background. We'll come
				# back to it later.
				if @config['static_ip'].nil?
					MU::MommaCat.nameKitten(self)
				end

				if !@config['src_dst_check'] and !@config["vpc"].nil?
					MU.log "Disabling source_dest_check #{node} (making it NAT-worthy)"
					MU::Cloud::AWS.ec2(@config['region']).modify_instance_attribute(
						instance_id: instance.instance_id,
						source_dest_check: { :value => false }
					)
				end

				# Set console termination protection. Autoscale nodes won't set this
				# by default.
				MU::Cloud::AWS.ec2(@config['region']).modify_instance_attribute(
					instance_id: instance.instance_id,
					disable_api_termination: { :value => true }
				)

				has_elastic_ip = false
				if !instance.public_ip_address.nil?
					begin
						resp = MU::Cloud::AWS.ec2((@config['region'])).describe_addresses(public_ips: [instance.public_ip_address])
						if resp.addresses.size > 0 and resp.addresses.first.instance_id == instance.instance_id
							has_elastic_ip = true
						end
					rescue Aws::EC2::Errors::InvalidAddressNotFound => e
						# XXX this is ok to ignore, it means the public IP isn't Elastic
					end
				end

				if !@config["vpc"].nil?
					is_private = MU::Cloud::AWS::VPC.isSubnetPrivate?(instance.subnet_id, region: @config['vpc']['region'])
					if !is_private or (!@config['static_ip'].nil? and !@config['static_ip']['assign_ip'].nil?)
						if !@config['static_ip'].nil?
							if !@config['static_ip']['ip'].nil?
								public_ip = associateElasticIp(instance.instance_id, classic: false, ip: @config['static_ip']['ip'])
							elsif !has_elastic_ip
								public_ip = associateElasticIp(instance.instance_id)
							end
						end
					end

					nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
					if is_private and !nat_ssh_host and !MU::Cloud::AWS::VPC.haveRouteToInstance?(instance.instance_id)
						raise MuError, "#{node} is in a private subnet, but has no NAT host configured, and I have no other route to it"
					end

					# If we've asked for additional subnets (and this @config is not a
					# member of a Server Pool, which has different semantics), create
					# extra interfaces to accomodate.
					if !@config['vpc']['subnets'].nil? and @config['basis'].nil?
						device_index = 1
						@config['vpc']['subnets'].each { |subnet|
							tag_key, tag_value = @config['vpc']['tag'].split(/=/, 2) if !@config['vpc']['tag'].nil?
							existing_vpc, vpc_name = MU::Cloud::VPC.find(
								id: @config['vpc']['vpc_id'],
								name: @config['vpc']['vpc_name'],
								deploy_id: @config['vpc']['deploy_id'],
								tag_key: tag_key,
								tag_value: tag_value,
								region: @config['vpc']['region']
							)
							tag_key, tag_value = @config['vpc']['tag'].split(/=/, 2) if !subnet['tag'].nil?

							subnet_struct = MU::Cloud::AWS::VPC::findSubnet(
								id: subnet["subnet_id"],
								name: subnet["subnet_name"],
								vpc_id: existing_vpc.vpc_id,
								deploy_id: @config['vpc']['deploy_id'],
								tag_key: tag_key,
								tag_value: tag_value,
								region: @config['vpc']['region']
							)
							if subnet_struct.nil?
								raise MuError, "#{node} is configured to have an interface in #{subnet}, but no such subnet exists"
							end
							subnet_id = subnet_struct.subnet_id
							MU.log "Adding network interface on subnet #{subnet_id} for #{node}"
							iface = MU::Cloud::AWS.ec2(@config['region']).create_network_interface(subnet_id: subnet_id).network_interface
							MU::MommaCat.createStandardTags(iface.network_interface_id, region: @config['region'])
						  MU::MommaCat.createTag(iface.network_interface_id,"Name",node+"-ETH"+device_index.to_s, region: @config['region'])
							if !@config['tags'].nil?
								@config['tags'].each { |tag|
									MU::MommaCat.createTag(iface.network_interface_id,tag['key'],tag['value'], region: @config['region'])
								}
							end
							MU::Cloud::AWS.ec2(@config['region']).attach_network_interface(
								network_interface_id: iface.network_interface_id,
								instance_id: instance.instance_id,
								device_index: device_index
							)
							device_index = device_index + 1
						}
					end
				elsif !@config['static_ip'].nil?
					if !@config['static_ip']['ip'].nil?
						public_ip = associateElasticIp(instance.instance_id, classic: true, ip: @config['static_ip']['ip'])
					elsif !has_elastic_ip
						public_ip = associateElasticIp(instance.instance_id, classic: true)
					end
				end


				if !@config['image_then_destroy']
					notify
				end

			  MU.log "EC2 instance #{node} has id #{instance.instance_id}", MU::DEBUG

				instance, mu_name = MU::Cloud::Server.find(id: instance.instance_id, region: @config['region'])

				if !@config['dns_records'].nil?
					@config['dns_records'].each { |dnsrec|
						dnsrec['name'] = node.downcase if !dnsrec.has_key?('name')
					}
				end
				if !instance.public_ip_address.nil? and !instance.public_ip_address.empty?
#					MU::Cloud::DNSZone.createRecordsFromConfig(@config['dns_records'], target: instance.public_ip_address)
				else
#					MU::Cloud::DNSZone.createRecordsFromConfig(@config['dns_records'], target: instance.private_ip_address)
				end

				@config["private_dns_name"] = instance.private_dns_name
				@config["public_dns_name"] = instance.public_dns_name
				@config["private_ip_address"] = instance.private_ip_address
				@config["public_ip_address"] = instance.public_ip_address

				ext_mappings = MU.structToHash(instance.block_device_mappings)

			  # Root disk on standard CentOS AMI
			  # tagVolumes(instance.instance_id, "/dev/sda", "Name", "ROOT-"+MU.mu_id+"-"+@config["name"].upcase)
			  # Root disk on standard Ubuntu AMI
			  # tagVolumes(instance.instance_id, "/dev/sda1", "Name", "ROOT-"+MU.mu_id+"-"+@config["name"].upcase)
			
			  # Generic deploy ID tag
			  # tagVolumes(instance.instance_id)

				# Tag volumes with all our standard tags. 
				# Maybe replace tagVolumes with this? There is one more place tagVolumes is called from
				volumes = MU::Cloud::AWS.ec2(@config['region']).describe_volumes(filters: [name: "attachment.instance-id", values: [instance.instance_id]])
				volumes.each {|vol|
					vol.volumes.each{ |volume|
						volume.attachments.each { |attachment|
							MU::MommaCat.listStandardTags.each_pair { |key, value|
								MU::MommaCat.createTag(attachment.volume_id, key, value, region: @config['region'])

								if attachment.device == "/dev/sda" or attachment.device == "/dev/sda1"
									MU::MommaCat.createTag(attachment.volume_id, "Name", "ROOT-#{MU.mu_id}-#{@config["name"].upcase}", region: @config['region'])
								else
									MU::MommaCat.createTag(attachment.volume_id, "Name", "#{MU.mu_id}-#{@config["name"].upcase}-#{attachment.device.upcase}", region: @config['region'])
								end
							}

							if @config['tags']
								@config['tags'].each { |tag|
									MU::MommaCat.createTag(attachment.volume_id, tag['key'], tag['value'], region: @config['region'])
								}
							end
						}
					}
				}

				canonical_name = instance.public_dns_name
				canonical_name = instance.private_dns_name if !canonical_name or nat_ssh_host != nil
				@config['canonical_name'] = canonical_name

				if !@config['add_private_ips'].nil?
					instance.network_interfaces.each { |int|
						if int.private_ip_address == instance.private_ip_address and int.private_ip_addresses.size < (@config['add_private_ips'] + 1)
							MU.log "Adding #{@config['add_private_ips']} extra private IP addresses to #{instance.instance_id}"
							MU::Cloud::AWS.ec2(@config['region']).assign_private_ip_addresses(
								network_interface_id: int.network_interface_id,
								secondary_private_ip_address_count: @config['add_private_ips'],
								allow_reassignment: false
							)
						end
					}
					notify
				end


				# Make an initial connection with SSH to see if this host is ready to
				# have configuration management inflicted on it. Also run some prep.
				ssh_wait = 25 
				max_retries = 25
				if %w{win2k12r2 win2k12 windows}.include? @config['platform']
					ssh_wait = 60
					max_retries = 25
				end

			  begin
					Thread.abort_on_exception = false
					session = getSSHSession(ssh_wait, max_retries)
					MU::Cloud::AWS::Server.initialSSHTasks(session, @config)
			  rescue BootstrapTempFail
					sleep ssh_wait
			    retry
				ensure
					session.close if !session.nil?
			  end

				# See if this node already exists in our config management. If it does,
				# we're done.
				if @groomer.haveBootstrapped?
					MU.log "Node #{node} has already been bootstrapped, skipping groomer setup.", MU::NOTICE
					@groomer.syncDeployData
					MU::MommaCat.unlock(instance.instance_id+"-orchestrate")
					MU::MommaCat.unlock(instance.instance_id+"-groom")
					return true
				end

				if !@config['active_directory'].nil?
					if @config['mu_windows_name'].nil?
						@config['mu_windows_name'] = MU::MommaCat.getResourceName(@config['name'], max_length: 15, need_unique_string: true)
						@groomer.syncDeployData
					end
				end

				@groomer.bootstrap

				# Make sure we got our name written everywhere applicable
				MU::MommaCat.nameKitten(self)

				@groomer.syncDeployData
				MU::MommaCat.openFirewallForClients

				MU::MommaCat.unlock(instance.instance_id+"-groom")
				MU::MommaCat.unlock(instance.instance_id+"-orchestrate")
				return true
			end # postBoot


			# Locate a running instance. Can identify instances by their cloud
			# provider identifier, OR by their internal Mu resource name, OR by a 
			# cloud provider tag name/value pair, OR by an assigned IP address.
			# @param name [String]: An Mu resource name, usually the 'name' field of aa Basket of Kittens resource declaration. Will search the currently loaded deployment unless another is specified.
			# @param deploy_id [String]: The deployment to search using the 'name' parameter.
			# @param id [String]: The cloud provider's identifier for this resource.
			# @param tag_key [String]: A tag key to search.
			# @param tag_value [String]: The value of the tag specified by tag_key to match when searching by tag.
			# @param allow_multi [Boolean]: When searching by tags or name, permit an array of resources to be returned (if applicable) instead of just one.
			# @param ip [String]: An IP address assigned to this instance.
			# @param region [String]: The cloud provider region
			# @return [OpenStruct,String]: The cloud provider's complete description of this server, and its MU resource name (if applicable).
			def self.find(name: nil, deploy_id: MU.mu_id, id: nil, tag_key: "Name", tag_value: nil, allow_multi: false, ip: nil, region: MU.curRegion)
				return nil if !id and !name and !ip and !tag_value
				# If we got an instance id, go get that
				instance = nil
				if !region.nil?
					regions = [region]
				else
					regions = MU::Cloud::AWS.listRegions
				end

				found_instances = []
				search_semaphore = Mutex.new
				search_threads = []

				if !id.nil?
					regions.each { |region|
						search_threads << Thread.new(region) { |myregion|
							MU.log "Hunting for instance with cloud id '#{id}' in #{myregion}", MU::DEBUG
							retries = 0
							begin
								response = MU::Cloud::AWS.ec2(myregion).describe_instances(
									instance_ids: [id],
									filters: [
										{ name: "instance-state-name", values: ["running", "pending"] }
									]
								).reservations.first
								if response
									search_semaphore.synchronize {
										found_instances << response.instances.first
									}
								end
							rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
								if retries < 5
									retries = retries + 1
									sleep 5
								else
									raise MuError, "#{e.inspect} in region #{region}"
								end
							end
						}
					}
					done_threads = []
					begin
						search_threads.each { |t|
							joined = t.join(2)
							done_threads << joined if !joined.nil?
						}
					end while found_instances.size < 1 and done_threads.size != search_threads.size
				end

				instance = found_instances.shift if found_instances.size > 0

				# Ok, well, let's try looking it up by IP then
				if instance.nil? and !ip.nil?
					MU.log "Hunting for instance by IP '#{ip}'", MU::DEBUG
					["ip-address", "private-ip-address"].each { |filter|
						response = MU::Cloud::AWS.ec2(region).describe_instances(
							filters: [
								{ name: filter, values: [ip] },
								{ name: "instance-state-name", values: ["running", "pending"] }
							]
						).reservations.first
						instance = response.instances.first if !response.nil?
					}
				end

				# Let's say we've found this instance with the cloud id or IP. Let's go
				# get its Mu resource name and return that too, if there is one.
				if !instance.nil? and name.nil?
					servers = MU::MommaCat.getResourceDeployStruct(MU::Cloud::Server.cfg_plural, deploy_id: deploy_id)
					if !servers.nil?
						servers.each { |ext_server|
							if ext_server.values.size > 0 and ext_server.values.first['instance_id'] == instance.instance_id
								name = ext_server.values.first['#MU_NODE_CLASS']
								break
							end
						}
					end
				end

				return [instance, name] if !instance.nil?

				# If we've been asked to find by name, things get weird. In server pools
				# you can easily have multiple servers with the same Mu resource name.
				name_matches = []
				if !name.nil? and !deploy_id.nil?
					resource = MU::MommaCat.getResourceDeployStruct(MU::Cloud::Server.cfg_plural, name: name, deploy_id: deploy_id)
					MU.log "Searching for instance by name '#{name}'", MU::DEBUG, details: resource
					if !resource.nil? and resource.keys.size == 1
						nodename, server = resource.shift
						name_matches << server
					elsif !resource.nil? and resource.keys.size > 1
						if !allow_multi
							MU.log "Found multiple matching servers for name #{name} in deploy #{deploy_id}", MU::ERR, details: resource
							raise MuError, "Found multiple matching servers for name #{name} in deploy #{deploy_id}"
						else
							resource.each_pair { |nodename, server|
								name_matches << server
							}
						end
					end
				end
				matches = []
				name_matches.each { |server|
					next if server['instance_id'].nil?
					response = MU::Cloud::AWS.ec2(region).describe_instances(
						instance_ids: [server['instance_id']],
						filters: [
							{ name: "instance-state-name", values: ["running", "pending"] }
						]
					).reservations.first
					matches << response.instances.first if response
				}

				# Fine, let's try it by tag.
				if matches.size == 0 and !tag_value.nil?
					MU.log "Searching for instance by tag '#{tag_key}=#{tag_value}'", MU::DEBUG
					resp = MU::Cloud::AWS.ec2(region).describe_instances(
						filters:[
							{ name: "tag:#{tag_key}", values: [tag_value] },
							{ name: "instance-state-name", values: ["running", "pending"] }
						]
					).reservations.first
					if !resp.nil? and resp.instances.size == 1
						matches << resp.instances.first if resp
					elsif resp.instances.size > 1
						if !allow_multi
							MU.log "Found multiple matching servers for tag #{tag_key}=#{tag_value} in deploy #{deploy_id}", MU::ERR, details: resp
							raise MuError, "Found multiple matching servers for tag #{tag_key}=#{tag_value} in deploy #{deploy_id}"
						else
							matches = resp.instances
						end
					end
				end

				if allow_multi
					return [matches, name]
				else
					return [matches.first, name]
				end
			end

			# Return a description of this resource appropriate for deployment
			# metadata. Arguments reflect the return values of the MU::Cloud::[Resource].describe method
			def notify
				node, config, deploydata, instance = describe(@config['instance_id'], @config['mu_name'])
				deploydata = Hash.new if deploydata.nil?

				if instance.nil?
					raise MuError, "Failed to load instance metadata for #{@config['mu_name']}/#{@config['instance_id']}"
				end

				interfaces = Array.new

				private_ips = []
				instance.network_interfaces.each { |iface|
					iface.private_ip_addresses .each { |priv_ip|
						private_ips << priv_ip.private_ip_address
					}
					interfaces << {
						"network_interface_id" => iface.network_interface_id,
						"subnet_id" => iface.subnet_id,
						"vpc_id" => iface.vpc_id
					}
				}

				deploydata[node] = {
					"nodename" => @config['mu_name'],
					"run_list" => @config['run_list'],
					"iam_role" => @config['iam_role'],
					"instance_id" => @config['instance_id'],
					"private_dns_name" => instance.private_dns_name,
					"public_dns_name" => instance.public_dns_name,
					"private_ip_address" => instance.private_ip_address,
					"public_ip_address" => instance.public_ip_address,
					"private_ip_list" => private_ips,
					"key_name" => instance.key_name,
					"subnet_id" => instance.subnet_id,
					"instance_type" => instance.instance_type#,
#				"network_interfaces" => interfaces,
#				"config" => server
				}

				if !@config['mu_windows_name'].nil?
					deploydata[node]["mu_windows_name"] = @config['mu_windows_name']
				end
				if !@config['chef_data'].nil?
					deploydata[node].merge!(@config['chef_data'])
				end
				deploydata[node]["region"] = @config['region'] if !@config['region'].nil?
				@deploy.notify("servers", @config['name'], deploydata)
				MU::MommaCat.nameKitten(self)

				return deploydata
			end

			# If the specified server is in a VPC, and has a NAT, make sure we'll
			# be letting ssh traffic in from said NAT.
			# @param server [Hash]: The MU resource descriptor for this instance.
			# @param node [String]: The full Mu name for this instance.
			def self.punchAdminNAT(server, node)
				if !server["vpc"].nil?
					MU::Cloud.artifact("AWS", :VPC)
					vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::Cloud::AWS::VPC.parseVPC(server['vpc'])
					if !nat_host_name.nil?
						nat_instance, mu_name = MU::Cloud::Server.find(
							id: server["vpc"]["nat_host_id"],
							name: server["vpc"]["nat_host_name"],
							region: server['region']
						)
						if nat_instance.nil?
							raise MuError, "#{node} (#{MU.mu_id}) is configured to use #{server['vpc']} but I can't find a running instance matching nat_host_id or nat_host_name"
						end
						MU.log "Adding administrative holes for NAT host #{nat_instance["private_ip_address"]} to #{node}", MU::DEBUG
						MU::Cloud.artifact("AWS", :FirewallRule)
						return MU::Cloud::AWS::FirewallRule.setAdminSG(
							vpc_id: vpc_id,
							add_admin_ip: nat_instance["private_ip_address"],
							region: server['region']
						)
					end
				end
			end

			# Called automatically by {MU::Deploy#createResources}
			def groom
				if @config["instance_id"].nil?
					MU.log "MU::Cloud::AWS::Server.groom was called without an instance id", MU::ERR
					raise MuError, "MU::Cloud::AWS::Server.groom was called without an instance id"
				end
				MU::MommaCat.lock(@config["instance_id"]+"-groom")

				node = @config['mu_name']

				if node.nil? or node.empty?
					MU.log "MU::Cloud::AWS::Server.groom was called without a mu_name", MU::ERR, details: server
					raise MuError, "MU::Cloud::AWS::Server.groom was called without a mu_name"
				end

				admin_sg = MU::Cloud::AWS::Server.punchAdminNAT(@config, node)

				instance, mu_name = MU::Cloud::Server.find(id: @config["instance_id"], region: @config['region'])
				MU::Cloud::AWS::Server.tagVolumes(@config["instance_id"])
			        
			  # If we depend on database instances, make sure those database instances'
			  # security groups will let us in.
				if @config["dependencies"] != nil then
					@config["dependencies"].each { |dependent_on|
						if dependent_on['type'] != nil and dependent_on['type'] == "database" then
							database = MU::Cloud::Database.find(name: dependent_on["name"], region: @config["region"])
							if database.nil?
								MU.log "Couldn't find identifier for dependent database #{dependent_on['name']} in #{@config["region"]}", MU::ERR
								raise MuError, "Couldn't find identifier for dependent database #{dependent_on['name']} in #{@config["region"]}"
							end
							db_id = database.db_instance_identifier
							private_ip = @config['private_ip_address']
							if private_ip != nil and db_id != nil then
								MU.log "Adding #{private_ip}/32 to database security groups for #{db_id}"
								MU::Cloud::AWS::Database.allowHost("#{private_ip}/32", db_id, region: @config['region'])
							end
						end
					}
				end

			  # If we have a loadbalancer configured, attach us to it
				# XXX refactor this into the LoadBalancer resource
				if !@config['loadbalancers'].nil?
					@config['loadbalancers'].each { |lb|
						lb_res = MU::Cloud::LoadBalancer.find(
							name: lb['concurrent_load_balancer'],
							dns_name: lb["existing_load_balancer"],
							region: @config['region']
						)
						raise MuError, "I need a LoadBalancer named #{lb['concurrent_load_balancer']}" if lb_res.nil?
						MU::Cloud::AWS::LoadBalancer.registerInstance(lb_res.load_balancer_name, @config["instance_id"], region: @config['region'])
					}
				end

				@groomer.syncDeployData

				# Make double sure we don't lose a cached mu_windows_name value.
				# XXX fugly
				if %w{win2k12r2 win2k12 windows}.include?(@config['platform']) or !@config['active_directory'].nil?
					if !@config['mu_windows_name'] and
#XXX need a "find me" method man
							!@deploy.deployment.nil? and
							@deploy.deployment.has_key?('servers') and
							@deployment['servers'].has_key?(@config['name']) and
							@deployment['servers'][@config['name']].has_key?(node)
						@config['mu_windows_name'] = @deployment['servers'][@config['name']][node]['mu_windows_name']
					end
				end

				begin
					@groomer.run(purpose: "Full Initial Run")
				rescue MU::Groomer::RunError
					MU.log "Proceeding after failed initial Groomer run, but #{node} may not behave as expected!", MU::WARN
				end
# XXX figure out what the condition was for this and implement here
#				if !chef_rerun_only
					MU::MommaCat.syncSiblings(@config["name"], true, triggering_node: node)
					syncDeployData if !@config['sync_siblings']
#				end


						# XXX ugh, man, this is incomplete
				if @config['create_ami'] and !chef_rerun_only
					if @config['image_then_destroy']
						knife_args = ['ssh', '-m', node, "rm -rf /etc/chef /root/.ssh/authorized_keys ; sed -i 's/^HOSTNAME=.*//' /etc/sysconfig/network"]
						begin
							Chef::Knife.run(knife_args, {})
						rescue SystemExit => e
							MU.log "Error scouring #{node} for AMI generation: #{e.message}", MU::ERR, details: e.backtrace
						end
					end
					ami_id = MU::Cloud::AWS::Server.createImage(name: name = @config['name'],
																instance_id: instance_id = @config['instance_id'],
																storage: @config['storage'],
																exclude_storage: @config['image_exclude_storage'],
																region: @config['region'])
					if @config['image_then_destroy']
						waitForAMI(ami_id, region: @config['region'])
						MU.log "AMI ready, removing source node #{node}"
						MU::Cloud::AWS::Server.terminateInstance(id: @config["instance_id"])
						%x{#{MU::Config.knife} node delete -y #{node}};
						return
					end
				end

				MU::MommaCat.unlock(@config["instance_id"]+"-groom")
			end

			# Create an AMI out of a running server. Requires either the name of a MU resource in the current deployment, or the cloud provider id of a running instance.
			# @param name [String]: The MU resource name of the server to use as the basis for this image.
			# @param instance_id [String]: The cloud provider resource identifier of the server to use as the basis for this image.
			# @param storage [Hash]: The storage devices to include in this image.
			# @param exclude_storage [Boolean]: Do not include the storage device profile of the running instance when creating this image.
			# @param region [String]: The cloud provider region
			# @return [String]: The cloud provider identifier of the new machine image.
			def self.createImage(name: name,
														instance_id: instance_id,
														storage: storage,
														exclude_storage: exclude_storage,
														region: MU.curRegion)

			  node = MU::MommaCat.getResourceName(name)
				ami_descriptor = {
					:instance_id => instance_id,
					:name => node,
					:description => "Image automatically generated by Mu from deployment of #{node}"
				}

				storage_list = Array.new
				if exclude_storage
					instance, mu_name = MU::Cloud::Server.find(id: instance_id, region: region)
					instance.block_device_mappings.each { |vol|
						if vol.device_name != instance.root_device_name 
							storage_list << MU::Cloud::AWS::Server.convertBlockDeviceMapping(
								{
									"device" => vol.device_name,
									"no-device" => ""
								}
							)
						end
					}
				elsif !storage.nil?
					storage.each { |vol|
						storage_list << MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
					}
				end
				ami_descriptor[:block_device_mappings] = storage_list
				if !exclude_storage
					ami_descriptor[:block_device_mappings].concat(@ephemeral_mappings)
				end
				MU.log "Creating AMI from #{node}", details: ami_descriptor
				begin
					resp = MU::Cloud::AWS.ec2(region).create_image(ami_descriptor)
				rescue Aws::EC2::Errors::InvalidAMINameDuplicate => e
					MU.log "AMI #{node} already exists, skipping", MU::WARN
					return nil
				end
				MU.log "AMI of #{node} is #{resp.data.image_id}"
				MU::MommaCat.createStandardTags(resp.data.image_id, region: region)
			  MU::MommaCat.createTag(resp.data.image_id, "Name", node, region: region)
#						if !server['tags'].nil?
#							server['tags'].each { |tag|
#								MU::MommaCat.createTag(iface.network_interface_id,tag['key'],tag['value'])
#							}
#						end
				MU.mommacat.notify("images", name, { "image_id" => resp.data.image_id })
				return resp.data.image_id
			end

			# Given a cloud platform identifier for a machine image, wait until it's
			# flagged as ready.
			# @param image_id [String]: The machine image to wait for.
			# @param region [String]: The cloud provider region
			def self.waitForAMI(image_id, region: MU.curRegion)
				MU.log "Checking to see if AMI #{image_id} is available", MU::DEBUG
				begin
					images = MU::Cloud::AWS.ec2.describe_images(image_ids: [image_id]).images
					if images.nil? or images.size == 0
						raise MuError, "No such AMI #{image_id} found"
					end
					state = images.first.state
					if state == "failed"
						raise MuError, "#{image_id} is marked as failed! I can't use this."
					end
					if state != "available"
						MU.log "Waiting for AMI #{image_id} (#{state})", MU::NOTICE
						sleep 60
					end
				end while state != "available"
				MU.log "AMI #{image_id} is ready", MU::DEBUG
			end

			# Maps our configuration language's 'storage' primitive to an Amazon-style
			# block_device_mapping.
			# @param storage [Hash]: The {MU::Config}-style storage description.
			# @return [Hash]: The Amazon-style storage description.
			def self.convertBlockDeviceMapping(storage)
				vol_struct = Hash.new
				if storage["no_device"]
					vol_struct[:no_device] = storage["no_device"]
				end

				if storage["device"]
					vol_struct[:device_name] = storage["device"]
				elsif storage["no_device"].nil?
					vol_struct[:device_name] = @disk_devices.shift
				end

				vol_struct[:virtual_name] = storage["virtual_name"] if storage["virtual_name"]

				if storage["snapshot_id"] or storage["size"]
					vol_struct[:ebs] = Hash.new
					vol_struct[:ebs][:snapshot_id] = storage["snapshot_id"] if storage["snapshot_id"]
					vol_struct[:ebs][:volume_size] = storage["size"] if storage["size"]
					vol_struct[:ebs][:volume_type] = storage["volume_type"] if storage["volume_type"]
					vol_struct[:ebs][:iops] = storage["iops"] if storage["iops"] and storage["volume_type"] == "io1"
					vol_struct[:ebs][:delete_on_termination] = storage["delete_on_termination"]
					vol_struct[:ebs][:encrypted] = storage["encrypted"] if storage["encrypted"]
				end

				return vol_struct
			end

			# Generate a random password which will satisfy the complexity requirements
			# of stock Amazon Windows AMIs.
			# return [String]: A password string.
			def self.generateWindowsAdminPassword
			  # We have dopey complexity requirements, be stringent here. I'll be nice
			  # and not condense this into one elegant-but-unreadable regular expression
			  attempts = Array.new
			  safe_metachars = Regexp.escape('~!@#%^&*_-+=`|(){}[]:;<>,.?')
			  begin
			    if attempts.size > 25
			      puts "Lousy passwords:"
			      puts attempts
			      raise MuError, "Failed to generate an adequate password!"
			    end
			    winpass=Password.random(14..16)
			    attempts << winpass
			  end while winpass.nil? or !winpass.match(/[A-Z]/) or !winpass.match(/[a-z]/) or !winpass.match(/\d/) or !winpass.match(/[#{safe_metachars}]/) or winpass.match(/[^\w\d#{safe_metachars}]/)
				MU.log "Generated Windows admin password #{winpass} after #{attempts} attempts", MU::DEBUG
				return winpass
			end

			@eips_used = Array.new
			# Find a free AWS Elastic IP.
			# @param classic [Boolean]: Toggle whether to allocate an IP in EC2 Classic
			# instead of VPC.
			# @param ip [String]: Request a specific IP address.
			# @param region [String]: The cloud provider region
			def self.findFreeElasticIp(classic = false, ip: ip, region: MU.curRegion)
					filters = Array.new
					filters << { name: "domain", values: ["vpc"] } if !classic
					filters << { name: "public-ip", values: [ip] } if ip != nil

					if filters.size > 0
						resp = MU::Cloud::AWS.ec2(region).describe_addresses(filters: filters)
					else
						resp = MU::Cloud::AWS.ec2(region).describe_addresses()
					end
					resp.addresses.each { |address|
						return address if (address.instance_id.nil? or address.instance_id.empty?) and address.network_interface_id.nil? and !@eips_used.include?(address.public_ip)
					}
					if ip != nil
						if !classic
							raise MuError, "Requested EIP #{ip}, but no such IP exists in VPC domain"
						else
							raise MuError, "Requested EIP #{ip}, but no such IP exists in Classic domain"
						end
					end
					if !classic
						resp = MU::Cloud::AWS.ec2(region).allocate_address(domain: "vpc")
						new_ip = resp.public_ip
					else
						new_ip = MU::Cloud::AWS.ec2(region).allocate_address().public_ip
					end
					filters = [ { name: "public-ip", values: [new_ip] } ]
					if resp.domain
						filters << { name: "domain", values: [resp.domain] }
					end rescue NoMethodError
					if new_ip.nil?
						MU.log "Unable to allocate new Elastic IP. Are we at quota?", MU::ERR
						raise MuError, "Unable to allocate new Elastic IP. Are we at quota?"
					end
					MU.log "Allocated new EIP #{new_ip}, fetching full description"


					begin
						begin
							sleep 5
							resp = MU::Cloud::AWS.ec2(region).describe_addresses(
								filters: filters
							)
							addr = resp.addresses.first
						end while resp.addresses.size < 1 or addr.public_ip.nil?
					rescue NoMethodError
						MU.log "EIP descriptor came back without a public_ip attribute for #{new_ip}, retrying", MU::WARN
						sleep 5
						retry
					end

					return addr
			end

			@eip_semaphore = Mutex.new
			# Associate an Amazon Elastic IP with an instance.
			# @param instance_id [String]: The cloud provider identifier of the instance.
			# @param classic [Boolean]: Whether to assume we're using an IP in EC2 Classic instead of VPC.
			# @param ip [String]: Request a specific IP address.
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.associateElasticIp(instance_id, classic: classic = false, ip: ip, region: MU.curRegion)
				MU.log "associateElasticIp called: #{instance_id}, classic: #{classic}, ip: #{ip}, region: #{region}", MU::DEBUG
				elastic_ip = nil
				@eip_semaphore.synchronize {
					if !ip.nil?
						filters = [ { name: "public-ip", values: [ip] } ]
						resp = MU::Cloud::AWS.ec2(region).describe_addresses(filters: filters)
						if @eips_used.include?(ip)
							is_free = false
							resp.addresses.each { |address|
								if address.public_ip == ip and (address.instance_id.nil? and address.network_interface_id.nil?) or address.instance_id == instance_id
									@eips_used.delete(ip)
									is_free = true
								end
							}
		
							raise MuError, "Requested EIP #{ip}, but we've already assigned this IP to someone else" if !is_free
						else
							resp.addresses.each { |address|
								if address.public_ip == ip and address.instance_id == instance_id
									return ip
								end
							}
						end
					end
					elastic_ip = findFreeElasticIp(classic, ip: ip)
					if !ip.nil? and (elastic_ip.nil? or ip != elastic_ip.public_ip)
						raise MuError, "Requested EIP #{ip}, but this IP does not exist or is not available"
					end
					if elastic_ip.nil?
						raise MuError, "Couldn't find an Elastic IP to associate with #{instance_id}"
					end
					@eips_used << elastic_ip.public_ip
					MU.log "Associating Elastic IP #{elastic_ip.public_ip} with #{instance_id}", details: elastic_ip
				}
				attempts = 0
				begin
					if classic
						resp = MU::Cloud::AWS.ec2(region).associate_address(
							instance_id: instance_id,
							public_ip: elastic_ip.public_ip
						)
					else
						resp = MU::Cloud::AWS.ec2(region).associate_address(
							instance_id: instance_id,
							allocation_id: elastic_ip.allocation_id,
							allow_reassociation: false
						)
					end
				rescue Aws::EC2::Errors::IncorrectInstanceState => e
					attempts = attempts + 1
					if attempts < 6
						MU.log "Got #{e.message} associating #{elastic_ip.allocation_id} with #{instance_id}, retrying", MU::WARN
						sleep 5
						retry
					end
					raise MuError "#{e.message} associating #{elastic_ip.allocation_id} with #{instance_id}"
				rescue Aws::EC2::Errors::ResourceAlreadyAssociated => e
					# A previous association attempt may have succeeded, albeit slowly.
					resp = MU::Cloud::AWS.ec2(region).describe_addresses(
						allocation_ids: [elastic_ip.allocation_id]
					)
					first_addr = resp.addresses.first
					if !first_addr.nil? and first_addr.instance_id == instance_id
						MU.log "#{elastic_ip.public_ip} already associated with #{instance_id}", MU::WARN
					else
						MU.log "#{elastic_ip.public_ip} shows as already associated!", MU::ERR, details: resp
						raise MuError, "#{elastic_ip.public_ip} shows as already associated with #{first_addr.instance_id}!"
					end
				end

				instance = MU::Cloud::AWS.ec2(region).describe_instances(instance_ids: [instance_id]).reservations.first.instances.first
				waited = false
				if instance.public_ip_address != elastic_ip.public_ip
					waited = true
					begin
						sleep 10
						MU.log "Waiting for Elastic IP association of #{elastic_ip.public_ip} to #{instance_id} to take effect", MU::NOTICE
						instance = MU::Cloud::AWS.ec2(region).describe_instances(instance_ids: [instance_id]).reservations.first.instances.first
					end while instance.public_ip_address != elastic_ip.public_ip
				end

				MU.log "Elastic IP #{elastic_ip.public_ip} now associated with #{instance_id}" if waited

				return elastic_ip.public_ip
			end  

			# Remove all instances associated with the currently loaded deployment. Also cleans up associated volumes, droppings in the MU master's /etc/hosts and ~/.ssh, and in Chef.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, skipsnapshots: false, onlycloud: false)
				tagfilters = [
					{ name: "tag:MU-ID", values: [MU.mu_id] }
				]
				if !ignoremaster
					tagfilters << { name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip] }
				end
				instances = Array.new
				unterminated = Array.new

				# Build a list of instances we need to clean up. We guard against
				# accidental deletion here by requiring someone to have hand-terminated
				# these, by default.
				resp = MU::Cloud::AWS.ec2(region).describe_instances(
					filters: tagfilters
				)

				return if resp.data.reservations.nil?
				resp.data.reservations.each { |reservation|
					reservation.instances.each { |instance|
					  if instance.state.name != "terminated"
							unterminated << instance
					  end
					}
				}

				parent_thread_id = Thread.current.object_id

				threads = []
				unterminated.each { |instance|
					threads << Thread.new(instance) { |myinstance|
						MU.dupGlobals(parent_thread_id)
						Thread.abort_on_exception = true
						MU::Cloud::AWS::Server.terminateInstance(id: myinstance.instance_id, noop: noop, onlycloud: onlycloud, region: region)
					}
				}

				resp = MU::Cloud::AWS.ec2(region).describe_volumes(
					filters: tagfilters
				)
				resp.data.volumes.each { |volume|
					threads << Thread.new(volume) { |myvolume|
						MU.dupGlobals(parent_thread_id)
						MU::Cloud::AWS::Server.delete_volume(myvolume, noop, skipsnapshots)
					}
				}

				# Wait for all of the instances to finish cleanup before proceeding
				threads.each { |t|
					t.join
				}


			end

			# Terminate an instance.
			# @param instance [OpenStruct]: The cloud provider's description of the instance.
			# @param id [String]: The cloud provider's identifier for the instance, to use if the full description is not available.
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.terminateInstance(instance = nil, noop: false, id: id, onlycloud: false, region: MU.curRegion)
				ips = Array.new
				if !instance
					if id
						begin
							resp = MU::Cloud::AWS.ec2(region).describe_instances(instance_ids: [id])
						rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
							MU.log "Instance #{id} no longer exists", MU::WARN
						end
						if !resp.nil? and !resp.reservations.nil? and !resp.reservations.first.nil?
							instance = resp.reservations.first.instances.first
							ips << instance.public_ip_address if !instance.public_ip_address.nil?
							ips << instance.private_ip_address if !instance.private_ip_address.nil?
						end
					else
						MU.log "You must supply an instance handle or id to terminateInstance", MU::ERR
					end
				else
					id = instance.instance_id
				end
				if !MU.mu_id.empty?
					deploy_dir = File.expand_path("#{MU.dataDir}/deployments/"+MU.mu_id)
					if Dir.exist?(deploy_dir) and !noop
						FileUtils.touch("#{deploy_dir}/.cleanup-"+id)
					end
				end

				cleaned_dns = false
				mu_name = nil
				MU::Cloud.artifact("AWS", :DNSZone)
				mu_zone, junk = MU::Cloud::DNSZone.find(name: "mu")
				if !mu_zone.nil?
					dns_targets = []
					rrsets = MU::Cloud::AWS.route53(region).list_resource_record_sets(hosted_zone_id: mu_zone.id)
				end
				begin
					junk, mu_name = MU::Cloud::Server.find(id: id, region: region)
				rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
					MU.log "Instance #{id} no longer exists", MU::DEBUG
				end

				if !onlycloud and !mu_name.nil?
					if !rrsets.nil?
						rrsets.resource_record_sets.each { |rrset|
							if rrset.name.match(/^#{mu_name.downcase}\.server\.#{MU.myInstanceId}\.mu/i)
								rrset.resource_records.each { |record|
									MU::Cloud::DNSZone.genericMuDNSEntry(mu_name, record.value, MU::Cloud::Server, delete: true)
									cleaned_dns = true
								}
							end
						}
					end

					deploydata = MU::MommaCat.getResourceDeployStruct(MU::Cloud::Server.cfg_plural, name: mu_name)
					nodename = nil
					deploydata.each_pair { |node, data|
						if data['instance_id'] == id
							nodename = node
							break
						end
					}
					
					orig_config = nil
					sources = []
					if MU.mommacat.original_config.has_key?(MU::Cloud::Server.cfg_plural)
						sources.concat(MU.mommacat.original_config[MU::Cloud::Server.cfg_plural])
					end
					if MU.mommacat.original_config.has_key?(MU::Cloud::ServerPool.cfg_plural)
						sources.concat(MU.mommacat.original_config[MU::Cloud::ServerPool.cfg_plural])
					end
					sources.each { |svr|
						if svr['name'] == mu_name
							orig_config = svr
							break
						end
					}

					# Expunge the IAM profile for this instance class
					if orig_config["#MU_CLOUDCLASS"] == "MU::Cloud::Server"
						MU::Cloud::AWS::Server.removeIAMProfile("Server-"+mu_name) if !noop
					else
						MU::Cloud::AWS::Server.removeIAMProfile("ServerPool-"+mu_name) if !noop
					end

# XXX abstraction motherfucker
					MU::Groomer::Chef.cleanup(nodename, orig_config['vault_access'], noop)

					MU.mommacat.notify(MU::Cloud::Server.cfg_plural, mu_name, nodename, remove: true, sub_key: nodename) if !noop and MU.mommacat

					# If we didn't manage to find this instance's Route53 entry by sifting
					# deployment metadata, see if we can get it with the Name tag.
					if !mu_zone.nil? and !cleaned_dns and !instance.nil?
						instance.tags.each { |tag|
							if tag.key == "Name"
								rrsets.resource_record_sets.each { |rrset|
									if rrset.name.match(/^#{tag.value.downcase}\.server\.#{MU.myInstanceId}\.mu/i)
										rrset.resource_records.each { |record|
											MU::Cloud::DNSZone.genericMuDNSEntry(tag.value, record.value, MU::Cloud::Server, delete: true) if !noop
										}
									end
								}
							end
						}
					end
				end

				if ips.size > 0 and !onlycloud
					known_hosts_files = [Etc.getpwuid(Process.uid).dir+"/.ssh/known_hosts"] 
					if Etc.getpwuid(Process.uid).name == "root"
						known_hosts_files << Etc.getpwnam("nagios").dir+"/.ssh/known_hosts"
					end
					known_hosts_files.each { |known_hosts|
						next if !File.exists?(known_hosts)
						MU.log "Cleaning up #{ips} from #{known_hosts}"
						if !noop 
							File.open(known_hosts, File::CREAT|File::RDWR, 0644) { |f|
								f.flock(File::LOCK_EX)
								newlines = Array.new
								f.readlines.each { |line|
									ip_match = false
									ips.each { |ip|
										if line.match(/(^|,| )#{ip}( |,)/)
											MU.log "Expunging #{ip} from #{known_hosts}"
											ip_match = true
										end
									}
									newlines << line if !ip_match
								}
								f.rewind
								f.truncate(0)
								f.puts(newlines)
								f.flush
								f.flock(File::LOCK_UN)
							}
						end
					}
				end


				return if instance.nil?

				name = ""
				instance.tags.each { |tag|
					name = tag.value if tag.key == "Name"
				}

				if instance.state.name == "terminated"
					MU.log "#{instance.instance_id} (#{name}) has already been terminated, skipping"
				else
					if instance.state.name == "terminating"
						MU.log "#{instance.instance_id} (#{name}) already terminating, waiting"
					elsif instance.state.name != "running" and instance.state.name != "pending" and instance.state.name != "stopping" and instance.state.name != "stopped"
						MU.log "#{instance.instance_id} (#{name}) is in state #{instance.state.name}, waiting"
					else
						MU.log "Terminating #{instance.instance_id} (#{name}) #{noop}"
						if !noop
							begin
								MU::Cloud::AWS.ec2(region).modify_instance_attribute(
									instance_id: instance.instance_id,
									disable_api_termination: { value: false }
								)
								MU::Cloud::AWS.ec2(region).terminate_instances(instance_ids: [instance.instance_id])
								# Small race window here with the state changing from under us
							rescue Aws::EC2::Errors::IncorrectInstanceState => e
								resp = MU::Cloud::AWS.ec2(region).describe_instances(instance_ids: [id])
								if !resp.nil? and !resp.reservations.nil? and !resp.reservations.first.nil?
									instance = resp.reservations.first.instances.first
									if !instance.nil? and instance.state.name != "terminated" and instance.state.name != "terminating"
										sleep 5
										retry
									end
								end
							rescue Aws::EC2::Errors::InternalError => e
								MU.log "Error #{e.inspect} while Terminating instance #{instance.instance_id} (#{name}), retrying", MU::WARN, details: e.inspect
								sleep 5
								retry
							end
						end
					end
					while instance.state.name != "terminated" and !noop
						sleep 30
						instance_response = MU::Cloud::AWS.ec2(region).describe_instances(instance_ids: [instance.instance_id])
						instance = instance_response.reservations.first.instances.first
					end
					MU.log "#{instance.instance_id} (#{name}) terminated" if !noop
				end
			end

			private

			# Destroy a volume.
			# @param volume [OpenStruct]: The cloud provider's description of the volume.
			# @param id [String]: The cloud provider's identifier for the volume, to use if the full description is not available.
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.delete_volume(volume, noop, skipsnapshots, id: id, region: MU.curRegion)
				if !volume.nil?
					resp = MU::Cloud::AWS.ec2(region).describe_volumes(volume_ids: [volume.volume_id])
					volume = resp.data.volumes.first
				end
				name = ""
				volume.tags.each { |tag|
					name = tag.value if tag.key == "Name"
				}

				MU.log("Deleting volume #{volume.volume_id} (#{name})")
				if !noop
					if !skipsnapshots
						if !name.nil? and !name.empty?
								desc = "#{MU.mu_id}-MUfinal (#{name})"
						else
								desc = "#{MU.mu_id}-MUfinal"
						end

						MU::Cloud::AWS.ec2(region).create_snapshot(
							volume_id: volume.volume_id,
							description: desc
						)
					end

					retries = 0
					begin
						MU::Cloud::AWS.ec2(region).delete_volume(volume_id: volume.volume_id)
					rescue Aws::EC2::Errors::InvalidVolumeNotFound
						MU.log "Volume #{volume.volume_id} (#{name}) disappeared before I could remove it!", MU::WARN
					rescue Aws::EC2::Errors::VolumeInUse
						if retries < 10
							volume.attachments.each { |attachment|
								MU.log "#{volume.volume_id} is attached to #{attachment.instance_id} as #{attachment.device}", MU::NOTICE
							}
							MU.log "Volume '#{name}' is still attached, waiting...", MU::NOTICE
							sleep 30
							retries = retries + 1
							retry
						else
							MU.log "Failed to delete #{name}", MU::ERR
						end
					end
				end
			end


		end #class
	end #class
	end
end #module
