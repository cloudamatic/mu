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

module MU
	# Plugins under this namespace serve as interfaces to host configuration
	# management tools, like Chef or Puppet.
	class Groomer
		# Support for Chef as a host configuration management layer.
		class Chef

			# @param server [MU::Cloud::Server]: The server object on which we'll be operating
			def initialize(server)
				@server = server
				if @server.mu_name.nil? or @server.mu_name.empty?
					raise MuError, "Cannot groom a server that doesn't tell me its mu_name"
				end
				if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
					::Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
				end
				::Chef::Config[:chef_server_url] = "https://#{MU.mu_public_addr}/organizations/#{MU.chef_user}"
				::Chef::Config[:environment] = @server.deploy.environment
			end

			# Indicate whether our server has been bootstrapped with Chef
			def haveBootstrapped?
				MU.log "Chef config", MU::DEBUG, details: ::Chef::Config.inspect
				nodelist = ::Chef::Node.list()
				nodelist.has_key?(@server.mu_name)
			end

			# Invoke the Chef client on the node at the other end of a provided SSH
			# session.
			# @param purpose [String] = A string describing the purpose of this client run.
			# @param max_retries [Integer] = The maximum number of attempts at a successful run to make before giving up.
			def run(purpose: "Chef run", update_runlist: true, max_retries: 5)
				if update_runlist and !@server.config['run_list'].nil?
					@server.config['run_list'].each { |rl_entry|
						knifeAddToRunList(rl_entry)
					}
				end

				if !@server.config['application_attributes'].nil?
					chef_node = ::Chef::Node.load(@server.mu_name)
					MU.log "Setting node:#{@server.mu_name} application_attributes", MU::DEBUG, details: @server.config['application_attributes']
					chef_node.normal.application_attributes = @server.config['application_attributes']
					chef_node.save
				end
				syncDeployData

				ssh = @server.getSSHSession
				MU.log "Invoking Chef on #{@server.mu_name}: #{purpose}"
				retries = 0
				output = []
				error_signal = "CHEF EXITED BADLY: "+(0...25).map { ('a'..'z').to_a[rand(26)] }.join
				begin
					cmd = nil
					if !%w{win2k12r2 win2k12 windows}.include?(@server['platform'])
						if !@server["ssh_user"].nil? and !@server["ssh_user"].empty? and @server["ssh_user"] != "root"
							cmd = "sudo chef-client --color || echo #{error_signal}"
						else
							cmd = "chef-client --color || echo #{error_signal}"
						end
					else
						cmd = "$HOME/chef-client --color || echo #{error_signal}"
					end
					retval = ssh.exec!(cmd) { |ch, stream, data|
#					if stream == :stderr
						puts data
						output << data
						if data.match(/#{error_signal}/)
							raise MU::Groomer::RunError, output.grep(/ ERROR: /).last
						end
					}
				rescue MU::Groomer::RunError => e
					begin
						ssh.close if !ssh.nil?
					rescue Net::SSH::Disconnect, IOError => e
						if %w{win2k12r2 win2k12 windows}.include?(@server['platform'])
							MU.log "Windows has probably closed the ssh session before we could. Waiting before trying again", MU::NOTICE
						else
							MU.log "ssh session was closed unexpectedly, waiting before trying again", MU::NOTICE
						end
						sleep 10
					end

					if retries < max_retries
						retries = retries + 1
						MU.log "#{@server.mu_name}: Chef run '#{purpose}' failed, retrying", MU::WARN, details: e.message
						sleep 10
						retry
					else
						MU.log "#{@server.mu_name}: Chef run '#{purpose}' failed #{max_retries} times", MU::ERR, details: e.message
						raise e
					end
				end

				syncDeployData
			end

			# Bootstrap our server with Chef
			def bootstrap
				nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_addr, ssh_user, ssh_key_name = @server.getSSHConfig
			  MU.log "Bootstrapping #{@server.mu_name} (#{canonical_addr}) with knife"

				run_list = ["recipe[mu-tools::newclient]", "role[mu-node]"]

				# XXX These shouldn't be needed, see Autoloads in mu.rb. Whyy Chef why? 
				require 'chef/knife/bootstrap'
				require 'chef/knife/core/bootstrap_context'
				require 'chef/knife/bootstrap_windows_ssh'

				json_attribs = {}
				if !@server.config['application_attributes'].nil?
					json_attribs['application_attributes'] = @server.config['application_attributes']
				end
				if !@server.config['vault_access'].nil?
					vault_access = @server.config['vault_access']
				else
					vault_access = []
				end

				if !%w{win2k12r2 win2k12 windows}.include?(@server.config['platform'])
					kb = ::Chef::Knife::Bootstrap.new([canonical_addr])
			    kb.config[:use_sudo] = true
			    kb.config[:distro] = 'chef-full'
			  else
			    kb = ::Chef::Knife::BootstrapWindowsSsh.new([canonical_addr])
			    kb.config[:cygwin] = true
			    kb.config[:distro] = 'windows-chef-client-msi'
			    kb.config[:node_ssl_verify_mode] = 'none'
			    kb.config[:node_verify_api_cert] = false
			  end
				if json_attribs.size > 1
					kb.config[:json_attribs] = JSON.generate(json_attribs)
				end
# XXX this seems to break Knife Bootstrap for the moment
#			if vault_access.size > 0
#				v = {}
#				vault_access.each { |vault|
#					v[vault['vault']] = [] if v[vault['vault']].nil?
#					v[vault['vault']] << vault['item']
#				}
#				kb.config[:bootstrap_vault_json] = JSON.generate(v)
#			end
		    kb.config[:run_list] = run_list
		    kb.config[:ssh_user] = ssh_user
		    kb.config[:forward_agent] = ssh_user
			  kb.name_args = "#{canonical_addr}"
			  kb.config[:chef_node_name] = @server.mu_name
			  kb.config[:bootstrap_version] = MU.chefVersion
# XXX key off of MU verbosity level
				kb.config[:log_level] = :debug
				kb.config[:identity_file] = Etc.getpwuid(Process.uid).dir+"/.ssh/"+ssh_key_name
				if !nat_ssh_host.nil?
					kb.config[:ssh_gateway] = nat_ssh_user+"@"+nat_ssh_host
				end
				# This defaults to localhost for some reason sometimes. Brute-force it.
			
			  MU.log "Knife Bootstrap settings for #{@server.mu_name} (#{canonical_addr})", MU::NOTICE, details: kb.config

				retries = 0
				begin
					# A Chef bootstrap shouldn't take this long, but we get these random
					# inexplicable hangs sometimes.
					Timeout::timeout(600) {	
						require 'chef'
					  kb.run
					}
				rescue Net::SSH::Disconnect, Errno::EPIPE, IOError, SystemExit, Timeout::Error, SocketError, Net::HTTPServerException => e
					if retries < 10
						retries = retries + 1
						MU.log "#{@server.mu_name}: Knife Bootstrap failed #{e.inspect}, retrying (#{retries} of 10)", MU::WARN
						sleep 10
						retry
					else
						raise MuError, "#{@server.mu_name}: Knife Bootstrap failed too many times with #{e.inspect}"
					end
				end

				# Now that we're done, remove one-shot bootstrap recipes from the
				# node's final run list
				["mu-tools::newclient"].each { |recipe|
					begin
						::Chef::Knife.run(['node', 'run_list', 'remove', @server.mu_name, "recipe[#{recipe}]"], {})
					rescue SystemExit => e
						MU.log "#{@server.mu_name}: Run list removal of recipe[#{recipe}] failed with #{e.inspect}", MU::ERR
					end
				}

				createGenericHostSSLCert

				# Making sure all Windows nodes get the mu-tools::windows-client recipe
				if %w{win2k12r2 win2k12 windows}.include? @server.config['platform']
					knifeAddToRunList("recipe[mu-tools::windows-client]")
					run(purpose: "Base Windows configuration", update_runlist: false, max_retries: 10)
				end

				# This will deal with Active Directory integration.
				if !@server.config['active_directory'].nil?
					if @server.config['active_directory']['domain_operation'] == "join"
						knifeAddToRunList("recipe[mu-activedirectory::domain-node]")
						run(purpose: "Join Active Directory", update_runlist: false, max_retries: 10)
					elsif @server.config['active_directory']['domain_operation'] == "create"
						knifeAddToRunList("recipe[mu-activedirectory::domain]")
						run(purpose: "Create Active Directory Domain", update_runlist: false, max_retries: 15)
					elsif @server.config['active_directory']['domain_operation'] == "add_controller"
						knifeAddToRunList("recipe[mu-activedirectory::domain-controller]")
						run(purpose: "Add Domain Controller to Active Directory", update_runlist: false, max_retries: 15)
					end
				end

				if !@server.config['run_list'].nil?
					@server.config['run_list'].each { |rl_entry|
						knifeAddToRunList(rl_entry)
					}
				end

				saveInitialMetadata
				syncDeployData
			end

			# Synchronize the deployment structure managed by {MU::MommaCat} to Chef,
			# so that nodes can access this metadata.
			def syncDeployData
				deployment = @server.deploy.deployment
				begin
					chef_node = ::Chef::Node.load(@server.mu_name)

					MU.log "Updating node: #{@server.mu_name} deployment attributes", details: deployment
					chef_node.normal.deployment.merge!(@server.deploy.deployment)

					chef_node.save
				rescue Net::HTTPServerException => e
					MU.log "Attempted to save deployment to Chef node #{@server.mu_name} before it was bootstrapped.", MU::DEBUG
				end
			end

			# Expunge Chef resources associated with a node.
			# @param node [String]: The Mu name of the node in question.
			# @param vaults_to_clean [Array<Hash>]: Some vaults to expunge
			# @param noop [Boolean]: Skip actual deletion, just state what we'd do
			def self.cleanup(node, vaults_to_clean = [], noop = false)
				MU.log "Deleting Chef resources associated with #{node}"
				vaults_to_clean.each { |vault|
					MU::MommaCat.lock("vault-"+vault['vault'], false, true)
					MU.log "knife vault remove #{vault['vault']} #{vault['item']} --search name:#{node}", MU::NOTICE
					puts `#{MU::Config.knife} vault remove #{vault['vault']} #{vault['item']} --search name:#{node}` if !noop
					MU::MommaCat.unlock("vault-"+vault['vault'])
				}
				MU.log "knife node delete -y #{node}"
				`#{MU::Config.knife} node delete -y #{node}` if !noop
				MU.log "knife client delete -y #{node}"
				`#{MU::Config.knife} client delete -y #{node}` if !noop
				MU.log "knife data bag delete -y #{node}"
				`#{MU::Config.knife} data bag delete -y #{node}` if !noop
				["crt", "key"].each { |ext|
					if File.exists?("#{MU.mySSLDir}/#{node}.#{ext}")
						MU.log "Removing #{MU.mySSLDir}/#{node}.#{ext}"
						File.unlink("#{MU.mySSLDir}/#{node}.#{ext}") if !noop
					end
				}
			end

			private

			# Save common Mu attributes to this node's Chef node structure.
			def saveInitialMetadata
				config = @server.config
				nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_addr, ssh_user, ssh_key_name = @server.getSSHConfig
				MU.log "Saving #{@server.mu_name} Chef artifacts"
				chef_node = ::Chef::Node.load(@server.mu_name)
				# Figure out what this node thinks its name is
				system_name = chef_node['fqdn']
				MU.log "#{@server.mu_name} local name is #{system_name}", MU::DEBUG

				chef_node.normal.app = config['application_cookbook'] if config['application_cookbook'] != nil
				chef_node.normal.service_name = config["name"]
				chef_node.normal.windows_admin_username = config['windows_admin_username']
				chef_node.chef_environment = MU.environment.downcase

				if %w{win2k12r2 win2k12 windows}.include? config['platform']
					chef_node.normal.windows_admin_username = config['windows_admin_username']
					chef_node.normal.windows_auth_vault = node
					chef_node.normal.windows_auth_item = "windows_credentials"
					chef_node.normal.windows_auth_password_field = "password"
					chef_node.normal.windows_auth_username_field = "username"
					chef_node.normal.windows_ec2config_password_field = "ec2config_password"
					chef_node.normal.windows_ec2config_username_field = "ec2config_username"
					chef_node.normal.windows_sshd_password_field = "sshd_password"
					chef_node.normal.windows_sshd_username_field = "sshd_username"
				end

				# If AD integration has been requested for this node, give Chef what it'll need.
				if !config['active_directory'].nil?
					chef_node.normal.ad.computer_name = config['mu_windows_name']
					chef_node.normal.ad.node_class = config['name']
					chef_node.normal.ad.domain_name = config['active_directory']['domain_name']
					chef_node.normal.ad.node_type = config['active_directory']['node_type']
					chef_node.normal.ad.domain_operation = config['active_directory']['domain_operation']
					chef_node.normal.ad.domain_controller_hostname = config['active_directory']['domain_controller_hostname'] if config['active_directory'].has_key?('domain_controller_hostname')
					chef_node.normal.ad.netbios_name = config['active_directory']['short_domain_name']
					chef_node.normal.ad.computer_ou = config['active_directory']['computer_ou'] if config['active_directory'].has_key?('computer_ou')
					chef_node.normal.ad.dcs = config['active_directory']['domain_controllers']
					chef_node.normal.ad.domain_join_vault = config['active_directory']['domain_join_vault']['vault']
					chef_node.normal.ad.domain_join_item = config['active_directory']['domain_join_vault']['item']
					chef_node.normal.ad.domain_join_username_field = config['active_directory']['domain_join_vault']['username_field']
					chef_node.normal.ad.domain_join_password_field = config['active_directory']['domain_join_vault']['password_field']
					chef_node.normal.ad.domain_admin_vault = config['active_directory']['domain_admin_vault']['vault']
					chef_node.normal.ad.domain_admin_item = config['active_directory']['domain_admin_vault']['item']
					chef_node.normal.ad.domain_admin_username_field = config['active_directory']['domain_admin_vault']['username_field']
					chef_node.normal.ad.domain_admin_password_field = config['active_directory']['domain_admin_vault']['password_field']
				end

				# Amazon-isms
				awscli_region_widget = {
					"compile_time" => true,
					"config_profiles" => {
						"default" => {
							"options" => {
								"region" => config['region']
							}
						}
					}
				}
# XXX pass this crap in?
#				chef_node.normal.awscli = awscli_region_widget
#			  chef_node.normal.ec2 = MU.structToHash(instance)
#				chef_node.normal.cloudprovider = "ec2"
				tags = MU::MommaCat.listStandardTags
				if !config['tags'].nil?
					config['tags'].each { |tag|
						tags[tag['key']] = tag['value']
					}
				end
				chef_node.normal.tags = tags
			  chef_node.save

				# Finally, grant us access to some pre-existing Vaults.
				if !config['vault_access'].nil?
					config['vault_access'].each { |vault|
						grantVaultAccess(vault['vault'], vault['item'])
					}
				end
			end

			def grantVaultAccess(vault, item)
				MU::MommaCat.lock("vault-"+vault, false, true)
				retries = 0
				begin
					retries = retries + 1
					vault_cmd = "#{MU::Config.knife} vault update #{vault} #{item} #{MU::Config.vault_opts} --search name:#{@server.mu_name} 2>&1"
					MU.log "ADD attempt #{retries} enabling #{@server.mu_name} for vault access to #{vault} #{item} using command  #{vault_cmd}", MU::DEBUG
					output = `#{vault_cmd}`
          MU.log "Result of ADD attempt #{retries} enabling #{@server.mu_name} for vault access to #{vault} was #{output} with RC #{$?.exitstatus}", MU::DEBUG
					if $?.exitstatus != 0
						MU.log "Got bad exit code on try #{retries} from knife vault update #{vault} #{item} #{MU::Config.vault_opts} --search name:#{@server.mu_name}", MU::WARN, details: output
					end
					# Check and see if what we asked for actually got done
					vault_cmd = "#{MU::Config.knife} vault show #{vault} #{item} clients -p clients -f yaml #{MU::Config.vault_opts} 2>&1"
					#MU.log vault_cmd, MU::DEBUG
					output = `#{vault_cmd}`
					MU.log "VERIFYING #{@server.mu_name} access to #{vault} #{item}:\n #{output}", MU::DEBUG
					if !output.match(/#{@server.mu_name}/)
						MU.log "Didn't see #{@server.mu_name} in output of #{vault_cmd}, trying again...", MU::WARN, details: output
						if retries < 10
							MU::MommaCat.unlock("vault-"+vault)
							sleep 5
							redo
						else
							MU.log "ABORTING: Unable to add #{@server.mu_name} to #{vault} #{item}, instance unlikely to operate correctly!", MU::ERR
							raise MuError, "Unable to add node #{@server.mu_name} to #{vault} #{item}, aborting"
						end
					else
						MU.log "Granted #{@server.mu_name} access to #{vault} #{item} after #{retries} retries", MU::NOTICE
						return
					end
				end while true
				MU::MommaCat.unlock("vault-"+vault)
			end

			def createGenericHostSSLCert
				nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = @server.getSSHConfig
				# Manufacture a generic SSL certificate, signed by the Mu master, for
				# consumption by various node services (Apache, Splunk, etc).
				MU.log "Creating self-signed service SSL certificate for #{@server.mu_name} (CN=#{canonical_ip})"
		
				# Create and save a key
				key = OpenSSL::PKey::RSA.new 4096
				if !Dir.exist?(MU.mySSLDir)
					Dir.mkdir(MU.mySSLDir, 0700)
				end
				open("#{MU.mySSLDir}/#{@server.mu_name}.key", 'w', 0600) { |io|
					io.write key.to_pem
				}

				# Create a certificate request for this node
				csr = OpenSSL::X509::Request.new
				csr.version = 0
				csr.subject = OpenSSL::X509::Name.parse "CN=#{canonical_ip}/O=Mu/C=US"
				csr.public_key = key.public_key
				open("#{MU.mySSLDir}/#{@server.mu_name}.csr", 'w', 0644) { |io|
					io.write csr.to_pem
				}


				if MU.chef_user == "mu"
					MU.mommacat.signSSLCert("#{MU.mySSLDir}/#{@server.mu_name}.csr")
				else
					deploykey = OpenSSL::PKey::RSA.new(MU.mommacat.public_key)
					deploysecret = Base64.urlsafe_encode64(deploykey.public_encrypt(MU.mommacat.deploy_secret))
					res_type = "server"
					res_type = "server_pool" if !@server.config['basis'].nil?
					uri = URI("https://#{MU.mu_public_addr}:2260/")
					req = Net::HTTP::Post.new(uri)
					req.set_form_data(
						"mu_id" => MU.mu_id,
						"mu_resource_name" => @server.config['name'],
						"mu_resource_type" => res_type,
						"mu_ssl_sign" => "#{MU.mySSLDir}/#{@server.mu_name}.csr",
						"mu_user" => MU.chef_user,
						"mu_deploy_secret" => deploysecret
					)
					http = Net::HTTP.new(uri.hostname, uri.port)
					http.ca_file = "/etc/pki/Mu_CA.pem" # XXX why no worky?
					http.use_ssl = true
					http.verify_mode = OpenSSL::SSL::VERIFY_NONE
					response = http.request(req)
					if response.code != "200"
						MU.log "Got error back on signing request for #{MU.mySSLDir}/#{@server.mu_name}.csr", MU::ERR
					end
				end

				cert = OpenSSL::X509::Certificate.new File.read "#{MU.mySSLDir}/#{@server.mu_name}.crt"

				# Upload the certificate to a Chef Vault for this node
				vault_cmd = "#{MU::Config.knife} vault create #{@server.mu_name} ssl_cert '{ \"data\": { \"node.crt\":\"#{cert.to_pem.chomp!.gsub(/\n/, "\\n")}\", \"node.key\":\"#{key.to_pem.chomp!.gsub(/\n/, "\\n")}\" } }' #{MU::Config.vault_opts} --search name:#{@server.mu_name}"
				MU.log vault_cmd, MU::DEBUG
				puts `#{vault_cmd}`
				grantVaultAccess(@server.mu_name, "ssl_cert")

				# Any and all 'secrets' parameters should also be stuffed into our vault.
				if !@server.config['secrets'].nil?
					json = JSON.generate(@server.config['secrets'])
					vault_cmd = "#{MU::Config.knife} vault create #{@server.mu_name} secrets '#{json}' #{MU::Config.vault_opts} --search name:#{@server.mu_name}"
					MU.log vault_cmd, MU::DEBUG
					puts `#{vault_cmd}`
					grantVaultAccess(@server.mu_name, "secrets")
				end
				
				if %w{win2k12r2 win2k12 windows}.include? @server.config['platform']
					# We're creating the vault earlier to allow us to grab the Windows Admin password when running MU::Server.initialSSHTasks.
					grantVaultAccess(@server.mu_name, "windows_credentials")
				end
			end

			# Add a role or recipe to a node. Optionally, throw a fit if it doesn't
			# exist.
			# @param rl_entry [String]: The run-list entry to add.
			# @param type [String]: One of *role* or *recipe*.
			# @param ignore_missing [Boolean]: If set to true, will merely warn about missing recipes/roles instead of throwing an exception.
			# @return [void]
			def knifeAddToRunList(rl_entry, type="role", ignore_missing=false)
				return if rl_entry.nil?
		
				# Rather than argue about whether to expect a bare rl_entry name or require
				# rl_entry[rolename], let's just accomodate.
				if rl_entry.match(/^role\[(.+?)\]/) then
					type = "role"
					rl_entry = Regexp.last_match(1)
					query=%Q{#{MU::Config.knife} role show #{rl_entry}};
				elsif rl_entry.match(/^recipe\[(.+?)\]/) then
					type = "recipe"
					rl_entry = Regexp.last_match(1)
					query=%Q{#{MU::Config.knife} recipe list | grep '^#{rl_entry}$'};
				end
		
				%x{#{query}}
				if $? != 0 then
					raise MuError, "Attempted to add non-existing #{type} #{rl_entry}" if !ignore_missing
				end
		
				begin
					query=%Q{#{MU::Config.knife} node run_list add #{@server.mu_name} "#{type}[#{rl_entry}]"};
					MU.log("Adding #{type} #{rl_entry} to #{@server.mu_name}")
					MU.log("Running #{query}", MU::DEBUG)
					output=%x{#{query}}
					# XXX rescue Exception is bad style
				rescue Exception => e
					raise MuError, "FAIL: #{MU::Config.knife} node run_list add #{@server.mu_name} \"#{type}[#{rl_entry}]\": #{e.message} (output was #{output})"
				end
			end

		end # class Chef
	end # class Groomer
end # Module Mu
