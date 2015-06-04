# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'json'
require 'net/http'
require 'net/smtp'
require 'trollop'
require 'fileutils'

Thread.abort_on_exception = true

module MU

	# Routines for removing cloud resources.
	class Cleanup

		home = Etc.getpwuid(Process.uid).dir

		@muid = nil
		@noop = false
		@onlycloud = false

		# Purge all resources associated with a deployment.
		# @param muid [String]: The identifier of the deployment to remove (typically seen in the MU-ID tag on a resource).
		# @param noop [Boolean]: Do not delete resources, merely list what would be deleted.
		# @param skipsnapshots [Boolean]: Refrain from saving final snapshots of volumes and databases before deletion.
		# @param onlycloud [Boolean]: Purge cloud resources, but skip purging all Mu master metadata, ssh keys, etc.
		# @param verbose [Boolean]: Generate verbose output.
		# @param web [Boolean]: Generate web-friendly output.
		# @param ignoremaster [Boolean]: Ignore the tags indicating the originating MU master server when deleting.
		# @return [void]
		def self.run(muid, noop=false, skipsnapshots=false, onlycloud=false, verbose=false, web=false, ignoremaster=false, mommacat: nil)
			MU.setLogging(verbose, web)
			@noop = noop
			@skipsnapshots = skipsnapshots
			@onlycloud = onlycloud
			@ignoremaster = ignoremaster

			if MU.chef_user != "mu"
				MU.setVar("dataDir", Etc.getpwnam(MU.chef_user).dir+"/.mu/var")
			else
				MU.setVar("dataDir", MU.mainDataDir)
			end

			# Load up our deployment metadata
			if !mommacat.nil?
				@mommacat = mommacat
			else
				begin
					deploy_dir = File.expand_path("#{MU.dataDir}/deployments/"+muid)
					if Dir.exist?(deploy_dir)
#						key = OpenSSL::PKey::RSA.new(File.read("#{deploy_dir}/public_key"))
#						deploy_secret = key.public_encrypt(File.read("#{deploy_dir}/deploy_secret"))
						FileUtils.touch("#{deploy_dir}/.cleanup") if !@noop
					else
						MU.log "I don't see a deploy named #{muid}.", MU::WARN
						MU.log "Known deployments:\n#{Dir.entries(deploy_dir).reject{|item| item.match(/^\./) or !File.exists?(deploy_dir+"/"+item+"/public_key") }.join("\n")}", MU::WARN
						MU.log "Searching for remnants of #{muid}, though this may be an invalid MU-ID.", MU::WARN
					end
					@mommacat = MU::MommaCat.new(muid)
				rescue Exception => e
					MU.log "Can't load a deploy record for #{muid} (#{e.inspect}), cleaning up resources by guesswork", MU::WARN
					MU.setVar("mu_id", muid)
				end
			end

			parent_thread_id = Thread.current.object_id
			regions = MU::Config.listRegions
			deleted_nodes = 0
			@regionthreads = []
			keyname = "deploy-#{MU.mu_id}"
			regions.each { |r|
				@regionthreads << Thread.new {
					MU.dupGlobals(parent_thread_id)
					MU.setVar("curRegion", r)
					MU.log "Checking for cloud resources in #{r}", MU::NOTICE
					begin
						MU::CloudFormation.cleanup(@noop, @ignoremaster, region: r)
						MU::ServerPool.cleanup(@noop, @ignoremaster, region: r)
						MU::LoadBalancer.cleanup(@noop, @ignoremaster, region: r)
						MU::Server.cleanup(@noop, @ignoremaster, skipsnapshots: @skipsnapshots, onlycloud: @onlycloud, region: r)
						MU::Database.cleanup(@noop, @ignoremaster, region: r)
						MU::FirewallRule.cleanup(@noop, @ignoremaster, region: r)
						MU::DNSZone.cleanup(@noop, region: r)
						MU::VPC.cleanup(@noop, @ignoremaster, region: r)

						# Hit CloudFormation again- sometimes the first delete will quietly
						# fail due to dependencies.
						MU::CloudFormation.cleanup(@noop, wait: true, region: r)

						resp = MU.ec2(r).describe_key_pairs(
							filters: [ { name: "key-name", values: [keyname] } ]
						)
						resp.data.key_pairs.each { |keypair|
							MU.log "Deleting key pair #{keypair.key_name} from #{r}"
							MU.ec2(r).delete_key_pair(key_name: keypair.key_name) if !@noop
						}
					rescue Aws::EC2::Errors::RequestLimitExceeded, Aws::EC2::Errors::Unavailable, Aws::EC2::Errors::InternalError => e
						MU.log e.inspect, MU::WARN
						sleep 30
						retry
					end
				}
			}

			@regionthreads.each do |t|
				t.join
			end

			# Scrub any residual Chef records with matching tags
			if !@onlycloud
				if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
					Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
				end
				deadnodes = []
				Chef::Config[:environment] = MU.environment
				q = Chef::Search::Query.new
				q.search("node", "tags_MU-ID:#{MU.mu_id}").each { |item|
					next if item.is_a?(Fixnum)
					item.each { |node|
						deadnodes << node.name
					}
				}
				MU.log "Missed some Chef resources in node cleanup, purging now", MU::NOTICE if deadnodes.size > 0
				deadnodes.uniq.each { |node|
					MU::Server.purgeChefResources(node, [], noop)
				}
			end

			# XXX Rotate vault keys and remove any residual crufty clients. This
			# doesn't actually work right now (vault bug?) and is ungodly slow.
			if !@noop and !@onlycloud
#				MU::MommaCat.lock("vault-rotate", false, true)
#				MU.log "Rotating vault keys and purging unknown clients"
#				`#{MU::Config.knife} vault rotate all keys --clean-unknown-clients #{MU::Config.vault_opts}`
#				MU::MommaCat.unlock("vault-rotate")
			end

			if !@onlycloud and !@noop and @mommacat
				@mommacat.purge!
			end

			myhome = Etc.getpwuid(Process.uid).dir
			sshdir = "#{myhome}/.ssh"
			sshconf = "#{sshdir}/config"
			ssharchive = "#{sshdir}/archive"
			
			Dir.mkdir(sshdir, 0700) if !Dir.exists?(sshdir) and !@noop
			Dir.mkdir(ssharchive, 0700) if !Dir.exists?(ssharchive) and !@noop
			
			keyname = "deploy-#{MU.mu_id}"
			if File.exists?("#{sshdir}/#{keyname}")
				MU.log "Moving #{sshdir}/#{keyname} to #{ssharchive}/#{keyname}"
				if !@noop
					File.rename("#{sshdir}/#{keyname}", "#{ssharchive}/#{keyname}")
				end
			end
			
			if File.exists?(sshconf) and File.open(sshconf).read.match(/\/deploy\-#{MU.mu_id}$/)
				MU.log "Expunging #{MU.mu_id} from #{sshconf}"
				if !@noop 
					FileUtils.copy(sshconf, "#{ssharchive}/config-#{MU.mu_id}")
					File.open(sshconf, File::CREAT|File::RDWR, 0600) { |f|
						f.flock(File::LOCK_EX)
						newlines = Array.new
						delete_block = false
						f.readlines.each { |line|
							if line.match(/^Host #{MU.mu_id}\-/)
								delete_block = true
							elsif line.match(/^Host /)
								delete_block = false
							end
							newlines << line if !delete_block
						}
						f.rewind
						f.truncate(0)
						f.puts(newlines)
						f.flush
						f.flock(File::LOCK_UN)
					}
				end
			end
			
			# XXX refactor with above? They're similar, ish.
			hostsfile = "/etc/hosts"
			if File.open(hostsfile).read.match(/ #{MU.mu_id}\-/)
				MU.log "Expunging traces of #{MU.mu_id} from #{hostsfile}"
				if !@noop 
					FileUtils.copy(hostsfile, "#{hostsfile}.cleanup-#{muid}")
					File.open(hostsfile, File::CREAT|File::RDWR, 0644) { |f|
						f.flock(File::LOCK_EX)
						newlines = Array.new
						f.readlines.each { |line|
							newlines << line if !line.match(/ #{MU.mu_id}\-/)
						}
						f.rewind
						f.truncate(0)
						f.puts(newlines)
						f.flush
						f.flock(File::LOCK_UN)
					}
				end
			end

			if !@noop
				MU.s3(MU.myRegion).delete_object(
					bucket: MU.adminBucketName,
					key: "#{MU.mu_id}-secret"
				)
			end

			MU::MommaCat.syncMonitoringConfig if !@noop

		end
	end #class
end #module
