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

    @deploy_id = nil
    @noop = false
    @onlycloud = false
    @skipcloud = false

    # Purge all resources associated with a deployment.
    # @param deploy_id [String]: The identifier of the deployment to remove (typically seen in the MU-ID tag on a resource).
    # @param noop [Boolean]: Do not delete resources, merely list what would be deleted.
    # @param skipsnapshots [Boolean]: Refrain from saving final snapshots of volumes and databases before deletion.
    # @param onlycloud [Boolean]: Purge cloud resources, but skip purging all Mu master metadata, ssh keys, etc.
    # @param verbosity [Integer]: Debug level for MU.log output
    # @param web [Boolean]: Generate web-friendly output.
    # @param ignoremaster [Boolean]: Ignore the tags indicating the originating MU master server when deleting.
    # @return [void]
    def self.run(deploy_id, noop: false, skipsnapshots: false, onlycloud: false, verbosity: MU::Logger::NORMAL, web: false, ignoremaster: false, skipcloud: false, mommacat: nil)
      MU.setLogging(verbosity, web)
      @noop = noop
      @skipsnapshots = skipsnapshots
      @onlycloud = onlycloud
      @skipcloud = skipcloud
      @ignoremaster = ignoremaster

      if @skipcloud and @onlycloud # you actually mean noop
        @onlycloud = @skipcloud = false
        @noop = true
      end

      if MU.mu_user != "mu"
        MU.setVar("dataDir", Etc.getpwnam(MU.mu_user).dir+"/.mu/var")
      else
        MU.setVar("dataDir", MU.mainDataDir)
      end

      # Load up our deployment metadata
      if !mommacat.nil?
        @mommacat = mommacat
      else
        begin
          deploy_dir = File.expand_path("#{MU.dataDir}/deployments/"+deploy_id)
          if Dir.exist?(deploy_dir)
#						key = OpenSSL::PKey::RSA.new(File.read("#{deploy_dir}/public_key"))
#						deploy_secret = key.public_encrypt(File.read("#{deploy_dir}/deploy_secret"))
            FileUtils.touch("#{deploy_dir}/.cleanup") if !@noop
          else
            MU.log "I don't see a deploy named #{deploy_id}.", MU::WARN
            MU.log "Known deployments:\n#{Dir.entries(deploy_dir).reject { |item| item.match(/^\./) or !File.exists?(deploy_dir+"/"+item+"/public_key") }.join("\n")}", MU::WARN
            MU.log "Searching for remnants of #{deploy_id}, though this may be an invalid MU-ID.", MU::WARN
          end
          @mommacat = MU::MommaCat.new(deploy_id, mu_user: MU.mu_user)
        rescue Exception => e
          MU.log "Can't load a deploy record for #{deploy_id} (#{e.inspect}), cleaning up resources by guesswork", MU::WARN, details: e.backtrace
          MU.setVar("deploy_id", deploy_id)
        end
      end

      if !@skipcloud
        parent_thread_id = Thread.current.object_id
        regions = {}
        regions['AWS'] = MU::Cloud::AWS.listRegions
        regions['Google'] = MU::Cloud::Google.listRegions
        deleted_nodes = 0
        @regionthreads = []
        keyname = "deploy-#{MU.deploy_id}"
# XXX blindly checking for all of these resources in all clouds is now prohibitively slow. We should only do this when we don't see deployment metadata to work from.
        regions.each_pair { |provider, list|
          if provider == "Google" # mostly region-agnostic resources
            MU::Cloud::FirewallRule.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["FirewallRule", "Server", "ServerPool", "Database", "StoragePool"]) > 0
            MU::Cloud::VPC.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["VPC"]) > 0
          end
          list.each { |r|
            @regionthreads << Thread.new {
              MU.dupGlobals(parent_thread_id)
              MU.setVar("curRegion", r)
              MU.log "Checking for #{provider} cloud resources from #{MU.deploy_id} in #{r}", MU::NOTICE

              # We do these in an order that unrolls dependent resources
              # sensibly, and we hit :Collection twice because AWS
              # CloudFormation sometimes fails internally.
              MU::Cloud::Collection.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["Collection"]) > 0
              MU::Cloud::ServerPool.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["ServerPool"]) > 0
              MU::Cloud::LoadBalancer.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["LoadBalancer"]) > 0
              MU::Cloud::Server.cleanup(skipsnapshots: @skipsnapshots, onlycloud: @onlycloud, noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["Server"]) > 0
              MU::Cloud::Database.cleanup(skipsnapshots: @skipsnapshots, noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["Database"]) > 0
              MU::Cloud::CacheCluster.cleanup(skipsnapshots: @skipsnapshots, noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["CacheCluster"]) > 0
              MU::Cloud::StoragePool.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["StoragePool"]) > 0
              if provider == "AWS"
                MU::Cloud::FirewallRule.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["FirewallRule", "Server", "ServerPool", "Database", "StoragePool"]) > 0
              end
              MU::Cloud::Alarm.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["Alarm"]) > 0 # XXX other resources can make these appear, I think- which ones?
              MU::Cloud::Notification.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["Notification"]) > 0 # XXX other resources can make these appear, I think- which ones?
              MU::Cloud::Log.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["Log"]) > 0 # XXX other resources can make these appear, I think- which ones?
              if provider == "AWS"
                MU::Cloud::VPC.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["VPC"]) > 0
              end
              MU::Cloud::Collection.cleanup(noop: @noop, ignoremaster: @ignoremaster, region: r, wait: true, cloud: provider) if @mommacat.nil? or @mommacat.numKittens(types: ["Collection"]) > 0

              if provider == "AWS"
                resp = MU::Cloud::AWS.ec2(r).describe_key_pairs(
                    filters: [{name: "key-name", values: [keyname]}]
                )
                resp.data.key_pairs.each { |keypair|
                  MU.log "Deleting key pair #{keypair.key_name} from #{r}"
                  MU::Cloud::AWS.ec2(r).delete_key_pair(key_name: keypair.key_name) if !@noop
                }
              end
            }
          }
        }

        @regionthreads.each do |t|
          t.join
        end
        MU::Cloud::DNSZone.cleanup(noop: @noop, ignoremaster: @ignoremaster) if @mommacat.nil? or @mommacat.numKittens(types: ["DNSZone"]) > 0
      end

      # Scrub any residual Chef records with matching tags
      if !@onlycloud and (@mommacat.nil? or @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0)
        MU::Groomer::Chef.loadChefLib
        if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
          Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
        end
        deadnodes = []
        Chef::Config[:environment] = MU.environment
        q = Chef::Search::Query.new
        begin
          q.search("node", "tags_MU-ID:#{MU.deploy_id}").each { |item|
            next if item.is_a?(Fixnum)
            item.each { |node|
              deadnodes << node.name
            }
          }
        rescue Net::HTTPServerException
        end

        begin
          q.search("node", "name:#{MU.deploy_id}-*").each { |item|
            next if item.is_a?(Fixnum)
            item.each { |node|
              deadnodes << node.name
            }
          }
        rescue Net::HTTPServerException
        end
        MU.log "Missed some Chef resources in node cleanup, purging now", MU::NOTICE if deadnodes.size > 0
        deadnodes.uniq.each { |node|
          MU::Groomer::Chef.cleanup(node, [], noop)
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

      keyname = "deploy-#{MU.deploy_id}"
      if File.exists?("#{sshdir}/#{keyname}")
        MU.log "Moving #{sshdir}/#{keyname} to #{ssharchive}/#{keyname}"
        if !@noop
          File.rename("#{sshdir}/#{keyname}", "#{ssharchive}/#{keyname}")
        end
      end

      if File.exists?(sshconf) and File.open(sshconf).read.match(/\/deploy\-#{MU.deploy_id}$/)
        MU.log "Expunging #{MU.deploy_id} from #{sshconf}"
        if !@noop
          FileUtils.copy(sshconf, "#{ssharchive}/config-#{MU.deploy_id}")
          File.open(sshconf, File::CREAT|File::RDWR, 0600) { |f|
            f.flock(File::LOCK_EX)
            newlines = Array.new
            delete_block = false
            f.readlines.each { |line|
              if line.match(/^Host #{MU.deploy_id}\-/)
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
      if File.open(hostsfile).read.match(/ #{MU.deploy_id}\-/)
        MU.log "Expunging traces of #{MU.deploy_id} from #{hostsfile}"
        if !@noop
          FileUtils.copy(hostsfile, "#{hostsfile}.cleanup-#{deploy_id}")
          File.open(hostsfile, File::CREAT|File::RDWR, 0644) { |f|
            f.flock(File::LOCK_EX)
            newlines = Array.new
            f.readlines.each { |line|
              newlines << line if !line.match(/ #{MU.deploy_id}\-/)
            }
            f.rewind
            f.truncate(0)
            f.puts(newlines)
            f.flush
            f.flock(File::LOCK_UN)
          }
        end
      end

      if !@noop and !@skipcloud
        MU::Cloud::AWS.s3(MU.myRegion).delete_object(
            bucket: MU.adminBucketName,
            key: "#{MU.deploy_id}-secret"
        )
        MU::Cloud::AWS.openFirewallForClients # XXX should only run if we're in AWS...
      end

      if !@noop and !@skipcloud and (@mommacat.nil? or @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0)
        MU::MommaCat.syncMonitoringConfig
      end

    end
  end #class
end #module
