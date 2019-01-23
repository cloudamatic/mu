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
require 'optimist'
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
        creds = {}
        MU::Cloud.supportedClouds.each { |cloud|
          if $MU_CFG[cloud.downcase] and $MU_CFG[cloud.downcase].size > 0
            cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
            creds[cloud] ||= {}
            $MU_CFG[cloud.downcase].keys.each { |credset|
              creds[cloud][credset] = cloudclass.listRegions(credentials: credset)
            }
          end
        }
        parent_thread_id = Thread.current.object_id
        deleted_nodes = 0
        @regionthreads = []
        keyname = "deploy-#{MU.deploy_id}"
# XXX blindly checking for all of these resources in all clouds is now prohibitively slow. We should only do this when we don't see deployment metadata to work from.
        creds.each_pair { |provider, credsets|
          credsets.each_pair { |credset, regions|
            regions.each { |r|
              @regionthreads << Thread.new {
                MU.dupGlobals(parent_thread_id)
                MU.setVar("curRegion", r)
                projects = []
                if $MU_CFG[provider.downcase][credset]["project"]
# XXX GCP credential schema needs an array for projects
                  projects << $MU_CFG[provider.downcase][credset]["project"]
                else
                  projects << ""
                end

                if projects == [""]
                  MU.log "Checking for #{provider}/#{credset} resources from #{MU.deploy_id} in #{r}", MU::NOTICE
                end

                # We do these in an order that unrolls dependent resources
                # sensibly, and we hit :Collection twice because AWS
                # CloudFormation sometimes fails internally.
                projectthreads = []
                projects.each { |project|
                  projectthreads << Thread.new {
                    MU.dupGlobals(parent_thread_id)
                    MU.setVar("curRegion", r)
                    if project != ""
                      MU.log "Checking for #{provider}/#{credset} resources from #{MU.deploy_id} in #{r}, project #{project}", MU::NOTICE
                    end

                    MU.dupGlobals(parent_thread_id)
                    flags = {
                      "project" => project,
                      "onlycloud" => @onlycloud,
                      "skipsnapshots" => @skipsnapshots,
                    }
                    ["Collection", "Function", "ServerPool", "ContainerCluster", "SearchDomain", "Server", "MsgQueue", "Database", "CacheCluster", "StoragePool", "LoadBalancer", "FirewallRule", "Alarm", "Notifier", "Log", "VPC", "Collection"].each { |t|
                      resclass = Object.const_get("MU").const_get("Cloud").const_get(t)
# XXX check if class is supported in this cloud
                      if @mommacat.nil? or @mommacat.numKittens(types: [t]) > 0
                        begin
                          resclass.cleanup(
                            noop: @noop,
                            ignoremaster: @ignoremaster,
                            region: r,
                            cloud: provider,
                            flags: flags,
                            credentials: credset
                          )
                        rescue Seahorse::Client::NetworkingError => e
                          MU.log "Service not available in AWS region #{r}, skipping", MU::DEBUG, details: e.message
                        end
                      end
                    }
                  }
                }
                projectthreads.each do |t|
                  t.join
                end

                if provider == "AWS"
                  resp = MU::Cloud::AWS.ec2(region: r, credentials: credset).describe_key_pairs(
                      filters: [{name: "key-name", values: [keyname]}]
                  )
                  resp.data.key_pairs.each { |keypair|
                    MU.log "Deleting key pair #{keypair.key_name} from #{r}"
                    MU::Cloud::AWS.ec2(region: r, credentials: credset).delete_key_pair(key_name: keypair.key_name) if !@noop
                  }
                end
              }
            }
            MU::Cloud::Role.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: provider, credentials: credset) if @mommacat.nil? or @mommacat.numKittens(types: ["Role"]) > 0
            MU::Cloud::Group.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: provider, credentials: credset) if @mommacat.nil? or @mommacat.numKittens(types: ["Group"]) > 0
            MU::Cloud::User.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: provider, credentials: credset) if @mommacat.nil? or @mommacat.numKittens(types: ["User"]) > 0
          }
        }

        # knock over region-agnostic resources

        @regionthreads.each do |t|
          t.join
        end
        @projectthreads = []


        $MU_CFG['google'].each_pair { |credset, cfg|
          project = cfg["project"]
          @projectthreads << Thread.new {
            MU.dupGlobals(parent_thread_id)
            flags = {
              "project" => project,
              "onlycloud" => @onlycloud,
              "skipsnapshots" => @skipsnapshots,
            }
            MU::Cloud::ServerPool.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: "Google", flags: flags) if @mommacat.nil? or @mommacat.numKittens(types: ["ServerPool"]) > 0
            MU::Cloud::FirewallRule.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: "Google", flags: flags) if @mommacat.nil? or @mommacat.numKittens(types: ["FirewallRule"]) > 0
            MU::Cloud::LoadBalancer.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: "Google", flags: flags) if @mommacat.nil? or @mommacat.numKittens(types: ["LoadBalancer"]) > 0
            MU::Cloud::Database.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: "Google", flags: flags) if @mommacat.nil? or @mommacat.numKittens(types: ["Database"]) > 0
            MU::Cloud::VPC.cleanup(noop: @noop, ignoremaster: @ignoremaster, cloud: "Google", flags: flags) if @mommacat.nil? or @mommacat.numKittens(types: ["VPC"]) > 0
    
          }
        }

        if !MU::Cloud::AWS.isGovCloud?
          if $MU_CFG['aws']
            MU::Cloud::DNSZone.cleanup(noop: @noop, cloud: "AWS", ignoremaster: @ignoremaster) if @mommacat.nil? or @mommacat.numKittens(types: ["DNSZone"]) > 0
          end
        end

        @projectthreads.each do |t|
          t.join
        end

        MU::Cloud::Google.removeDeploySecretsAndRoles(MU.deploy_id) 
# XXX port AWS equivalent behavior and add a MU::Cloud wrapper
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
            next if item.is_a?(Integer)
            item.each { |node|
              deadnodes << node.name
            }
          }
        rescue Net::HTTPServerException
        end

        begin
          q.search("node", "name:#{MU.deploy_id}-*").each { |item|
            next if item.is_a?(Integer)
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
        if $MU_CFG['aws'] and $MU_CFG['aws']['account_number']
          MU::Cloud::AWS.s3(region: MU.myRegion).delete_object(
            bucket: MU.adminBucketName,
            key: "#{MU.deploy_id}-secret"
          )
        end
        if $MU_CFG['google'] and $MU_CFG['google']['project']
          begin
            MU::Cloud::Google.storage.delete_object(
              MU.adminBucketName,
              "#{MU.deploy_id}-secret"
            )
          rescue ::Google::Apis::ClientError => e
            raise e if !e.message.match(/^notFound: /)
          end
        end
        if MU.myCloud == "AWS"
          MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
        end
      end

      if !@noop and !@skipcloud and (@mommacat.nil? or @mommacat.numKittens(types: ["Server", "ServerPool"]) > 0)
#        MU::MommaCat.syncMonitoringConfig
      end

    end
  end #class
end #module
