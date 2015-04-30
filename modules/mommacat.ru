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

require 'pp'
require 'base64'
require 'etc'

# Load our configuration settings directly, rather than depending on our
# invoking environment having been completely sane. Really we shouldn't be
# doing much with the environment at all...
# @param path [String]: The path to a .murc file to load.
# @return [void]
def parseRCFile(path)
	if File.readable?(path)
		File.readlines(path).each {|line|
			line.strip!
			name, value = line.split(/=/, 2)
			name.sub!(/^export /, "")
			if !value.nil? and !value.empty?
				value.gsub!(/(^"|"$)/, "")
				ENV[name] = value if !value.match(/\$/)
				puts "Setting MURC variable #{name}=#{value}"
			end
		}
	end
end

if ENV.include?('MU_INSTALLDIR')
	parseRCFile ENV['MU_INSTALLDIR']+"/etc/mu.rc"
else
	parseRCFile "/opt/mu/etc/mu.rc"
end

home = Etc.getpwuid(Process.uid).dir
parseRCFile "#{home}/.murc"

if !ENV.include?('MU_INSTALLDIR')
	puts "Environment isn't set and I can't find a useful .murc, aborting."
	exit 1
end
if !ENV.include?('MU_LIBDIR')
	ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
end

$MUDIR = ENV['MU_LIBDIR']

$LOAD_PATH << "#{$MUDIR}/modules"

require 'mu'
#MU.setLogging($opts[:verbose], $opts[:web])

Signal.trap("URG") do
	puts "------------------------------"
	puts "Open flock() locks:"
	pp MU::MommaCat.locks
	puts "------------------------------"
end

begin
	MU::MommaCat.syncMonitoringConfig(false)
rescue Exception => e
	MU.log e.inspect, MU::ERR, details: e.backtrace
	# ...but don't die!
end

parent_thread_id = Thread.current.object_id
Thread.new {
	MU.dupGlobals(parent_thread_id)
	begin
		MU::MommaCat.cleanTerminatedInstances
		sleep 60
	rescue Exception => e
		MU.log "Error in cleanTerminatedInstances thread: #{e.inspect}", MU::ERR, details: e.backtrace
		retry
	end while true
}

required_vars = ["mu_id", "mu_deploy_secret", "mu_resource_name", "mu_resource_type", "mu_instance_id"]

# Return an error message to web clients.
def throw500(msg = "", details = nil)
	MU.log "Returning 500 to client: #{msg}", MU::ERR, details: details
	[
		500,
		{
			'Content-Type' => 'text/html',
			'Content-Length' => msg.length
		},
		[msg]
	]
end

@litters = Hash.new
@litter_semaphore = Mutex.new


# Load a {MU::MommaCat} instance for the requested deployment.
# @param req [Hash]: The web request describing the requested deployment. Must include a *mu_id* and *mu_deploy_secret*. 
# return [MU::MommaCat]
def getKittenPile(req)
	@litter_semaphore.synchronize {
		mu_id = req["mu_id"]
		if !@litters.has_key?(mu_id)
			kittenpile = MU::MommaCat.new(
				mu_id,
				deploy_secret: Base64.urlsafe_decode64(req["mu_deploy_secret"]),
				verbose: true,
				mu_user: req['mu_user']
			)
			@litters[mu_id] = Hash.new
			@litters[mu_id]['kittenpile'] = kittenpile
			@litters[mu_id]['kittencount'] = 1
			@litters[mu_id]['threads'] = [Thread.current.object_id]
		else
			@litters[mu_id]['kittencount'] += 1
			@litters[mu_id]['threads'] << Thread.current.object_id
			MU.dupGlobals(@litters[mu_id]['threads'].first)
		end
		# Make sure enough per-thread global MU class variables are set for us
		# to operate in this thread context

		MU.setVar("mu_id", mu_id)
		MU.setVar("mommacat", @litters[mu_id]['kittenpile'])
		MU.log "Adding kitten in #{mu_id}: #{@litters[mu_id]['kittencount']}", MU::DEBUG, details: @litters
		return @litters[mu_id]['kittenpile']
	}
end
# Release a {MU::MommaCat} object.
# @param mu_id [String]: The MU identifier of the loaded deploy to replace.
def releaseKitten(mu_id)
	@litter_semaphore.synchronize {
		if @litters.has_key?(mu_id)
			@litters[mu_id]['kittencount'] -= 1
			@litters[mu_id]['threads'].delete(Thread.current.object_id)
			MU.log "Releasing kitten in #{mu_id}: #{@litters[mu_id]['kittencount']}", MU::DEBUG, details: @litters
			if @litters[mu_id]['kittencount'] < 1
				@litters.delete(mu_id)
			end
			MU.purgeGlobals
		end
	}
end



app = proc do |env|
	ok = false
	begin
		if !env["rack.input"].nil?
			req = Rack::Utils.parse_nested_query(env["rack.input"].read)
			ok = true
#			required_vars.each { |var|
#				if req[var].nil? or req[var].empty?
#					ok = false
#					MU.log "Invalid request: #{var} must be specified", MU::ERR, details: req
#				end
#			}
#			if !ok
#				throw500 "Malformed request", req
#				MU.purgeGlobals
#				next
#			end
			if req["mu_user"].nil?
				req["mu_user"] = "mu"
			end

			MU.log "Processing request from #{env["REMOTE_ADDR"]} (MU-ID #{req["mu_id"]}, #{req["mu_resource_type"]}: #{req["mu_resource_name"]}, instance: #{req["mu_instance_id"]}, mu_ssl_sign: #{req["mu_ssl_sign"]}, mu_user #{req['mu_user']})"
			kittenpile = getKittenPile(req)
			if kittenpile.nil? or kittenpile.original_config.nil? or kittenpile.original_config[req["mu_resource_type"]+"s"].nil?
				throw500 "Couldn't find config data for #{req["mu_resource_type"]} in deploy_id #{req["mu_id"]}"
				ok = false
				next
			end
			server_cfg = nil
			kittenpile.original_config[req["mu_resource_type"]+"s"].each { |svr|
				if svr["name"] == req["mu_resource_name"]
					server_cfg = svr.dup
					break
				end
			}
			if server_cfg.nil?
				throw500 "Couldn't find config data for #{req["mu_resource_type"]} name: #{req["mu_resource_name"]} deploy_id: #{req["mu_id"]}"
				ok = false
				next
			end

			MU.log "Dug up server config for #{req["mu_resource_type"]} name: #{req["mu_resource_name"]} deploy_id: #{req["mu_id"]}", MU::DEBUG, details: server_cfg

			instance, mu_name = MU::Server.find(id: req["mu_instance_id"], region: server_cfg["region"])
			if !instance.nil?
				if !req["mu_bootstrap"].nil?
					kittenpile.groomNode(instance, req["mu_resource_name"], req["mu_resource_type"], sync_wait: true)
				else
					throw500 "Didn't get 'mu_bootstrap' parameter from instance id '#{req["mu_instance_id"]}'"
					ok = false
				end
			elsif !req["mu_ssl_sign"].nil?
				kittenpile.signSSLCert(req["mu_ssl_sign"])
			else
				throw500 "No such instance id '#{req["mu_instance_id"]}' nor was this an SSL signing request"
				ok = false
			end
		end
	rescue Exception => e
		throw500 "Invalid request: #{e.inspect} (#{req})", e.backtrace
		ok = false
	ensure
		releaseKitten(req['mu_id'])
		MU.purgeGlobals
	end
	next if !ok

	[
		200,
		{
			'Content-Type' => 'text/html',
			'Content-Length' => '2'
		},
		['hi']
	]
	
end

run app
