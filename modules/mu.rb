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
require 'bundler/setup'
require 'yaml'
require 'socket'
require 'net/http'
gem 'aws-sdk-core'
autoload :Aws, "aws-sdk-core"
gem 'nokogiri'
autoload :Nokogiri, "nokogiri"
gem 'simple-password-gen'
autoload :Password, "simple-password-gen"
autoload :Resolv, 'resolv'
gem 'netaddr'
autoload :NetAddr, 'netaddr'

gem "chef"
autoload :Chef, 'chef'
gem "knife-windows"
gem "chef-vault"
autoload :Chef, 'chef-vault'
autoload :ChefVault, 'chef-vault'

class Object
	def metaclass
		class << self; self; end
	end
end

# XXX Explicit autoloads for child classes of :Chef. This only seems to be
# necessary for independent groom invocations from MommaCat. It's not at all
# clear why. Chef bug? Autoload threading weirdness?
class Chef
  autoload :Knife, 'chef/knife'
  autoload :Search, 'chef/search'
  autoload :Node, 'chef/node'
	autoload :Mixin, 'chef/mixin'
	# XXX This only seems to be necessary for independent groom invocations from
	# MommaCat. It's not at all clear why. Chef bug? Autoload threading weirdness?
	class Knife
		autoload :Ssh, 'chef/knife/ssh'
		autoload :Bootstrap, 'chef/knife/bootstrap'
		autoload :BootstrapWindowsSsh, 'chef/knife/bootstrap_windows_ssh'
		autoload :Bootstrap, 'chef/knife/core/bootstrap_context'
		autoload :BootstrapWindowsSsh, 'chef/knife/core/bootstrap_context'
	end
end

if ENV['AWS_ACCESS_KEY_ID'] == nil or ENV['AWS_ACCESS_KEY_ID'].empty?
	ENV.delete('AWS_ACCESS_KEY_ID')
	ENV.delete('AWS_SECRET_ACCESS_KEY')
	Aws.config = { region: ENV['EC2_REGION'] }
else
	Aws.config = { access_key_id: ENV['AWS_ACCESS_KEY_ID'], secret_access_key: ENV['AWS_SECRET_ACCESS_KEY'], region: ENV['EC2_REGION'] }
end
ENV['HOME'] = Etc.getpwuid(Process.uid).dir

gem "chef"
autoload :Chef, 'chef'
gem "knife-windows"
gem "chef-vault"
autoload :Chef, 'chef-vault'
autoload :ChefVault, 'chef-vault'

# XXX Explicit autoloads for child classes of :Chef. This only seems to be
# necessary for independent groom invocations from MommaCat. It's not at all
# clear why. Chef bug? Autoload threading weirdness?
class Chef
  autoload :Knife, 'chef/knife'
  autoload :Search, 'chef/search'
  autoload :Node, 'chef/node'
	autoload :Mixin, 'chef/mixin'
	# XXX This only seems to be necessary for independent groom invocations from
	# MommaCat. It's not at all clear why. Chef bug? Autoload threading weirdness?
	class Knife
		autoload :Ssh, 'chef/knife/ssh'
		autoload :Bootstrap, 'chef/knife/bootstrap'
		autoload :BootstrapWindowsSsh, 'chef/knife/bootstrap_windows_ssh'
		autoload :Bootstrap, 'chef/knife/core/bootstrap_context'
		autoload :BootstrapWindowsSsh, 'chef/knife/core/bootstrap_context'
	end
end

require 'mu/logger'
module MU

	# Wrapper class for fatal Exceptions. Gives our internals something to
	# inherit that will log an error message appropriately before bubbling up.
	class MuError < StandardError
		def initialize(message = nil)
			MU.log message, MU::ERR if !message.nil?
			super ""
		end
	end

	# Wrapper class for temporary Exceptions. Gives our internals something to
	# inherit that will log a notice message appropriately before bubbling up.
	class MuNonFatal < StandardError
		def initialize(message = nil)
			MU.log message, MU::NOTICE if !message.nil?
			super ""
		end
	end

	if !ENV.has_key?("MU_LIBDIR") and ENV.has_key?("MU_INSTALLDIR")
		ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
	else
		ENV['MU_LIBDIR'] = "/opt/mu/lib"
	end
	# Mu's installation directory.
	@@myRoot = File.expand_path(ENV['MU_LIBDIR'])
	# Mu's installation directory.
	# @return [String]
	def self.myRoot; @@myRoot end

	# The main (root) Mu user's data directory.
	@@mainDataDir = File.expand_path(@@myRoot+"/../var")
	# The main (root) Mu user's data directory.
	# @return [String]
	def self.mainDataDir; @@mainDataDir end

	# The Mu config directory
	@@etcDir = File.expand_path(@@myRoot+"/../etc")
	# The Mu config directory
	# @return [String]
	def self.etcDir; @@etcDir end

	# The Mu install directory
	@@installDir = File.expand_path(@@myRoot+"/..")
	# The Mu install directory
	# @return [String]
	def self.installDir; @@installDir end

	# Mu's main metadata directory (also the deployment metadata for the 'mu'
	@@globals = Hash.new
	@@globals[Thread.current.object_id] = Hash.new
	# Rig us up to share some global class variables (as MU.var_name).
	# These values are PER-THREAD, so that things like Momma Cat can be more or
	# less thread-safe with global values.
	def self.globals; @@globals end
	@@global_var_semaphore = Mutex.new

	# Set one of our global per-thread variables.
	def self.setVar(name, value)
		@@global_var_semaphore.synchronize {
			@@globals[Thread.current.object_id] ||= Hash.new
			@@globals[Thread.current.object_id][name] ||= Hash.new
			@@globals[Thread.current.object_id][name] = value
		}
	end
	# Copy the set of global variables in use by another thread, typically our
	# parent thread.
	def self.dupGlobals(parent_thread_id)
		@@globals[parent_thread_id].each_pair { |name, value|
			setVar(name, value)
		}
	end
	# Expunge all global variables.
	def self.purgeGlobals
		@@globals.delete(Thread.current.object_id)
	end

	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.mommacat; @@globals[Thread.current.object_id]['mommacat'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.deploy_id; @@globals[Thread.current.object_id]['deploy_id'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.appname; @@globals[Thread.current.object_id]['appname'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.

	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.environment; @@globals[Thread.current.object_id]['environment'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.timestamp; @@globals[Thread.current.object_id]['timestamp'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.seed; @@globals[Thread.current.object_id]['seed'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.handle; @@globals[Thread.current.object_id]['handle'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.chef_user; @@globals[Thread.current.object_id]['chef_user'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.dataDir; @@globals[Thread.current.object_id]['dataDir'] end
	# Accessor for per-thread global variable. There is probably a Ruby-clever way to define this.
	def self.curRegion
		@@globals[Thread.current.object_id]['curRegion'] ||= ENV['EC2_REGION']
	end

	# Mu's deployment metadata directory.
	dataDir = File.expand_path(ENV['MU_DATADIR'])
	dataDir = @@mainDataDir if dataDir.nil?
	MU.setVar("dataDir", dataDir)

	# The verbose logging flag merits a default value.
	def self.verbose
		if @@globals[Thread.current.object_id].nil? or @@globals[Thread.current.object_id]['verbose'].nil?
			MU.setVar("verbose", false)
		end
		@@globals[Thread.current.object_id]['verbose']
	end

	# Set parameters parameters for calls to {MU#log}
	def self.setLogging(verbose, webify_logs)
		@@logger = MU::Logger.new(verbose, webify_logs)
	end
	setLogging(false, false)

	# Shortcut to invoke {MU::Logger#log}
	def self.log(msg, level=MU::INFO, details: details, html: html = false)
		return if(level == MU::DEBUG and !MU.verbose)

		if(level == MU::ERR or
				level == MU::WARN or
				level == MU::DEBUG or
				MU.verbose or
				(level == MU::NOTICE and !details.nil?)
			)
			# TODO add more stuff to details here (e.g. call stack)
			extra = nil
			if Thread.current.thread_variable_get("name") and (level > MU::NOTICE or MU.verbose)
				extra = Hash.new
			  extra = {
					:thread => Thread.current.object_id, 
					:name => Thread.current.thread_variable_get("name")
				}
			end
			if !details.nil?
				extra = Hash.new if extra.nil?
				extra[:details] = details
			end
			@@logger.log(msg, level, details: extra, verbose: true, html: html)
		else
			@@logger.log(msg, level, html: html)
		end
	end

	# Fetch an Amazon instance metadata parameter (example: public-ipv4).
	# @param param [String]: The parameter name to fetch
	# @return [String, nil]
	def self.getAWSMetaData(param)
		base_url = "http://169.254.169.254/latest/meta-data/"
		begin
			response = Net::HTTP.get_response(URI("#{base_url}/#{param}"))
			response.value
		rescue Net::HTTPServerException => e
		# This is fairly normal, just handle it gracefully
			logger = MU::Logger.new
			logger.log "Failed metadata request #{base_url}/#{param}: #{e.inspect}", MU::DEBUG
			return nil
		end

		return response.body
	end

	@@my_private_ip = MU.getAWSMetaData("local-ipv4")
	@@my_public_ip = MU.getAWSMetaData("public-ipv4")
	@@mu_public_addr = @@my_public_ip
	@@mu_public_ip = @@my_public_ip
	if !ENV['CHEF_PUBLIC_IP'].nil? and !ENV['CHEF_PUBLIC_IP'].empty? and @@my_public_ip != ENV['CHEF_PUBLIC_IP']
		@@mu_public_addr = ENV['CHEF_PUBLIC_IP']
		if !ENV['CHEF_PUBLIC_IP'].match(/^\d+\.\d+\.\d+\.\d+$/)
			resolver = Resolv::DNS.new
			@@mu_public_ip = resolver.getaddress(ENV['CHEF_PUBLIC_IP']).to_s
		else
			@@mu_public_ip = ENV['CHEF_PUBLIC_IP']
		end
	elsif !@@my_public_ip.nil? and !@@my_public_ip.empty?
		@@mu_public_addr = @@my_public_ip
		@@mu_public_ip = @@my_public_ip
	else
		@@mu_public_addr = @@my_private_ip
		@@mu_public_ip = @@my_private_ip
	end

	# Private Mu server IP address, per AWS
	def self.my_private_ip; @@my_private_ip end
	# Public Mu server IP address, per AWS
	def self.my_public_ip; @@my_public_ip end
	# Public Mu server name, not necessarily the same as MU.mu_public_ip
	def self.mu_public_ip; @@mu_public_ip end
	# Public Mu server IP address, not necessarily the same as MU.my_public_ip
	def self.mu_public_addr; @@mu_public_addr end


	chef_user ||= Etc.getpwuid(Process.uid).name
	chef_user = "mu" if chef_user == "root"
	MU.setVar("chef_user", chef_user)

	# Fetch the email address of a given Mu user
	def self.userEmail(user = MU.chef_user)
		if Dir.exists?("#{MU.mainDataDir}/users/#{user}")
			return File.read("#{MU.mainDataDir}/users/#{user}/email").chomp
		else
			MU.log "Attempted to load nonexistent user #{user}", MU::ERR
			return nil
		end
	end
	# Fetch the real-world name of a given Mu user
	def self.userName(user = MU.chef_user)
		if Dir.exists?("#{MU.mainDataDir}/users/#{user}")
			return File.read("#{MU.mainDataDir}/users/#{user}/realname").chomp
		else
			MU.log "Attempted to load nonexistent user #{user}", MU::ERR
			return nil
		end
	end

	# For log entries that should only be logged when we're in verbose mode
	DEBUG = 0.freeze
	# For ordinary log entries
	INFO = 1.freeze
	# For more interesting log entries which are not errors
	NOTICE = 2.freeze
	# Log entries for non-fatal errors
	WARN = 3.freeze
	# Log entries for non-fatal errors
	WARNING = 3.freeze
	# Log entries for fatal errors
	ERR = 4.freeze
	# Log entries for fatal errors
	ERROR = 4.freeze

	autoload :Cleanup, 'mu/cleanup'
	autoload :Deploy, 'mu/deploy'
	autoload :MommaCat, 'mu/mommacat'
	require 'mu/cloud'
	require 'mu/groomer'

# XXX these guys to move into mu/groomer
	# List of known/supported grooming agents (configuration management tools)
	def self.supportedGroomers
		["Chef"]
	end
	MU.supportedGroomers.each { |groomer|
		require "mu/groomers/#{groomer.downcase}"
	}
	# @param groomer [String]: The grooming agent to load. 
	# @return [Class]: The class object implementing this groomer agent
	def self.loadGroomer(groomer)
		if !File.size?(MU.myRoot+"/modules/mu/groomers/#{groomer.downcase}.rb")
			raise MuError, "Requested to use unsupported grooming agent #{groomer}"
		end
		require "mu/groomers/#{groomer.downcase}"
		return Object.const_get("MU").const_get("Groomer").const_get(groomer)
	end

	require 'mu/config'

	# Figure out our account number, by hook or by crook
	def self.account_number
		if !@@globals[Thread.current.object_id].nil? and
			 !@@globals[Thread.current.object_id]['account_number'].nil?
			return @@globals[Thread.current.object_id]['account_number']
		end
		user_list = MU::Cloud::AWS.iam.list_users.users
		if user_list.nil? or user_list.size == 0
			mac = MU.getAWSMetaData("network/interfaces/macs/").split(/\n/)[0]
			account_number = MU.getAWSMetaData("network/interfaces/macs/#{mac}owner-id")
			account_number.chomp!
		else
			account_number = MU::Cloud::AWS.iam.list_users.users.first.arn.split(/:/)[4]
		end
		MU.setVar("account_number", account_number)
		account_number
	end

	@@myRegion_var = nil
	# Find our AWS Region and Availability Zone
	def self.myRegion
		@@myRegion_var ||= MU::Cloud::AWS.ec2(ENV['EC2_REGION']).describe_availability_zones.availability_zones.first.region_name
		@@myRegion_var
	end	

	# XXX is there a better way to get this?
	@@myInstanceId = MU.getAWSMetaData("instance-id")
	# The AWS instance identifier of this Mu master
	def self.myInstanceId; @@myInstanceId end

	@@myAZ_var = nil
	# The AWS Availability Zone in which this Mu master resides
	def self.myAZ
		begin
			@@myAZ_var ||= MU::Cloud::AWS.ec2(MU.myRegion).describe_instances(instance_ids: [@@myInstanceId]).reservations.first.instances.first.placement.availability_zone
		rescue Aws::EC2::Errors::InternalError => e
			MU.log "Got #{e.inspect} on MU::Cloud::AWS.ec2(#{MU.myRegion}).describe_instances(instance_ids: [#{@@myInstanceId}])", MU::WARN
			sleep 10
		end
		@@myAZ_var
	end

	@@myVPC_var = nil
	# The AWS Availability Zone in which this Mu master resides
	def self.myVPC
		begin
			@@myVPC_var ||= MU::Cloud::AWS.ec2(MU.myRegion).describe_instances(instance_ids: [@@myInstanceId]).reservations.first.instances.first.vpc_id
		rescue Aws::EC2::Errors::InternalError => e
			MU.log "Got #{e.inspect} on MU::Cloud::AWS.ec2(#{MU.myRegion}).describe_instances(instance_ids: [#{@@myInstanceId}])", MU::WARN
			sleep 10
		end
		@@myVPC_var
	end


	# The version of Chef we will install on nodes.
	@@chefVersion = "12.3.0-1"
	# The version of Chef we will install on nodes.
	# @return [String]
	def self.chefVersion; @@chefVersion end

	# Mu's SSL certificate directory
	@@mySSLDir = File.expand_path(ENV['MU_DATADIR']+"/ssl")
	# Mu's SSL certificate directory
	# @return [String]
	def self.mySSLDir; @@mySSLDir end

	# Recursively turn a Ruby OpenStruct into a Hash
	# @param struct [OpenStruct]
	# @return [Hash]
	def self.structToHash(struct)
		if struct.is_a?(Struct)
			hash = struct.to_h
			hash.each_pair { |key, value|
				hash[key] = self.structToHash(value)
			}
			return hash
		elsif struct.is_a?(Hash)
			struct.each_pair { |key, value|
				struct[key] = self.structToHash(value)
			}
			return struct
		elsif struct.is_a?(Array)
			struct.map! { |elt|
				self.structToHash(elt)
			}
		else
			return struct
		end
	end

	# Return the name of the S3 Mu log and key bucket for this Mu server.
	# @return [String]
	def self.adminBucketName
		bucketname = ENV['LOG_BUCKET_NAME']
		if bucketname.nil? or bucketname.empty?
			bucketname = "Mu_Logs_"+Socket.gethostname+"_"+MU.getAWSMetaData("instance-id")
		end
		return bucketname
	end

	# Log bucket policy for enabling CloudTrail logging to our log bucket in S3.
	CLOUDTRAIL_BUCKET_POLICY = '{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AWSCloudTrailAclCheck20131101",
				"Effect": "Allow",
				"Principal": {
					"AWS": [
						"arn:aws:iam::086441151436:root",
						"arn:aws:iam::113285607260:root",
						"arn:aws:iam::388731089494:root",
						"arn:aws:iam::284668455005:root",
						"arn:aws:iam::903692715234:root",
						"arn:aws:iam::216624486486:root",
						"arn:aws:iam::859597730677:root",
						"arn:aws:iam::814480443879:root"
					]
				},
				"Action": "s3:GetBucketAcl",
				"Resource": "arn:aws:s3:::<%= $bucketname %>"
			},
			{
				"Sid": "AWSCloudTrailWrite20131101",
				"Effect": "Allow",
				"Principal": {
					"AWS": [
						"arn:aws:iam::086441151436:root",
						"arn:aws:iam::113285607260:root",
						"arn:aws:iam::388731089494:root",
						"arn:aws:iam::284668455005:root",
						"arn:aws:iam::903692715234:root",
						"arn:aws:iam::216624486486:root",
						"arn:aws:iam::859597730677:root",
						"arn:aws:iam::814480443879:root"
					]
				},
				"Action": "s3:PutObject",
				"Resource": "arn:aws:s3:::<%= $bucketname %>/AWSLogs/*",
				"Condition": {
					"StringEquals": {
						"s3:x-amz-acl": "bucket-owner-full-control"
					}
				}
			}
		]
	}'

end
