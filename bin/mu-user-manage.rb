#!/usr/local/ruby-current/bin/ruby
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

require File.expand_path(File.dirname(__FILE__))+"/mu-load-murc.rb"

require 'trollop'

$opts = Trollop::options do
  banner <<-EOS
Usage:
#{$0} [-e <environment>] [-r region] [-v] [-d] [-w] [-c] [-n] [-s] [-j] [-p parameter=value] /path/to/stack/config.[json|yaml] [-u deploy_id]
  EOS
  opt :environment, "Environment to set on creation.", :require => false, :default => "dev"
  opt :region, "Default region for newly-created cloud resources.", :require => false, :default => MU.myRegion, :type => :string
  opt :nocleanup, "Skip cleaning up resources on failed deployments. Used for debugging.", :require => false, :default => false
  opt :web, "Generate web-friendly (HTML) output.", :require => false, :default => false, :type => :boolean
  opt :dryrun, "Do not build a stack, only run configuration validation.", :require => false, :default => false, :type => :boolean
  opt :skipinitialupdates, "Node bootstrapping normally runs an internal recipe that does a full system update. This disables that behavior.", :require => false, :default => false, :type => :boolean
  opt :parameter, "Pass a parameter to the configuration parser (Name=Value). This will be presented to your config file as the ERB variable $Name.", :require => false, :type => :string, :multi => true
  opt :update, "Update the stored configuration of an existing deployment, instead of creating a new deploy.", :require => false, :type => :string
  opt :verbose, "Display debugging output.", :require => false, :default => false, :type => :boolean
end

MU.setVar("curRegion", $opts[:region]) if $opts[:region]
MU.setLogging($opts[:verbose], $opts[:web])

# Parse any paramater options into something useable.
params = Hash.new
$opts[:parameter].each { |param|
  name, value = param.split(/\s*=\s*/, 2)
  params[name] = value
}

# We want our config files (which can be ERB templates) to have this variable
# available to them.
$environment = $opts[:environment]

if !ARGV[0] or ARGV[0].empty?
  MU.log("You must specify a stack configuration file!", MU::ERR, html: $opts[:web])
  exit 1
end

begin
  config = File.realdirpath(ARGV[0])
  File.read(config)
rescue Errno::ENOENT => e
  MU.log "#{e.message}", MU::ERR, html: $opts[:web]
  exit 1
end


MU.log "Loading #{config}", html: $opts[:web], details: $opts

conf_engine = MU::Config.new(config, $opts[:skipinitialupdates], params: params)
stack_conf = conf_engine.config

if $opts[:dryrun] or $opts[:verbose]
  puts JSON.pretty_generate(stack_conf)
  conf_engine.visualizeDependencies
end

if $opts[:dryrun]
  MU.log("#{$config} loaded successfully.", html: $opts[:web])
  exit
end

if $opts[:update]
  deploy = MU::MommaCat.new($opts[:update])
  deploy.updateBasketofKittens(stack_conf)
  exit 0
end

$application_cookbook = stack_conf["application_cookbook"]
Dir.chdir(MU.installDir)

deployer = MU::Deploy.new(
    $opts[:environment],
    verbosity: $opts[:verbose],
    webify_logs: $opts[:web],
    nocleanup: $opts[:nocleanup],
    stack_conf: stack_conf
)

deployer.run
