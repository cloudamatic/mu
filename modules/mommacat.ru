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

Etc.getpwuid(Process.uid).dir

if !ENV.include?('MU_INSTALLDIR')
  ENV['MU_INSTALLDIR'] = "/opt/mu"
end
if !ENV.include?('MU_LIBDIR')
  ENV['MU_LIBDIR'] = ENV['MU_INSTALLDIR']+"/lib"
end

$MUDIR = ENV['MU_LIBDIR']

$LOAD_PATH << "#{$MUDIR}/modules"

require File.realpath(File.expand_path(File.dirname(__FILE__)+"/mu-load-config.rb"))
require 'mu'

begin
  MU::Groomer::Chef.loadChefLib # pre-cache this so we don't take a hit on a user-interactive need
  $ENABLE_SCRATCHPAD = true
rescue LoadError
  MU.log "Chef libraries not available, disabling Scratchpad", MU::WARN
end
#MU.setLogging($opts[:verbose], $opts[:web])
if MU.myCloud == "AWS"
  MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
end

Signal.trap("URG") do
  puts "------------------------------"
  puts "Open flock() locks:"
  pp MU::MommaCat.trapSafeLocks
  puts "------------------------------"
end

begin
  MU::Master.syncMonitoringConfig(false)
rescue StandardError => e
  MU.log e.inspect, MU::ERR, details: e.backtrace
  # ...but don't die!
end

parent_thread_id = Thread.current.object_id
Thread.new {
  MU.dupGlobals(parent_thread_id)
  begin
    MU::MommaCat.cleanTerminatedInstances
    MU::Master.cleanExpiredScratchpads if $ENABLE_SCRATCHPAD
    sleep 60
  rescue StandardError => e
    MU.log "Error in cleanTerminatedInstances thread: #{e.inspect}", MU::ERR, details: e.backtrace
    retry
  end while true
}

# Use a template to generate a pleasant-looking HTML page for simple messages
# and errors.
def genHTMLMessage(title: "", headline: "", msg: "", template: $MU_CFG['html_template'], extra_vars: {})
  logo_url = "/cloudamatic.png"
  page = "<img src='#{logo_url}'><h1>#{title}</h1>#{msg}"
  vars = {
    "title" => title,
    "msg" => msg,
    "headline" => headline,
    "logo" => logo_url
  }.merge(extra_vars)
  if !template.nil? and File.exist?(template) and File.readable?(template)
    page = Erubis::Eruby.new(File.read(template)).result(vars)
  elsif $MU_CFG.has_key?('html_template') and
     File.exist?($MU_CFG['html_template']) and
     File.readable?($MU_CFG['html_template'])
    page = Erubis::Eruby.new(File.read($MU_CFG['html_template'])).result(vars)
  elsif File.exist?("#{$MU_CFG['libdir']}/modules/html.erb") and
     File.readable?("#{$MU_CFG['libdir']}/modules/html.erb")
    page = Erubis::Eruby.new(File.read("#{$MU_CFG['libdir']}/modules/html.erb")).result(vars)
  end
  page
end

# Return an error message to web clients.
def throw500(msg = "", details = nil)
  MU.log "Returning 500 to client: #{msg}", MU::ERR, details: details
  page = genHTMLMessage(title: "500 Error", headline: msg, msg: details)
  [
      500,
      {
          'Content-Type' => 'text/html',
          'Content-Length' => page.length.to_s
      },
      [page]
  ]
end

def throw404(msg = "", details = nil)
  MU.log "Returning 404 to client: #{msg}", MU::ERR, details: details
  page = genHTMLMessage(title: "404 Not Found", headline: msg, msg: details)
  [
      404,
      {
          'Content-Type' => 'text/html',
          'Content-Length' => page.length.to_s
      },
      [page]
  ]
end

def returnRawJSON(data)
  MU.log "Returning 200 to client", MU::NOTICE, details: data
  [
      200,
      {
          'Content-Type' => 'application/json',
          'Content-Length' => data.length.to_s
      },
      [data]
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
      begin
        kittenpile = MU::MommaCat.new(
            mu_id,
            deploy_secret: Base64.urlsafe_decode64(req["mu_deploy_secret"]),
            set_context_to_me: true,
            mu_user: req['mu_user']
        )
      rescue MU::MommaCat::DeployInitializeError => e
        MU.log e.inspect, MU::ERR, details: req
        return nil
      end
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
  returnval = [
      200,
      {
          'Content-Type' => 'text/html',
          'Content-Length' => '2'
      },
      ['hi']
  ]
  begin
    if !env.nil? and !env['REQUEST_PATH'].nil? and env['REQUEST_PATH'].match(/^\/scratchpad/)
      if !$ENABLE_SCRATCHPAD
        msg = "Scratchpad disabled in non-Chef Mu installations"
        return [
          504,
          {
            'Content-Type' => 'text/html',
            'Content-Length' => msg.length.to_s
          },
          [msg]
        ]
      end
      itemname = env['REQUEST_PATH'].sub(/^\/scratchpad\//, "")
      begin
        if itemname.sub!(/\/secret$/, "")
          secret = MU::Master.fetchScratchPadSecret(itemname)
          MU.log "Retrieved scratchpad secret #{itemname} for #{env['REMOTE_ADDR']}"
          returnval = [
            200,
            {
              'Content-Type' => 'text/plain',
              'Content-Length' => secret.length.to_s
            },
            [secret]
          ]
        else
          secret = "
<script>
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      document.getElementById('scratchpad-button').outerHTML = this.responseText;
    }
  };
  function showScratchPadSecret(){
    xhttp.open('GET', '#{env['REQUEST_PATH']}/secret', true);
    xhttp.send();
  }
</script>
<button id='scratchpad-button' onclick='showScratchPadSecret()'>Show My Secret</button>
"
          page = nil
          if $MU_CFG.has_key?('scratchpad') and
             $MU_CFG['scratchpad'].has_key?("template_path") and
             File.exist?($MU_CFG['scratchpad']['template_path']) and
             File.readable?($MU_CFG['scratchpad']['template_path'])
            page = genHTMLMessage(
              title: "Your Scratchpad Secret",
              headline:"<strong>YOU MAY ONLY RETRIVE THIS SECRET ONCE!</strong> Be sure to copy it somewhere safe before reloading, browsing away, or closing your browser window.",
              msg: secret,
              template: $MU_CFG['scratchpad']['template_path'],
              extra_vars: { "secret" => secret }
            )
          else
            page = genHTMLMessage(
              title: "Your Scratchpad Secret",
              headline:"<strong>YOU MAY ONLY RETRIVE THIS SECRET ONCE!</strong> Be sure to copy it somewhere safe before reloading, browsing away, or closing your browser window.",
              msg: secret
            )
          end

          returnval = [
            200,
            {
              'Content-Type' => 'text/html',
              'Content-Length' => page.length.to_s
            },
            [page]
          ]
        end
      rescue MU::Groomer::MuNoSuchSecret
        page = nil
        if $MU_CFG.has_key?('scratchpad') and
           $MU_CFG['scratchpad'].has_key?("template_path") and
           File.exist?($MU_CFG['scratchpad']['template_path']) and
           File.readable?($MU_CFG['scratchpad']['template_path'])
          page = genHTMLMessage(
            title: "No such secret",
            headline: "No such secret",
            msg: "The secret '#{itemname}' does not exist or has already been retrieved",
            template: $MU_CFG['scratchpad']['template_path'],
            extra_vars: { "secret" => nil }
          )
        else
          page = genHTMLMessage(
            title: "No such secret",
            headline: "No such secret",
            msg: "The secret '#{itemname}' does not exist or has already been retrieved"
            )
        end
        returnval = [
          200,
          {
            'Content-Type' => 'text/html',
            'Content-Length' => page.length.to_s
          },
          [page]
        ]
      end
    elsif !env.nil? and !env['REQUEST_PATH'].nil? and env['REQUEST_PATH'].match(/^\/rest\//)

      action, filter, path = env['REQUEST_PATH'].sub(/^\/rest\/?/, "").split(/\//, 3)
      # Don't give away the store. This can't be public until we can
      # authenticate and access-control properly.
      if env['REMOTE_ADDR'] != "127.0.0.1" and action != "bucketname"
        returnval = throw500 "Service not available"
        next
      end

      if action == "hosts_add"
        if Process.uid != 0
          returnval = throw500 "Service not available"
        elsif !filter or !path
          returnval = throw404 env['REQUEST_PATH']
        else
          MU::Master.addInstanceToEtcHosts(path, filter)
          returnval = [
            200,
            {
              'Content-Type' => 'text/plain',
              'Content-Length' => 2
            },
            ["ok"]
          ]
        end
      elsif action == "deploy"
        returnval = throw404 env['REQUEST_PATH'] if !filter
        MU.log "Loading deploy data for #{filter} #{path}"
        kittenpile = MU::MommaCat.getLitter(filter)
        returnval = returnRawJSON JSON.generate(kittenpile.deployment)
      elsif action == "config"
        returnval = throw404 env['REQUEST_PATH'] if !filter
        MU.log "Loading config #{filter} #{path}"
        kittenpile = MU::MommaCat.getLitter(filter)
        returnval = returnRawJSON JSON.generate(kittenpile.original_config)
      elsif action == "list"
        MU.log "Listing deployments"
        returnval = returnRawJSON JSON.generate(MU::MommaCat.listDeploys)
      elsif action == "bucketname"
        returnval = [
          200,
          {
            'Content-Type' => 'text/plain',
            'Content-Length' => MU.adminBucketName(filter, credentials: path).length.to_s
          },
          [MU.adminBucketName(filter, credentials: path)]
        ]
      else
        returnval = throw404 env['REQUEST_PATH']
      end

    elsif !env["rack.input"].nil?
      req = Rack::Utils.parse_nested_query(env["rack.input"].read)

      if req["mu_user"].nil?
        req["mu_user"] = "mu"
      end
      requesttype = nil
      ["mu_ssl_sign", "mu_bootstrap", "mu_windows_admin_creds", "add_volume"].each { |rt|
        if req[rt]
          requesttype = rt
          break
        end
      }

      MU.log "Processing #{requesttype} request from #{env["REMOTE_ADDR"]} (MU-ID #{req["mu_id"]}, #{req["mu_resource_type"]}: #{req["mu_resource_name"]}, instance: #{req["mu_instance_id"]}, mu_user #{req['mu_user']}, path #{env['REQUEST_PATH']})"
      kittenpile = getKittenPile(req)
      if kittenpile.nil? or kittenpile.original_config.nil? or kittenpile.original_config[req["mu_resource_type"]+"s"].nil?
        returnval = throw500 "Couldn't find config data for #{req["mu_resource_type"]} in deploy_id #{req["mu_id"]}"
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
        returnval = throw500 "Couldn't find config data for #{req["mu_resource_type"]} name: #{req["mu_resource_name"]} deploy_id: #{req["mu_id"]}"
        next
      end

      MU.log "Dug up server config for #{req["mu_resource_type"]} name: #{req["mu_resource_name"]} deploy_id: #{req["mu_id"]}", MU::DEBUG, details: server_cfg

# XXX We can't assume AWS anymore. What does this look like otherwise?
# If this is an already-groomed instance, try to get a real object for it
      instance = MU::MommaCat.findStray("AWS", "server", cloud_id: req["mu_instance_id"], region: server_cfg["region"], deploy_id: req["mu_id"], name: req["mu_resource_name"], dummy_ok: true, calling_deploy: kittenpile).first
      mu_name = nil
      if instance.nil?
        # Now we're just checking for existence in the cloud provider, really
        MU.log "No existing groomed server found, verifying that a server with this cloud id exists"
        instance = MU::Cloud::Server.find(cloud_id: req["mu_instance_id"], region: server_cfg["region"])
#        instance = MU::MommaCat.findStray("AWS", "server", cloud_id: req["mu_instance_id"], region: server_cfg["region"], deploy_id: req["mu_id"], name: req["mu_resource_name"], dummy_ok: true, calling_deploy: kittenpile).first
        if instance.nil?
          returnval = throw500 "Failed to find an instance with cloud id #{req["mu_instance_id"]}"
        end
      else
        mu_name = instance.mu_name
        MU.log "Found an existing node named #{mu_name}"
      end

      if !req["mu_windows_admin_creds"].nil?
        if !instance.is_a?(MU::Cloud::Server)
          instance = MU::Cloud::Server.new(mommacat: kittenpile, kitten_cfg: server_cfg, cloud_id: req["mu_instance_id"])
        end
        returnval[2] = [kittenpile.retrieveWindowsAdminCreds(instance).join(";")]
        logstr = returnval[2].is_a?(Array) ? returnval[2].first.sub(/;.*/, ";*********") : returnval[2].sub(/;.*/, ";*********")
        MU.log logstr, MU::NOTICE
      elsif !req["mu_ssl_sign"].nil?
        kittenpile.signSSLCert(req["mu_ssl_sign"], req["mu_ssl_sans"].split(/,/))
        kittenpile.signSSLCert(req["mu_ssl_sign"], req["mu_ssl_sans"].split(/,/))
      elsif !req["add_volume"].nil?
        if instance.respond_to?(:addVolume)
# XXX make sure we handle mangled input safely
          params = JSON.parse(Base64.decode64(req["add_volume"]))
          MU.log "add_volume request", MU::NOTICE, details: params
          Thread.current.thread_variable_set("addVolume", req["mu_instance_id"])
          instance.addVolume(dev: params["dev"], size: params["size"], delete_on_termination: params["delete_on_termination"])
        else
          returnval = throw500 "I don't know how to add a volume for #{instance}"
        end
      elsif !instance.nil?
        if !req["mu_bootstrap"].nil?
          Thread.current.thread_variable_set("groomRequest", req["mu_instance_id"])
          kittenpile.groomNode(req["mu_instance_id"], req["mu_resource_name"], req["mu_resource_type"], mu_name: mu_name, sync_wait: true)
          returnval[2] = ["Grooming asynchronously, check Momma Cat logs on the master for details."]
        else
          returnval = throw500 "Didn't get 'mu_bootstrap' parameter from instance id '#{req["mu_instance_id"]}'"
        end
      else
        returnval = throw500 "No such instance id '#{req["mu_instance_id"]}' nor was this an SSL signing request"
      end
    end
  rescue StandardError => e
    returnval = throw500 "Invalid request: #{e.inspect} (#{req})", e.backtrace
  ensure
    if !req.nil?
      releaseKitten(req['mu_id'])
      MU.purgeGlobals
    end
  end
  if returnval[1] and returnval[1].has_key?("Content-Length") and
     returnval[2] and returnval[2].is_a?(Array)
    returnval[1]["Content-Length"] = returnval[2][0].size.to_s
  end
  returnval
end

run app
