#!/usr/local/ruby-current/bin/ruby

require 'optimist'
require 'json'
require 'net/http'

OPTS = Optimist::options do
  opt :host, "Kibana host to check", :required => true, :type => :string
  opt :username, "Kibana username", :required => false, :type => :string
  opt :password, "Kibana password", :required => false, :type => :string
  opt :port, "Port to check for Kibana", :required => false, :default => 5601, :type => :integer
  opt :basepath, "Path prefix for API requests", :required => false, :default => "", :type => :string
end

uri = "https://"+OPTS[:host]+":"+OPTS[:port].to_s+OPTS[:basepath]+"/api/status"
req = Net::HTTP::Get.new(uri)
if OPTS[:username] and OPTS[:password]
  req.basic_auth OPTS[:username], OPTS[:password]
end
begin
  Net::HTTP.start(OPTS[:host], OPTS[:port], :use_ssl => true) do |http|
    resp = JSON.parse(http.request(req).body)
    status = resp["status"]["overall"]
    output = status["nickname"]+" since "+status["since"]
    if resp["metrics"] and resp["metrics"] and resp["metrics"]["requests"]
      output += "\n"+resp["metrics"]["requests"]["total"].to_s+" requests since "+resp["metrics"]["last_updated"]
    end

    puts output
    if status["state"] == "green"
      exit 0
    elsif status["state"] == "yellow"
      exit 1
    else
      exit 2
    end
  end
rescue Net::HTTPServerException, SocketError, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNREFUSED => e
  puts e.inspect
  exit 2
rescue StandardError => e
  puts e.inspect
  exit 3
end

