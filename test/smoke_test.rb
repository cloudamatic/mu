#!/usr/local/ruby-current/bin/ruby

require 'thread'
require 'trollop'

$opts = Trollop::options do
  banner <<-EOS
Usage:
#{$0} [-s <skipaz>] [-n <nocleanup>]
  EOS
  opt :skipaz, "skip an availability zone", :require => false, :type => :string
  opt :nocleanup, "no cleanup on successful run"
end

def test(file, flags = "")
  bok = "/opt/mu/lib/demo/#{file}"
  filename = file.split('.').first+flags.gsub(/ /, "")
  output = "#{Dir.home}/#{filename}.out"

  puts "deploying #{bok} #{flags}; sending output to #{output}"

  cmd="/opt/mu/bin/mu-deploy #{bok} #{flags}"
  if $opts[:skipaz]
    cmd += " -p azskip=#{$opts[:skipaz]}"
  end
  
  `#{cmd} >& #{output}`
  status = $?.to_i

  deploy_id = File.foreach(output).grep(/Deployment id:/)[0].scan(/\(([^\)]+)\)/).last.first
  if status == 0
    message = "Deployment of #{bok} as #{deploy_id} was successful"
    if !$opts[:nocleanup] 
      message += ", tore down #{deploy_id}" 
      `/opt/mu/bin/mu-cleanup -s #{deploy_id} >> #{output}`
    end
  else
    message = "error deploying #{bok}. See #{output} for details" 
  end
  puts message

  status
end

def main
  boks = %w(simple-server-rails.yaml simple-windows.yaml simple-server.yaml dnszone.yaml cache_cluster.yaml aurora_cluster.yaml simple-server-wordpress.yaml)
  successes = 0
  failures = 0

  work_q = Queue.new
  boks.each{ |x|
    work_q.push({ "bok" => x, "arg" => "-c" })
    work_q.push({ "bok" => x, "arg" => "" })
  }
  workers = (0...4).map do
    Thread.new do
      begin
        while job = work_q.pop(true)
          status = test job["bok"], job["arg"]
          if status == 0
            successes += 1
          else
            failures += 1
          end
        end
      rescue ThreadError
      end
    end
  end; "ok"
  workers.map(&:join); "ok"

  puts "#{successes} successes, #{failures} failures"
end

main
