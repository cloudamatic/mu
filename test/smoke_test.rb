#!/usr/local/ruby-current/bin/ruby

require 'thread'
require 'trollop'

$opts = Trollop::options do
  banner <<-EOS
Usage:
#{$0} [-s <skip_az>]  
  EOS
  opt :skip_az, "skip an availability zone", :require => false, :type => :string
end

def test(file)
  bok = "/opt/mu/lib/demo/#{file}"
  filename = file.split('.').first
  output = "~/#{filename}.out"

  puts "deploying #{bok} and outputing to #{output}"
  cmd="/opt/mu/bin/mu-deploy #{bok}"
  if $opts[:skip_az]
    cmd+= " -p azskip=#{$opts[:skip_az]}"
  end
  
  `#{cmd} > #{output}`
  status = $?.to_i

  message = "error deploying #{bok}. See #{output} for details" unless status == 0
  message ||= "Deployment of #{bok} was sucessful"
  puts message

  status
end

def main
  boks = %w(simple-server-php.yaml simple-server-rails.yaml simple-server.yaml not_a_deploy.yaml)
  successes = 0
  failures = 0

  work_q = Queue.new
  boks.each{|x| work_q.push x }
  workers = (0...4).map do
    Thread.new do
      begin
        while bok = work_q.pop(true)
          status = test bok
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
