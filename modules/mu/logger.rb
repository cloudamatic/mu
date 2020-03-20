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

require 'syslog'
require 'pp'
# ANSI colors
require 'colorize'
# HTML colors
require 'color'

module MU

  # This class should be used for all output from MU. By default it logs to
  # stdout with human-friendly ANSI coloring, and to syslog.
  class Logger
    # Show nothing at all
    SILENT = -1.freeze
    # Only show NOTICE, WARN, and ERROR log entries
    QUIET = 0.freeze
    # Show INFO log entries
    NORMAL = 1.freeze
    # Show DEBUG log entries and extra call stack and threading info
    LOUD = 2.freeze

    # stash a hash map for color outputs
    COLORMAP = {
      MU::DEBUG => { :html => "orange", :ansi => :yellow },
      MU::INFO => { :html => "green", :ansi => :green },
      MU::NOTICE => { :html => "yellow", :ansi => :yellow },
      MU::WARN => { :html => "orange", :ansi => :light_red },
      MU::ERR => { :html => "red", :ansi => :red }
    }.freeze

    # minimum log verbosity at which we'll print various types of messages
    PRINT_MSG_IF = {
      MU::DEBUG => { :msg => LOUD, :details => LOUD },
      MU::INFO => { :msg => NORMAL, :details => LOUD },
      MU::NOTICE => { :msg => nil, :details => QUIET },
      MU::WARN => { :msg => nil, :details => SILENT },
      MU::ERR => { :msg => nil, :details => nil }
    }.freeze

    # Syslog equivalents of our log levels
    SYSLOG_MAP = {
      MU::DEBUG => Syslog::LOG_DEBUG,
      MU::INFO => Syslog::LOG_NOTICE,
      MU::NOTICE => Syslog::LOG_NOTICE,
      MU::WARN => Syslog::LOG_WARNING,
      MU::ERR => Syslog::LOG_ERR
    }.freeze

    attr_accessor :verbosity
    @verbosity = MU::Logger::NORMAL
    @quiet = false
    @html = false
    @color = true
    @handle = STDOUT

    @@log_semaphere = Mutex.new

    # @param verbosity [Integer]: See {MU::Logger.QUIET}, {MU::Logger.NORMAL}, {MU::Logger.LOUD}
    # @param html [Boolean]: Enable web-friendly log output.
    def initialize(verbosity=MU::Logger::NORMAL, html=false, handle=STDOUT, color=true)
      @verbosity = verbosity
      @html = html
      @handle = handle
      @color = color
      @summary = []
    end

    attr_reader :summary
    attr_accessor :color
    attr_accessor :quiet
    attr_accessor :html
    attr_accessor :handle

    # @param msg [String]: A short message to log
    # @param level [Integer]: The level at which to log (DEBUG, INFO, NOTICE, WARN, ERR)
    # @param details [String,Hash,Array]: Extra information for verbose logging modes.
    # @param html [Boolean]: Toggle web-friendly output.
    # @param verbosity [Integer]: Explicit verbosity settings for this message
    def log(msg,
            level=INFO,
            details: nil,
            html: nil,
            verbosity: nil,
            handle: nil,
            color: nil,
            deploy: MU.mommacat
    )
      verbosity ||= @verbosity
      html ||= @html
      handle ||= @handle
      color ||= @color

      if verbosity == MU::Logger::SILENT or (verbosity < MU::Logger::LOUD and level == DEBUG) or (verbosity < MU::Logger::NORMAL and level == INFO)
        return
      end

      caller_name = extract_caller_name(caller[1])

      time = Time.now.strftime("%b %d %H:%M:%S").to_s

      Syslog.open("Mu/"+caller_name, Syslog::LOG_PID, Syslog::LOG_DAEMON | Syslog::LOG_LOCAL3) if !Syslog.opened?

      details = format_details(details, html)

      msg = msg.first if msg.is_a?(Array)
      msg = "" if msg == nil
      msg = msg.to_s if !msg.is_a?(String) and msg.respond_to?(:to_s)

      @@log_semaphere.synchronize {
        handles = [handle]
        extra_logfile = if deploy and deploy.deploy_dir and Dir.exist?(deploy.deploy_dir)
          File.open(deploy.deploy_dir+"/log", "a")
        end
        handles << extra_logfile if extra_logfile
        msgs = []

        if !PRINT_MSG_IF[level][:msg] or level >= PRINT_MSG_IF[level][:msg]
          if html
            html_out "#{time} - #{caller_name} - #{msg}", COLORMAP[level][:html]
          else
            str = "#{time} - #{caller_name} - #{msg}"
            str = str.send(COLORMAP[level][:ansi]).on_black if color
            msgs << str
          end
          Syslog.log(SYSLOG_MAP[level], msg.gsub(/%/, ''))
        end

        if details and (!PRINT_MSG_IF[level][:details] or level >= PRINT_MSG_IF[level][:details])
          if html
            html_out "&nbsp;#{details}"
          else
            details = details.white.on_black if color
            msgs << details
          end
          Syslog.log(SYSLOG_MAP[level], details.gsub(/%/, ''))
        end

#          else
#            if html
#              html_out "#{time} - #{caller_name} - #{msg}"
#              html_out "&nbsp;#{details}" if details
#            elsif color
#              msgs << "#{time} - #{caller_name} - #{msg}".white.on_black
#              msgs << "#{details}".white.on_black if details
#            else
#              msgs << "#{time} - #{caller_name} - #{msg}"
#              msgs << "#{details}" if details
#            end
#            Syslog.log(Syslog::LOG_NOTICE, msg.gsub(/%/, ''))
#            Syslog.log(Syslog::LOG_NOTICE, details.gsub(/%/, '')) if details

        write(handles, msgs)

        extra_logfile.close if extra_logfile
      }

    end

    private

    def format_details(details, html = false)
      return if details.nil?

      if details.is_a?(Hash) and details.has_key?(:details)
        details = details[:details]
      end
      details = PP.pp(details, '') if !details.is_a?(String)

      details = "<pre>"+details+"</pre>" if html
      # We get passed literal quoted newlines sometimes, fix 'em. Get Windows'
      # ugly line feeds too.

      details = details.dup # in case it's frozen or something
      details.gsub!(/\\n/, "\n")
      details.gsub!(/(\\r|\r)/, "")

      details
    end

    # By which we mean, "get the filename (with the .rb stripped off) which
    # originated the call to this method. Which, for our purposes, is the
    # MU subclass that called us. Useful information. And it looks like Perl.
    def extract_caller_name(caller_name)
      return nil if !caller_name or !caller_name.is_a?(String)
      mod_root = Regexp.quote("#{ENV['MU_LIBDIR']}/modules/mu/")
      bin_root = Regexp.quote("#{ENV['MU_INSTALLDIR']}/bin/")

      caller_name.sub!(/:.*/, "")
      caller_name.sub!(/^\.\//, "")
      caller_name.sub!(/^#{mod_root}/, "")
      caller_name.sub!(/^#{bin_root}/, "")
      caller_name.sub!(/\.r[ub]$/, "")
      caller_name.sub!(/#{Regexp.quote(MU.myRoot)}\//, "")
      caller_name.sub!(/^modules\//, "")
      caller_name
    end

    # Output a log message as HTML.
    #
    # @param msg [String]: The log message to print
    # @param color_name [String]: A color name. Must be a valid CSS color.
    def html_out(msg, color_name="black")
      rgb = Color::RGB::by_name color_name
      @handle.puts "<span style='color:#{rgb.css_rgb};'>#{msg}</span>"
    end

    # wrapper for writing a log entry to multiple filehandles
    # @param handles [Array<IO>]
    # @param msgs [Array<String>]
    def write(handles = [], msgs = [])
      return if handles.nil? or msgs.nil?
      handles.each { |h|
        msgs.each { |m|
          h.puts m
        }
      }
    end

  end #class
end #module
