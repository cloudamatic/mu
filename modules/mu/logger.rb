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

    @verbosity = MU::Logger::NORMAL
    @quiet = false
    @html = false
    @handle = STDOUT

    @@log_semaphere = Mutex.new

    # @param verbosity [Integer]: See {MU::Logger.QUIET}, {MU::Logger.NORMAL}, {MU::Logger.LOUD}
    # @param html [Boolean]: Enable web-friendly log output.
    def initialize(verbosity=MU::Logger::NORMAL, html=false, handle=STDOUT)
      @verbosity = verbosity
      @html = html
      @handle = handle
    end

    # @param msg [String]: A short message to log
    # @param level [Integer]: The level at which to log (DEBUG, INFO, NOTICE, WARN, ERR)
    # @param details [String,Hash,Array]: Extra information for verbose logging modes.
    # @param html [Boolean]: Toggle web-friendly output.
    # @param verbosity [Integer]: Explicit verbosity settings for this message
    def log(msg,
            level=INFO,
            details: nil,
            html: @html,
            verbosity: @verbosity,
            handle: @handle
    )
      verbosity = MU::Logger::NORMAL if verbosity.nil?
      return if verbosity == MU::Logger::SILENT

      # By which we mean, "get the filename (with the .rb stripped off) which
      # originated the call to this method. Which, for our purposes, is the
      # MU subclass that called us. Useful information. And it looks like Perl.
      mod_root = Regexp.quote("#{ENV['MU_LIBDIR']}/modules/mu/")
      bin_root = Regexp.quote("#{ENV['MU_INSTALLDIR']}/bin/")
      caller_name = caller[1]

      caller_name.sub!(/:.*/, "")
      caller_name.sub!(/^\.\//, "")
      caller_name.sub!(/^#{mod_root}/, "")
      caller_name.sub!(/^#{bin_root}/, "")
      caller_name.sub!(/\.r[ub]$/, "")

      time = Time.now.strftime("%b %d %H:%M:%S").to_s

      Syslog.open("Mu/"+caller_name, Syslog::LOG_PID, Syslog::LOG_DAEMON | Syslog::LOG_LOCAL3) if !Syslog.opened?

      details = PP.pp(details, '') if !details.nil?
      details = "<pre>"+details+"</pre>" if @html
      # We get passed literal quoted newlines sometimes, fix 'em
      details.gsub!(/\\n/, "\n") if !details.nil?

      msg = msg.first if msg.is_a?(Array)
      msg = "" if msg == nil

      @@log_semaphere.synchronize {
        case level
          when DEBUG
            if verbosity >= MU::Logger::LOUD
              if @html
                html_out "#{time} - #{caller_name} - #{msg}", "orange"
                html_out "&nbsp;#{details}" if details
              else
                handle.puts "#{time} - #{caller_name} - #{msg}".yellow.on_black
                handle.puts "\t#{details}".white.on_black if details
              end
              Syslog.log(Syslog::LOG_DEBUG, msg.gsub(/%/, ''))
              Syslog.log(Syslog::LOG_DEBUG, details.gsub(/%/, '')) if details
            end
          when INFO
            if verbosity >= MU::Logger::NORMAL
              if @html
                html_out "#{time} - #{caller_name} - #{msg}", "green"
              else
                handle.puts "#{time} - #{caller_name} - #{msg}".green.on_black
              end
              if verbosity >= MU::Logger::LOUD
                if @html
                  html_out "&nbsp;#{details}"
                else
                  handle.puts "\t#{details}".white.on_black if details
                end
              end
              Syslog.log(Syslog::LOG_NOTICE, msg.gsub(/%/, ''))
              Syslog.log(Syslog::LOG_NOTICE, details.gsub(/%/, '')) if details
            end
          when NOTICE
            if @html
              html_out "#{time} - #{caller_name} - #{msg}", "yellow"
            else
              handle.puts "#{time} - #{caller_name} - #{msg}".yellow.on_black
            end
            if verbosity >= MU::Logger::LOUD
              if @html
                html_out "#{caller_name} - #{msg}"
              else
                handle.puts "\t#{details}".white.on_black if details
              end
            end
            Syslog.log(Syslog::LOG_NOTICE, msg.gsub(/%/, ''))
            Syslog.log(Syslog::LOG_NOTICE, details.gsub(/%/, '')) if details
          when WARN
            if @html
              html_out "#{time} - #{caller_name} - #{msg}", "orange"
            else
              handle.puts "#{time} - #{caller_name} - #{msg}".light_red.on_black
            end
            if verbosity >= MU::Logger::LOUD
              if @html
                html_out "#{caller_name} - #{msg}"
              else
                handle.puts "\t#{details}".white.on_black if details
              end
            end
            Syslog.log(Syslog::LOG_WARNING, msg.gsub(/%/, ''))
            Syslog.log(Syslog::LOG_WARNING, details.gsub(/%/, '')) if details
          when ERR
            if @html
              html_out "#{time} - #{caller_name} - #{msg}", "red"
              html_out "&nbsp;#{details}" if details
            else
              handle.puts "#{time} - #{caller_name} - #{msg}".red.on_black
              handle.puts "\t#{details}".white.on_black if details
            end
            Syslog.log(Syslog::LOG_ERR, msg.gsub(/%/, ''))
            Syslog.log(Syslog::LOG_ERR, details.gsub(/%/, '')) if details
          else
            if @html
              html_out "#{time} - #{caller_name} - #{msg}"
              html_out "&nbsp;#{details}" if details
            else
              handle.puts "#{time} - #{caller_name} - #{msg}".white.on_black
              handle.puts "\t#{details}".white.on_black if details
            end
            Syslog.log(Syslog::LOG_NOTICE, msg.gsub(/%/, ''))
            Syslog.log(Syslog::LOG_NOTICE, details.gsub(/%/, '')) if details
        end
      }

    end

    private

    # Output a log message as HTML.
    #
    # @param msg [String]: The log message to print
    # @param color_name [String]: A color name. Must be a valid CSS color.
    def html_out(msg, color_name="black")
      rgb = Color::RGB::by_name color_name
      @handle.puts "<span style='color:#{rgb.css_rgb};'>#{msg}</span>"
    end

  end #class
end #module
