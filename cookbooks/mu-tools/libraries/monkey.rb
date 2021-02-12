class Chef
  class Provider
    class Package
      class Rubygems < Chef::Provider::Package

        def install_via_gem_command(name, version)
          src = []
          if new_resource.source.is_a?(String) && new_resource.source =~ /\.gem$/i
            name = new_resource.source
          else
            src << "--clear-sources" if new_resource.clear_sources
            src += gem_sources.map { |s| "--source=#{s}" }
          end
          src_str = src.empty? ? "" : " #{src.join(" ")}"
          cmd = if !version.nil? && !version.empty?
            "#{gem_binary_path} install #{name} -q --no-rdoc --no-ri -v \"#{version}\"#{src_str}#{opts}"
          else
            "#{gem_binary_path} install \"#{name}\" -q --no-rdoc --no-ri #{src_str}#{opts}"
          end

          begin
            shell_out(cmd, env: nil)
          rescue StandardError => e
            if cmd.match(/--no-rdoc|--no-ri/)
              cmd.gsub!(/--no-rdoc --no-ri/, "--no-document")
              retry
            end
            raise e
          end
        end

      end
    end
  end
end
