class Chef
  class Provider
    class Package
      class Rubygems < Chef::Provider::Package

        def install_via_gem_command(name, version)
#puts "\n\nCALLING MONKEYPATCHED GEM COMMAND THING #{opts.to_s}\n\n"
          src = []
          if new_resource.source.is_a?(String) && new_resource.source =~ /\.gem$/i
            name = new_resource.source
          else
            src << "--clear-sources" if new_resource.clear_sources
            src += gem_sources.map { |s| "--source=#{s}" }
          end
          src_str = src.empty? ? "" : " #{src.join(" ")}"
          if !version.nil? && !version.empty?
            shell_out_with_timeout!("#{gem_binary_path} install #{name} -q --no-rdoc --no-ri -v \"#{version}\"#{src_str}#{opts}", env: nil)
          else
            shell_out_with_timeout!("#{gem_binary_path} install \"#{name}\" -q --no-rdoc --no-ri #{src_str}#{opts}", env: nil)
          end
        end

      end
    end
  end
end
