
# monkey patch knife ssh so we can capture logs from knife bootstrap
class Chef
  # monkey patch knife ssh so we can capture logs from knife bootstrap
  class Knife
    # monkey patch knife ssh so we can capture logs from knife bootstrap
    class Ssh < Knife

      # monkey patch knife ssh so we can capture logs from knife bootstrap
      def print_line(host, data)
        padding = @longest - host.length
        str = ui.color(host, :cyan) + (" " * (padding + 1)) + data
        ui.msg(str)
        if MU.mommacat and Dir.exist?(MU.mommacat.deploy_dir)
          File.open(MU.mommacat.deploy_dir+"/log", "a") { |f|
            f.puts str
          }
        end
      end

    end
  end
end
