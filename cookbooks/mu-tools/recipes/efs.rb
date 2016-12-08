if node['deployment'].has_key?('storage_pools')
  require 'net/http'
  require 'json'

  case node['platform']
  when 'ubuntu'
    package "nfs-common"
  when 'redhat', 'centos', 'amazon'
    package %w{nfs-utils nfs4-acl-tools}
  end

  instance_identity = JSON.parse(Net::HTTP.get(URI("http://169.254.169.254/latest/dynamic/instance-identity/document")))

  node['deployment']['storage_pools'].each { |name, pool|
    pool['mount_targets'].each { |name, target|
      if target['availability_zone'] == instance_identity["availabilityZone"]
      # Should also make it possible to choose a random endpoint if there isn't one for a specific AZ

        directory target['mount_directory'] do
          recursive true
          mode 0755
        end

        endpoint = target['endpoint']
        resolver = Resolv::DNS.new
        begin
          resolver.getaddress(endpoint)
        rescue  Resolv::ResolvError
          endpoint = target['ip_address']
        end

        if node[:platform_family] == "rhel" and node[:platform_version].to_i < 6
          service "portmap" do
            action [:enable, :start]
          end
        end

        mount target['mount_directory'] do
          device "#{endpoint}:/"
          fstype "nfs4"
          action [:mount, :enable]
          options "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2"
          #not_if "grep ' #{target['mount_directory']} ' /etc/mtab | egrep '^(#{target['endpoint']}|#{target['ip_address']}):'"
        end

        break
      end
    }
  }
end
