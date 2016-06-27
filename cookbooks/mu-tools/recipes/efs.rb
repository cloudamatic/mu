require 'net/http'
require 'json'

case node.platform
when 'ubuntu'
  package "nfs-common"
when 'redhat', 'centos', 'amazon'
  package %w{nfs-utils nfs4-acl-tools}
end

instance_identity = JSON.parse(Net::HTTP.get(URI("http://169.254.169.254/latest/dynamic/instance-identity/document")))

node.deployment.storage_pools.each { |name, pool|
  pool.mount_targets.each { |name, target|
    if target.availability_zone == instance_identity["availabilityZone"]
    # Should also make it possible to choose a random endpoint if there isn't one for a specific AZ

      directory target.mount_directory do
        recursive true
      end

      mount target.mount_directory do
        device "#{target.endpoint}:/"
        fstype "nfs4"
        action [:mount, :enable]
      end

      break
    end
  }
}
