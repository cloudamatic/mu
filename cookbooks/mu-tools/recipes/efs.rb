case node.platform
when 'ubuntu'
  package "nfs-common"
when 'redhat', 'centos', 'amazon'
  package %w{nfs-utils nfs4-acl-tools}
end

directory node.efs.target.directory do
  recursive true
end

mount node.efs.target.directory do
  device "#{node.efs.target.dns}:/"
  fstype "nfs4"
  action [:mount, :enable]
  only_if { node.efs.target.filesystem_id }
end
