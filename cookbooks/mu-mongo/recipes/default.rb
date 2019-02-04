#
# Cookbook Name:: mu-mongo
# Recipe:: default
#
# Copyright 2015, eGlobalTech
#
# All rights reserved - Do Not Redistribute
#

::Chef::Recipe.send(:include, Chef::Mixin::ShellOut)

include_recipe "mongodb::install"
include_recipe 'chef-vault'
node.normal['mongodb']['config']['replSet'] = "mu"
node.save


node['application_attributes']['mongo_dirs'].each { |path|
  directory path['dir'] do
    owner "mongod"
    group "mongod"
  end
  execute "mkfs -t ext4 #{path['dev']}" do
    not_if "tune2fs -l #{path['dev']}"
  end
  mount path['dir'] do
    device path['dev']
    action [:mount, :enable]
    notifies :restart, "service[#{node['mongodb']['default_init_name']}]", :delayed
  end
}
execute "fix /tmp permissions" do
  command "chmod 1777 /tmp ; /sbin/restorecon -R /tmp"
  notifies :restart, "service[mongod]", :delayed
end

[27017, 27018].each { |port|
  bash "Allow TCP #{port} through iptables" do
    user "root"
    not_if "/sbin/iptables -nL | egrep '^ACCEPT.*dpt:#{port}($| )'"
    code <<-EOH
      iptables -I INPUT -p tcp --dport #{port} -j ACCEPT
      service iptables save
    EOH
  end
}

cookbook_file "/mongo_data/keyfile" do
  source "keyfile"
  mode 0400
  owner "mongod"
  group "mongod"
  notifies :restart, "service[mongod]", :delayed
end

template "/etc/logrotate.d/mongodb" do
  source "mongo_logrotate.erb"
  owner "root"
  group "root"
  mode 0644
  notifies :restart, "service[mongod]", :delayed
end

include_recipe "mongodb::replicaset"

mongo_admin_auth_info = chef_vault_item("mongodb", "admin")
$mongo_admin_usr = mongo_admin_auth_info['username']
$mongo_admin_pwd = mongo_admin_auth_info['password']

mongo_mu_auth_info = chef_vault_item("mongodb", "mu")
$mongo_mu_usr = mongo_mu_auth_info['username']
$mongo_mu_pwd = mongo_mu_auth_info['password']

# Figure out whether we're the first node to the party (CAP will enforce this
# being atomic). If so, we'll be managing the cluster memberships.
found_master = false
i_am_master = false
node['deployment']['servers']['mongo'].each_pair { |name, data|
  if data['mongo_master']
    found_master = true
    if name == Chef::Config[:node_name]
      i_am_master = true
    end
  end
}
if !found_master
  node.normal['deployment']['servers']['mongo'][Chef::Config['node_name']]['mongo_master'] = true
  node.save
  i_am_master = true
end

if i_am_master

  template "/root/replset_init.js" do
    source "replset_init.js.erb"
    mode 0400
    sensitive true
  end

  cmd = shell_out("mongo admin --quiet --eval 'rs.conf()'")
  if cmd.stdout.chop == 'null'
    execute "/usr/bin/mongo admin /root/replset_init.js" do
      notifies :restart, "service[mongod]", :delayed
    end
  end

  template "/root/mongo_init.js" do
    source "mongo_init.js.erb"
    mode 0400
    sensitive true
  end
  execute "/usr/bin/mongo admin /root/mongo_init.js" do
    not_if "mongo admin --quiet -u #{$mongo_admin_usr} -p #{$mongo_admin_pwd} --eval \"db.system.users.find({user: '#{$mongo_admin_usr}'}).count()\""
    retries 4
    retry_delay 15
    sensitive true
  end

  bash "mongo Create DB #{node['mongodb']['mu_db_name']}" do
    code <<-EOH
			mongo admin -u #{$mongo_admin_usr} -p #{$mongo_admin_pwd} <<-EOF
			use #{node['mongodb']['mu_db_name']}
			db.createUser({user: "#{$mongo_mu_usr}", pwd: "#{$mongo_mu_pwd}", roles: ['readWrite']})
			exit
			EOF
    EOH
    sensitive true
  end

  template "/root/mongo_replset_addnodes.js" do
    source "mongo_replset_addnodes.js.erb"
    mode 0400
    #notifies :restart, "service[mongod]", :immediately
  end
  bash "Adding nodes to ReplicaSet" do
    code "/usr/bin/mongo admin -u #{$mongo_admin_usr} -p #{$mongo_admin_pwd} /root/mongo_replset_addnodes.js"
    sensitive true
  end

  cookbook_file "/root/remove_nodes.js" do
    source "remove_nodes.js"
    mode 0400
  end
  bash "Removing nodes from ReplicatSet" do
    code "/usr/bin/mongo admin -u #{$mongo_admin_usr} -p #{$mongo_admin_pwd} /root/remove_nodes.js"
    sensitive true
  end

end
