mongo_data = {"dev" => "/dev/xvdg", "dir" => "/mongo_data"}
mongo_logs = {"dev" => "/dev/xvdh", "dir" => "/mongo_logs"}
mongo_journal = {"dev" => "/dev/xvdf", "dir" => "/mongo_data/journal"}

default['application_attributes']['mongo_dirs'] = [mongo_data, mongo_logs, mongo_journal]

default['mongodb']['config']['dbpath'] = "/mongo_data"
default['mongodb']['log_dir'] = mongo_logs['dir']
default['mongodb']['config']['logpath'] = "#{node['mongodb']['log_dir']}/mongo.log"
default['mongodb']['cluster_name'] = "fema"
default['mongodb']['config']['keyFile'] = "/mongo_data/keyfile"
default['mongodb']['config']['auth'] = true
default['mongodb']['config']['setParameter'] = "enableLocalhostAuthBypass=1"
default['mongodb']['admin'] = "admin"
default['mongodb']['auto_configure']['replicaset'] = false
default['mongodb']['mu_db_name'] = "Mu"
default['mongodb']['package_version'] = "2.6.6-1"

default['mongodb']['auth'] = {
    'data_bag' => 'mongodb',
    'data_bag_item' => "admin_user"
}
