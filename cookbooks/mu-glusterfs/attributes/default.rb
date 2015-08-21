default['gluster_node_class'] = "glusterfs"

default['glusterfs']['client']['mount_path'] = '/gluster'

default['glusterfs']['server']['brick_base_mount_path'] = '/gluster'
default['glusterfs']['server']['volume_type'] = "replica"
default['glusterfs']['server']['num_replicas'] = 2
default['glusterfs']['server']['raid'] = true
default['glusterfs']['server']['raid_level'] = 1
default['glusterfs']['server']['raid_dev'] = "/dev/md0"
default['glusterfs']['server']['raid_spare_vol'] = false
default['glusterfs']['server']['volume'] = "gv0"
default['glusterfs']['server']['portmapper'] = 111
default['glusterfs']['server']['devices'] = ["/dev/xvdf", "/dev/xvdg"]

default['glusterfs']['fw'] = [
    {'usage' => 'management', 'port_range' => "24007:24008"},
    {'usage' => 'data', 'port_range' => "49152:49160"},
    {'usage' => 'smb', 'port_range' => "137:139"},
    {'usage' => 'management', 'port_range' => "445:445"},
]

default['glusterfs']['server']['raid_levels_map'] = [
    {'level' => 0, 'spare' => false, 'min_devcies' => 2},
    {'level' => 1, 'spare' => false, 'min_devcies' => 2},
    {'level' => 5, 'spare' => false, 'min_devcies' => 3},
    {'level' => 6, 'spare' => false, 'min_devcies' => 4},
    {'level' => 1, 'spare' => true, 'min_devcies' => 3},
    {'level' => 5, 'spare' => true, 'min_devcies' => 4},
    {'level' => 6, 'spare' => true, 'min_devcies' => 5}
]
