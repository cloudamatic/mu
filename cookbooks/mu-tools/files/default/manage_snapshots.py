import argparse
import datetime
import logging
import sys
import boto
import boto.ec2
import boto.utils
import requests
import platform

parser = argparse.ArgumentParser(description='Script to automaticly snapshot EBS volumes',
                                 prog='snpashot_volumes.py', formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=40))
parser.add_argument('-n', '--num_snaps_keep', metavar='', help='Number of Snapshots to Keep. Default is 30', default=30, type=int)
parser.add_argument('-l', '--logdir', metavar='', help='Location of logfile. Default is c:/chef/cache', default='c:/chef/cache')
parser.add_argument('-d', '--device_name', metavar='', help='Device name of EBS volume. If not specified the script will guess which volumes to snapshot based on OS type', default=None)
parser.add_argument('-dt', '--desc_tag', metavar='', help='Description tag for new snapshot', default='Created by Automated Snapshot Script')
parser.add_argument('-nt', '--name_tag', metavar='', help='Name tag for the new snapshots', default=None)
parsed_args = parser.parse_args()

snaps_keep = parsed_args.num_snaps_keep
dev_name = parsed_args.device_name
name_tag = parsed_args.name_tag
logdir = parsed_args.logdir

if logdir:
    log_name = '{logdir}/ebs_snapshots.log'.format(logdir=logdir)
else:
    log_name = 'ebs_snapshots.log'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)-15s %(levelname)-8s %(lineno)d %(message)s',
                    datefmt='%m-%d-%Y %H:%M:%S',
                    filename=log_name,
                    filemode='a')

console_log = logging.StreamHandler()
console_log.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-10s: %(levelname)-8s %(message)s')
console_log.setFormatter(formatter)
logging.getLogger('').addHandler(console_log)
logger = logging.getLogger('logger')

class EBSSnapshots():
    def ec2Conn(self):
        region = boto.utils.get_instance_identity()['document']['region']
        self.ec2_conn = boto.ec2.connect_to_region(region)
        self.instance_id = boto.utils.get_instance_metadata()['instance-id']

    def getVolumes(self):
        volume_filters = {'attachment.instance-id':self.instance_id}
        try:
            self.volumes = self.ec2_conn.get_all_volumes(filters=volume_filters)
        except:
            logger.critical('Failed to authenticate to AWS')

    def createSnapshot(self, volume):
        date = datetime.datetime.utcnow().strftime('%m%d%Y-%H:%M')
        try:
            new_snapshot = volume.create_snapshot('{snapshot_description} on {date}'.format(snapshot_description=parsed_args.desc_tag, date=date))
        except:
            logger.error('Failed to create snapshot')
        if name_tag:
            volume_name_tag = name_tag
        elif 'Name' in volume.tags.keys():
            volume_name_tag = volume.tags['Name']
        else:
            volume_name_tag = volume.tags['MU-ID']
        new_snapshot.add_tag('Name', '{name_tag}-{device_id}'.format(name_tag=volume_name_tag, device_id=volume.attach_data.device.upper()))
        new_snapshot.add_tag('SnapshotType', 'Automated-Snapshots')
        new_snapshot.add_tag('Attachment-Device', volume.attach_data.device.upper())
        for tag_key in volume.tags.iterkeys():
            if tag_key =! "Name"
                new_snapshot.add_tag(tag_key, volume.tags[tag_key])
        new_snapshot.add_tag('MU-ID', volume.tags['MU-ID'])
        logger.info('Created snapshot {snap_id} {snap_name}'.format(snap_id=new_snapshot.id, snap_name=new_snapshot.tags['Name']))

    def deleteSnapshots(self, volume):
        snapshots_filters = {'volume-id':volume.id, 'tag-key':'SnapshotType', 'tag-value':'Automated-Snapshots', 'tag-key':'MU-ID', 'tag-value':volume.tags['MU-ID']}
        all_snapshots = self.ec2_conn.get_all_snapshots(filters=snapshots_filters)
        sorted_snapshots = sorted(all_snapshots, key=lambda snapshot: snapshot.start_time)
        snpashots_to_delete = len(sorted_snapshots) - snaps_keep
        for i in range(snpashots_to_delete):
            try:
                sorted_snapshots[i].delete()
            except:
                logger.error('Failed to delete snapshot {snap_id} {snap_name}'.format(snap_id=sorted_snapshots[i].id, snap_name=sorted_snapshots[i].tags['Name']))
                continue
            logger.info('Deleted snapshot {snap_id} {snap_name}'.format(snap_id=sorted_snapshots[i].id, snap_name=sorted_snapshots[i].tags['Name']))
    def run(self):
        ebs_snapshots.ec2Conn()
        ebs_snapshots.getVolumes()
        os_type = platform.system()
        for volume in self.volumes:
            if dev_name is None:
                if os_type == 'Windows':
                    if volume.attach_data.device != '/dev/sda1':
                        if snaps_keep > 0:
                            ebs_snapshots.createSnapshot(volume)
                        ebs_snapshots.deleteSnapshots(volume)
                else:
                    if volume.attach_data.device not in ['/dev/sda1', '/dev/sda', '/dev/xvdn', '/dev/xvdo', '/dev/xvdp', '/dev/xvdq', 'xvdn', 'xvdo', 'xvdp', 'xvdq']: 
                        if snaps_keep > 0:
                            ebs_snapshots.createSnapshot(volume)
                        ebs_snapshots.deleteSnapshots(volume)
            else:
                if volume.attach_data.device == dev_name:
                    if snaps_keep > 0:
                        ebs_snapshots.createSnapshot(volume)
                    ebs_snapshots.deleteSnapshots(volume)
                        
ebs_snapshots = EBSSnapshots()
ebs_snapshots.run()
