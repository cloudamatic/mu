import argparse
import datetime
import logging
import sys
import boto
import boto.ec2
import boto.utils
import requests

parser = argparse.ArgumentParser(
    description='Script to automaticly snapshot EBS volumes',
    prog='ebs_snpashots.py', 
    formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=40)
)

parser.add_argument('-n', '--num_snaps_keep', metavar='', help='Number of Snapshots to Keep', type=int, default=15)
parser.add_argument('-l', '--logfile', metavar='', help='Location of logfile', type=str, default='ebs_snapshots.log')
parser.add_argument('-d', '--device_name', metavar='', help='Device name of EBS volume. If not specified, a snapshot will be created to all attached volumes', type=str, default=None)
parser.add_argument('-x', '--exclude_devices', metavar='', help='Mounted volumes endpoints to exclude from automated snapshtos', type=str, default='/dev/sda1, /dev/sda, /dev/xvdn, /dev/xvdo, /dev/xvdp, /dev/xvdq, xvdn, xvdo, xvdp, xvdq')
parser.add_argument('-dt', '--desc_tag', metavar='', help='Description tag for new snapshot', type=str, default='Created by Automated Snapshot Script')
parser.add_argument('-nt', '--name_tag', metavar='', help='Name tag for the new snapshots', type=str, default=None)
parsed_args = parser.parse_args()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-15s %(levelname)-8s %(lineno)d %(message)s',
    datefmt='%m-%d-%Y %H:%M:%S',
    filename=parsed_args.logfile,
    filemode='a'
)

console_log = logging.StreamHandler()
console_log.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-10s: %(levelname)-8s %(message)s')
console_log.setFormatter(formatter)
logging.getLogger('').addHandler(console_log)
logger = logging.getLogger('logger')

class ebs_snapshot:
    def __init__(self, args=parsed_args):
        self.region = boto.utils.get_instance_identity()['document']['region']
        self.ec2 = boto.ec2.connect_to_region(self.region)
        self.instance_id = boto.utils.get_instance_metadata()['instance-id']
        self.name_tag = args.name_tag
        self.description_tag = args.desc_tag
        self.device_name = args.device_name
        self.num_snapshots_keep = args.num_snaps_keep
        self.exclude_devices = map(str.strip, args.exclude_devices.split(','))

    def get_volumes(self):
        volumes = []
        volume_filters = {'attachment.instance-id': self.instance_id}
        try:
            volumes = self.ec2.get_all_volumes(filters=volume_filters)
        except boto.exception.EC2ResponseError as err:
            logger.exception('Failed to authenticate to AWS {err}'.format(err=err.message))
            raise err

        return volumes

    def create_snapshot(self, volume):
        date = datetime.datetime.utcnow().strftime('%m%d%Y-%H%M')
        try:
            new_snapshot = volume.create_snapshot('{snapshot_description} on {date}'.format(snapshot_description=self.description_tag, date=date))
        except boto.exception.EC2ResponseError as err:
            logger.exception('Failed to create snapshot {err}'.format(err=err.message))
            raise err

        if self.name_tag:
            snap_tag = self.name_tag
        elif 'Name' in volume.tags:
            snap_tag = volume.tags['Name']
        else:
            snap_tag = "{volume_id}-{device_name}-{instance_id}".format(volume_id=volume.id, instance_id=self.instance_id, device_name=volume.attach_data.device.upper())

        new_snapshot.add_tag('Name', snap_tag)
        new_snapshot.add_tag('SnapshotType', 'Automated-Snapshots')
        new_snapshot.add_tag('Attachment-Device', volume.attach_data.device.upper())

        for tag_key in volume.tags:
            if tag_key != "Name":
                new_snapshot.add_tag(tag_key, volume.tags[tag_key])

        logger.info('Snapshot {snap_id}/{snap_name} Created'.format(snap_id=new_snapshot.id, snap_name=new_snapshot.tags['Name']))

    def delete_snapshots(self, volume):
        snapshots_filters = {
            'volume-id': volume.id,
            'tag-key': 'SnapshotType',
            'tag-value':'Automated-Snapshots'
        }

        all_snapshots = self.ec2.get_all_snapshots(filters=snapshots_filters)
        sorted_snapshots = sorted(all_snapshots, key=lambda snapshot: snapshot.start_time)
        snpashots_to_delete = len(sorted_snapshots) - self.num_snapshots_keep

        for i in range(snpashots_to_delete):
            try:
                sorted_snapshots[i].delete()
            except boto.exception.EC2ResponseError as err:
                logger.exception('Failed to delete snapshot {snap_id}/{snap_name}: {err}'.format(snap_id=sorted_snapshots[i].id, snap_name=sorted_snapshots[i].tags['Name'], err=err.message))
                continue

            logger.info('Deleted snapshot {snap_id}/{snap_name}'.format(snap_id=sorted_snapshots[i].id, snap_name=sorted_snapshots[i].tags['Name']))

    def process_volume(self, volume):
        if self.num_snapshots_keep > 0:
            self.create_snapshot(volume)
        self.delete_snapshots(volume)

    def run(self):
        volumes = self.get_volumes()

        if volumes:
            for volume in volumes:
                if self.device_name is None:
                    if volume.attach_data.device not in self.exclude_devices: 
                        self.process_volume(volume)
                else:
                    if volume.attach_data.device == self.device_name:
                        self.process_volume(volume)

ebs_snapshot().run()
