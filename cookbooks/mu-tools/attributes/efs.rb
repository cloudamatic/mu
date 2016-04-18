require 'net/http'
require 'json'

instance_identity = JSON.parse(Net::HTTP.get(URI("http://169.254.169.254/latest/dynamic/instance-identity/document")))
region = instance_identity["region"]
availability_zone = instance_identity["availabilityZone"]

default.efs.target.directory = "/efs"
default.efs.target.filesystem_id = nil
default.efs.target.region = region
default.efs.target.availability_zone = availability_zone
default.efs.target.dns = "#{node.efs.target.availability_zone}.#{node.efs.target.filesystem_id}.efs.#{node.efs.target.region}.amazonaws.com"
