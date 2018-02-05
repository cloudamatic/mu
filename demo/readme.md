# Mu BoK Demos

These demo Baskets of Kittens (BoK) serve as a springboard for you as your begin developing your own BoK's. I would reccomend starting with the Simple Server BOK's, and then move into more advanced configurations. 

The BOK API overview can be found here https://yourMuServer.com/docs/MU/Config/BasketofKittens.html

## BoK Descriptions

## Servers

#### Simple Server PHP (simple-server-php.yaml)
Deploys a basic Linux Apache PHP stack to a Ubuntu server

#### Simple Server Rails (simple-server-rails.yaml)
Deploys [Concerto 2 Digital Sinage System](https://github.com/concerto/concerto) to a Ubuntu server. 

#### Simple Windows (simple-windows.yaml)
Deploys a base Windows Server to specified VPC. If no VPC is specified, use current VPC.

#### Simple Windows IIS (simple-server-iis.yaml)
This doesn't exist yet, but I think it should. TODO

#### Windows With Userdata (windows-with-userdata.yaml)
Deploys a Windows Server with the default Mu userdata.

## Networking

#### DNS Zone (dnszone.yaml)
Creates a new DNS zone, and demos some advance DNS functionality

#### VPC (vpc.yaml)
Creates a new VPC

#### VPC AWS NAT Endpoint (vpc-aws-nat-endpoint.yaml)
description

#### Create Autoscale in Existing VPC (vpc-create-autoscale-use-existing-vpc.yaml)
description

#### Create Services in Existing VPC (vpc-create-services-use-existing-vpc-add-sgs.yaml)
description

#### Create Service and Database in Existing VPC (vpc-create-service-use-existing-vpc-and-db.yaml)
description

## Databases

#### Build Aurora Cluster (aurora_cluster.yaml)
Builds an MySQL Aurora DB Cluster consisting of 3 nodes. (Beware, if you don't clean this deployment up, it can rack up a heafty bill)

### Applications

#### Deploy Jenkins (jenkins.yaml)
Deploys [Jenkins](https://jenkins.io/) pipeline automation platform.

#### Deploy Splunk (splunk-server.yaml)
Deploys [Splunk](https://www.splunk.com/) log management platform.

#### Deploy Wordpress (wordpress.yaml)
Deploys [Wordpress](https://wordpress.org/) bloging platform.

#### OpenVPN (openvpn.yaml)
Deploys [OpenVPN](https://openvpn.net/) VPN server.

#### Deploy GitLab (gitlab.yaml)
Deploys the most recient version of [GitLab CE](https://gitlab.com/gitlab-org/gitlab-ce) software development platform.

IN DEVELOPMENT


## Other/Unknown

#### auto-launch-config-ami-on-the-fly.yaml
description

#### autoscale_step_scaling.yaml
description

#### cache_cluster.yaml
description

#### cloudwatch-logs-cloudtrail.yaml
description

#### multi-ebs-device.yaml
description

#### storage_pool.yaml
description


## Demo BoK Status
| Demo BoK Name                              | Requires Parameters | Last Successfully Tested  |
| -                              |:-:      | --:                    |
| aurora_cluster.yaml                        | No                  | 10/17/17                  |
| auto-launch-config-ami-on-the-fly.yaml     | No                  |                           |
| autoscale_step_scaling.yaml                | No                  |                           |
| cache_cluster.yaml                         | No                  |                           |
| cloudwatch-logs-cloudtrail.yaml            | No                  |                           |
| dnszone.yaml                               | No                  |                           |
| jenkins.yaml                               | No                  |                           |
| multi-ebs-device.yaml                      | No                  |                           |
| openvpn.yaml                               | No                  |                           |
| simple-server.yaml                         | No                  | 10/17/17                  |
| simple-server-php.yaml                     | No                  |                           |
| simple-server-rails.yaml                   | No                  |                           |
| simple-windows.yaml                        | No                  | 10/17/17                  |
| splunk-server.yaml                         | No                  |                           |
| storage_pool.yaml                          | No                  |                           |
| vpc.yaml                                   | No                  |                           |
| vpc-aws-nat-endpoint.yaml                  | No                  | 10/17/17                  |
| vpc-create-autoscale-use-existing-vpc.yaml | No                  |                           |
| vpc-create-services-use-existing-vpc-add-sgs.yaml | No           |                           |
| vpc-create-service-use-existing-vpc-and-db.yaml   | No           |                           |
| windows-with-userdata.yaml                 | No                  |                           |
| wordpress.yaml                             | No                  | 10/17/17                  |
| gitlab.yaml                                | No                  |                           |