# Cloudamatic Mu Master Installation
There are two paths to creating a Mu Master. _Typical Installation_ and _CloudFormation Installation_

## Typical Instalation
In the standard instsatation create your original VPC and manually provision a Mu Master instance.

### Prerequisites

1. Fully configured VPC to house the Mu Master
	* Must have access to the internet
	* Must manually configure any neccicary security on the VPC
1. Properly configured instance
	* Supported OS CentOS 6-7, RHEL 6-7, and Amazon Linux 2
	* A role, other API credentials to grant proper Mu-Master permissions

### Instalation 

**To Install From Master**
```
curl https://raw.githubusercontent.com/cloudamatic/mu/master/install/installer > installer
chmod +x installer
./installer
```

**To Install From Development or Other Branch**
```
curl https://raw.githubusercontent.com/cloudamatic/mu/development/install/installer > installer
chmod +x installer
MU_BRANCH=development ./installer
```

For detailed instructions on installation techniques see [our Wiki Installation page](https://github.com/cloudamatic/mu/wiki/Install-Home)

## CloudFormation Installation
> This method is depricated and may be removed from future releases

The simplest path is to use our CloudFormation script to configure an appropriate Virtual Private Cloud and master with all features enabled. 

### Get Started by Clicking the Launch Button!!

>This does create all the AWS resources in `us-east-1` region.

[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=CloudamaticInstaller&templateURL=https://s3.amazonaws.com/mu-cfn-installer/cfn_create_mu_master.json)