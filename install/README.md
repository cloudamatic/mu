# Cloudamatic Mu Master Installation
There are two paths to creating a Mu Master.  

- **Typical Installation**: The simplest and recommended path is to use our CloudFormation script to configure an appropriate Virtual Private Cloud and master with all features enabled, including both a command line and Jenkins GUI user interface.
- **Custom Installation:** If you prefer, you can also create your own VPC and manually provision a Mu Master.  This gives you more control over the shape of the master VPC and individual settings

## Typical Installation -- CloudFormation bootstrap script
In this approach we use AWS Cloudformation to bootstrap a Cloudamatic mu master, which you can then use for the Cloudamatic extended capabilities.

1. Create two required AWS account artifacts:
    - Create a file in S3 containing the private key you want mu to use to access GitHub.  Cloudamatic may be public, but your ancillary repositories may not be.
    - Create or note an AWS role with permissions you want your mu master to have on your AWS account.  You'll need permissions for provisioning instances, adjusting tags, creating EBS volumes, perhaps RDS databases, etc.
2. Download the [Cloudamatic CloudFormation template](https://github.com/cloudamatic/mu/blob/headless/install/cfn_create_mu_master.json) for master creation.
2. Launch the template from AWS command line or console 
3. You'll need to fill in required parameters for:
    -  **adminEmail**: The e-mail address of the administrative user for the server, for notifications
    - **JenkinsAdminEmail**: The e-mail address for the administrative Jenkins user. Sadly Chef requires this be different than admin email 
    -  **AdminIPCIDR**: The IP address you will initially use to connect to the master for admin access, in CIDR format, e.g.. 50.1.1.1/32 
    -  **adminPassword**: Password used for mu and Jenkins admin users.  Both are parallel admin functions using different interfaces
    -  **KeyName**: Name of an existing EC2 KeyPair to enable SSH access to Cloudamatic Server
    -  **GitHubKey**: The S3 address of a private key to access GitHub for your repositories.
    -  **masterIAMRole**: The IAM Role you created that defines what your Master can do on AWS
    
    The other parameters to the template are filled with reasonable defaults -- change them if needed.

4. Execute the template, changing defaults and filling in parameters as needed.  It takes about a half hour to set up a Mu master.  
5. Access the master via the Cloudformation output parameters.
    - Use the address from sshURL output parameter to SSH to the instance, using the private key of the keypair you referenced in KeyName.  Tail the /root/setup.out file to view progress.
    - Once setup is complete, use the address from the JenkinsURL out parameter to access the Jenkins interface.  Log in as the default administrator "mu_user" with the password you supplied in adminPassword

## Custom Installation
The Cloudformation installation works by populating environment variables then firing the mu_setup script.  mu_setup has a manual mode where you can supply all parameters by hand.  Using this technique you must create a virtual private cloud and Master instance yourself.

### Creating a Virtual Private Cloud
You have a wide range of options for your VPC, depending on your security needs and intended use.  The simplest VPC is one with a public subnet for the Mu Master, but this configuration will not meet the requirements for all demos, specifically those that target the master VPC for demo deploys and require a private subnet.

As general guidance the CloudFormation stack can serve as a model for more complex VPC's, but you're free to create whatever is needed, up to and including placing the master itself in a private subnet fronted by a bastion host, a high security pattern.

### Setting up the Master
1. Launch an AMI in the public subnet of a VPC for simplest deploy.  More secure and advanced deploys can be done in the private subnet of a VPC with a bastion.  We recommend our hardened public CentOS 6 AMI which you can find in the repository in *mu/modules/mu/defaults/amazon_images.yaml* as the CentOS 6 AMI.
2. ssh to your instance using the key you launched with
3. As a one-time operation put the installer in /root, from the install directory of our repository.  You can install wget and pull it there, or just paste it in an editor.
4. Make the installer executable and run it
5. Fill in the required environmental variables in the display, along the lines of:

![](images/\Usage.png) 
