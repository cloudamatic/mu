Mu
===

Secure Cloud Public Infrastructure as a service.  Currently supported on RHEL
or CentOS 6 in Amazon Web Services.

##Installation
Create a virtual private cloud to house your Mu server by running the CloudFormation template in applications/mu_server_template.json with appropriate parameters from an AWS command line or the AWS console.  The template will create a virtual private cloud for your Mu server with a bastion host and an unconfigured Mu server located at 10.0.1.100.

Log into the bastion host at the address returned by the CloudFormation run using the ec2-user ID and the key you supplied in the CloudFormation launch.  Place the private key to access the Mu server on the bastion and ssh from bastion to the empty Mu server.

Run **install/mu_setup**. This will install and configure the Mu
deployment tools as well as your _chef-master_ repository. You will be prompted
for a number of parameters. Here is an example configuration.

    1) AWS_ACCESS: [redacted]
    2) AWS_SECRET: [redacted]
    3) AWS_ACCOUNT_NUMBER: 12345678901234
    4) CHEFREPOS: MyORG/MyRepo.git NotMyORG/ThirdPartyRepo.git
    5) EC2_REGION: us-east-1
    6) MU_REPO: eGT-Labs/mu.git
    7) INSTALL_USER: root
    8) CHEF_PUBLIC_IP (OPTIONAL; will try to guess): 10.0.0.1
    9) HOSTNAME (be descriptive): mychefmaster
    10) EC2SECGROUP (OPTIONAL; will try to guess): sg-1234abcd

Your configuration will be placed into *~/.murc* by default.


If you need to change your configuration after initial installation, run the _mu-configure_ script.

##Use

A number of utilities will be installed into your path.

####Managing Chef resources in your Chef master instance

**mu-upload-chef-artifacts** handles the synchronization of your Chef recipe repositories into your running Chef server instance.

    # mu-upload-chef-artifacts -h
    Syncs Chef code to running Chef master. Optionally refreshes from git.
    Usage: /opt/mu/lib/bin/mu-upload-chef-artifacts [-a|-r repo_name[:branch] [-r repo_name[:branch] [...]]] [-f [-c <commit>] ] [-d] [-n] [-s]
        -f: Forcibly re-sync Chef repos from Git before uploading
            to Chef. Saves your working changes unless -d is specified.
        -c <commit> (requires -f and at most one -r): Reset to a specific commit.
        -d: Discard any uncommited changes to currently checked-out branches.
        -n: No purging of Chef resources, just uploads new Chef data without
            expunging old resources from the running server.
        -s: Shortcut mode. Update cookbooks only. Implies -n.
        -a: Upload currently checked-out branch from ALL Chef repos. Cannot be used
            with -c or -r.
        -b <branchname>: Upload the named branch from ALL Chef repos. Useful if
            you want to use, for example, only master from every repo.
        -r: A Chef artifact repository to upload. Can specify multiple. See list
            below. Optionally, specify a branch by appending :branchname (this will
            override -b).
    
    Known Chef artifact repositories, as set by mu-configure. Ordered
    from lowest priority to highest:
    mu
    myorg_platform

Example uses:

_Upload Chef code from currently checked-out branches of all known repositories, but skip purging existing Chef artifacts from the running server:_

    mu-upload-chef-artifacts -n

_Upload Chef code from whatever Mu branch is currently checked out, and from the **newfeature** branch of the **myrepo** repository:_

    mu-upload-chef-artifacts -r mu -r myrepo:newfeature

_Upload Chef code from all known repositories, forcing them to use the **master** branch:_

    mu-upload-chef-artifacts -b master

_Upload Chef code from all known repositories, forcing them to use the **master** branch, resetting to the last commit and discarding all unstaged changes:_

    mu-upload-chef-artifacts -f -d -b master

####Updating the Mu tools or using alternate versions

**mu-self-update** manages your local copy of the Mu deployment tools and
baseline Chef recipes.  Its main use is to switch between Git branches to
work with experimental features.

    # mu-self-update -h
    Updates Mu scripts in /opt/mu/lib/bin. Optionally refreshes from git.
    Usage: /opt/mu/lib/bin/mu-self-update [-b <branch>] [-f [-c <commit>] ] [-d]
        -f: Forcibly re-sync /opt/mu/lib from Git.  Saves your
            working changes unless -d is specified.
        -c <commit> (requires -f): Reset to a specific commit.
        -b <branch>: Use a branch in /opt/mu/lib other than master.
        -d: Discard local changes to current branch.


####Managing your Mu and Chef server configurations.

**mu-configure** can be used to reconfigure the parameters of your local Chef/Mu instance. It works identically to **mu_setup**. Your configuration is stored in _~/.murc_ by default.

####Deploying an application stack

**mu-deploy** creates a deployed application stack AWS from a .json
description file.  See the _applications/_ directory of your Mu repository for
examples.

####Removing an application stack

**mu-cleanup** removes an application stack created by **mu-deploy**
