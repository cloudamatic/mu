mu-tools Cookbook
=================
The mu-tools cookbook implements the core patterns for Mu platform construction across any platform, including
image hardening, security reporting and secure credential retrieval and usage.  Use this cookbook for patterns relating specifically to Mu, and the utility cookbook for more generic recipes for specific packages, etc. and community repository imports

Components
==========
Libraries
---------
The capvolume library deals with all aspects of acquiring, attaching, mounting, unmounting and securing volumes for Mu.  It contains utility methods for secure key handling volume operations, etc. 

Recipes
-------

#### apply_security 
apply_security carries out platform level OS security hardening that takes place before recipes install application-
specific platform enablers and applications.  apply_security may be supplemented with application-specific
hardening in application recipes

#### cisbenchmark
cisbenchmark installs and runs the CIS benchmark.  It is currently (12/13) a stub

#### set_application_attributes
set_application_attributes retrieves application attributes, including credentials from
a secure store, and configures the attributes on a node under the key "application_attributes"

1.  Initially "application_attributes" is set in the environment and includes bootstrapping pointers to the
    secure message store and the JSON-formatted configuration file for the application
2.  set_application_attributes retrives the configuration file and augments the initial
    "application_attributes" with its contents
3.  Subsequent recipes depend upon the "application_attributes" structure in the node.

Application configuration is stored in an out-of-band secure encrypted repository in a specific
    JSON format, with a key for each area, e.g. see the -git- key below, and child keys beneath:

```json
{
    "id": "icras_dev_properties",
    "project": {
            "id": "ICRAS",
            "name": "ICRAS Project"
    },
    "icras_hhs": {
        "git" : {
            "repo": "someRepoPath.git",
            "repo_name": "someRepoName",
            "username": "someUsername",
            "password": "somePassword"
        },
        "database" : {
            "connect_string" : "someConnect",
            "username"  : "someUser",
            "password"  :   "somePassword"
        }
    },
    "icras_edu": {
        "git" : {
            "repo": "someRepoPath.git",
            "repo_name": "someRepoName",
            "username": "someUsername",
            "password": "somePassword"
        },
        "database" : {
            "connect_string" : "someConnectMySQL",
            "username"  : "someUserMySQL",
            "password"  :   "somePasswordMySQL"
        }
    }
}
 
```
#### create application volume
This recipe invokes the methods in the capvolume library to
- create a volume for storing an application, currently implemented for AWS
- Attach the volume to a device
- Encrypt the device pulling the key from a secure source and storing it in ram so it never touches the node disk
- Mount the device on an indicated mount point from the node structure
- Destroy the ram device as soon as mount is complete

When run without an encryption key location attribute the recipe will create, attach and mount an ordinary volume without encryption and log a warning.


Requirements
------------
#### operating systems
Currently the hardening recipes have been completed for CentOS6 only.  Stubs are present for
Ubuntu operating systems

#### compile phase
set_application_attributes, must run in the compile phase so that
a target node's attributes are preconfigured for the subsequent recipes.  

#### recipes
awscli recipe required by set_application_attributes to provide the aws cli
command to fetch creds from the secure repository.  No require is listed in the recipe in order to work around the limitations of the curren(12/13) version of egt-get-cookbooks.sh.  Credential and configuration fetch is accomplished by a required AWS IAM role on the node, sufficient to fetch creds from the secure repository.

#### attributes
set_application_attributes depends on preexisting base application attributes for:
  ['application_attributes']['secure_location']
  ['application_attributes']['attributes_file']
  these attributes are typically set in the environment, for example:

```json
"application_attributes" : {
                        "secure_location" : "somePathToCredentials, e.g. s3:://whatever, file:///whatever, etc.",
                        "attributes_file" : "nameOfAppSpecificPropertiesFile.json",
                        "ebs" : {
                            "mount_device" : "/dev/xvdh",
                            "mount_directory" : "/apps"
                        },
                        "otherInitialAttributes" : "Whatever you need to get started"
}
```

Other required recipes such as awscli may also need to be run in compile phase, with appropriate controlling attributes typically set in an environment

The overall capvolume library depends on a node structure for volumes, defaulted in the default attributes and modifiable both by recipe and the environment, which typically is used for overrides.

Each volume has a structure like this:
```json
   "application_attributes": {
      "application_volume": {
        "mount_directory": "/apps",
        "mount_device": "/dev/xvdh",
        "filesystem": "ext3",
        "volume_size_gb": "5",
        "ebs_keyfile": "the name of the key to use on the secure location"
      },
      "secure_location": "where the creds live",
      "attributes_file": "the attributes of the app on the secure location"
    }

```
In addition, once a volume is actually created, you get:

```json
 "application_volume": {
        "volume_id": "vol-5392d61e",
        "mount_device": "/dev/xvdh"
      }

```


#### packages
* set_application_attributes depends on the rubygems and json gem for parse
* apply_security depends on yum on centos and will depend on apt in ubuntu


Attributes
----------
default.rb has a default set of attributes for a typical small application volume

Usage
-----
#### set_application_attributes::default
Ensure that the environment presets the seed attributes for credential fetch as detailed
in dependencies

Ensure that the required credential fetch cookbook has previously run in compile phase as detailed in dependencies

Run the recipe.  Success can be demonstrated by viewing a fully populated application_attributes hash in nodes

A typical run list looks like:

```json
        "env_run_lists" : {
                "production_icras_hhs" : [
                ],
                "development_icras_hhs": [
                        "recipe[utility::epel]",
                        "recipe[awscli]",
                        "recipe[mu-tools::set_application_attributes]"
                ]
        }
```

####To Do
Add temporary ram volume destroy
Add cloud independent abstraction wrappers

Contributing
------------

License and Authors
-------------------
Authors: Robert Patt-Corner, Jai Bapna, Ami Rahav, John Stang
c. 2013 eGlobalTech
