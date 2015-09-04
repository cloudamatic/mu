Groomers
--------

This is where we implement support for host configuration providers like Chef
or Puppet.  If you are writing a new Groomer plugin, we suggest you use the
existing Chef Groomer implementation and this README as a guide.

A `MU::Groomer` object is the generic interface to host configuration
platforms, used so that other parts of Mu can operate on nodes without needing
to know specifics about Chef or its ilk. 

`MU::Groomer` objects are created for and invoked from `MU::Cloud::Server`
objects during certain phases of their creation and upkeep. They run
recipes/manifests/scripts to manage the host's configuration and share metadata
from the rest of a Mu deployment.

Any Groomer plugin must implement the following instance methods:

**preClean**: Invoked to remove unsanctioned installs of host management
software, which might be inherited from a machine image which came with Chef or
its like pre-installed.

**bootstrap**: Install our Groomer software on the Server to be managed and
initialize it, e.g. by creating the node as a client on a Puppet or Chef
master, setting up keys, etc.

**haveBootstrapped?**: Should return true if bootstrap has already been
successfully run on this node.

**run**: Invoke our configuration management agent, e.g. *chef-client* or
*puppet agent*.

**saveDeployData**: Propagate Mu deployment metadata into the host management
system so that it will be accessible from recipes/manifests.

**getSecret**/**saveSecret**: Set or retrieve a piece of secured (encrypted,
access-controlled) data from whatever mechanism this host management system
uses for that job, e.g. Chef's Vault add-on.

Additionally, you should implement class methods for the following:

**getSecret**: Same as above, but without an object context. There is the
occasional need.

**cleanup**: Destroy all traces of saved Groomer data for a given node. This is
a class method becauase cleanup operations are often performed on incomplete
resources which may or may not have an available instance object.

A Groomer object's constructor (the *initialize* method) will be passed a
`MU::Cloud::Server` object on which to operate. These objects have a number of
useful public instance methods, but the ones which will matter most when
implementing a new Groomer are:

**mu_name**: The "official" name of this node within Mu. This name is guaranteed to be unique amongst all `MU::Cloud::Server` objects managed by your Mu Master. If the host management platform you're implementing needs to name nodes something, it should be this.

**getSSHSession**: This method will return a `Net::SSH::Session` object connected to the host which is being groomed.


