mu -- Cloudamatic Automation Tooling
===
[![pipeline status](https://gitlab.com/cloudamatic/mu/badges/master/pipeline.svg)](https://gitlab.com/cloudamatic/mu/commits/master)
[![Gem Version](https://badge.fury.io/rb/cloud-mu.svg)](https://badge.fury.io/rb/cloud-mu)
[![Maintainability](https://api.codeclimate.com/v1/badges/dd4e5d867890336accd1/maintainability)](https://codeclimate.com/github/cloudamatic/mu/maintainability)
[![Inline docs](http://inch-ci.org/github/cloudamatic/mu.svg?branch=master)](http://inch-ci.org/github/cloudamatic/mu)

# About mu
**Mu**  is the deployer and developer toolset for the Cloudamatic suite of services, designed to provision, orchestrate and manage complex platforms and applications. At [eGT Labs](https://www.eglobaltech.com/egt-labs/), we use mu for rapid prototyping of cloud migration efforts for federal customers, for managing cloud applications throughout their lifecycles, and as a tools library for cloud maintenance tasks.

**Install instructions and tutorials**: https://github.com/cloudamatic/mu/wiki

**API and configuration language documentation**: https://cloudamatic.gitlab.io/mu/

# Quick Start

1. `gem install cloud-mu` - Install the toolkit in your Ruby 2.4+ ecosystem. See our [install wiki](https://github.com/cloudamatic/mu/wiki/Install) for other installation options

2. `mu-configure` - Set up credentials to your cloud provider of choice. See the [mu-configure manual](https://github.com/cloudamatic/mu/wiki/Configuration) for more.

3. `mu-deploy` - Build something! This will make a complete public/private VPC:

```
cat <<EOF > myvpc.yaml
---
appname: myvpc
- vpcs:
  name: thisvpc
EOF
mu-deploy myvpc.yaml
```
