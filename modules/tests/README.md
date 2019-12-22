Any `.yaml` or `.yml` file dropped into this directory will be invoked in our
test pipeline for appropriate branches and PRs, by `bin/mu-run-tests`.

For most commits this will do a `mu-deploy --dryrun` to verify parsing and 
config validation. For release candidates, these stacks will be deployed and
cleaned up.

By default, each BoK will be invoked one time for each supported cloud
provider. To restrict providers, such as for a stack which tests resource only
supported by a subset of our supported clouds, add a comment like the
following:

```
# clouds: AWS, Google
```
