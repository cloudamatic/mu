This directory contains schema definitions for the various cloud resource types
supported by Mu. There should be one file per resource type here, each defining
one class under `MU::Config` and implementing, at minimum, the class methods `self.schema` and `self.validate`.

The schema and validation should by cloud-generic, that is it should only
contain properties common across cloud providers. Platform-specific schema and
validation behaviors should be written into the actual implementation, e.g.
`MU::Cloud::AWS::Log` will contain AWS-specific schema components and
validation checks.
