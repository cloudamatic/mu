Built-in LDAP
-------------

Unless you’ve configured your Mu server to use another directory service, it
will use its bundled installation of 389 Directory Services. Users created by
*mu-user-manage* are stored here. Note that this does **not** include the
default root/mu system user.

We’re using 389 DS’ built-in schema, but not all software knows by default how
to look for the particular object classes/attributes we’re using (our design
may merit a custom schema in the future). If you’re configuring software to
authenticate against Mu’s LDAP, you may need to know the following:

Users (**inetorgperson**) are in `OU=Users,OU=Mu,DC=platform-mu`:
- `uid`: system username
- `employeeNumber`: Numeric POSIX uid
- `departmentNumber`: Numeric POSIX gid for default group
- `cn`, `displayName`, and `givenName` + `sn`: Firstname Lastname
- `mail`: email address
- `userPassword`: password (write-only)

Groups (posixGroup) are in `OU=Groups,OU=Mu,DC=platform-mu`:
- `cn`: group name
- `description`: Human-friendly descriptive string
- `gidNumber`: Numeric POSIX gid
- `memberUid`: username(s) of group members (same as `uid` attribute in **inetorguser**)

