These tools validate vaults, recreate them and  migrate vaults from one Mu server to another. The vaults are stored unencrypted, with each item in it's own JSON file. This will create a directory structure that looks like this:
-vault --item1.json --item2.json -vault2 --item1.json ...

* On original server, export vaults to a folder structure using export_vaults.sh
* Transfer the ‘vaults’ directory to another Mu server by any convenient means.  Scripts will look for vaults directory in the current home directory, e.g. ~
* Recreate the vaults with recreate_vaults.sh
