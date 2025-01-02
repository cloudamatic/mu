#!/bin/bash
# Exports existing vaults to a vaults directory for use by test_vaults and recreate_vaults
mkdir -p ~/vaults
cd
for i in `knife vault list | egrep -v '^INFO:'`;do
  echo "VAULTNAME: $i"
  mkdir -p vaults/$i
  for j in `knife data bag show $i | egrep -v '^INFO:|_keys$'`;do
    echo "   ITEM: $j"
    knife vault show "$i" "$j" -F json | grep -v '^INFO:' > ~/vaults/$i/$j.json
  done
done
find ~/vaults -empty -delete
