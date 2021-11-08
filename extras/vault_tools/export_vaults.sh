#!/bin/bash
# Exports existing vaults to a vaults directory for use by test_vaults and recreate_vaults
mkdir -p ~/vaults ; for i in `knife data bag list | grep -vE -- '-[0-9]{10}-'`;do echo $i; mkdir -p vaults/$i ; for j in `knife data bag show $i | grep -v '_keys$'`;do echo "   $j"; knife vault show $i $j -F json > vaults/$i/$j.json;done;done ; find vaults -empty -delete
