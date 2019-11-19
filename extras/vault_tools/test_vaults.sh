#!/bin/bash
# Tests access to vaults listed in ~/vaults directory, which must exist
cd ~/vaults
for i in `ls`;do for j in `ls $i`;do item="`echo $j | cut -d. -f1`"; knife vault show $i $item ; done; done;

