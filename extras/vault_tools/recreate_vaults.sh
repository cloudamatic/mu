#!/bin/bash
# This is a destructive operation!  Recreates all vaults listed in the ~/vaults directory, which must exist.
cd ~/vaults
for i in `ls`;do knife data bag delete -y $i ; for j in `ls $i`;do item="`echo $j | cut -d. -f1`"; echo "$i $item" ; knife vault create $i $item -J $i/$j;done;done

