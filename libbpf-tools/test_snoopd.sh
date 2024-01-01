#!/bin/bash

# Make sure that the exclusion list does not exclude /tmp

export F=snoopd-test

# Test file openat for writing (1)
touch /tmp/$F

# Test uinlinkat (2)
rm /tmp/$F

# Test mkdirat (5)
mkdir /tmp/$F

# Test chdir (4)
cd /tmp/

# Test rmdir (6)
rmdir /tmp/$F

