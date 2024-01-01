#!/bin/bash

# Make sure that the exclusion list does not exclude /tmp before running
# this test.
#
# The actions printed to stdout (as of writing) must be in the order
# specified below in parentheses.

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

