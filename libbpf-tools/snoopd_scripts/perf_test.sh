#!/bin/bash

# For obvious reasons, this needs to be run as root. Use sudo.

# For entirely non-obvious reasons, a good performance test
# cannot simply create, update, and remove files and directories.
# A test that does that won't measure the impact of starting new
# processes.
#
# Starting a new process is very sensitive, performance-wise, to
# both kernel slowdowns as well as filesystem operations. Since
# we want to measure how much slower the system gets, simply
# modifying the filesystem ignores how much slower the kernel is
# due to all the hooks snoopd has put in.
#
# A better test is to open an application. On application startup,
# multiple system library paths are search for multiple system
# libraries. Each of those searches and open() attempts will call
# the snoopd hook.
#
# Once started, the application itself will open multiple files
# such as configuration files, user data files, etc. Vim is ideal
# for this due to how many startup files it loads.
#
# This is why this test simply measures how much of a slowdown
# results from having snoopd running vs normal operations with
# snoopd not running.
#
# Reading and writing the actual 'test' file is negligible.
#

echo "Timing without snoopd running ..."
time for X in {1..100}; do
   echo -ne ":wqa\n" | vim test &> /dev/null;
done >> perf_test.txt

echo "Starting snoopd ..."
../snoopd &> /dev/null &
export SPID=$!

echo "Timing with snoopd running ..."
time for X in {1..100}; do
   echo -ne ":wqa\n" | vim test &> /dev/null;
done > perf_test.txt

echo Killing $SPID
kill $SPID
