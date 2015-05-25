#!/bin/bash
#
# Plugin to monitor http load time for sites
#
# Parameters:
#
# 	config
# 	autoconf
#
# Configuration variables
#
#   sites    - site names seperated by space e.g. "google.com mail.ru"
#
#
#%# family=auto
#%# capabilities=autoconf

CURL=${curl:-curl}

if [ "$1" = "autoconf" ]; then
	if [ -x $CURL ]; then
		echo no
		exit 1
	fi
	
	if [ "X${SITES}" = "X" ]; then
		echo no
		exit 1
	fi
	echo yes
	exit 0
fi

if [ "$1" = "config" ]; then
	echo "graph_title Page load time"
	echo "graph_args --base 1000"
	#echo "graph_args --base 1000 --upper-limit 5"
	echo "graph_vlabel time in seconds"
	echo "graph_category http"
	echo "graph_scale no"
	echo "graph_info Amount on seconds taken to load website from this host."

	I=0
	for S in $SITES
	do
		let I+=1
		echo "site${I}.label ${S}"
		echo "site${I}.min 0"
		echo "site${I}.draw LINE2"
		echo "site${I}.max 800"
	done
	exit 0
fi

I=0
for S in $SITES
do
	let I+=1
	#echo $CURL -s -w "site${I}.value %{time_total}\n" -o /dev/null http://${S}/
	$CURL -L -s -w "site${I}.value %{time_total}\n" -o /dev/null http://${S}/
done
exit 0

