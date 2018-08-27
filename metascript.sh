#!/usr/bin/env bash
python=python3
org=sys-tmo
space=test
appname=spring-music
webpage="http://spring-music-interested-bonobo.apps.tt-stg02.cf.t-mobile.com"

pause() {
    read -n1 -r -p 'Press any key to continue...'
}

echo "TEST CLI INTERFACE"
echo "=================="

echo "Test Help"
$python -m cfblocker.cli -h
echo "The help message should have printed above."
pause

echo "Test discovery"
$python -m cfblocker.cli $org $space $appname --discover
echo "The list of hosts and services should have been printed above."
pause

echo "Before continuing, make sure ${webpage} loads as expected and displays albums."
pause

echo "Blocking access to services"
$python -m cfblocker.cli $org $space $appname --block-services
echo "If you navigate to ${webpage}, it should load but have no albums."
pause

echo "Block all traffic"
$python -m cfblocker.cli $org $space $appname --block
echo "If you navigate to ${webpage}, it should not load."
pause

echo "Unblock everything"
$python -m cfblocker.cli $org $space $appname --unblock
echo "If you navigate to ${webpage}, it should load normally."
pause


echo "TEST CHAOS TOOLKIT INTERFACE"
echo "============================"

echo "Test probes"
$python -m chaostoolkit --verbose run experiments/probes.json
echo "The above probes should produce information about the hosts and services of ${appname}"
pause

echo "Test blocking traffic"
$python -m chaostoolkit --verbose run experiments/block-traffic.json
echo "If the experiment ran and says it did not pass the chaos experiment, it should be good."
pause

echo "Test blocking music db"
$python -m chaostoolkit --verbose run experiments/block-service.json
echo "The experiment should run and pass."
