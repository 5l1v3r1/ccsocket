#!/bin/sh

# check root

if [ $(whoami) != "root" ]
then
  echo "You must run this script as root.\n"
  exit 1
fi

rm -r -f ./zetaron-python-udp-p2p-chat

cat install.log > /dev/null 2>&1 && echo "\n\nRemoving ccsocket lib\n" || \
{ echo "\n\nError: instalation logfile was not found. Uninstaller exits..\n"; exit 1;}

# remove files
for i in $(less install.log); do
  echo "Deleting: $i"
  sudo rm $i;
done && echo "\n[OK]\n\n"

rm install.log