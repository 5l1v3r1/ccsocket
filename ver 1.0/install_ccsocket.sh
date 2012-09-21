#!/bin/sh

# check root
if [ $(whoami) != "root" ]; then
  echo "You must run this script as root.\n"
  exit 1
fi

apt-get update

# check Python version
python -c "import sys; ver=sys.version_info[:]; sys.exit(not(ver[0]==2 and ver[1] in [7]))" || \
{ echo "Python 2.7 not found.."; apt-get install python2.7 || apt-get install python || exit 1; }

# check ip6 support
python -c "import sys, socket; sys.exit(not socket.has_ipv6)" || \
{ echo "[FAIL] Your system does not support IPv6.."; exit 1; }

# extract archive
echo "\n\nExtracting data.."
if unzip -q -o ccsocket.zip; then
    echo "[OK]"
elif echo "Y\n" | apt-get install unzip; then
    unzip -q -o ccsocket.zip && echo "[OK]" || { echo "Can not unzip archive.."; exit 1; }
else
    echo "Can not unzip archive.."; exit 1
fi

# install ccsocket module
echo "\n\nInstalling ccsocket..\n"
cd ccsocket; python setup.py install --record install.log && echo "[OK]" && mv install.log .. || { echo "[FAIL]"; exit 1; }
cd ..

# install nfqueue for Python
echo "\n\nInstalling nfqueue bindings for Python..\n"
echo "Y\n" | apt-get install nfqueue-bindings-python && echo "[OK]" || \
{ cd nfqueue_install; apt-get install libnetfilter-queue1 && dpkg -i ./python-nfqueue_0.3-4_i386.deb && \
dpkg -i ./nfqueue-bindings-python_0.3-3_i386.deb && echo "[OK]" || \
echo "[FAIL] Try manual installation."; cd ..; } 

# install scapy
echo "\n\nInstalling scapy 2.2.0..\n"
cd scapy-2.2.0; python setup.py install && echo "[OK]" || echo "[FAIL] Try manual installation."
cd ..

# test importing ccsocket
echo "\n\nTesting import.."
python -c "import sys; import ccsocket; sys.exit(0)" > /dev/null 2>&1 && \
echo "[OK]"; echo "\n\nYou can use ccsocket in Python by typing: \n>>> import ccsocket\n" || echo "[FAIL]" 

# remove tmp files
rm -r -f ./ccsocket
rm -r -f ./scapy-2.2.0
rm -r -f ./nfqueue-install

# instal python gui support
echo "\n\nInstalling Tkinter for Python..\n"
echo "Y\n" | apt-get install python python-tk idle python-pmw python-imaging && echo "[OK]" || { echo "[FAIL]"; exit 1; }

echo "\n\nInstalling Ttk wrapper for Python..\n"
cd pyttk-0.3.2; python setup.py install && echo "[OK]" || { echo "[FAIL]"; exit 1; }
cd ..
# remove tmp files
rm -r -f ./pyttk-0.3.2

# run sample app
cd zetaron-python-udp-p2p-chat
echo "\n\nRunning sample application..\n"
python chat.py > /dev/null 2>&1