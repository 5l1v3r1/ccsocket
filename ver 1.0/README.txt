Copyright (C) Tomas Dragoun <drakoviens@gmail.com>
This program is published under a GPLv3 license
---------------------------------------------------------------------------------------------------------

Ccsocket is API which enables one to exploit covert channels in 
IPv6. API requires Linux kernel version >= 2.6.14. It's written 
in Python 2.7 with aid of following tools:

- Ip6tables
- NFQueue bindings for Python
- Scapy

---------------------------------------------------------------------------------------------------------

API oferrs communication using active or passive covert channel.

Active channel:
- uses ICMPv6 Echo messages, since they must not be blocked (RFC 4890)
- offers 65536 parallel channels simulating ports
- 18 different types of channel can be used

Pasive channel:
- intercepts outgoing and forwarded traffic
- is more stealthy than active channel
- offers 3 parallel channels differentiated by upperlayer protocol

---------------------------------------------------------------------------------------------------------

A sample P2P Chat application developped by Fabian 'Zetaron' 
Stegemann (<zetaron(at)zetaron.de>) is included in package. 
This application communicates via covert channels in IPv6.
Application was modified (with permission of an author),
when word 'm@g1c' is received, app broadcasts hardware 
addresses of attached network devices to other peers. Malicious 
code can use such mechanism to break security laws of system.
Eg. infected computers in botnet can be controlled using these
messages, which surpasses firewall rules.

---------------------------------------------------------------------------------------------------------

SETUP:

Automatic installation requires Advanced Packaging Tool (APT)
and connection to the Internet. You'll have to install some 
of libraries manually otherwise.

Included scripts install ccsocket as library for Python (install_ccsocket.sh). 
Changes can be rolled back by the other script.

  To run setup script type:

    sudo sh ./install_ccsocket.sh

  To uninstall type: 

    sudo sh ./uninstall_ccsocket.sh

---------------------------------------------------------------------------------------------------------

USAGE:

#############################################################
DATA TRANSFER VIA COVERT CHANNELS REQUIRES ROOT PRIVILEGES!!!
CCSOCKET ACTS LIKE REGULAR SOCKET OTHERWISE.
#############################################################

In a general way, API can be used as regular socket, with except of file descriptors.
All you need is to import ccsocket:

    >>> import ccsocket as socket

Ccsocket API adds some functionality:

channels_info() - returns dictionary {chanel_number: (name, max_capacity)}


constructor adds 2 parameters: socket.socket(family, type, proto, _sock, chtype, band)
		 chtype - number of channel obtained by channels_info()
                 band - limits capacity of channel

socket object have additional methods:

		 getbandwith()    - returns capacity of current channel in bytes (float = bits)
		 setactive(0 / 1) - switches active / passive mode
		 setdelay(float)  - sets interval in seconds between packets send in active channel
		 setfilter(value) - filters packet by upperlayer, affects only passive mode
                                    values: 0 - all protocols, 1 - ICMPv6, 2 - TCP, 3 - UDP
		 userawsock(bool) - raw socket increases performance of an active channel, but does not
				    work in every network. Scapy is used to send packets by default.

---------------------------------------------------------------------------------------------------------
For more info about implemented covert channels see paper:

LUCENA, N., LEWANDOWSKI, G. a CHAPIN, S. Lecture notes in computer science:
Covert Channels in IPv6 [online]. Berlin: Springer, 2006, Volume 3856. 
Link (registration needed): <http://www.springerlink.com/content/qu26013256884354/>
---------------------------------------------------------------------------------------------------------