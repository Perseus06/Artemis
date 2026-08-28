## Artemis - windows network scanner

Artemis is a tool written in C language, that allows to map the LAN completely. Artemis finds all the endpoints in the LAN by using the ICMP protocol (ping-pong mechanism), which is a famous protocol for mapping networks. Furthermore, the tool includes an OS detection - Artemis is able to determine if an endpoint found in the LAN is using Linux, Mac, Windows or network devices operating system. The OS detection happens via analyzing the TTL value of each ICMP response packet found. Artemis is pretty simple yet very sufficient tooll, as it requires nothing from the user and can give a lot of information about the LAN in a very short time.

NOTE: Artemis uses winsock2 library so it's a <b>windows</b> exclusive tool!



### Fast or slow - what's better?

Artemis allows you to choose if to execute either a fast scan or a slow one. the difference in the length of each scan is emphasized, yet the scans are both the same and they differ only by the time the program accepts to wait for a response. In the slow scan, the program waits much longer for a response after sending each ICMP request packet. Therefore the slow scan is less likely to miss endpoints in the LAN.


In addition, the slow scanning is considered safer in terms of cybersecurity, because of the larger time breaks between each packet sent. The larger time breaks can make the traffic created by the tool to disappear or at least look less suspicious by cybersecurity people and softwares.


Therefore, overall the slow scan in better for you, and if you don't care too much about performance and speed you better use it.

### How to execute Artemis?

very simple - use the command line and give the argument for the kind of scanning you will to execute.

artemis -s --> for slow scanning
artemis -f -> for fast scanning
artemis -h --> for help message



the tool is called artemis in the name of the Greek goddess of hunting, because it hunts all the victims in the network.

