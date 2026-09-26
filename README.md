## Artemis - windows network scanner

Artemis is a tool written in C language, that allows to map the LAN completely. Artemis finds all the endpoints in the LAN by using the ICMP protocol (ping-pong mechanism), which is a famous protocol for mapping networks. Furthermore, the tool includes an OS detection - Artemis is able to determine if an endpoint found in the LAN is based on a Linux/Mac, Windows or network devices system. The OS detection happens via analyzing the TTL value of each ICMP response packet found. Artemis is pretty simple yet very sufficient tool, as it requires nothing from the user and can give a lot of information about the LAN in a very short time.

The tool is named Artemis in the name of the Greek goddess of hunting, because it hunts down all the victims in the network.


NOTE: Artemis uses winsock2 library so it's a **windows** exclusive tool!



### Fast or slow - what's better?

Artemis allows you to choose if to execute either a fast scan or a slow one. the difference in the length of each scan is emphasized, yet the scans are both the same and they differ only by the time the program accepts to wait for a response. In the slow scan, the program waits much longer for a response after sending each ICMP request packet. Therefore the slow scan is less likely to miss endpoints in the LAN.



In addition, the slow scanning is considered safer in terms of cybersecurity, because of the larger time breaks between each packet sent. The larger time breaks can make the traffic created by the tool to "disappear" or at least look less suspicious by cybersecurity people and softwares such as firwall or IDS.



Therefore, overall the slow scan in better for you, and if you don't care too much about performance and speed you better use it.

### How to execute Artemis?

very simple - use the command line and give an argument based on the kind of scanning you wish to execute.

artemis -ff --> for extremely fast scanning

artemis -f --> for fast scanning

artemis -s --> for slow scanning

artemis -ss --> for extremely slow scanning

artemis -h --> for help message




