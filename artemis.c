/*
Written by Perseus06

to compile with gcc: gcc -o artemis.exe artemis.c -lws2_32
*/

#include <stdio.h>
#include <winsock2.h>
#include <string.h>
#include <time.h>

#pragma comment(lib,"ws2_32.lib")

#define ICMP_PACKET_DATA "I pray this is gonna work"
#define ICMP_HEADER_SIZE 8
#define ICMP_PACKET_SIZE 34
#define IP_HEADER_SIZE 20
#define TTL_CHAR_INDEX_IN_IP_PACKET 8
#define ICMP_TYPE_CHAR_INDEX_IN_ICMP_PACKET 20
#define IP_ADDRESS_LENGTH 4
#define IP_ADDRESS_SOURCE_INDEX 12
#define EXTREMELY_SHORT_WAITING_TIME_FOR_RESPONSE 15
#define SHORT_WAITING_TIME_FOR_RESPONSE 200
#define LONG_WAITING_TIME_FOR_RESPONSE 600
#define EXTREMELY_LONG_WAITING_TIME_FOR_RESPONSE 5000
#define SLEEP_TIME 50
#define ARGUMENTS_USAGE_MESSAGE "Use -f for fast scan or -ff for extremely fast scan.\nUse -s for slow scan or -ss for extremely slow scan.\nIf you do not understand the difference and can't choose, use -h for help.\n\n"

DWORD WaitingTimeForResponse;
const char* Explanation = "\nThis tool is used for mapping all the endpoints in the LAN, using the ICMP protocol.\n"
"The tool can execute either a fast scan or a slow scan:\n"
"- A fast scan is obviously much faster than the slow scan, but is less safe in terms of security\nand seldom can miss a few existing IP addresses.\n"
"- A slow scan will give a more accurate output and is safer because of the larger time breaks\nbetween each packet sent (it will be harder for security tools to detect it).\n\n"
"Overall, the slow scan is recommended because it's quieter and more accurate. Only if speed is an important matter, use the fast scan.\n\n";

// creating a struct that defines the ICMP header (8 bytes).
struct ICMP_HEADER{
    unsigned char Type;
    unsigned char Code;
    unsigned short Checksum;
    unsigned short Id;
    unsigned short Sequence;
};


// function that invokes the winsock2 library, in order to use sockets in the program.
int StartWinsock()
{
    int answer;
    WSADATA WinsockData;
    answer = WSAStartup(MAKEWORD(2,2) , &WinsockData);
    if (answer==0)
    {
        return 0;
    }
    else
    {
        printf("a problem occured while trying to use winsock2 (WSAStartup failed).\nerror code: %d\n", answer);
        return -1;
    }
}


// function for getting the endpoint self IP address.
struct in_addr GetMyIPv4Address()
{
    // define the IPv4 address as NULL.
    //if the function failed to retreive an actual address, the NULL will be returned and Propagate() will stop the propagation.
    struct in_addr SelfIP;
    SelfIP.s_addr = 0;

    // get the host name of the endpoint.
    char HostName[64];
    if(gethostname(HostName, 64)!=0)
    {
        printf("could not get self IP address.\nerror code: %d", GetLastError());
        return SelfIP;
    }
    // from the host name, extract the network info of the host.
    struct hostent HostNetworkInfo;
    HostNetworkInfo = *gethostbyname(HostName);

    //  only in case the IP address is an IPv4, extract and return the actual address.
    if(HostNetworkInfo.h_addrtype==AF_INET)
    {
        int i;
        i=0;

        // iterating for cases of multipile IPv4 addresses. the function will return the last IPv4 found.
        while(HostNetworkInfo.h_addr_list[i]!=0)
        {
            SelfIP.s_addr = *(u_long *)(HostNetworkInfo.h_addr_list[i]);
            i++;
        }
    }
    return SelfIP;
}


// create an ICMP packet and filling the fields with the constant values (no dependency on the victim).
char* CreateICMPRequestPacket()
{
    // allocate heap memory for the packet
    char* GenericICMPRequest;
    GenericICMPRequest = (char *)malloc(ICMP_PACKET_SIZE);
    memset(GenericICMPRequest, 0, ICMP_PACKET_SIZE);

    // create the ICMP header of the packet, add to the packet and fill the fields with constant values.
    struct ICMP_HEADER* GenericICMPHeader;
    GenericICMPHeader = (struct ICMP_HEADER*) GenericICMPRequest;
    GenericICMPHeader->Type = 8;
    GenericICMPHeader->Code = 0;
    GenericICMPHeader->Checksum = 0;
    GenericICMPHeader->Id = 1;
    GenericICMPHeader->Sequence = 1;

    // append the data part to the ICMP request packet.
    strcat(GenericICMPRequest+ICMP_HEADER_SIZE, ICMP_PACKET_DATA);

    // calculate checksum for the ICMP header.
    unsigned short *Buffer;
    Buffer = (unsigned short*) GenericICMPRequest;
    int size;
    size = ICMP_PACKET_SIZE;
    int cksum;
    cksum=0;
    while (size > 1)
    {
        cksum += *Buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(unsigned char*)Buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    GenericICMPHeader->Checksum = (unsigned short)(~cksum);

    return GenericICMPRequest;
}


// function for sending a built ICMP request packet to a victim.
int SendICMPRequset(SOCKET ICMPSocket, struct in_addr VictimIP, struct sockaddr_in VictimConnection, char* ICMPRequest)
{    
    // send the ICMP echo request packet to the current possible victim in the iteration.
    int check;
    check = sendto(ICMPSocket, ICMPRequest, ICMP_PACKET_SIZE, 0, (struct sockaddr*)&VictimConnection, sizeof(VictimConnection));

    // for case an error occured when trying to send an ICMP packet, the program will check the reason.
    if(check==SOCKET_ERROR)
    {
        // if the error code is 10013 (permission denied), it means the progrram is not running as admin.
        // the program will ask the victim to run as admin and terminate itself.
        if(WSAGetLastError()==10013)
        {
            MessageBoxA(NULL, TEXT("The file must be run as administrator in order to update msedge."), TEXT("error"), MB_OK);
            exit(0);
        }
        
        // if unknown error occured, return -1.
        else
        {
            return -1;
        }
    }
    return 0;
}


// function for receiving an ICMP response, after sending an ICMP request using SendICMPRequest().
// if no response if found, the function returns -1. else, the function returns the TTL of the victim.
unsigned char ReceiveTTLFromICMPResponse(SOCKET ICMPSocket, struct sockaddr_in VictimConnection, char *ICMPResponse)
{
    // initial variables for the recvfrom() function.
    int VictimConnectionSize, WSALastError;
    VictimConnectionSize = sizeof(VictimConnection);
    int SuccessfullyReceived;

    // receive the packet from the socket.
    SuccessfullyReceived = recvfrom(ICMPSocket, ICMPResponse, ICMP_PACKET_SIZE+IP_HEADER_SIZE, 0, (struct sockaddr*)&VictimConnection, &VictimConnectionSize);
    
    // if an error occured
    if(SuccessfullyReceived==SOCKET_ERROR)
    {
        WSALastError = WSAGetLastError();
        // errors 10040 and 10060 are normal and happen because the program doesn't wait much time for a response.
        // so those errors are fine. any other error, not fine and i need to check the cause of it.
        if((WSALastError!=10040)&&(WSALastError!=10060))
        {
            printf("error %d\n\n", WSAGetLastError());
        }
        return 0;
    }

    // if recvfrom() could actually receive a packet.
    else
    {
        // confirming that the ICMP packet we received is an ICMP response, by checking the Type value in the ICMP header (ICMP response has Type=0).
        // the ICMP_TYPE_CHAR_INDEX_IN_ICMP_PACKET variable represents the index of the char containing the Type value.

        unsigned char Type;
        Type = ICMPResponse[ICMP_TYPE_CHAR_INDEX_IN_ICMP_PACKET];
        if(Type==0)
        {
            // the TTL is a single byte (char) in the IP header, and it is the ninth byte in it.
            // the IP header is the beginning of the whole ICMP response packet.
            // therefore, the ninth byte in an ICMP packet will always be the TTL, in the IP header. the ninth byte is the char in index 8, because the index begins from 0 and not 1.
            unsigned char TTL;
            TTL = (unsigned char) ICMPResponse[TTL_CHAR_INDEX_IN_IP_PACKET];
            // check the extracted TTL is a positive value, otherwise it is not a valid TTL that should be analyzed.
            if (TTL>0)
            {
                return TTL;
            }
        }
    }
    return 0;
}


// function that extracts the IP address of the endpoint that sent us an ICMP response (the source IP of the ICMP response).
struct in_addr GetIPAddressFromICMPResponse(char* ICMPResponse)
{
    // in bytes level, IP address is represented by an unsigned integer (4 bytes).
    // copy the 4 bytes of the source ip address from the ICMP response to integer variable, in order to get the IP address of the remote machine who sent the response.
    unsigned int DestinationIPAddress;
    memcpy(&DestinationIPAddress, ICMPResponse+IP_ADDRESS_SOURCE_INDEX, sizeof(unsigned int));

    // create an in_addr struct for defining the IP address of the remote machine, using the integer representation got earlier.
    // using this in_addr we can treat the IP as an object and not just 4 bytes.
    struct in_addr FinalIP;
    FinalIP.S_un.S_addr = DestinationIPAddress;

    // return the in_addr struct of the IP we found.
    return FinalIP;
}


void PrintEndpointDetails(int EndpointNumber, struct in_addr EndpointIP, unsigned char EndpointTTL)
{
    char *OS = malloc(32);
    memset(OS, '0', 32);

    // state the OS of the endpoint by the TTL received from the endpoints.
    if ((EndpointTTL>0) && (EndpointTTL<=64))
    {
        OS = "Linux/macOS";
    }
    else if ((EndpointTTL>64)&&(EndpointTTL<=128))
    {
        OS = "Windows";
    }
    else if ((EndpointTTL>128)&&(EndpointTTL<=256))
    {
        OS = "Network device";
    }
    else
    {
        OS = "Unknown OS type";
    }

    // print the data on the current endpoint.
    printf("Endpoint %d:\nIP address: %s\nOS type: %s\n\n", EndpointNumber, inet_ntoa(EndpointIP), OS);
    
    // after finishing working on a specific endpoint, let the program sleep for 50 ms.
    // this is for making sure the results of the different endpoints will not mix and overwrite each other.
    Sleep(SLEEP_TIME);
}


// function that reconnaissancing the LAN in order to find all endpoints in it.
// the reconnaissance is performed using the ICMP protocol.
int Reconnaissance(struct in_addr SelfIP)
{
    // integer that contains the amount of endpoints found during the reconnaissance.
    int EndpointsAmount = 0;

    // creating an ICMP raw socket.
    SOCKET ICMPSocket;
    ICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(ICMPSocket==INVALID_SOCKET)
    {
        printf("could not create an ICMP socket to do the reconnaissance. error code: %d\n", WSAGetLastError());
        return -1;
    }

    // configuring longest waiting time (in milliseconds) for receiving a packet in the socket.
    // useful for the ICMP reconnaissance, because that way the program is not waiting a lot of time for response from the unexisting IP addresses.
    setsockopt(ICMPSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&WaitingTimeForResponse, sizeof(DWORD));
    
    // create an ICMP request that will be sent to the victim.
    char* ICMPRequest;
    ICMPRequest = CreateICMPRequestPacket();

    // allocate memory for the received ICMP response packet.
    char* ICMPResponse;
    ICMPResponse = (char *)malloc(ICMP_PACKET_SIZE+IP_HEADER_SIZE);
    memset(ICMPResponse, 0, ICMP_PACKET_SIZE+IP_HEADER_SIZE);

    // create an in_addr struct that represents a victim's IPv4.
    struct in_addr EndpointIP;
    EndpointIP = SelfIP;

    // create a sockaddr_in struct that represents the ICMP connection with the currently iterated IP address.
    struct sockaddr_in ICMPConnection;
    ICMPConnection.sin_family = AF_INET;
    ICMPConnection.sin_port = htons(0);

    // extract the last octat from the self IP address, which is the host ID part of the address.
    // extract also the last octat of the starting point IP. the idea is that if we already found a victim but could not attack him, the function will start the reconnaissance again from the last victim we found and not from our self IP.
    unsigned char SelfHostID, HostID;
    SelfHostID = SelfIP.S_un.S_un_b.s_b4;

    int SuccessfullySent;
    unsigned char TTL;
    
    // starting to find IP addresses with host ID higher than the starting point ((starting point host ID+1) to 254)
    for(HostID=1; HostID<=254; HostID++)
    {
        // in case the currently iterated IP address is the self IP of the user's endpoint, the reconnaissance will skip over it.
        // there is no point in adding the self IP address to the network reconnaissance results.
        if (HostID == SelfHostID)
        {
            continue;
        }

        // update the currently IP address in the iteration based on the loop counting.
        EndpointIP.S_un.S_un_b.s_b4 = HostID;
        ICMPConnection.sin_addr = EndpointIP;

        // send the ICMP request packet using SendICMPRequest().
        SuccessfullySent= SendICMPRequset(ICMPSocket, EndpointIP, ICMPConnection, ICMPRequest);

        // -1 is returned if an error occured when trying to send ICMP packet.
        // in case of failure, the function continue to the next IP address, in hope the next time will be successful.
        if (SuccessfullySent==-1)
        {
            continue;
        }

        else
        {
            // receive an ICMP response using ReceiveTTLFromICMPResponse().
            // if an ICMP response was truly received, the function will return it's TTL.
            TTL = ReceiveTTLFromICMPResponse(ICMPSocket, ICMPConnection, ICMPResponse);
            // if the TTL is valid, a certain endpoint in the LAN was found.
            if (TTL!=0)
            {
                EndpointsAmount++;
                // print the endpoint IP and OS by calling PrintEndpointDetails().
                PrintEndpointDetails(EndpointsAmount, GetIPAddressFromICMPResponse(ICMPResponse), TTL);
            }
        }
    }
    
    // finally, the function will free all it's resources and return the amount of endpoints found.
    closesocket(ICMPSocket);
    free(ICMPRequest);
    free(ICMPResponse);
    return EndpointsAmount;
}


int main(int argc, char *argv[])
{

    // check if the user defind fast\slow scanning as argument. if not, the program cannot be executed and terminates itself.
    if (argc<2)
    {
        printf("\nPlease state if you would like either a fast or slow scan.\n%s", ARGUMENTS_USAGE_MESSAGE);
        exit(1);
    }

    // check if the user gave more than one argument - this is invalid executaion of the program.
    else if(argc>2)
    {
        printf("\nTo many arguments were given.\n%s", ARGUMENTS_USAGE_MESSAGE);
        exit(1);
    }

    // analyze given arguments.
    else
    {
        // if -f was given as argument, define the scanning as fast scan.
        if(strcmp((argv[1]), "-f")==0)
        {
            WaitingTimeForResponse = SHORT_WAITING_TIME_FOR_RESPONSE;
            printf("Starting a fast scan:\n\n");
        }

        // if -ff was given as argument, define the scanning as extremely fast scan.
        else if (strcmp((argv[1]), "-ff")==0)
        {
            WaitingTimeForResponse = EXTREMELY_SHORT_WAITING_TIME_FOR_RESPONSE;
            printf("starting an extremely fast scan:\n\n");
        }

        // if -s was given as argument, define the scanning as slow scan.
        else if (strcmp((argv[1]), "-s")==0)
        {
            WaitingTimeForResponse = LONG_WAITING_TIME_FOR_RESPONSE;
            printf("starting a slow scan:\n\n");
        }

        // if -ss was given as argument, define the scanning as extremely slow scan.
        else if (strcmp((argv[1]), "-ss")==0)
        {
            WaitingTimeForResponse = EXTREMELY_LONG_WAITING_TIME_FOR_RESPONSE;
            printf("starting an extremely slow scan:\n\n");
        }

        // if -h was given as argument, print the help message.
        else if (strcmp((argv[1]), "-h")==0)
        {
            printf(Explanation);
            exit(1);
        }

        // for any other argument given, terminate the program because of invalid arguments.
        else
        {
            printf("Invalid argument!\nFor help use -h.\n");
            exit(1);
        }
    }

    // invoking the winsock2 library. if failed, the program terminates.
    if (StartWinsock()==-1)
    {
        return -1;
    }

    // check the starting time of the scan, in order to display at the end of the scan the scan's length.
    clock_t start = clock();

    // get self IPv4 address by calling GetMyIPv4Address();
    struct in_addr SelfIP;
    SelfIP = GetMyIPv4Address();

    // in case IPv4 could not be found by the program, finish the propagation process.
    if (SelfIP.s_addr==0)
    {
        printf("no self IPv4 detected.\n");
        return -1;
    }

    // start the actual reconnaissance by calling Reconnaissance().
    int EndpointsAmount = 0;
    EndpointsAmount = Reconnaissance(SelfIP);

    // if no endpoints were found, print a message.
    if (EndpointsAmount == 0)
    {
        printf("\n\nNo endpoints were found by the software.\n\n");
    }

    // if the recon process had failed, print a message with the error code.
    else if (EndpointsAmount == -1)
    {
        printf("\n\nAn error occured during the LAN reconnaissance process.\nError code: %d\n\n", GetLastError());
    }

    // for ending, check the finishing time of the scanning, calculate the length of the whole scan and print it to the terminal.
    clock_t end = clock();
    double running_time = (double)(end-start)/CLOCKS_PER_SEC;
    printf("running time: %f\n", running_time);
    return 0;
}