# Scapy Assignment 

import sys, socket, time
from scapy.all import IP, ICMP, sr1, TCP, sniff, send, sr

def changeBoolToPartAnswers(partResponse):
    if partResponse:
        return "Yes"
    else:
        return "No"

def changeWebsiteToIP(websiteUrl):
    # Change user input of website into its corresponding IP address
    try:
        websiteIP = socket.gethostbyname(websiteUrl)
        return websiteIP
    except socket.gaierror:
        return None

def allValuesAreSame(tempList):
    if tempList is not None:
        return all(element == tempList[0] for element in tempList)

def isProgressivelyIncreasing(tempList):
    if tempList is not None:
        return all(tempList[i] <= tempList[i + 1] for i in range(len(tempList) - 1))

def partALogic(websiteIP):
    # Craft ICMP echo request packet
    packet = IP(dst=websiteIP)/ICMP()

    # Send the packet and wait for a response
    response = sr1(packet,timeout=10,verbose=False)

    return response
    
def partBLogic(websiteIP):
    # Determine IP-ID counter observed in ICMP-reply packets
    # Create an array to store all IP-ID values from the responses 
    icmp_IPID = []
    
    # Looping through 5 times to recieve IP-ID values for sequential requests
    # Chose 5 as the for-loop count
    for _ in range(3):
        responseTemp = partALogic(websiteIP)
        
        if responseTemp is not None:
            # Storing the IP-ID from the response into the array 
            response = responseTemp
            if response.haslayer(IP) and response is not None:
                ipidTemp = response[IP].id
                icmp_IPID.append(ipidTemp)
                response = None
                responseTemp = None
    
    # After getting all the IP-ID's then we determine the type of counter
    for _ in range(3):
        if allValuesAreSame(icmp_IPID):
            return "Zero"
        elif isProgressivelyIncreasing(icmp_IPID):
            return "Incremental"
        else:
            return "Random"
            
    return "Random"
    
def partCLogic(websiteIP):
    # Determine if TCP port 80 on this device is open
    # First create TCP-SYN packets 
    tcp_synPkt = IP(dst=websiteIP)/TCP(dport=80,flags="S")
    
    # Send packet and if response=SYN-ACK then return true else return false
    response = sr1(tcp_synPkt,timeout=10,verbose=False)
    
    return response
    
def partDLogic(websiteIP):
    # Determine IP-ID counter observed in TCP replies
    # Create an array to store all IP-ID values from the responses 
    tcp_IPID = []
    
    # Looping through 5 times to recieve IP-ID values for sequential requests
    # Chose 5 as the for-loop count
    for _ in range(3):
        responseTemp = partCLogic(websiteIP)
        
        if responseTemp is not None:
            # Storing the IP-ID from the response into the array 
            response = responseTemp
            if response.haslayer(IP):
                ipidTemp = response[IP].id
                tcp_IPID.append(ipidTemp)
                response = None
                responseTemp = None
            
    
    # After getting all the IP-ID's then we determine the type of counter
    for _ in range(3):
        if allValuesAreSame(tcp_IPID):
            return "Zero"
        elif isProgressivelyIncreasing(tcp_IPID):
            return "Incremental"
        else:
            return "Random"
            
    return "Random"

# def partELogic(websiteIP):
    # # Determine if SYN cookies deployed by service running on TCP port 80
    # # Set 2 variables to determine startTime and endTime (which will be 2 minutes)
    # endTime = time.time() + 120
    # responseCount = 0
    # responses = []
    
    # # Create and send 1 TCP-SYN request to destination ip address
    # tcp_synPkt = IP(dst=websiteIP)/TCP(dport=80,flags="S")
    # send(tcp_synPkt, verbose=False)
    
    # # Make sure we recieve all response packets within 2 minutes
    # sniffResponses = sniff(filter='dst port 80', timeout=120)
    
    # # Storing all response packets that meet the filter into an array
    # for pkt in sniffResponses:
        # responses.append(packet)
    
    # # After getting the responseCount value, we now have to determmine if SYN cookies are deployed
    # if len(responses) == 1:
        # return True
    # else:
        # return False
        
def partELogic(websiteIP):
    syn_packet = IP(dst=websiteIP) / TCP(dport=80, flags="S")
    responses, _ = sr(syn_packet, timeout=10, verbose=False, multi=True)
    if len(responses) == 1 and responses is not None:
        return True
    else:
        return False

def partFLogic(websiteIP):
    # Determine max number of SYN-ACK packets retransmitted by service on TCP port 80
    syn_packets = [IP(dst=websiteIP)/TCP(dport=80,flags="S") for _ in range(3)]
    responses, _ = sr(syn_packets, timeout=10, verbose=False)
    return len(responses)

# def partGLogic(websiteIP):
    # # Determine OS system deployed on this device
    # # Send ICMP packet and save response
    # icmpResponse = partALogic(websiteIP)
    # tcpResponse = partCLogic(websiteIP)
    # print(icmpResponse)
    # print(tcpResponse)
    # # Check if icmpResponse is not empty
    # if icmpResponse is not None and tcpResponse is not None:
        # # Set response's TTL value as a variable 
        # responseTTLVal = icmpResponse.ttl
        # responseWindowsSize = tcpResponse[TCP].window
        
        # print(responseTTLVal)
        # print(responseWindowsSize)
    
        # # If ttl value is less than or equal to 64 then it's a Linux system 
        # # If ttl value is greater than 64 and between 128 then its a windows system
        # # If the ttl value does not correspond to either of the above ranges, then it is either another OS system or there was an issue determining the system
        # if responseWindowsSize is not None and responseTTLVal is not None:
            # if responseTTLVal == 64 or (responseWindowsSize == 5840 or responseWindowsSize == 5720 or responseWindowsSize == 32120):
                # return "Linux"
            # elif responseTTLVal == 128 or (responseWindowsSize == 8192 or responseWindowsSize == 65535 or responseWindowsSize == 16384):
                # return "Windows"
            # else:
                # return "Another type of system "
    # else:
        # return "Unable to detect, no response recieved from server"

def partGLogic(websiteIP):
    icmpResponse = partALogic(websiteIP)
    if icmpResponse is not None:
        responseTTLVal = icmpResponse.ttl
        if responseTTLVal is not None:
            if responseTTLVal == 64:
                return "Linux"
            else:
                return "Windows"

if __name__ == "__main__":
    # Check if IPv4 address is provided as an argument
    if len(sys.argv) != 2:
        print("Usage: python ScapyAssignment-VedikaMaheshwari.py <website_url>")
        sys.exit(1)

    # Get the destination IPv4 address from command line argument
    websiteUrl = sys.argv[1]
    
    websiteIP = changeWebsiteToIP(websiteUrl)
    
    if websiteIP is not None:
        # Perform the nested if-else logic of all parts
        partAResponse = partALogic(websiteIP)
        print("A: Device with this IP address responds to ICMP-ping request pkts [yes/no]: ", changeBoolToPartAnswers(partAResponse))
        if partAResponse is not None:
            partBResponse = partBLogic(websiteIP)
            print("B: IP-ID counter observed in ICMP-reply pkts [zero/incremental/random]: ", partBResponse)
    
        partCResponse = partCLogic(websiteIP)
        print("C: TCP port 80 on this device is open [yes/no]: ", changeBoolToPartAnswers(partCResponse))
        if partCResponse is not None:
            partDResponse = partDLogic(websiteIP)
            print("D: IP-ID counter observed in TCP replies [zero/incremental/random]: ", partDResponse)
            partEResponse = partELogic(websiteIP)
            print("E: SYN cookies deployed by service running on TCP port 80 [yes/no]: ", changeBoolToPartAnswers(partEResponse))
            if partEResponse:
                partFResponse = partFLogic(websiteIP)
                print("F: max # of SYN-ACK pkts retransmitted by service on TCP port 80: ", partFResponse)
    
        partGResponse = partGLogic(websiteIP)
        print("G: Likely OS system deployed on this device [Linux/Windows]: ", partGResponse)
    else:
        print("Unable to get IP address of inputted website")