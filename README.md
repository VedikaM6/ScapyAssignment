# ScapyAssignment
Network Reconaissance And Security Analysis


## Project Instructions: 
In this programming project, you are asked to:

#### Stage 1 - Code a Scapy program which will allow you to do minimally invasive reconnaissance on a remote
#### networked device
#### Stage 2 - Deploy the program from Stage 1 to gather reconnaissance information about a set of real-world
#### Web servers/hosts
#### Sage 3 - Write a report about the main findings from Stage 2.


### INSTRUCTIONS ABOUT STAGE 1 
Your Scapy program should take the IPv4 address of a remote networked device as input parameter and –
following an appropriate packet exchange with the given device – provide (i.e., print out) the following as its
output:

#### A: Device with this IP address responds to ICMP-ping request pkts [yes/no]: <obtained answer>
(if answer to A is ‘yes’, output for B should also be provided)

#### B: IP-ID counter observed in ICMP-reply pkts [zero/incremental/random]: <obtained answer>

#### C: TCP port 80 on this device is open [yes/no]: <obtained answer>
(if answer to C is ‘yes’, output for D and E should also be provided)

#### D: IP-ID counter observed in TCP replies [zero/incremental/random]: <obtained answer>

#### E: SYN cookies deployed by service running on TCP port 80 [yes/no]: <obtained answer>
(if answer to E is ‘no’, output for F should also be provided)

#### F: max # of SYN-ACK pkts retransmitted by service on TCP port 80: <obtained answer>

#### G: Likely OS system deployed on this device [Linux/Windows]: <obtained answer>


### INSTRUCTIONS ABOUT STAGE 2
In Appendix 1, you will find a list of DNS names corresponding to Web servers of 10 largest Canadian universities
(by enrollment). Your task in Stage 2 is to run the script from Stage 1 on each Web server from the given list, and
then analyze/summarize the collected results.


### INSTRUCTIONS ABOUT STAGE 3
Based on the results collected in Stage 2, you need to write a short report which will include the following
information:
1) Overall number of servers (from the provided set) that respond to ICMP ping-requests.
2) Percentages of responsive servers from 1) with zero/incremental/random IP-ID in ICMP pkts.
3) Percentage of servers with port 80 open (i.e., responsive).
4) Percentages of responsive servers form 3) with zero/incremental/random IP-ID in TCP pkts.
5) Percentage of responsive servers from 3) that deploys SYN cookies.
6) Percentage of servers with Linux/Windows OS.
