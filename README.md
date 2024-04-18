## High-Level Summary

The analysis_pcap_tcp program is designed to analyze TCP traffic from a .pcap file to extract and calculate various metrics related to TCP flows initiated by a sender. The program uses the dpkt library to parse the pcap file and extract TCP flows based on the combination of source and destination IP addresses and ports. It identifies the beginning and end of TCP flows marked by SYN and FIN flags, respectively. For each identified flow, the program records the initial transactions, calculates sender throughput, and estimates the congestion window sizes. Additionally, it counts retransmissions due to triple duplicate ACKs and timeouts.

#### Key metrics calculated and extracted for each TCP flow include:

- Flow identification (source port, source IP address, destination port, destination IP address).
- Sequence number, Acknowledgment number, and Receive Window size for the first two transactions.
- Sender throughput (total data sent over the time between the first byte sent and the last acknowledgment received).
- First three congestion window sizes, estimated empirically based on the packets sent in approximately one Round-Trip Time (RTT) intervals.
- The number of retransmissions due to triple duplicate ACKs and timeouts.

### Identifying and Analyzing TCP Flows
#### TCP Flow Identification:
- The program defines a TCP flow as a sequence of packets sharing the same source and destination IP addresses and ports, beginning with a packet flagged with SYN and concluding with a packet flagged with FIN.
- It meticulously records each flow's details, including source/destination IPs and ports, by parsing each packet, leveraging the dpkt library for packet dissection and extraction of TCP, IP, and Ethernet layer information.
- A unique identifier (tuple of source IP, source port, destination IP, destination port) is used to track and differentiate multiple simultaneous flows.
#### Transaction Details
- For each flow, the program captures and reports the sequence number, acknowledgment number, and receive window size of the first two transactions after the TCP connection is established. This includes transactions that may follow immediately after the three-way handshake, with special consideration for packets where the last ACK of the handshake is combined with the first data packet (piggybacking).
- The values are extracted directly from the TCP header of each packet, ensuring accurate representation of the flow's initial communication sequence.
#### Sender Throughput Calculation:
- Throughput is calculated as the total amount of data sent (in bytes) divided by the time from sending the first byte to receiving the last acknowledgment.
- The program accurately measures the duration of each flow and aggregates the size of all sent TCP segments (including headers) to compute the throughput

### Congestion Window Estimation and Retransmission Analysis
#### Congestion Window Estimation:
- The congestion window size, an essential component of TCP's congestion control mechanism, is estimated by counting the number of packets sent in intervals approximately equal to the round-trip time (RTT).
- Initial RTT estimation is derived from the time difference between sending a SYN packet and receiving its corresponding ACK. Subsequent packets are monitored to infer congestion window adjustments based on observed transmission rates and intervals, acknowledging that these estimations are approximations due to the lack of explicit congestion window data in packet headers.
#### Retransmission Detection:
- The program distinguishes between retransmissions caused by triple duplicate ACKs and those initiated by timeout expiration. This differentiation is crucial for understanding the underlying network conditions and TCP's response to perceived packet loss.
- Retransmissions due to triple duplicate ACKs are identified when the program observes four acknowledgments for the same sequence number, indicative of packet loss and subsequent fast retransmission.
- Timeout-triggered retransmissions are detected by tracking the time elapsed since a sequence number was last sent; if this exceeds a dynamically estimated timeout threshold (calculated as twice the estimated RTT), a timeout retransmission is assumed.

### Implementation and Theoretical Foundations
The program's implementation is grounded in TCP's foundational principles, including connection management (via SYN and FIN flags), flow control (through window scaling and acknowledgment numbers), and congestion control (observed through empirical estimation of congestion window sizes and retransmission behaviors). It intricately parses each packet to extract and compute the required metrics, ensuring accuracy and insight into each TCP flow's characteristics and the sender's network performance.

Through meticulous packet analysis and application of TCP protocol understanding, the analysis_pcap_tcp program offers a comprehensive toolkit for network analysts and researchers to dissect and understand TCP flows within pcap files, revealing intricate details about data transmission patterns, efficiency, and network conditions.

## Instructions on How to Run the Code

### Prerequisites:
- Ensure Python 3.x is installed on your system.
- Install the dpkt library if not already installed. This can be done using pip:
pip install dpkt
### Setup:
- Place the .pcap file in an accessible location on your system. This file should contain the TCP traffic you wish to analyze.
### Run the Program
- Navigate to the directory containing the analysis_pcap_tcp.py file in a terminal or command prompt.
- Run the program by passing the path to your .pcap file as an argument. For example:
python analysis_pcap_tcp.py /path/to/your/file.pcap
- Replace /path/to/your/file.pcap with the actual path to your .pcap file.

OR 

- Open the analysis_pcap_tcp.py in an IDE and call the analysis_pcap_tcp function with the pcap file path as an argument.

### Review the Output
The program will print the analysis results to the console. This includes the number of TCP flows initiated from the sender, details for each TCP flow such as the flow identification, transaction details, sender throughput, estimated congestion window sizes, and the number of retransmissions due to triple duplicate ACKs and timeouts.

