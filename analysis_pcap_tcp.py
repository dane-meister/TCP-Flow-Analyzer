import dpkt
import socket


# Define the maximum port and window size
def get_tcp_window_scale_option(tcp_options):
    for opt in dpkt.tcp.parse_opts(tcp_options):
        if opt[0] == dpkt.tcp.TCP_OPT_WSCALE:
            scale_factor = int.from_bytes(opt[1], byteorder='big')
            return 2 ** scale_factor
    return 1  # Default scale if option is not present


def analysis_pcap_tcp(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        tcp_flows = {}
        sender_ip = None

        for timestamp, buf in pcap:
            try:
                # Parse the packet
                eth = dpkt.ethernet.Ethernet(buf)
                # Ensure the packet is an IP packet
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                # Ensure the packet is a TCP packet
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data

                # Extract relevant information from the packet
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)

                # Determine if this is the first packet in the conversation to set the sender
                if sender_ip is None and (tcp.flags & dpkt.tcp.TH_SYN):
                    sender_ip = src_ip  # The sender is the one who sends the first SYN
                if sender_ip != dst_ip and sender_ip != src_ip and (tcp.flags & dpkt.tcp.TH_SYN):
                    sender_ip = src_ip  # The sender is the one who sends the first SYN
                # If this packet is not from the sender, ignore it
                if src_ip != sender_ip:
                    continue

                # Extract the source and destination ports
                src_port = tcp.sport
                dst_port = tcp.dport

                # Sort IP addresses and ports to identify flows uniquely irrespective of direction.
                flow_id = (src_ip, src_port, dst_ip, dst_port)

                # Ensure flow is initialized for any TCP packet, adjusting the logic accordingly.
                if flow_id not in tcp_flows:
                    tcp_flows[flow_id] = {
                        'start_time': None, 'end_time': timestamp, 'data_bytes': 0,
                        'transactions': [], 'handshake_complete': False, 'packet_count': 0, 
                        'flow_tuple': flow_id, 'window_scale': 1, 'syn': False, 'fin': False,
                        'initial_rtt': None, 'rtt_estimation': None, 'cwnd_packets': [], 
                        'last_packet_time': None, 'ack_freq': {}, 'seq_numbers': {},   
                        'triple_dup_acks': 0, 'timeouts': 0, 'retransmissions': -1, 'seen_seqs': {},
                    }

                # Get the flow object
                flow = tcp_flows[flow_id]
                flow['end_time'] = timestamp

                # Update the flow information
                if flow['start_time'] is None and tcp.flags & dpkt.tcp.TH_SYN:
                    flow['start_time'] = timestamp  # Set the start time of the flow
                    flow['window_scale'] = get_tcp_window_scale_option(tcp.opts) # Get the window scale option
                if flow['start_time'] is not None:
                    flow['data_bytes'] += len(tcp)
                    flow['packet_count'] += 1
                    
                # Check for handshake completion
                if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                    flow['syn'] = True
                if tcp.flags & dpkt.tcp.TH_ACK and flow['syn'] and not flow['handshake_complete']:
                    flow['handshake_complete'] = True

                # Check for flow termination
                if tcp.flags & dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST:
                    flow['fin'] = True
                
                
                # Check for data packets
                if flow['handshake_complete'] and len(tcp.data) > 0:
                    # Add the transaction to the flow if one of first 2
                    if len(flow['transactions']) < 2:
                        flow['transactions'].append((tcp.seq, tcp.ack, tcp.win * flow['window_scale']))

                # Adjusting logic to capture initial RTT and counting packets per RTT
                if tcp.flags & dpkt.tcp.TH_SYN and not flow['initial_rtt']:
                    flow['last_packet_time'] = timestamp  # Mark the time of the SYN packet
                elif tcp.flags & dpkt.tcp.TH_ACK and flow['syn'] and not flow['initial_rtt']:
                    # Assuming this ACK is part of the handshake completion
                    flow['initial_rtt'] = timestamp - flow['last_packet_time']  # Initial RTT estimation
                    flow['rtt_estimation'] = flow['initial_rtt']  # Storing initial RTT as the estimate
                    flow['last_packet_time'] = timestamp  # Resetting for packet counting

                # Logic to count packets per estimated RTT
                if flow['initial_rtt']:
                    time_since_last_packet = timestamp - flow['last_packet_time']
                    if time_since_last_packet < flow['rtt_estimation']:
                        # Still within the same RTT, count the packet
                        if len(flow['cwnd_packets']) == 0:
                            flow['cwnd_packets'].append(1)  # Starting the first count
                        else:
                            flow['cwnd_packets'][-1] += 1  # Increment current RTT's packet count 
                            pass
                    else:
                        # New RTT period, reset packet count
                        if len(flow['cwnd_packets']) < 4:  # Only if we need more CWND sizes
                            flow['cwnd_packets'].append(1)  # Start counting for a new CWND size
                        flow['last_packet_time'] = timestamp  # Resetting for next RTT counting

                if (tcp.flags & dpkt.tcp.TH_ACK) and not (tcp.flags & dpkt.tcp.TH_SYN):
                    ack = tcp.ack
                    # Track ACKs for triple duplicate detection
                    if ack not in flow['ack_freq']:
                        flow['ack_freq'][ack] = 1
                    else:
                        flow['ack_freq'][ack] += 1
                        current_ack_freq = flow['ack_freq'][ack]
                        if current_ack_freq == 4:  # Triple duplicate ACK detected
                            flow['triple_dup_acks'] += 1

                # Track sequence numbers to identify retransmissions
                if tcp.seq not in flow['seq_numbers']:
                    flow['seq_numbers'][tcp.seq] = timestamp
                else:
                    # Check if the packet is a retransmission
                    if timestamp - flow['seq_numbers'][tcp.seq] > 2 * flow['rtt_estimation']: # Timeout threshold
                        flow['timeouts'] += 1

                # Track sequence numbers to detect retransmissions
                seq = tcp.seq
                if flow['handshake_complete'] and seq in flow['seen_seqs'] and flow['seen_seqs'][seq] is True:
                    # If the sequence number has been seen before, it's a retransmission
                    flow['retransmissions'] += 1
                    flow['seen_seqs'][seq] = False
                elif flow['handshake_complete']:
                    # Otherwise, mark the sequence number as seen
                    flow['seen_seqs'][seq] = True

            except Exception as e:
                # Print the error and continue to the next packet
                print(f"Error processing packet: {e}")

    # Output results
    print(f"\nNumber of TCP flows initiated from the sender: {len(tcp_flows)}\n")
    flow_count = 1
    for flow_id, data in tcp_flows.items():
        print(f"Flow {flow_count}:")
        flow_count += 1
        print(f"  Source IP: {data['flow_tuple'][0]}, Source Port: {data['flow_tuple'][1]} -> Destination IP: {data['flow_tuple'][2]}, Destination Port: {data['flow_tuple'][3]}")
        for i, transaction in enumerate(data['transactions'], 1):
            seq_num, ack_num, rec_win_size = transaction
            print(f"  Transaction {i}: Seq Num: {seq_num}, Ack Num: {ack_num}, Rec Win Size: {rec_win_size}")
        if 'end_time' in data and data['end_time'] is not None:
            duration = data['end_time'] - data['start_time']
            throughput = data['data_bytes'] / duration if duration > 0 else 0
            print(f"  Sender Throughput: {throughput} bytes/sec")
            print(f"  == ({data['data_bytes']} bytes sent in {data['end_time'] - data['start_time']} seconds)")
            print(f"  First 3 Congestion Window Sizes: {data['cwnd_packets'][0:3]}")
            print(f"  Retransmissions due to Triple Duplicate ACKs: {data['retransmissions'] - data['timeouts']}")
            print(f"  Retransmissions due to Timeouts: {data['timeouts']}")
        else:
            print("  Incomplete flow.")
        print()


analysis_pcap_tcp('assignment2.pcap')