def extract_features(packet_size, dst_port, protocol):
    protocol_map = {
        "TCP": 1,
        "UDP": 2,
        "ICMP": 3
    }

    protocol_code = protocol_map.get(protocol, 0)

    # Replace None ports
    if dst_port is None:
        dst_port = 0

    return [packet_size, dst_port, protocol_code]