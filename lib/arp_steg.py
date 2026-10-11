"""Modified ARPNetSteg: covert data carried in ARP-reply source MAC addresses.

Each packet carries 44 bits of data + a 4-bit control quad. Both sides derive
the same random IP list and XOR key stream from a shared seed.
"""


def _hex_encode(data_string):
    return data_string.encode("utf-8").hex()


def _hex_decode(hex_string):
    return bytes.fromhex(hex_string).decode("utf-8")


def _hex_to_chunks(hex_string, chunk_size=11):
    """Split hex into 11-digit chunks, tagging each with a control quad.

    Control quad: '0' more follows, 'f' last chunk full, '1'-'a' last chunk
    with that many padding zeros.
    """
    chunks = []
    total_len = len(hex_string)
    pos = 0

    while pos < total_len:
        remaining = total_len - pos
        piece = hex_string[pos : pos + chunk_size]

        if remaining > chunk_size:
            chunks.append((piece, "0"))
        elif remaining == chunk_size:
            chunks.append((piece, "f"))
        else:
            padding_count = chunk_size - remaining
            padded = piece + "0" * padding_count
            control = format(padding_count, "x")
            chunks.append((padded, control))

        pos += chunk_size

    return chunks


def _xor_encrypt(data_int, key_int):
    return data_int ^ key_int


def _int_to_mac(value):
    hex_str = format(value, "012x")
    return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2))


def _mac_to_int(mac_str):
    return int(mac_str.replace(":", ""), 16)


def _encode_payload(data_hex_11, control_quad):
    combined = data_hex_11 + control_quad
    return int(combined, 16)


def _decode_payload(value_48bit):
    hex_str = format(value_48bit, "012x")
    return (hex_str[:11], hex_str[11])


def _scan_subnet(interface, timeout=2.0):
    """ARP-scan 192.168.100.0/24 and return the set of responding IPs."""
    from scapy.all import Ether, ARP, srp

    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.100.0/24"),
        timeout=timeout,
        iface=interface,
        verbose=False,
    )
    allocated = {rcv[ARP].psrc for _, rcv in ans}
    print(f"[ARP] Subnet scan: found {len(allocated)} allocated IPs")
    return allocated


def _filter_usable_ips(random_ips, allocated_ips):
    """Drop allocated IPs and duplicates, preserving order."""
    seen = set()
    result = []
    for ip in random_ips:
        if ip not in allocated_ips and ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def arp_send(data_string, seed, sender_ip, receiver_ip, interface):
    """Send data_string covertly through ARP-reply MAC addresses."""
    import random
    import time
    from scapy.all import Ether, ARP, sendp, sniff
    from lib.config import generate_random_ips, generate_48bit_key

    hex_data = _hex_encode(data_string)
    chunks = _hex_to_chunks(hex_data)
    total_chunks = len(chunks)

    rng = random.Random(seed)

    # A scan can't see the scanner itself, so add our own IP to keep both
    # sides' allocated sets identical.
    allocated_ips = _scan_subnet(interface) | {sender_ip}
    random_ips = generate_random_ips(seed)
    usable_ips = _filter_usable_ips(random_ips, allocated_ips)

    if len(usable_ips) < total_chunks:
        raise RuntimeError(
            f"[ARP] Not enough usable IPs: need {total_chunks}, have {len(usable_ips)}"
        )

    print(f"[ARP] Sending {total_chunks} chunks via ARP covert channel")

    receiver_mac = None

    for i, (chunk_hex, control_quad) in enumerate(chunks):
        target_ip = usable_ips[i]

        payload_int = _encode_payload(chunk_hex, control_quad)
        key_int = generate_48bit_key(rng)
        encrypted_int = _xor_encrypt(payload_int, key_int)
        covert_mac = _int_to_mac(encrypted_int)

        # Wait for the receiver to ARP-request this target IP before replying
        pkts = sniff(
            filter="arp",
            lfilter=lambda pkt, tip=target_ip: (
                pkt.haslayer(ARP)
                and pkt[ARP].op == 1
                and pkt[ARP].pdst == tip
            ),
            count=1,
            timeout=11,
            iface=interface,
        )

        if not pkts:
            raise RuntimeError(
                f"[ARP] Timeout waiting for ARP request for {target_ip} "
                f"(chunk {i + 1}/{total_chunks})"
            )

        if receiver_mac is None:
            receiver_mac = pkts[0][ARP].hwsrc
            print(f"[ARP] Receiver MAC: {receiver_mac}")

        # Set the covert MAC on both Ether.src and ARP.hwsrc
        reply = (
            Ether(dst=receiver_mac, src=covert_mac)
            / ARP(
                op=2,
                hwsrc=covert_mac,
                psrc=target_ip,
                hwdst=receiver_mac,
                pdst=receiver_ip,
            )
        )
        sendp(reply, iface=interface, verbose=False)
        print(f"[ARP] Sent chunk {i + 1}/{total_chunks}")

    print("[ARP] All chunks sent")


def arp_receive(seed, sender_ip, receiver_ip, interface):
    """Pull covert data back out of the sender's ARP-reply MAC addresses."""
    import random
    import time
    from scapy.all import Ether, ARP, sendp, AsyncSniffer
    from lib.config import generate_random_ips, generate_48bit_key

    rng = random.Random(seed)

    allocated_ips = _scan_subnet(interface) | {receiver_ip}
    random_ips = generate_random_ips(seed)
    usable_ips = _filter_usable_ips(random_ips, allocated_ips)

    print("[ARP] Listening for incoming ARP covert data...")

    received_hex = ""
    chunk_count = 0
    ip_index = 0

    while True:
        if ip_index >= len(usable_ips):
            raise RuntimeError("[ARP] Ran out of usable IPs before transmission completed")

        target_ip = usable_ips[ip_index]
        ip_index += 1

        key_int = generate_48bit_key(rng)

        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip)

        # Start the sniffer before sending so we don't miss a fast reply.
        reply_mac = None
        for attempt in range(3):
            sniffer = AsyncSniffer(
                filter="arp",
                lfilter=lambda pkt, tip=target_ip: (
                    pkt.haslayer(ARP)
                    and pkt[ARP].op == 2
                    and pkt[ARP].psrc == tip
                ),
                count=1,
                iface=interface,
            )
            sniffer.start()
            time.sleep(0.2)

            sendp(request, iface=interface, verbose=False)

            sniffer.join(timeout=10)
            pkts = sniffer.results or []
            if not pkts:
                sniffer.stop(join=False)

            if pkts:
                reply_mac = pkts[0][ARP].hwsrc
                break

            if attempt < 2:
                print(f"[ARP] No reply for {target_ip}, retrying ({attempt + 2}/3)...")

        if reply_mac is None:
            raise RuntimeError(
                f"[ARP] Failed to receive reply for {target_ip} after 3 attempts"
            )

        encrypted_int = _mac_to_int(reply_mac)
        decrypted_int = _xor_encrypt(encrypted_int, key_int)
        data_hex_11, control_quad = _decode_payload(decrypted_int)

        chunk_count += 1
        print(f"[ARP] Received chunk {chunk_count}")

        if control_quad == "0":
            received_hex += data_hex_11
        elif control_quad == "f":
            received_hex += data_hex_11
            break
        else:
            padding_count = int(control_quad, 16)
            received_hex += data_hex_11[: 11 - padding_count]
            break

    result = _hex_decode(received_hex)
    print(f"[ARP] Received {chunk_count} chunks, data reconstructed")
    return result


if __name__ == "__main__":
    import sys

    print("=" * 60)
    print("ARP Steganography Module")
    print("=" * 60)
    print()
    print("Usage: Run on both VMs. Pass 'send' or 'recv' as argument.")
    print("  sudo python3 arp_steg.py send")
    print("  sudo python3 arp_steg.py recv")
    print()

    if len(sys.argv) < 2:
        print("No argument provided. Running quick self-test of helpers...")
        test_data = "1-abc123|2-def456"
        encoded = _hex_encode(test_data)
        chunks = _hex_to_chunks(encoded)
        print(f"  Original:  {test_data}")
        print(f"  Hex:       {encoded}")
        print(f"  Chunks:    {chunks}")
        decoded = _hex_decode(encoded)
        print(f"  Decoded:   {decoded}")
        print(f"  Match:     {decoded == test_data}")
    elif sys.argv[1] == "send":
        from lib.config import SEED_VALUE, SENDER_IP, RECEIVER_IP, INTERFACE

        test_data = "1-390a1400234|2-2dae573130d"
        print(f"[ARP] Sending test data: {test_data}")
        arp_send(test_data, SEED_VALUE, SENDER_IP, RECEIVER_IP, INTERFACE)
    elif sys.argv[1] == "recv":
        from lib.config import SEED_VALUE, SENDER_IP, RECEIVER_IP, INTERFACE

        result = arp_receive(SEED_VALUE, SENDER_IP, RECEIVER_IP, INTERFACE)
        print(f"[ARP] Received data: {result}")
    else:
        print(f"Unknown argument: {sys.argv[1]}")
