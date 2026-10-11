"""Modified MTNS: covert data hidden in TCP/IP packets via hash-bit marking.

For each chunk the sender brute-forces a random payload until the SHA-256 of the
packet metadata yields the wanted data bits at seed-derived permutation indices.
"""

import hashlib


def _hex_to_binary(hex_string):
    num = int(hex_string, 16)
    expected_bits = len(hex_string) * 4
    return bin(num)[2:].zfill(expected_bits)


def _binary_to_hex(binary_string):
    num = int(binary_string, 2)
    hex_len = (len(binary_string) + 3) // 4
    return format(num, f"0{hex_len}x")


def _generate_permutation(rng, size):
    """Unique random indices in [0, 255]; sender and receiver call this in lockstep.

    Uniqueness matters: duplicate indices would make some bit patterns
    unmatchable (two positions would read the same hash bit).
    """
    return rng.sample(range(256), size)


def _compute_packet_hash(sender_ip, receiver_ip, src_port, dst_port, seq_num, payload_hex):
    """SHA-256 of the packet params, as a 256-char binary string."""
    hash_input = (
        sender_ip + receiver_ip + str(src_port) + str(dst_port)
        + str(seq_num) + payload_hex
    )
    hex_digest = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
    return bin(int(hex_digest, 16))[2:].zfill(256)


def _check_marking(hash_binary, permutation, data_bits):
    """'marked' (data matches, check bit 1), 'unmarked' (no match, bit 0), or 'discard'."""
    extracted = "".join(hash_binary[permutation[i]] for i in range(len(data_bits)))
    check_bit = hash_binary[permutation[-1]]
    if extracted == data_bits and check_bit == "1":
        return "marked"
    elif extracted != data_bits and check_bit == "0":
        return "unmarked"
    else:
        return "discard"


def _hex_encode(data_string):
    return data_string.encode("utf-8").hex()


def _hex_decode(hex_string):
    return bytes.fromhex(hex_string).decode("utf-8")


def mtns_send(data_string, seed, eval_bits, sender_ip, receiver_ip, src_port, dst_port, interface):
    """Send data_string covertly via MTNS hash-bit matching; FIN ends the stream."""
    import os
    import random as random_module
    from scapy.all import IP, TCP, Raw, send
    from lib.config import MTNS_MAX_ITERATIONS

    hex_data = _hex_encode(data_string)
    binary_data = _hex_to_binary(hex_data)
    total_chunks = (len(binary_data) + eval_bits - 1) // eval_bits

    rng = random_module.Random(seed)

    seq_num = 1
    packets_sent = 0
    chunk_index = 0

    for i in range(0, len(binary_data), eval_bits):
        data_bits = binary_data[i : i + eval_bits]
        data_bits = data_bits.ljust(eval_bits, "0")
        chunk_index += 1

        # One permutation per chunk; RNG advances once per chunk
        permutation = _generate_permutation(rng, eval_bits + 1)

        chunk_sent = False
        for attempt in range(MTNS_MAX_ITERATIONS):
            payload_len = random_module.randint(20, 100)
            payload = os.urandom(payload_len)
            payload_hex = payload.hex()

            hash_binary = _compute_packet_hash(
                sender_ip, receiver_ip, src_port, dst_port, seq_num, payload_hex
            )
            result = _check_marking(hash_binary, permutation, data_bits)

            if result == "marked":
                pkt = IP(src=sender_ip, dst=receiver_ip) / TCP(
                    sport=src_port, dport=dst_port, seq=seq_num, flags=0
                ) / Raw(load=payload)
                send(pkt, iface=interface, verbose=False)
                seq_num += 1
                packets_sent += 1
                chunk_sent = True
                print(f"[MTNS] Chunk {chunk_index}/{total_chunks} matched after {attempt + 1} attempts")
                break
            elif result == "unmarked":
                pkt = IP(src=sender_ip, dst=receiver_ip) / TCP(
                    sport=src_port, dport=dst_port, seq=seq_num, flags=0
                ) / Raw(load=payload)
                send(pkt, iface=interface, verbose=False)
                seq_num += 1
                packets_sent += 1
                # keep going -- still owe a marked packet for this chunk
            # discard: don't send, don't advance seq_num, retry

        if not chunk_sent:
            raise RuntimeError(
                f"[MTNS] Failed to match chunk {chunk_index} "
                f"(data_bits='{data_bits}') after {MTNS_MAX_ITERATIONS} attempts"
            )

    fin_pkt = IP(src=sender_ip, dst=receiver_ip) / TCP(
        sport=src_port, dport=dst_port, seq=seq_num, flags="F"
    )
    send(fin_pkt, iface=interface, verbose=False)
    print(f"[MTNS] Transmission complete. Sent {packets_sent} data packets + 1 FIN")


def mtns_receive(seed, eval_bits, sender_ip, receiver_ip, src_port, dst_port, interface):
    """Sniff TCP until FIN, replay the permutation sequence, extract marked bits."""
    import random
    from scapy.all import IP, TCP, Raw, sniff

    rng = random.Random(seed)

    bpf_filter = (
        f"tcp and src host {sender_ip} and dst host {receiver_ip} "
        f"and src port {src_port} and dst port {dst_port}"
    )

    def _is_fin(pkt):
        return pkt.haslayer(TCP) and (pkt[TCP].flags & 0x01)

    print("[MTNS] Listening for incoming MTNS packets...")
    packets = sniff(
        filter=bpf_filter,
        iface=interface,
        stop_filter=_is_fin,
    )
    print(f"[MTNS] Captured {len(packets)} packets (including FIN)")

    received_bits = ""
    pkt_index = 0
    chunk_count = 0

    while pkt_index < len(packets):
        pkt = packets[pkt_index]

        if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x01):
            break

        # One permutation per chunk, matching the sender's sequence
        permutation = _generate_permutation(rng, eval_bits + 1)
        chunk_count += 1

        while pkt_index < len(packets):
            pkt = packets[pkt_index]

            if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x01):
                break

            if not pkt.haslayer(Raw):
                pkt_index += 1
                continue

            payload_hex = bytes(pkt[Raw].load).hex()
            seq_num = pkt[TCP].seq
            hash_binary = _compute_packet_hash(
                sender_ip, receiver_ip, src_port, dst_port, seq_num, payload_hex
            )

            check_bit = hash_binary[permutation[-1]]
            pkt_index += 1

            if check_bit == "1":
                extracted = "".join(
                    hash_binary[permutation[i]] for i in range(eval_bits)
                )
                received_bits += extracted
                print(f"[MTNS] Chunk {chunk_count}: extracted {eval_bits} bits (marked)")
                break
            # unmarked: skip, keep this chunk's permutation

    hex_data = _binary_to_hex(received_bits)
    result = _hex_decode(hex_data)
    print(f"[MTNS] Received {len(received_bits)} bits, {chunk_count} chunks")
    return result


if __name__ == "__main__":
    import sys

    print("=" * 60)
    print("MTNS Steganography Module")
    print("=" * 60)
    print()
    print("Usage: Run on both VMs. Pass 'send' or 'recv' as argument.")
    print("  sudo python3 lib/ip_steg.py send")
    print("  sudo python3 lib/ip_steg.py recv")
    print()

    if len(sys.argv) < 2:
        print("No argument provided. Running quick self-test of helpers...")
        test_hex = "deadbeef"
        binary = _hex_to_binary(test_hex)
        back = _binary_to_hex(binary)
        print(f"  Hex:     {test_hex}")
        print(f"  Binary:  {binary}")
        print(f"  Back:    {back}")
        print(f"  Match:   {back == test_hex}")
    elif sys.argv[1] == "send":
        from lib.config import (
            SEED_VALUE, EVAL_BITS, SENDER_IP, RECEIVER_IP,
            SOURCE_PORT, DEST_PORT, INTERFACE,
        )
        test_data = "3-4f2f91e1fe1c435b924d15f72|4-936cdcafa9fd9499e55fc394e"
        print(f"[MTNS] Sending test data: {test_data}")
        mtns_send(
            test_data, SEED_VALUE, EVAL_BITS,
            SENDER_IP, RECEIVER_IP, SOURCE_PORT, DEST_PORT, INTERFACE,
        )
    elif sys.argv[1] == "recv":
        from lib.config import (
            SEED_VALUE, EVAL_BITS, SENDER_IP, RECEIVER_IP,
            SOURCE_PORT, DEST_PORT, INTERFACE,
        )
        result = mtns_receive(
            SEED_VALUE, EVAL_BITS,
            SENDER_IP, RECEIVER_IP, SOURCE_PORT, DEST_PORT, INTERFACE,
        )
        print(f"[MTNS] Received data: {result}")
    else:
        print(f"Unknown argument: {sys.argv[1]}")
