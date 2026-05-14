import os
import socket
from pathlib import Path

from aes_socket_utils import (
    LENGTH_HEADER_SIZE,
    decrypt_aes_cbc,
    parse_key_packet,
    parse_length_header,
    recv_exact,
)

HOST = os.getenv("RECEIVER_HOST", "0.0.0.0")
DATA_PORT = int(os.getenv("DATA_PORT", "6000"))
KEY_PORT = int(os.getenv("KEY_PORT", "6001"))
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "")
LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")


def _make_server(host: str, port: int, timeout: float) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(timeout)
    srv.bind((host, port))
    srv.listen(1)
    return srv


def main() -> None:
    lines = []

    # Bind both ports before accepting any connection so the sender never gets
    # ConnectionRefused on DATA_PORT while receiver is still processing KEY_PORT.
    key_server = _make_server(HOST, KEY_PORT, TIMEOUT)
    data_server = _make_server(HOST, DATA_PORT, TIMEOUT)

    try:
        print(f"[*] Receiver đang lắng nghe kênh khóa tại {HOST}:{KEY_PORT}", flush=True)
        lines.append(f"[*] Receiver đang lắng nghe kênh khóa tại {HOST}:{KEY_PORT}")

        conn, _ = key_server.accept()
        with conn:
            conn.settimeout(TIMEOUT)
            key_len_header = recv_exact(conn, 4)
            key_len = int.from_bytes(key_len_header, "big")
            rest = recv_exact(conn, key_len + 16)
            key_packet = key_len_header + rest

        key, iv = parse_key_packet(key_packet)

        line = "[+] Đã nhận AES key và IV."
        print(line)
        lines.append(line)

        line = f"[*] Receiver đang lắng nghe kênh dữ liệu tại {HOST}:{DATA_PORT}"
        print(line)
        lines.append(line)

        conn, _ = data_server.accept()
        with conn:
            conn.settimeout(TIMEOUT)
            length_header = recv_exact(conn, LENGTH_HEADER_SIZE)
            length = parse_length_header(length_header)
            ciphertext = recv_exact(conn, length)
            data_packet = length_header + ciphertext

        if len(ciphertext) != length:
            raise ValueError("Ciphertext nhận được không khớp length header.")

        line = "[+] Đã nhận ciphertext."
        print(line)
        lines.append(line)

        plaintext = decrypt_aes_cbc(key, iv, ciphertext)
        message = plaintext.decode("utf-8", errors="replace")

        lines.extend([
            "[+] Đã giải mã thành công.",
            f"[+] Bản tin gốc: {message}",
        ])

        print("[+] Đã giải mã thành công.")
        print(f"[+] Bản tin gốc: {message}")

        if OUTPUT_FILE:
            Path(OUTPUT_FILE).write_bytes(plaintext)

        if LOG_FILE:
            Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
            Path(LOG_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")

    finally:
        key_server.close()
        data_server.close()


if __name__ == "__main__":
    main()
