import argparse
import sys
import socket
import json
import random
import base64
import rsa
import dh
import sec

debug_levels = {"ERROR": 0, "WARN": 1, "INFO": 2, "DEBUG": 2}


class SecureCommunicationApp:
    def __init__(self, role, host="127.0.0.1", port=65432, debug_level=0):
        self.role = role
        self.host = host
        self.port = port
        self.debug_level = debug_level
        self.username = role
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def log(self, message, debug_level):
        """Utility function for logging messages with different levels."""
        lvl_int = debug_levels[debug_level]
        if lvl_int > self.debug_level:
            return

        if lvl_int == 0:
            print(f"\033[91m[{debug_level}] {message}\033[0m")  # Red text
        elif lvl_int == 1:
            print(f"\033[93m[{debug_level}] {message}\033[0m")  # Yellow text
        elif lvl_int == 2:
            print(f"\033[0;36m[{debug_level}] {message}\033[0m")  # Blue text
        else:
            print(f"{debug_level} {message}")

    def start(self):
        if self.role == "server":
            self.start_server()
        elif self.role == "client":
            self.start_client()
        else:
            self.log("Invalid role specified. Use --server or --client.", "ERROR")

    def start_server(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.log(f"Server listening on {self.host}:{self.port}", "INFO")
        client_socket, addr = self.socket.accept()
        self.log(f"Connection established with {addr}", "INFO")
        self.handle_connection(client_socket, server_mode=True)

    def start_client(self):
        self.socket.connect((self.host, self.port))
        self.log(f"Connected to server at {self.host}:{self.port}", "INFO")
        self.handle_connection(self.socket, server_mode=False)

    def handle_connection(self, conn_socket, server_mode):
        try:
            # Placeholder for key exchange
            skey, sid, seq = self.key_exchange(conn_socket, server_mode)

            while True:
                if server_mode:
                    # Server receiving a message
                    data = conn_socket.recv(1024)
                    if not data:
                        break
                    self.log(f"Received (encrypted): {data.decode()}", "DEBUG")

                    # Placeholder for decrypting the message
                    message = self.unprotect_message(data, skey)
                    print(f"Received: {message.decode()}")

                    # Checking for secure termination
                    if message.decode() == f"TERMINATE {sid}":
                        self.log("Terminating connection...", "INFO")
                        break

                    # Send an acknowledgment (protected)
                    response = self.protect_message(b"ACK", skey, sid, seq)
                    conn_socket.sendall(response)
                    self.log(f"Sent: {response.decode()}", "DEBUG")

                else:
                    # Client sending a message
                    message = input("Enter message to send: ").encode()
                    encrypted_message = self.protect_message(message, skey, sid, seq)
                    conn_socket.sendall(encrypted_message)
                    self.log(f"Sent: {encrypted_message.decode()}", "DEBUG")

                    # Receive a response from the server
                    data = conn_socket.recv(1024)
                    if not data:
                        break

                    # Placeholder for decrypting the response
                    self.log(f"Server response (encrypted): {data.decode()}", "DEBUG")
                    response = self.unprotect_message(data, skey)
                    print(f"Server response: {response.decode()}")

                # Increment the sequence number
                seq += 1

        except Exception as e:
            if isinstance(e, EOFError):
                # Send a termination message to the other party
                term_msg = self.protect_message(f"FIN {sid}".encode(), skey, sid, seq)
                conn_socket.sendall(term_msg)
                self.log("Connection terminated.", "INFO")
            else:
                self.log(f"An error occurred: {e}", "ERROR")

        finally:
            conn_socket.close()

    def key_exchange(self, conn_socket, server_mode):
        # Generate a private key and certificate for everyone
        my_pkey = rsa.generate_pkey()
        my_cert = rsa.generate_cert(my_pkey)

        if server_mode:
            # Receive the client's certificate and nonce
            data = conn_socket.recv(2048)
            data = json.loads(data.decode())
            # Verify the client's certificate
            certC = rsa.parse_cert(data["cert"])
            if not rsa.verify_cert(certC):
                raise Exception("Client certificate verification failed.")

            # Send the server's certificate, signature and nonce to the client
            sign = rsa.sign(str(data["nonce"]), my_pkey)
            my_nonce = dh.generate_nonce()
            msg = dict(cert=rsa.encode_cert(my_cert), nonce=my_nonce, nsign=sign)
            conn_socket.sendall(json.dumps(msg).encode())

            # Receive the client's nonce signature, dh_pubkey and dh_signature
            data = conn_socket.recv(2048)
            data = json.loads(data.decode())
            # Verify the client's signature of nonce
            if not rsa.verify_sign(str(my_nonce), data["nsign"], certC):
                raise Exception("Client nonce signature verification failed.")
            # Verify the client's signature of public diffie-hellman key
            if not rsa.verify_sign(str(data["dh_pubkey"]), data["dh_sign"], certC):
                raise Exception("Client dh_pubkey signature verification failed.")

            # Send the server's dh_pubkey, dh_signature and session_id to the client
            dh_pkey = dh.pkey_generation()
            dh_pubkey = dh.compute_pubkey(dh_pkey)
            sid = random.randint(0, 2**32)
            msg = dict(
                dh_pubkey=dh_pubkey,
                dh_sign=rsa.sign(str(dh_pubkey), my_pkey),
                sid=sid,
                sid_sign=rsa.sign(str(sid), my_pkey),
            )
            conn_socket.sendall(json.dumps(msg).encode())

            # Compute the shared secret
            skey = dh.compute_secret(data["dh_pubkey"], dh_pkey)
            seq = random.randint(0, 2**32)

        else:
            # Send the client's certificate and nonce to the server
            my_nonce = dh.generate_nonce()
            msg = dict(cert=rsa.encode_cert(my_cert), nonce=my_nonce)
            conn_socket.sendall(json.dumps(msg).encode())

            # Receive the server's certificate, nonce and signature
            data = conn_socket.recv(2048)
            data = json.loads(data.decode())
            # Verify the server's certificate
            certS = rsa.parse_cert(data["cert"])
            if not rsa.verify_cert(certS):
                raise Exception("Server certificate verification failed.")
            # Verify the server's signature of nonce
            if not rsa.verify_sign(str(my_nonce), data["nsign"], certS):
                raise Exception("Server nonce signature verification failed.")

            # Send the client's nonce signature, dh_pubkey and dh_signature to the server
            dh_pkey = dh.pkey_generation()
            dh_pubkey = dh.compute_pubkey(dh_pkey)
            msg = dict(
                nsign=rsa.sign(str(data["nonce"]), my_pkey),
                dh_pubkey=dh_pubkey,
                dh_sign=rsa.sign(str(dh_pubkey), my_pkey),
            )
            conn_socket.sendall(json.dumps(msg).encode())

            # Receive the server's public diffie-hellman key and signature
            data = conn_socket.recv(2048)
            data = json.loads(data.decode())
            # Verify the server's signature of public diffie-hellman key
            if not rsa.verify_sign(str(data["dh_pubkey"]), data["dh_sign"], certS):
                raise Exception("Server dh_pubkey signature verification failed.")
            # Verify the server's signature of session_id
            if not rsa.verify_sign(str(data["sid"]), data["sid_sign"], certS):
                raise Exception("Server sid signature verification failed.")

            # Compute the shared secret
            skey = dh.compute_secret(data["dh_pubkey"], dh_pkey)
            sid = data["sid"]
            seq = random.randint(0, 2**32)

        # Return the shared secret, session_id and the initial sequence number
        return skey, sid, seq

    def protect_message(self, message, skey, sid, seq):
        header = f"{sid}:{seq}".encode()
        data = sec.protect(message, skey, header)
        json_data = json.dumps(data).encode()
        return base64.b64encode(json_data)

    def unprotect_message(self, data, skey):
        decoded = base64.b64decode(data).decode()
        json_data = json.loads(decoded)
        return sec.unprotect(json_data, skey)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action="store_true", help="Run as server")
    parser.add_argument("--client", action="store_true", help="Run as client")
    parser.add_argument(
        "--debug-level",
        type=int,
        choices=[0, 1, 2],
        default=0,
        help="Debug level: 0 for ERROR, 1 for WARNING, 2 for INFO/DEBUG.",
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Hostname to bind/connect to"
    )
    parser.add_argument(
        "--port", type=int, default=65432, help="Port to bind/connect to"
    )

    args = parser.parse_args()

    if args.server:
        role = "server"
    elif args.client:
        role = "client"
    else:
        print("\033[91m[ERROR] Please specify either --server or --client\033[0m")
        sys.exit(1)

    app = SecureCommunicationApp(
        role, host=args.host, port=args.port, debug_level=args.debug_level
    )
    app.start()


if __name__ == "__main__":
    main()
