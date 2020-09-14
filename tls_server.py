import socket
import ssl
import argparse
import os
import json
import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from base64 import b64encode, b64decode
import socket
import traceback
import shutil
import random
import secrets
import logging
logging.basicConfig(format='Date-Time : %(asctime)s : Line No. : %(lineno)d - %(message)s', \
                    level = logging.DEBUG)

PADDING_SIZE = 32
DEFAULT_FILE_PACKET_SIZE = 1024
CA_PUBLIC_CERTIFICATE_PATH = "./certs/ca.crt"
SERVER_PRIVATE_KEY_PATH = "./certs/serverkey.pem"
SERVER_CERTIFICATE_KEY_PATH = "./certs/server.crt"
ALLOWED_CIPHERS_LIST = [
    "ECDHE-ECDSA-AES256-GCM-SHA384", 
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384"
]
DEFAULT_SHARED_SECRET_DIFFIE_HELLMAN_CURVE = "secp521r1"

class TLSBase:
    def __init__(self):
        pass

    def send_json(self, socket, data):
        # Serialize the json data
        try:
            serialized = json.dumps(data)
        except:
            raise Exception('You can only send JSON-serializable data')
        # Send the length of the serialized data first
        socket.send(('%d\n' % len(serialized)).encode())
        # Send the serialized data
        socket.sendall(serialized.encode())

    def recv_json(self, socket):
        # Read the length of the data, letter by letter until we reach EOL
        length_str = ''
        char = socket.recv(1).decode()
        if not char:
            return None
        while char != '\n':
            length_str += char
            char = socket.recv(1).decode()
            if not char:
                return None
        total = int(length_str)
        # Use a memoryview to receive the data chunk by chunk efficiently
        view = memoryview(bytearray(total))
        next_offset = 0
        while total - next_offset > 0:
            recv_size = socket.recv_into(view[next_offset:], total - next_offset)
            next_offset += recv_size
        # Deserialize the data
        try:
            deserialized = json.loads(view.tobytes())
        except:
            raise Exception('Data received was not in JSON format')
        return deserialized

    def encrypt(self, secret, envelope_encryption, data):
        # Create a cipher with the secret and default nonce
        # AES GCM will also guarantee that the ciphertext was not modified by anyone, including the server which the client may not trust.
        cipher = AES.new(secret.encode(), AES.MODE_GCM)
        header_dek = None
        if envelope_encryption:
            # Create a DEK as the header for this packet
            header_dek = secrets.token_hex(16)
            # Use the header as an extra const associated data for this message encryption
            cipher.update(header_dek.encode())
        # Encrypt the data and generate a tag for later validation of the encryption 
        # The tag is used for the verification later on on the decryption
        # We also pad the input for further hardening
        # The primary use of padding with classical ciphers is to prevent the cryptanalyst from using that predictability to find known plaintext that aids in breaking the encryption. 
        # Random length padding also prevents an attacker from knowing the exact length of the plaintext message.
        ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode(), PADDING_SIZE))
        # Create the json encrypted packet (all values are also base64 encoded)
        json_k = [ 'nonce', 'ciphertext', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, ciphertext, tag] ]
        if envelope_encryption:
            # Add the DEK extra data encryption key
            json_k.append('header_dek')
            json_v.append(b64encode(header_dek.encode()).decode('utf-8'))
        return dict(zip(json_k, json_v))

    def decrypt(self, secret, envelope_encryption, data):
        # Prepare the base 64 decoded json
        jv = {k:b64decode(data[k]) for k in data.keys()}
        # Perform the decryption and verification
        cipher = AES.new(args.secret.encode(), AES.MODE_GCM, nonce=jv['nonce'])
        if envelope_encryption:
            # Add the DEK for extra decryption key
            cipher.update(jv['header_dek'])
        # Use the tag to also verify the cipher text
        return unpad(cipher.decrypt_and_verify(jv['ciphertext'], jv['tag']), PADDING_SIZE)

class TLSClient(TLSBase):
    def __init__(self):
        TLSBase.__init__(self)

    def run_client(self, args):
        # Since we know we are working locally, we will use our hostname simillar to the certificate generation request
        hostname = socket.gethostname()
        # Prepare a client ssl context and load the server public certificate 
        # PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        logging.info("Loading and verifying certificate")
        # Load a set of “certification authority” (CA) certificates used to validate other peers’ certificates when verify_mode is other than CERT_NONE. 
        # At least one of cafile or capath must be specified.
        context.load_verify_locations(CA_PUBLIC_CERTIFICATE_PATH)

        # Check if the local file exists if upload before connecting
        if args.action == "upload" and not os.path.exists(args.file_path):
            logging.error("File path does not exist, aborting")
            return

        # Create the TLS connection
        logging.info("Connecting to server")
        with socket.create_connection((hostname, 4431)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                if args.action == "upload":
                    logging.info(f"Starting to upload file {args.file_path}")
                    # Upload mode, read and encrypt the file and send it to the server
                    # Send metadata
                    self.send_json(ssock, {"mode": "upload", "envelope": args.envelope_encryption, "file_name": os.path.basename(args.file_path)})
                    # Encrypt and send file packets
                    f = open(args.file_path, "r")
                    try:
                        while True:
                            data = f.read(args.packet_size)
                            if not data:
                                break
                            self.send_json(ssock, self.encrypt(args.secret, args.envelope_encryption, data))
                            resp = self.recv_json(ssock)
                            if 'response' in resp and resp['response'] != 'ok':
                                raise Exception("Failed to send all the file")
                        logging.info(f"Done uploading file {args.file_path}")
                    except:
                        logging.error(f"Couldnt finish uploading file")
                        logging.error(traceback.format_exc())
                    finally:
                        f.close()
                elif args.action == "download":
                    logging.info(f"Starting to download file {args.file_name} to {args.out_path}")
                    # Download mode, get packets and decrypt them to file from the server
                    # Send metadata
                    self.send_json(ssock, {"mode": "download", "envelope": args.envelope_encryption, "file_name": args.file_name})
                    # Start reciving encrypted packets and decrypt them
                    f = open(args.out_path, "w")
                    try:
                        while True:
                            data = self.recv_json(ssock)
                            if not data:
                                break
                            f.write(self.decrypt(args.secret, args.envelope_encryption, data).decode())
                            self.send_json(ssock, {"response": "ok"})
                        logging.info(f"Done downloading file {args.file_name} to {args.out_path}")
                    except:
                        self.send_json(ssock, {"response": "fail"})
                        logging.error(f"Couldnt finish downloading file")
                        logging.error(traceback.format_exc())
                    finally:
                        f.close()

class TLSServer(TLSBase):
    def __init__(self):
        TLSBase.__init__(self)
        # Generate the kek envelope key and nonce for later use
        # Nonce is an arbitrary number that can be used just once in a cryptographic communication
        # In EAX Mode, the nonce can be an artbitrary size
        self._kek_envelope_key = get_random_bytes(16)
        self._kek_envelope_nonce = get_random_bytes(16)
        
    def deal_with_client_upload(self, connstream, file_name, envelope_encryption):
        out_path = f"./store/{file_name}.json"
        json_data = {"packets": [], "file_name": file_name, "stamp": str(datetime.datetime.now())}
        # Read until the socket is closed
        try:
            while True:
                data = self.recv_json(connstream)
                if not data:
                    break
                # Encrypt the header DEK with the extra server KEK
                if envelope_encryption and 'header_dek' in data:
                    kek_envelope_cipher = AES.new(self._kek_envelope_key, AES.MODE_EAX, nonce=self._kek_envelope_nonce)
                    data['header_dek'] = str(b64encode(kek_envelope_cipher.encrypt(bytes(data['header_dek'], "utf-8"))), 'utf-8')
                json_data["packets"].append(data)
                self.send_json(connstream, {"response": "ok"})
        except:
            self.send_json(connstream, {"response": "fail"})
            logging.error(traceback.format_exc())
        finally:
            # Store all the packets to the file name given as json file
            f = open(out_path, "w")
            f.truncate()
            json.dump(json_data, f, indent=4)
            f.close()
        return out_path

    def deal_with_client_download(self, connstream, file_name, envelope_encryption):
        file_path = f"./store/{file_name}.json"
        if not os.path.exists(file_path):
            logging.error(f"File does not exist [{file_path}]")
            return None
        # Start writing the file contents until the end
        json_data = json.load(open(file_path, "r"))
        for json_packet in json_data["packets"]:
            # Decrypt the header DEK with the extra server KEK
            if envelope_encryption and 'header_dek' in json_packet:
                kek_envelope_cipher = AES.new(self._kek_envelope_key, AES.MODE_EAX, nonce=self._kek_envelope_nonce)
                json_packet['header_dek'] = str(kek_envelope_cipher.decrypt(b64decode(bytes(json_packet['header_dek'], 'utf-8'))), 'utf-8')
            self.send_json(connstream, json_packet)
            resp = self.recv_json(connstream)
            if 'response' in resp and resp['response'] != 'ok':
                raise Exception("Failed to send all the file")
        return file_path

    def deal_with_client(self, connstream):
        if not os.path.exists("./store"):
            os.makedirs("./store")
        # Read metadata
        try:
            metadata = self.recv_json(connstream)
            envelope_encryption = False
            if not metadata or "mode" not in metadata or "file_name" not in metadata:
                logging.error("Invalid metadata recieved, aborting")
                return None
            if "envelope" in metadata and metadata["envelope"]:
                envelope_encryption = True
            # Uplaod mode
            if metadata["mode"] == "upload":
                return self.deal_with_client_upload(connstream, metadata['file_name'], envelope_encryption)
            # Download mode
            elif metadata["mode"] == "download":
                return self.deal_with_client_download(connstream, metadata['file_name'], envelope_encryption)
            else:
                logging.error("Invalid mode given, aborting")
        except:
            traceback.print_exc()
        return None

    def run_server(self, args):
        if args.clear_datastore and os.path.exists("./store"):
            shutil.rmtree("./store")
        # We are working with client authentications
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # Set the options, we only allow TLS 1.2 and 1.3
        logging.info("Setting only TLS 1.2 / 1.3 to be allowed")
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        # Set the allowed ciphers
        logging.info("Setting ciphers")
        logging.debug(f"Ciphers: {ALLOWED_CIPHERS_LIST}")
        context.set_ciphers(":".join(ALLOWED_CIPHERS_LIST))
        # Set the accepted key sharing mechanism
        # https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
        logging.info(f"Setting ecdh curve to be {DEFAULT_SHARED_SECRET_DIFFIE_HELLMAN_CURVE}")
        context.set_ecdh_curve(DEFAULT_SHARED_SECRET_DIFFIE_HELLMAN_CURVE)
        # Load the certificate chain
        logging.info("Loading certificate chain")
        context.load_cert_chain(certfile=SERVER_CERTIFICATE_KEY_PATH,
                                keyfile=SERVER_PRIVATE_KEY_PATH)
        # Start the server with a backlog of 5
        logging.info("Starting server")
        server_bind_socket = socket.socket()
        server_bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_bind_socket.bind(('0.0.0.0', 4431))
        server_bind_socket.listen(5)

        # Listen for requests endlessly
        while True:
            newsocket, fromaddr = server_bind_socket.accept()
            try:
                connstream = context.wrap_socket(newsocket, server_side=True)
                logging.info(f"New connection arrived from {fromaddr}")
                self.deal_with_client(connstream)
            except:
                logging.warn(traceback.print_exc())
            finally:
                try:
                    connstream.shutdown(socket.SHUT_RDWR)
                    connstream.close()
                except:
                    pass

# Create the client server parser
parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="type", required=True)
server_sub = subparsers.add_parser("server")
server_sub.add_argument("-cds", "--clear-datastore", action="store_true")
client_sub = subparsers.add_parser("client")
client_sub.add_argument("-s", "--secret", required=True)
client_sub.add_argument("-ee", "--envelope-encryption", action="store_true")
client_parsers = client_sub.add_subparsers(dest="action", required=True)
client_download_sub = client_parsers.add_parser("download")
client_upload_sub = client_parsers.add_parser("upload")
client_upload_sub.add_argument("-fp", "--file-path", required=True)
client_upload_sub.add_argument("-ps", "--packet-size", default=DEFAULT_FILE_PACKET_SIZE, type=int)
client_download_sub.add_argument("-fn", "--file-name", required=True)
client_download_sub.add_argument("-op", "--out-path", required=True)

args = parser.parse_args()

if args.type == "server":
    tls_server = TLSServer()
    tls_server.run_server(args)
elif args.type == "client":
    tls_client = TLSClient()
    tls_client.run_client(args)
else:
    logging.error("Invalid command")
