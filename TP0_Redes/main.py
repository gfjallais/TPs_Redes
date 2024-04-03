import sys
import socket
import struct

MESSAGE_TYPES = {
    "itr": 1,  
    "itv": 3,
    "gtr": 5,
    "gtv": 7,
    "error": 256,
}

ERROR_CODES = {
    1: "INVALID_MESSAGE_CODE",
    2: "INCORRECT_MESSAGE_LENGTH",
    3: "INVALID_PARAMETER",
    4: "INVALID_SINGLE_TOKEN",
    5: "ASCII_DECODE_ERROR",
}


def read_and_validate_cli_args():
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <host> <port> <command> [<args>]")
        sys.exit(1)

    host, port, command = sys.argv[1:4]
    try:
        port = int(port)
    except ValueError:
        print("Invalid port number.")
        sys.exit(1)

    command_args = sys.argv[4:]

    if command not in ["itr", "itv", "gtr", "gtv"]:
        print(f"Invalid command: {command}")
        sys.exit(1)
    if command == "itr" and len(command_args) != 2:
        print(f"Invalid itr command arguments, should be: itr <id> <nonce>")
        sys.exit(1)
    if command == "itv" and not command_args:
        print(f"Invalid itv command arguments, should be: itv <SAS>")
        sys.exit(1)
    if command == "gtr":
        try:
            n = int(command_args[0])
        except ValueError:
            print("Invalid argument <N>. Should be a valid number")
            sys.exit(1)
        if n > 16:
            print("Invalid argument <N>. Should be less than 16")
        if len(command_args) < n + 1:
            print("List of SAS does not have N elements")
            sys.exit(1)

    return host, port, command, command_args

def create_individual_token_request_message(user_id, nonce):
    user_id_padded = user_id.ljust(12, " ")
    data = struct.pack("!12sI", user_id_padded.encode("ascii"), nonce)
    return data

def create_individual_token_validation_message(sas):
    user_id, nonce, token = sas.split(":")
    nonce = int(nonce)
    user_id_padded = user_id.ljust(12, " ").encode("ascii")
    token = token.encode("ascii")
    data = struct.pack("!12sI64s", user_id_padded, nonce, token)
    return data

def create_group_token_request_message(N, sas_list):
    data = struct.pack("!H", N)
    for sas in sas_list:
        data += create_individual_token_validation_message(sas)
    return data

def create_group_token_validation_message(gas):
    splitted_gas = gas.split("+")
    gas_token = splitted_gas[-1].encode("ascii")
    sas_list = splitted_gas[:-1]
    data = struct.pack("!h", len(sas_list))
    for sas in sas_list:
        data += create_individual_token_validation_message(sas)
    data += struct.pack("!64s", gas_token)
    return data

def get_message_data(command, args):
    if command == "itr":
        id, nonce = args[0], int(args[1])
        return create_individual_token_request_message(id, nonce)
    elif command == "itv":
        sas = args[0]
        return create_individual_token_validation_message(sas)
    elif command == "gtr":
        N, sas_list = int(args[0]), args[1:]
        return create_group_token_request_message(N, sas_list)
    elif command == "gtv":
        gas = args[0]
        return create_group_token_validation_message(gas)

def send_message(host, port, msg_type, data, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    message = struct.pack("!H", MESSAGE_TYPES[msg_type]) + data

    try:
        sock.sendto(message, (host, port))
        data, addr = sock.recvfrom(1024)
        return data
    except socket.timeout:
        print(f"Timeout waiting for response from server.")
        return None
    finally:
        sock.close()

def decode_sas(data, idx):
    sas_id = data[idx:idx+12].decode("ascii").strip()
    sas_nonce = int.from_bytes(data[idx+12:idx+16], "big")
    sas_token = data[idx+16:idx+80].decode("ascii")
    sas = f"{sas_id}:{sas_nonce}:{sas_token}"
    return sas

def parse_response(data):
    message_type = struct.unpack("!H", data[:2])[0]
    if message_type == MESSAGE_TYPES["error"]:
        error_code = struct.unpack("!H", data[2:4])[0]
        return {"error": ERROR_CODES[error_code]}

    if message_type == MESSAGE_TYPES["itv"] + 1 or message_type == MESSAGE_TYPES["gtv"] + 1:
        return data[-1]
    elif message_type == MESSAGE_TYPES["gtr"] + 1:
        N = int.from_bytes(data[2:4], "big")
        sas_list = ""
        for i in range(4, 4+80*N, 80):
            sas = decode_sas(data, i)
            sas_list += sas + "+"
        token = data[4+80*N:].decode("ascii")
        return sas_list+token
    elif message_type < 5:
        sas = decode_sas(data, 2)
        return sas

def main():
    HOST, PORT, COMMAND, ARGS = read_and_validate_cli_args()
    data = get_message_data(COMMAND, ARGS)
    response = send_message(HOST, PORT, COMMAND, data)
    if response:
        parsed_response = parse_response(response)
        print(parsed_response)

if __name__ == "__main__":
    main()