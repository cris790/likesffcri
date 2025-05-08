from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import hashlib
from secret import *  # Importa as chaves 'key' e 'iv'
import uid_generator_pb2
import requests
import struct
import datetime
from flask import Flask, jsonify
import json
from zitado_pb2 import Users  # Importa a estrutura de dados protobuf
import random
import logging

app = Flask(__name__)

# Configura o logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Converte uma string hexadecimal em bytes
def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

# Cria o protobuf com o UID (saturn_) e tipo de login (garena)
def create_protobuf(saturn_, garena):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = saturn_
    message.garena = garena
    return message.SerializeToString()

# Converte os dados protobuf em uma string hexadecimal
def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

# Decodifica os dados hexadecimais usando a estrutura Users do zitado_pb2
def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

# Criptografa os dados usando AES no modo CBC
def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

# Envia a requisição à API para obter informações do jogador
def apis(idd, token):
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = bytes.fromhex(idd)
    try:
        response = requests.post('https://client.us.freefiremobile.com/GetPlayerPersonalShow', headers=headers, data=data)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')
        logging.debug(f"API Response Status: {response.status_code}, Content-Type: {content_type}")
        logging.debug(f"API Response Content (raw): {response.content}")
        logging.debug(f"API Response Content (hex): {response.content.hex()}")
        if 'application/json' in content_type:
            logging.debug(f"JSON Response: {response.json()}")
            return response.json()
        elif 'text' in content_type:
            logging.debug(f"Text Response: {response.text}")
            return response.text
        return response.content.hex()
    except requests.RequestException as e:
        logging.error(f"API Request Failed: {e}")
        return None

# Escolhe um token aleatório da lista retornada pela API local
def token():
    try:
        response = requests.get("http://localhost:5003/token")
        response.raise_for_status()
        tokens = response.json()
        token_list = tokens['tokens']
        logging.debug(f"Available Tokens: {token_list}")
        if not token_list:
            raise ValueError("No tokens available")
        random_token = random.choice(token_list)
        return random_token
    except (requests.RequestException, ValueError) as e:
        logging.error(f"Token Fetch Error: {e}")
        return None

# Rota para favicon.ico para evitar erro
@app.route('/favicon.ico')
def favicon():
    return '', 204

# Rota principal da API que recebe o UID e retorna os dados do jogador
@app.route('/<uid>', methods=['GET'])
def main(uid):
    logging.info(f"Received UID: {uid}")
    if not uid.isdigit():
        logging.error("Invalid UID: not numeric")
        return jsonify({"error": "UID inválido"}), 400

    saturn_ = int(uid)
    garena = 1
    protobuf_data = create_protobuf(saturn_, garena)
    logging.debug(f"Protobuf Data: {protobuf_data.hex()}")
    hex_data = protobuf_to_hex(protobuf_data)
    logging.debug(f"Hex Data: {hex_data}")
    aes_key = key
    aes_iv = iv
    encrypted_hex = encrypt_aes(hex_data, aes_key, aes_iv)
    logging.debug(f"Encrypted Hex: {encrypted_hex}")
    tokenn = token()
    if not tokenn:
        logging.error("Failed to fetch token")
        return jsonify({"error": "Failed to fetch valid token"}), 500
    logging.debug(f"Selected Token: {tokenn}")
    infoo = apis(encrypted_hex, tokenn)

    if not infoo:
        logging.error("API returned no data")
        return jsonify({"error": "Failed to get data from API"}), 500

    # Handle different response types
    if isinstance(infoo, dict):
        logging.error("API returned JSON, expected Protobuf")
        return jsonify({"error": "API returned JSON, expected Protobuf", "data": infoo}), 500
    elif isinstance(infoo, str) and not infoo.replace(' ', '').isalnum():
        logging.error("API returned text, expected Protobuf")
        return jsonify({"error": "API returned text, expected Protobuf", "data": infoo}), 500

    hex_data = infoo
    logging.debug(f"API Response (hex): {hex_data}")

    try:
        users = decode_hex(hex_data)
        logging.debug(f"Parsed Users: {users}")
    except binascii.Error:
        logging.error(f"Invalid hex data: {hex_data}")
        return jsonify({"error": "Invalid hex data"}), 400
    except Exception as e:
        logging.error(f"Protobuf Parsing Error: {e}")
        return jsonify({"error": f"Failed to parse response: {str(e)}"}), 500

    result = {}

    # Informações básicas do jogador
    if users.basicinfo:
        result['basicinfo'] = []
        for user_info in users.basicinfo:
            result['basicinfo'].append({
                'username': user_info.username,
                'region': user_info.region,
                'level': user_info.level,
                'Exp': user_info.Exp,
                'bio': users.bioinfo[0].bio if users.bioinfo else None,
                'banner': user_info.banner,
                'avatar': user_info.avatar,
                'brrankscore': user_info.brrankscore,
                'BadgeCount': user_info.BadgeCount,
                'likes': user_info.likes,
                'lastlogin': user_info.lastlogin,
                'csrankpoint': user_info.csrankpoint,
                'csrankscore': user_info.csrankscore,
                'brrankpoint': user_info.brrankpoint,
                'createat': user_info.createat,
                'OB': user_info.OB
            })

    # Informações da guilda
    if users.claninfo:
        result['claninfo'] = []
        for clan in users.claninfo:
            result['claninfo'].append({
                'clanid': clan.clanid,
                'clanname': clan.clanname,
                'guildlevel': clan.guildlevel,
                'livemember': clan.livemember
            })

    # Informações dos administradores da guilda
    if users.clanadmin:
        result['clanadmin'] = []
        for admin in users.clanadmin:
            result['clanadmin'].append({
                'idadmin': admin.idadmin,
                'adminname': admin.adminname,
                'level': admin.level,
                'exp': admin.exp,
                'brpoint': admin.brpoint,
                'lastlogin': admin.lastlogin,
                'cspoint': admin.cspoint
            })

    # Créditos
    result['Owners'] = ['RubensK']

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)