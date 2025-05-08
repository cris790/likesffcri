import asyncio
import aiohttp
import os
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import uid_generator_pb2
import time
from datetime import datetime

app = Flask(__name__)

# Obter chaves de variáveis de ambiente
AES_KEY = os.getenv('AES_KEY')
AES_IV = os.getenv('AES_IV')

# Verificar se as chaves estão definidas
if not AES_KEY or not AES_IV:
    raise ValueError("AES_KEY and AES_IV must be set as environment variables")

# Armazenar chaves da API
api_keys = set()

# Rastrear o tempo do último like
last_like_time = {}

def create_protobuf(saturn_, garena):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = saturn_
    message.garena = garena
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

# Gerenciamento de chaves
@app.route('/make_key', methods=['GET'])
def make_key():
    key = request.args.get('key')
    if not key:
        return jsonify({'error': 'Missing key parameter'}), 400
    api_keys.add(key)
    return jsonify({'message': 'Key added successfully', 'key': key}), 200

@app.route('/del_key', methods=['GET'])
def del_key():
    key = request.args.get('key')
    if not key:
        return jsonify({'error': 'Missing key parameter'}), 400
    if key in api_keys:
        api_keys.remove(key)
        return jsonify({'message': 'Key deleted successfully', 'key': key}), 200
    return jsonify({'error': 'Key not found'}), 404

@app.route('/del_all_keys', methods=['GET'])
def del_all_keys():
    api_keys.clear()
    return jsonify({'message': 'All keys deleted successfully'}), 200

@app.route('/all_keys', methods=['GET'])
def all_keys():
    return jsonify({'keys': list(api_keys)}), 200

def verify_key(key):
    return key in api_keys

async def like(id, session, token):
    like_url = 'https://clientbp.ggblueshark.com/LikeProfile'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    data = bytes.fromhex(id)

    async with session.post(like_url, headers=headers, data=data) as response:
        status_code = response.status
        response_text = await response.text()
        return {
            'status_code': status_code,
            'response_text': response_text
        }

async def get_account_info(uid, session):
    info_url = f'http://164.92.134.31:5002/{uid}'
    async with session.get(info_url) as response:
        if response.status == 200:
            return await response.json()
        return None

async def get_tokens(session):
    url = 'http://164.92.134.31:5003/token'
    async with session.get(url) as response:
        if response.status == 200:
            tokens = await response.json()
            token_list = tokens.get('tokens', [])
            return token_list[:100]
        return []

async def sendlike(uid, count=1):
    try:
        saturn_ = int(uid)
        garena = 1
        protobuf_data = create_protobuf(saturn_, garena)
        hex_data = protobuf_to_hex(protobuf_data)
        id = encrypt_aes(hex_data, AES_KEY, AES_IV)

        start_time = time.time()

        current_time = datetime.now()
        last_like_time[uid] = current_time

        async with aiohttp.ClientSession() as session:
            tokens = await get_tokens(session)
            if not tokens:
                return jsonify({"error": "No tokens available"}), 500

            account_info_before = await get_account_info(uid, session)
            if not account_info_before:
                return jsonify({"error": "Unable to fetch account info before sending likes"}), 500

            likes_before = account_info_before['basicinfo'][0]['likes']

            tasks = [like(id, session, token) for token in tokens[:count]]
            results = await asyncio.gather(*tasks)

            account_info_after = await get_account_info(uid, session)
            if not account_info_after:
                return jsonify({"error": "Unable to fetch account info after sending likes"}), 500

            likes_after = account_info_after['basicinfo'][0]['likes']
            likes_added = likes_after - likes_before
            failed_likes = sum(1 for result in results if result['status_code'] != 200)

            end_time = time.time()
            elapsed_time = end_time - start_time

            return jsonify({
                'uid': uid,
                'name': account_info_after['basicinfo'][0].get('username', 'Unknown'),
                'level': account_info_after['basicinfo'][0].get('level', 'N/A'),
                'likes_before': likes_before,
                'likes_after': likes_after,
                'likes_added': likes_added,
                'failed_likes': failed_likes,
                'region': account_info_after['basicinfo'][0].get('region', 'Unknown'),
                'elapsed_time': elapsed_time
            }), 200
    except ValueError as e:
        return jsonify({'error': 'Invalid UID format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/like', methods=['GET'])
def like_endpoint():
    try:
        uid = request.args.get('uid')
        api_key = request.args.get('key')
        count = int(request.args.get('count', 99))

        if not uid or not api_key:
            return jsonify({'error': 'Missing uid or key parameter'}), 400
        if not uid.isdigit():
            return jsonify({'error': 'UID must be a valid number'}), 400
        if not verify_key(api_key):
            return jsonify({'error': 'Invalid API key'}), 403

        # Usar asyncio.run para executar a função assíncrona
        return asyncio.run(sendlike(uid, count))
    except ValueError as e:
        return jsonify({'error': 'Invalid count parameter'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008)
