from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import time
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

def load_tokens(server_name):
    try:
        # Link direto para o JSON BR
        url = "https://token-w2wd.onrender.com/token"

        response = requests.get(url)
        response.raise_for_status()  # Vai dar erro se a resposta não for 200 OK

        tokens = response.json()  # Converte diretamente para dict/list
        return tokens

    except Exception as e:
        print(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        start_time = time.time()
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None, 0
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None, 0
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None, 0

        # Enviar exatamente 99 requests
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        execution_time = end_time - start_time
        return results, execution_time
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None, 0

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({
            "success": False,
            "error": "UID and server_name are required"
        }), 400

    try:
        start_time = time.time()
        tokens = load_tokens(server_name)
        if tokens is None:
            raise Exception("Failed to load tokens.")

        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            raise Exception("Encryption of UID failed.")

        # Get player info before sending likes
        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            raise Exception("Failed to retrieve initial player info.")

        try:
            jsone = MessageToJson(before)
        except Exception as e:
            raise Exception(f"Error converting 'before' protobuf to JSON: {e}")

        data_before = json.loads(jsone)
        before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
        player_name = data_before.get('AccountInfo', {}).get('PlayerNickname', 'Unknown')
        player_uid = data_before.get('AccountInfo', {}).get('UID', uid)

        try:
            before_like = int(before_like)
        except Exception:
            before_like = 0

        # Determine the like endpoint based on server
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send exactly 99 like requests
        results, execution_time = asyncio.run(send_multiple_requests(uid, server_name, url))

        # Get player info after sending likes
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            raise Exception("Failed to retrieve player info after like requests.")

        try:
            jsone_after = MessageToJson(after)
        except Exception as e:
            raise Exception(f"Error converting 'after' protobuf to JSON: {e}")

        data_after = json.loads(jsone_after)
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        total_likes_sent = after_like - before_like

        # Determine if likes were sent successfully
        success_status = total_likes_sent > 0

        # Prepare the response in the requested format
        response = {
            "success": success_status,
            "message": f"{total_likes_sent} likes adicionado com sucesso" if success_status else "Nenhum like foi enviado",
            "PlayerName": player_name,
            "UID": str(player_uid),
            "Region": server_name,
            "Before Like": str(before_like),
            "Likes After": str(after_like),
            "Total likes sent": total_likes_sent,
            "Time Takes": f"{execution_time:.2f} seconds"
        }

        return jsonify(response)

    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
