from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import Fore, Style, init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import schedule
import time
import threading

# Ignore SSL certificate warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Initialize colorama
init(autoreset=True)

# Initialize Flask app
app = Flask(__name__)

# Configure Flask-Caching
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})  # 7 ساعات بالثواني (7 * 60 * 60)

def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None
    return response.json()

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def load_tokens(file_path, limit=None):
    try:
        with open(file_path, 'r') as file:
            tokens = [line.strip().split(':') for line in file if ':' in line]
            if limit is not None:
                tokens = random.sample(tokens, min(limit, len(tokens)))  # اختيار التوكنات بشكل عشوائي
            print(f"Loaded {len(tokens)} tokens from {file_path}")  # Debug message
            return tokens
    except Exception as e:
        print(f"Error loading tokens from {file_path}: {e}")  # Debug message
        return []

def parse_response(response_content):
    # تحليل الـ response لاستخراج الحقول المهمة
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_token(uid, password):
    print(f"Processing token for UID: {uid}")  # Debug message
    token_data = get_token(password, uid)
    if not token_data:
        print(f"Failed to retrieve token for UID: {uid}")  # Debug message
        return {"uid": uid, "error": "Failed to retrieve token"}

    # إنشاء GameData Protobuf
    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.109.16"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    # تسلسل البيانات
    serialized_data = game_data.SerializeToString()

    # تشفير البيانات
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    # إرسال البيانات المشفرة إلى الخادم
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }
    edata = bytes.fromhex(hex_encrypted_data)

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code == 200:
            # محاولة فك تشفير الـ Protobuf
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                # تحليل الـ response لاستخراج الحقول المهمة
                response_dict = parse_response(str(example_msg))
                print(f"Successfully processed token for UID: {uid}")  # Debug message
                return response_dict.get("token", "N/A")  # إرجاع التوكن فقط
            except Exception as e:
                print(f"Failed to deserialize the response for UID: {uid}: {e}")  # Debug message
                return None
        else:
            print(f"Failed to get response for UID: {uid}: HTTP {response.status_code}, {response.reason}")  # Debug message
            return None
    except requests.RequestException as e:
        print(f"An error occurred while making the request for UID: {uid}: {e}")  # Debug message
        return None

def fetch_tokens():
    with app.app_context():
        # تحميل التوكنات من ملف acc.txt مع تحديد الحد الأقصى
        tokens = load_tokens("acc.txt", limit=100)
        if not tokens:
            print("No tokens loaded. Check the file 'acc.txt'.")  # Debug message
            return

        responses = []

        # استخدام ThreadPoolExecutor لتنفيذ المهام بشكل متوازي
        with ThreadPoolExecutor(max_workers=15) as executor:
            future_to_uid = {executor.submit(process_token, uid, password): uid for uid, password in tokens}
            for future in as_completed(future_to_uid):
                try:
                    token = future.result()
                    if token:  # إذا كان التوكن صالحًا
                        responses.append(token)
                except Exception as e:
                    print(f"Error processing token: {e}")  # Debug message

        # تخزين النتائج في الكاش
        cache.set('responses', responses)
        print(f"Stored {len(responses)} tokens in cache.")  # Debug message

@app.route('/token', methods=['GET'])
def get_responses():
    # الحصول على النتائج من الكاش
    responses = cache.get('responses')
    if responses is None:
        print("No data available in cache.")  # Debug message
        return jsonify({"error": "No data available yet"})
    return jsonify({"tokens": responses})  # إرجاع التوكنات في قائمة

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    # جدولة المهمة كل 7 ساعات
    schedule.every(7).hours.do(fetch_tokens)

    # تشغيل fetch_tokens فورًا عند بدء التشغيل
    fetch_tokens()

    # تشغيل السكيدولر في ثانوية منفصلة
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()

    # تشغيل تطبيق Flask
    app.run(host="0.0.0.0", port=5003)
