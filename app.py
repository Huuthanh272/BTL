import os
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Cơ sở dữ liệu "trong bộ nhớ" đơn giản để lưu trữ
# Trong thực tế, bạn sẽ dùng database thật như SQLite, PostgreSQL
db = {
    "users": {},  # { "username": "base64_public_key" }, lưu username và public key của user
    "messages": {} # { "recipient_username": [encrypted_packet, ...] }, lưu tin nhắn đã mã hóa của user
}

@app.route('/')
def index():
    """Cung cấp trang web chính."""
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    """Đăng ký user mới với public key của họ."""
    data = request.json
    username = data.get('username')
    rsaPublicKey = data.get('rsaPublicKey')
    signPublicKey = data.get('signPublicKey')

    if not username or not rsaPublicKey or not signPublicKey:
        return jsonify({"status": "error", "message": "Thiếu thông tin username hoặc public key"}), 400

    # Nếu username đã tồn tại, ghi đè public key và xóa hộp thư cũ
    db["users"][username] = {
        "rsaPublicKey": rsaPublicKey,
        "signPublicKey": signPublicKey
    }
    db["messages"][username] = [] # Reset hộp thư cho user
    print(f"Registered (overwritten): {username}")
    return jsonify({"status": "success", "message": f"User {username} đã được đăng ký/ghi đè."})

@app.route('/send', methods=['POST'])
def send():
    """Nhận gói tin đã mã hóa từ người gửi và lưu vào hộp thư người nhận."""
    data = request.json
    recipient = data.get('recipient')
    packet = data.get('packet')
    sender = data.get('sender') 

    if not recipient or not packet or not sender:
        return jsonify({"status": "error", "message": "Thiếu người nhận, người gửi hoặc gói tin"}), 400

    if recipient not in db["users"] or sender not in db["users"]:
        return jsonify({"status": "error", "message": "Người nhận hoặc người gửi không tồn tại"}), 404

    # Gói tin lưu trữ sẽ bao gồm cả gói tin mã hóa và public key của người gửi
    message_to_store = {
        "sender_username": sender,
        "packet": packet
    }

    db["messages"][recipient].append(message_to_store)
    print(f"Received message from {sender} for {recipient}")
    # Emit sự kiện WebSocket tới client nhận
    socketio.emit("new_message", {"recipient": recipient, "message": message_to_store})
    return jsonify({"status": "success", "message": "Đã gửi tin nhắn."})

@app.route('/receive/<username>', methods=['GET'])
def receive(username):
    """Cho phép user lấy các tin nhắn mới."""
    if username not in db["users"]:
        return jsonify({"status": "error", "message": "User không tồn tại"}), 404
# trả về tất cả tin nhắn trong hộp thư
    messages = db["messages"].get(username, [])
    # Không xóa tin nhắn để cho phép đọc lại
    return jsonify({"status": "success", "messages": messages})

@app.route('/get_users', methods=['GET'])
def get_users():
    """Lấy danh sách tất cả user và public key của họ."""
    return jsonify({"status": "success", "users": db["users"]})

if __name__ == '__main__':
    # Tạo thư mục nếu chưa có
    if not os.path.exists('templates'):
        os.makedirs('templates')
    if not os.path.exists('static'):
        os.makedirs('static')
    socketio.run(app, debug=True, port=5001) 