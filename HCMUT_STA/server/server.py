import logging
import socket
import threading
import json
import hashlib
import mysql.connector
from mysql.connector import Error
import sys
import json
import time

conn = None
cur = None
stop_event = threading.Event()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    # Thiết lập kết nối đến cơ sở dữ liệu MySQL
    conn = mysql.connector.connect(
        host="localhost",         # Địa chỉ máy chủ của bạn (có thể là "localhost")
        database="sta_server",  # Tên cơ sở dữ liệu của bạn
        user="tom_user",     # Tên người dùng MySQL của bạn
        password="1234"  # Mật khẩu của người dùng
    )

    if conn.is_connected():
        cur = conn.cursor()
        # Thực hiện các truy vấn SQL ở đây

except Error as e:
    print("Không thể kết nối đến cơ sở dữ liệu.")
    print(e)

def log_event(message):
    logging.info(message)

def xor_distance(id1, id2):
    return int(id1, 16) ^ int(id2, 16)

# def create_user(username, password):
#     # Kiểm tra nếu tên đăng nhập đã tồn tại
#     cur.execute("SELECT username FROM users WHERE username = %s", (username,))
#     if cur.fetchone():
#         return False  # Nếu tên đăng nhập đã tồn tại, trả về False

#     # Mã hóa mật khẩu bằng SHA256
#     password_hash = hashlib.sha256(password.encode()).hexdigest()

#     # Thêm người dùng mới vào cơ sở dữ liệu
#     cur.execute("""
#             INSERT IGNORE INTO users (username, password_hash)
#             VALUES (%s, %s)
#         """, (username, password_hash))

#     return True

# def verify_user(username, password):
#     # Lấy thông tin người dùng từ cơ sở dữ liệu
#     cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
#     row = cur.fetchone()

#     if row:
#         stored_password_hash = row[0]
#         # So sánh mật khẩu đã băm
#         return stored_password_hash == hashlib.sha256(password.encode()).hexdigest()
#     else:
#         return False

def get_peers_list(conn):
    try:
        # Lấy toàn bộ danh sách peer
        cur.execute("SELECT * FROM DHT_peers")
        peers_list = cur.fetchall()

        # Danh sách để lưu kết quả cuối cùng
        result_list = []

        for peer_id, peers_ip, peers_port, peers_hostname, hash_info in peers_list:
            file_names = []

            if hash_info:
                try:
                    hash_info_entries = json.loads(hash_info)  # Giải nén JSON
                    for entry in hash_info_entries:
                        hash_val = entry.get('hash_info')
                        if hash_val:
                            cur.execute("""
                                SELECT file_name
                                FROM torrent_file
                                WHERE hash_info = %s
                            """, (hash_val,))
                            file_name = cur.fetchone()
                            file_names.append(file_name[0] if file_name else None)
                except json.JSONDecodeError:
                    pass  # Nếu JSON không hợp lệ, bỏ qua

            # Nếu không có file_name hoặc hash_info, gán [None]
            result_list.append({
                'peer_id': peer_id,
                'peers_ip': peers_ip,
                'peers_port': peers_port,
                'peers_hostname': peers_hostname,
                'file_name': file_names or [None]
            })

        # Gửi danh sách kết quả tới client
        conn.sendall(json.dumps(result_list).encode())
        print("Peers list sent to client successfully")

    except Exception as e:
        print(f"Error in get_peers_list: {e}")

def update_client_info_DHT(peers_id, peers_ip, peers_port, peers_hostname):

    try:
        # Thêm hoặc cập nhật peer vào bảng DHT
        cur.execute("""
            INSERT INTO DHT_peers (peer_id, peers_ip, peers_port, peers_hostname)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                peers_ip = VALUES(peers_ip),
                peers_port = VALUES(peers_port),
                peers_hostname = VALUES(peers_hostname)
        """, (peers_id, peers_ip, peers_port, peers_hostname))

        # Commit các thay đổi
        conn.commit()

    except mysql.connector.Error as e:
        print(f"Error in update_client_info_DHT: {e}")
        conn.rollback()

def update_client_info_torrentFile(hash_info, file_name, file_size, piece_size, number_of_pieces):
    try:
        cur.execute("""
            INSERT IGNORE INTO torrent_file (hash_info, file_name, file_size, piece_size, number_of_pieces)
            VALUES (%s, %s, %s, %s, %s)
        """, (hash_info, file_name, file_size, piece_size, number_of_pieces))
         
        # Commit các thay đổi
        conn.commit()

    except mysql.connector.Error as e:
        print(f"Error in update_client_info_torrentFile: {e}")
        conn.rollback()

def update_hash_info(peers_id, new_hash_info, role):
    try:
        # Lấy dữ liệu hash_info hiện tại từ bảng
        cur.execute("""
            SELECT hash_info FROM DHT_peers WHERE peer_id = %s
        """, (peers_id,))
        result = cur.fetchone()

        # Kiểm tra nếu peer đã có hash_info
        if result and result[0]:
            existing_hash_info = json.loads(result[0])
            found = False
            for entry in existing_hash_info:
                if entry['hash_info'] == new_hash_info:
                    # Nếu hash_info đã tồn tại nhưng role khác, cập nhật role
                    if entry['role'] != role:
                        entry['role'] = role
                        found = True
                    break
            if not found:
                existing_hash_info.append({"hash_info": new_hash_info, "role": role})
        else:
            existing_hash_info = []
            existing_hash_info.append({"hash_info": new_hash_info, "role": role})

        updated_hash_info = json.dumps(existing_hash_info)

        # Cập nhật vào cơ sở dữ liệu
        cur.execute("""
            UPDATE DHT_peers
            SET hash_info = %s
            WHERE peer_id = %s
        """, (updated_hash_info, peers_id))
        
        # Commit các thay đổi
        conn.commit()
        print(f"Hash info đã được cập nhật cho peer_id: {peers_id}")

    except mysql.connector.Error as e:
        print(f"Error in update_hash_info: {e}")
        conn.rollback()

def update_download_count(hash_info):
    try:
        # Cập nhật download_count cho bản ghi có hash_info tương ứng
        cur.execute("""
            UPDATE torrent_file
            SET download_count = download_count + 1
            WHERE hash_info = %s
        """, (hash_info,))
        
        # Xác nhận thay đổi vào cơ sở dữ liệu
        conn.commit()
        print(f"Lượt tải đã được cập nhật cho hash_info: {hash_info}")

    except mysql.connector.Error as e:
        print(f"Error in update_download_count: {e}")
        conn.rollback()

def delete_peer_from_DHT_peers(peer_id, peers_ip, peers_port, peers_hostname):
    try:
        # Xóa thông tin peer khỏi bảng DHT_peers
        cur.execute("""
            DELETE FROM DHT_peers WHERE peer_id = %s
        """, (peer_id,))
        
        # Commit các thay đổi
        conn.commit()
        print(f"Connection closed with {peers_hostname}/{peers_ip}:{peers_port}")
    
    except mysql.connector.Error as e:
        print(f"Error in deleting peer data: {e}")
        conn.rollback()

def tracker_torrent_file(conn, hash_info):
    try:
        # Đếm số lượng seeder cho hash_info cụ thể
        cur.execute("""
            SELECT COUNT(*) FROM DHT_peers
            WHERE JSON_CONTAINS(hash_info, JSON_OBJECT('hash_info', %s, 'role', 'seeder'))
        """, (hash_info,))
        seeder_count = cur.fetchone()[0]

        # Đếm số lượng leecher cho hash_info cụ thể
        cur.execute("""
            SELECT COUNT(*) FROM DHT_peers
            WHERE JSON_CONTAINS(hash_info, JSON_OBJECT('hash_info', %s, 'role', 'leecher'))
        """, (hash_info,))
        leecher_count = cur.fetchone()[0]

        # Lấy download count từ bảng torrent_file
        cur.execute("""
            SELECT download_count FROM torrent_file
            WHERE hash_info = %s
        """, (hash_info,))
        result = cur.fetchone()
        download_count = result[0] if result else 0  # Nếu không tìm thấy, download_count mặc định là 0

        # Kết quả cuối cùng
        tracker_info = {
            "seeder_count": seeder_count,
            "leecher_count": leecher_count,
            "download_count": download_count
        }
        conn.sendall(json.dumps(tracker_info).encode())
        print("Tracker info sent to client successfully")

    except mysql.connector.Error as e:
        error_msg = f"Error in tracker_torrent_file: {e}"
        print(error_msg)
        conn.sendall(json.dumps({"error": error_msg}).encode())

active_connections = {}  
host_files = {}

def client_handler(conn, addr):
    peers_id = None
    peers_ip= None
    peers_port = None
    peers_hostname = None
    try:
        while True:
            data = conn.recv(4096).decode()
            # log_event(f"Received data from {addr}: {data}")
            if not data:
                break

            command = json.loads(data)

            peers_ip = addr[0]
            peers_id = command['peers_id'] if 'peers_id' in command else "" 
            peers_port = command['peers_port'] if 'peers_port' in command else ""
            peers_hostname = command['peers_hostname'] if 'peers_hostname' in command else ""
            file_name = command['file_name'] if 'file_name' in command else ""
            file_size = command['file_size'] if 'file_size' in command else ""
            piece_size = command['piece_size'] if 'piece_size' in command else ""
            number_of_pieces = command['number_of_pieces'] if 'number_of_pieces' in command else ""

            username = command['username'] if 'username' in command else ""
            password_hash = command['password_hash'] if 'password_hash' in command else ""
            
            # hash_info = hashlib.sha1(f"{file_name}{piece_hash}{len(num_order_in_file)}".encode()).hexdigest()
            hash_info = hashlib.sha1(f"{file_name}".encode()).hexdigest()

            if command.get('action') == 'introduce':
                update_client_info_DHT(peers_id, peers_ip, peers_port, peers_hostname) # addr[0] is the IP address
                log_event(f"Connection established with {peers_hostname}/{peers_ip}:{peers_port})")

            # elif command['action'] == 'login':
            #     if verify_user(username, password_hash):
            #         response = {"status": "success", "message": "Đăng nhập thành công"}
            #     else:
            #         response = {"status": "fail", "message": "Tên đăng nhập hoặc mật khẩu sai"}
            #     conn.sendall(json.dumps(response).encode())
            elif command['action'] == 'register':
                if create_user(username, password_hash):
                    response = {"status": "success", "message": "Tạo tài khoản thành công"}
                else:
                    response = {"status": "fail", "message": "Tên đăng nhập đã tồn tại"}
                conn.sendall(json.dumps(response).encode())

            elif command['action'] == 'list':
                get_peers_list(conn)

            elif command['action'] == 'seeding':
                log_event(f"Upload file info and its piece hash into database with hash_info: {hash_info}")
                update_client_info_torrentFile(hash_info, file_name, file_size, piece_size, number_of_pieces)   
                update_hash_info(peers_id, hash_info, "seeder")
                log_event(f"Database update complete with hash_info: {hash_info}")
                conn.sendall("Piece info updated successfully.".encode())

            elif command['action'] == 'update':
                update_hash_info(peers_id, hash_info, "seeder")
                update_download_count(hash_info)
                conn.sendall("Peer info updated successfully.".encode())

            elif command['action'] == 'tracker':
                tracker_torrent_file(conn, hash_info)

            elif command['action'] == 'download':
                try:
                    # Truy vấn tìm tất cả các peer có hash_info trong bảng DHT
                    cur.execute("""
                        SELECT peer_id, peers_ip, peers_port, peers_hostname 
                        FROM DHT_peers
                        WHERE JSON_CONTAINS(hash_info, JSON_OBJECT('hash_info', %s))
                    """, (hash_info,))
                    results = cur.fetchall()

                    if results:
                        update_hash_info(peers_id, hash_info, "leecher")
                        # Tạo danh sách thông tin các peer
                        peers_info = [
                            {
                                'peers_id': peer_id,
                                'peers_ip': peers_ip,
                                'peers_port': peers_port,
                                'peers_hostname': peers_hostname
                            }
                            for peer_id, peers_ip, peers_port, peers_hostname in results
                        ]
                        cur.execute("""
                            SELECT number_of_pieces
                            FROM torrent_file
                            WHERE hash_info = %s
                        """, (hash_info,))
                        number_of_pieces = cur.fetchall()

                        response_data = {
                            'active_peers': peers_info,
                            'number_of_pieces': number_of_pieces
                        }           
                        # Gửi thông tin peer đã sắp xếp cho client
                        conn.sendall(json.dumps(response_data).encode())
                        print(f"Đã gửi danh sách peer cho client với hash_info: {hash_info}")
                    else:
                        # Không tìm thấy peer nào với hash_info yêu cầu
                        conn.sendall(json.dumps({'error': 'No peers found for the specified hash_info'}).encode())
                        print("No peers found for the specified hash_info")

                except mysql.connector.Error as e:
                    print(f"Error in fetch: {e}")
                    conn.sendall(json.dumps({'error': str(e)}).encode())

    except Exception as e:
        logging.exception(f"An error occurred while handling client {addr}: {e}")
    finally:
        delete_peer_from_DHT_peers(peers_id, peers_ip, peers_port, peers_hostname)

def ping_host(peers_hostname):
    # Lấy địa chỉ IP và port từ bảng DHT_peers dựa trên hostname
    cur.execute("SELECT peers_ip, peers_port FROM DHT_peers WHERE peers_hostname = %s", (peers_hostname,))
    results = cur.fetchall()  # Lấy tất cả các kết quả thay vì chỉ 1 kết quả

    if results:
        # Duyệt qua từng dòng kết quả nếu có nhiều hơn 1 kết quả
        for result in results:
            peers_ip, peers_port = result  # Gán giá trị cho peers_ip và peers_port từ kết quả truy vấn
            print(f"Ping to {peers_hostname} at IP: {peers_ip}, Port: {peers_port}")

            try:
                # Tạo socket và kết nối đến peer
                peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_sock.settimeout(5)  # Đặt timeout cho kết nối
                
                peer_sock.connect((peers_ip, peers_port))  # Kết nối tới peer
                request = {'action': 'ping'}  # Tạo yêu cầu ping
                peer_sock.sendall(json.dumps(request).encode() + b'\n')  # Gửi yêu cầu ping

                # Nhận phản hồi từ peer
                response = peer_sock.recv(4096).decode()
                peer_sock.close() 
                
                if response:
                    print(f"{peers_hostname} is online!")
                else:
                    print(f"{peers_hostname} is offline!")
        
            except socket.timeout:
                print(f"Connection to {peers_hostname} timed out.")
            except socket.error as e:
                print(f"Error connecting to {peers_hostname}: {e}")
    else:
        print(f"There is no host with the name {peers_hostname}")

def monitor_connections():
    while not stop_event.is_set():
        # Sử dụng active_count() để đếm số thread đang chạy, trừ đi 1 để không tính thread chính
        active_connections = threading.active_count() - 3  # Trừ thread chính & bản thân nó & thread start server
        log_event(f"Active connections: {active_connections}")

        # Giám sát tình trạng kết nối
        time.sleep(30)

def server_command_shell():
    while True:
        cmd_input = input("Server command: ")
        cmd_parts = cmd_input.split()
        if cmd_parts:
            action = cmd_parts[0]
            if action == "ping" and len(cmd_parts) == 2:
                hostname = cmd_parts[1]
                thread = threading.Thread(target=ping_host, args=(hostname,))
                thread.start()
            elif action == "exit":
                stop_event.set()
                break
            else:
                print("Unknown command or incorrect usage.")

def start_server(host='0.0.0.0', port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    log_event("Server started and is listening for connections.")

    try:
        while not stop_event.is_set():  # Kiểm tra cờ stop_event
            server_socket.settimeout(1.0)
            try:
                conn, addr = server_socket.accept()
                thread = threading.Thread(target=client_handler, args=(conn, addr))
                thread.start()  # Mỗi client sẽ được xử lý trong một thread riêng
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        log_event("Server shutdown requested.")
    finally:
        # Đóng socket server
        server_socket.close()
        log_event("Server socket closed.")

if __name__ == "__main__":
    # SERVER_HOST = '192.168.56.1'
    SERVER_PORT = 65432
    SERVER_HOST='0.0.0.0'

    # Start server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Start monitor in a separate thread
    monitor_thread = threading.Thread(target=monitor_connections)
    monitor_thread.start()

    # Start the server command shell in the main thread
    server_command_shell()

    # Signal the server to shutdown
    print("Server shutdown requested.")
    
    sys.exit(0)