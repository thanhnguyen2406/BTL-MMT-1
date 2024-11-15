import logging
import socket
import threading
import json
import hashlib
import mysql.connector
from mysql.connector import Error
import sys
import json

conn = None
cur = None

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

def create_user(username, password):
    # Kiểm tra nếu tên đăng nhập đã tồn tại
    cur.execute("SELECT username FROM users WHERE username = %s", (username,))
    if cur.fetchone():
        return False  # Nếu tên đăng nhập đã tồn tại, trả về False

    # Mã hóa mật khẩu bằng SHA256
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Thêm người dùng mới vào cơ sở dữ liệu
    cur.execute("""
            INSERT IGNORE INTO users (username, password_hash)
            VALUES (%s, %s)
        """, (username, password_hash))

    return True

def verify_user(username, password):
    # Lấy thông tin người dùng từ cơ sở dữ liệu
    cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
    row = cur.fetchone()

    if row:
        stored_password_hash = row[0]
        # So sánh mật khẩu đã băm
        return stored_password_hash == hashlib.sha256(password.encode()).hexdigest()
    else:
        return False

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

def update_client_info_peerStorage(peer_id, piece_hash, hash_info, file_name, num_order_in_file):
    try:
        # Lưu thông tin vào bảng peer_storage
        for i in range(len(piece_hash)):
            cur.execute("""
                INSERT IGNORE INTO peer_storage (peer_id, piece_hash, hash_info, file_name, num_order_in_file)
                VALUES (%s, %s, %s, %s, %s)
            """, (peer_id, piece_hash[i], hash_info, file_name, num_order_in_file[i]))
        
        # Commit các thay đổi
        conn.commit()
        print(f"Thông tin đã được lưu cho peer_id: {peer_id} với hash_info: {hash_info}")

    except mysql.connector.Error as e:
        print(f"Error in update_client_info_peerStorage: {e}")
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

def delete_peer_from_DHT_peers(peer_id):
    try:
        # Xóa các bản ghi liên quan đến peer_id trong bảng peer_storage
        cur.execute("""
            DELETE FROM peer_storage
            WHERE peer_id = %s
        """, (peer_id,))
        conn.commit()
        
        # Xóa thông tin peer khỏi bảng DHT_peers
        cur.execute("""
            DELETE FROM DHT_peers WHERE peer_id = %s
        """, (peer_id,))
        
        # Commit các thay đổi
        conn.commit()
        print(f"Peer với peer_id: {peer_id} đã được xóa khỏi cả peer_storage và DHT_peers.")
    
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
            piece_hash = command['piece_hash'] if 'piece_hash' in command else ""
            piece_size = command['piece_size'] if 'piece_size' in command else ""
            num_order_in_file = command['num_order_in_file'] if 'num_order_in_file' in command else ""
            number_of_pieces = command['number_of_pieces'] if 'number_of_pieces' in command else ""

            username = command['username'] if 'username' in command else ""
            password_hash = command['password_hash'] if 'password_hash' in command else ""
            
            # hash_info = hashlib.sha1(f"{file_name}{piece_hash}{len(num_order_in_file)}".encode()).hexdigest()
            hash_info = hashlib.sha1(f"{file_name}".encode()).hexdigest()

            if command.get('action') == 'introduce':
                # active_connections[peers_hostname] = conn
                update_client_info_DHT(peers_id, peers_ip, peers_port, peers_hostname) # addr[0] is the IP address
                log_event(f"Connection established with {peers_hostname}/{peers_ip}:{peers_port})")

            elif command['action'] == 'login':
                if verify_user(username, password_hash):
                    response = {"status": "success", "message": "Đăng nhập thành công"}
                else:
                    response = {"status": "fail", "message": "Tên đăng nhập hoặc mật khẩu sai"}
                conn.sendall(json.dumps(response).encode())
            elif command['action'] == 'register':
                if create_user(username, password_hash):
                    response = {"status": "success", "message": "Tạo tài khoản thành công"}
                else:
                    response = {"status": "fail", "message": "Tên đăng nhập đã tồn tại"}
                conn.sendall(json.dumps(response).encode())

            elif command['action'] == 'list':
                get_peers_list(conn)

            elif command['action'] == 'upload':
                log_event(f"Upload file info and its piece hash into database with hash_info: {hash_info}")
                update_client_info_torrentFile(hash_info, file_name, file_size, piece_size, number_of_pieces)   
                update_hash_info(peers_id, hash_info, "seeder")
                update_client_info_peerStorage(peers_id, piece_hash, hash_info, file_name, num_order_in_file)
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

                        # Tính khoảng cách XOR giữa client_peer_id và từng peer trong danh sách
                        sorted_peers_info = sorted(
                            peers_info,
                            key=lambda peer: xor_distance(peers_id, peer['peers_id'])
                        )

                        selected_peer_ids = [peer['peers_id'] for peer in sorted_peers_info]
                        unique_piece_data = set()
                        piece_hash_list = []
                        order_num_list = []

                        try:
                            # Kiểm tra nếu số lượng peer lớn hơn 1
                            if len(selected_peer_ids) > 1:
                                # Tạo danh sách các placeholder cho từng `peer_id`
                                placeholders = ", ".join(["%s"] * len(selected_peer_ids))
                                query = f"""
                                    SELECT file_name, piece_hash, num_order_in_file, peer_id
                                    FROM peer_storage
                                    WHERE peer_id IN ({placeholders}) AND hash_info = %s
                                """
                                cur.execute(query, (*selected_peer_ids, hash_info))  # Truyền selected_peer_ids dưới dạng unpacked arguments
                            else:
                                # Truy vấn khi chỉ có 1 peer_id
                                cur.execute("""
                                    SELECT file_name, piece_hash, num_order_in_file, peer_id
                                    FROM peer_storage
                                    WHERE peer_id = %s AND hash_info = %s
                                """, (selected_peer_ids[0], hash_info))
                            results = cur.fetchall()

                            torrent_file_info = []
                            for row in results:
                                # Thêm từng piece_hash vào tập hợp unique_piece_hashes để tránh trùng lặp
                                unique_piece_data.add((row[1], row[2]))
                                torrent_file_info.append({
                                    'file_name': row[0],
                                    'piece_hash': row[1],
                                    'num_order_in_file': row[2],
                                    'peers_id': row[3]
                                })

                            # Chuyển tập hợp thành danh sách
                            piece_hash_list = [piece[0] for piece in unique_piece_data]
                            order_num_list = [piece[1] for piece in unique_piece_data]
                            
                            response_data = {
                                'active_peers': sorted_peers_info,
                                'torrent_file_info': torrent_file_info
                            }           
                            # Gửi thông tin peer đã sắp xếp cho client
                            conn.sendall(json.dumps(response_data).encode())
                            print(f"Đã gửi danh sách peer cho client với hash_info: {hash_info}")

                        except mysql.connector.Error as e:
                            print(f"Error in fetch: {e}")
                            conn.sendall(json.dumps({'error': str(e)}).encode())

                        # Publish and Upload new file for peers
                        update_client_info_peerStorage(peers_id, piece_hash_list, hash_info, file_name, order_num_list)

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
        delete_peer_from_DHT_peers(peers_id)

def request_file_list_from_client(peers_hostname):
    if peers_hostname in active_connections:
        conn = active_connections[peers_hostname]
        print(active_connections[peers_hostname])
        ip_address, _ = conn.getpeername()
        # print(ip_address)
        peer_port = 65433  
        peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_sock.connect((ip_address, peer_port))
        request = {'action': 'request_file_list'}
        peer_sock.sendall(json.dumps(request).encode() + b'\n')
        response = json.loads(peer_sock.recv(4096).decode())
        peer_sock.close()
        if 'files' in response:
            return response['files']
        else:
            return "Error: No file list in response"
    else:
        return "Error: Client not connected"

def discover_files(peers_hostname):
    # Connect to the client and request the file list
    files = request_file_list_from_client(peers_hostname)
    print(f"Files on {peers_hostname}: {files}")

def ping_host(peers_hostname):
    cur.execute("SELECT address FROM client_files WHERE hostname = %s", (peers_hostname,))
    results = cur.fetchone()  
    ip_address = results[0]
    print(ip_address)
    if ip_address:
        peer_port = 65433
        peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_sock.connect((ip_address, peer_port))
        request = {'action': 'ping'}
        peer_sock.sendall(json.dumps(request).encode() + b'\n')
        response = peer_sock.recv(4096).decode()
        peer_sock.close()
        if response:
            print(f"{peers_hostname} is online!")
        else:
            print(f"{peers_hostname} is offline!")
    else:
        print("There is no host with that name")



def server_command_shell():
    while True:
        cmd_input = input("Server command: ")
        cmd_parts = cmd_input.split()
        if cmd_parts:
            action = cmd_parts[0]
            if action == "discover" and len(cmd_parts) == 2:
                hostname = cmd_parts[1]
                thread = threading.Thread(target=discover_files, args=(hostname,))
                thread.start()
            elif action == "ping" and len(cmd_parts) == 2:
                hostname = cmd_parts[1]
                thread = threading.Thread(target=ping_host, args=(hostname,))
                thread.start()
            elif action == "exit":
                break
            else:
                print("Unknown command or incorrect usage.")

def start_server(host='0.0.0.0', port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    log_event("Server started and is listening for connections.")

    try:
        while True:
            conn, addr = server_socket.accept()
            # host = server_socket.getsockname()
            # log_event(f"Accepted connection from {addr}, hostname is {host}")
            thread = threading.Thread(target=client_handler, args=(conn, addr))
            thread.start()
            log_event(f"Active connections: {threading.active_count() - 1}")
    except KeyboardInterrupt:
        log_event("Server shutdown requested.")
    finally:
        # Đóng socket server
        server_socket.close()
        # Đóng con trỏ và kết nối đến cơ sở dữ liệu MySQL
        cur.close()
        conn.close()


if __name__ == "__main__":
    # SERVER_HOST = '192.168.56.1'
    SERVER_PORT = 65432
    SERVER_HOST='0.0.0.0'
    # Start server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Start the server command shell in the main thread
    server_command_shell()

    # Signal the server to shutdown
    print("Server shutdown requested.")
    
    sys.exit(0)