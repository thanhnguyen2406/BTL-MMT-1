import logging
import socket
import threading
import json
import hashlib
import mysql.connector
from mysql.connector import Error
import sys

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
        print("Kết nối thành công!")
        cur = conn.cursor()
        # Thực hiện các truy vấn SQL ở đây

except Error as e:
    print("Không thể kết nối đến cơ sở dữ liệu.")
    print(e)

def log_event(message):
    logging.info(message)

def xor_distance(id1, id2):
    return int(id1, 16) ^ int(id2, 16)

def update_client_info_DHT(peer_id, hash_info, peers_ip, peers_port, peers_hostname):

    try:
        # Thêm hoặc cập nhật peer vào bảng DHT
        cur.execute("""
            INSERT INTO DHT (peer_id, hash_info, peers_ip, peers_port, peers_hostname)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                peers_ip = VALUES(peers_ip),
                peers_port = VALUES(peers_port),
                peers_hostname = VALUES(peers_hostname)
        """, (peer_id, hash_info, peers_ip, peers_port, peers_hostname))

        # Commit các thay đổi
        conn.commit()
        print(f"Thông tin peer đã được lưu với peer_id: {peer_id} và hash_info: {hash_info}")

    except mysql.connector.Error as e:
        print(f"Error in update_client_info_DHT: {e}")
        conn.rollback()

def update_client_info_torrentFile(peers_id, file_name, file_size, piece_hash, piece_size, num_order_in_file):
    try:
        # Lưu thông tin file vào bảng torrent_file
        for i in range(len(num_order_in_file)):
            cur.execute("""
                INSERT INTO torrent_file (peers_id, file_name, file_size, piece_hash, piece_size, num_order_in_file)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (peers_id, file_name, file_size, piece_hash[i], piece_size, num_order_in_file[i]))
        
        # Commit các thay đổi
        conn.commit()
        print(f"Thông tin file đã được lưu cho peer_id: {peers_id}")

    except mysql.connector.Error as e:
        print(f"Error in update_client_info_torrentFile: {e}")
        conn.rollback()


active_connections = {}  
host_files = {}

def client_handler(conn, addr):
    client_peers_hostname = None
    try:
        while True:
            data = conn.recv(4096).decode()
            # log_event(f"Received data from {addr}: {data}")
            if not data:
                break

            command = json.loads(data)

            peers_ip = addr[0]
            peers_id = command['peers_id']
            peers_port = command['peers_port']
            peers_hostname = command['peers_hostname']
            file_name = command['file_name'] if 'file_name' in command else ""
            file_size = command['file_size'] if 'file_size' in command else ""
            piece_hash = command['piece_hash'] if 'piece_hash' in command else ""
            piece_size = command['piece_size'] if 'piece_size' in command else ""
            num_order_in_file = command['num_order_in_file'] if 'num_order_in_file' in command else ""
            
            hash_info = hashlib.sha1(f"{file_name}".encode()).hexdigest()

            if command.get('action') == 'introduce':
                active_connections[peers_hostname] = conn
                log_event(f"Connection established with {peers_hostname}/{peers_ip}:{peers_port})")

            elif command['action'] == 'publish':
                # peers_ip,peers_port,peers_hostname,file_name,piece_hash
                log_event(f"Updating client info in database for hostname: {peers_hostname}/{peers_ip}:{peers_port}")
                update_client_info_DHT(peers_id, hash_info,peers_ip,peers_port, peers_hostname)  # addr[0] is the IP address
                update_client_info_torrentFile(peers_id, file_name, file_size, piece_hash, piece_size, num_order_in_file)
                log_event(f"Database update complete for hostname: {peers_hostname}/{peers_ip}:{peers_port}")
                conn.sendall("File list updated successfully.".encode())

            elif command['action'] == 'fetch':
                try:
                    # Truy vấn tìm tất cả các peer có hash_info trong bảng DHT
                    cur.execute("""
                        SELECT peer_id, peers_ip, peers_port, peers_hostname 
                        FROM DHT
                        WHERE hash_info = %s
                    """, (hash_info,))
                    results = cur.fetchall()

                    if results:
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

                        # Lọc ra những peer đang kết nối (giả sử active_connections chứa các peer đang hoạt động)
                        active_sorted_peers_info = [
                            peer for peer in sorted_peers_info if peer['peers_hostname'] in active_connections
                        ]

                        selected_peer_ids = [peer['peers_id'] for peer in active_sorted_peers_info]

                        try:
                            # Kiểm tra nếu số lượng peer lớn hơn 1
                            if len(selected_peer_ids) > 1:
                                # Tạo danh sách các placeholder cho từng `peer_id`
                                placeholders = ", ".join(["%s"] * len(selected_peer_ids))
                                query = f"""
                                    SELECT file_name, file_size, piece_hash, piece_size, num_order_in_file, peers_id
                                    FROM torrent_file
                                    WHERE peers_id IN ({placeholders}) AND file_name = %s
                                """
                                cur.execute(query, (*selected_peer_ids, file_name))  # Truyền selected_peer_ids dưới dạng unpacked arguments
                            else:
                                # Truy vấn khi chỉ có 1 peer_id
                                cur.execute("""
                                    SELECT file_name, file_size, piece_hash, piece_size, num_order_in_file, peers_id
                                    FROM torrent_file
                                    WHERE peers_id = %s AND file_name = %s
                                """, (selected_peer_ids[0], file_name))
                            results = cur.fetchall()

                            torrent_file_info = [
                                {
                                    'file_name': row[0],
                                    'file_size': row[1],
                                    'piece_hash': row[2],
                                    'piece_size': row[3],
                                    'num_order_in_file': row[4],
                                    'peers_id': row[5]  
                                }
                                for row in results
                            ]
                            
                            response_data = {
                                'active_peers': active_sorted_peers_info,
                                'torrent_file_info': torrent_file_info
                            }           
                            # Gửi thông tin peer đã sắp xếp cho client
                            conn.sendall(json.dumps(response_data).encode())
                            print(f"Đã gửi danh sách peer cho client với hash_info: {hash_info}")

                        except mysql.connector.Error as e:
                            print(f"Error in fetch: {e}")
                            conn.sendall(json.dumps({'error': str(e)}).encode())
                    else:
                        # Không tìm thấy peer nào với hash_info yêu cầu
                        conn.sendall(json.dumps({'error': 'No peers found for the specified hash_info'}).encode())
                        print("Không tìm thấy peer nào phù hợp với hash_info")

                except mysql.connector.Error as e:
                    print(f"Error in fetch: {e}")
                    conn.sendall(json.dumps({'error': str(e)}).encode())


            elif command['action'] == 'file_list':
                files = command['files']
                print(f"List of files : {files}")

    except Exception as e:
        logging.exception(f"An error occurred while handling client {addr}: {e}")
    finally:
        if client_peers_hostname:
            del active_connections[client_peers_hostname]  

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