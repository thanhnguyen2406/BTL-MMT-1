import socket
import json
import os
import threading
import shlex
import hashlib
import random
import sys
import termios
import tty
from collections import defaultdict

stop_event = threading.Event()

def generate_peer_id(): 
    return hashlib.sha1(str(random.getrandbits(160)).encode()).hexdigest()

peers_id = generate_peer_id()
lock = threading.Lock()

def calculate_piece_hash(piece_data):
    sha1 = hashlib.sha1()
    sha1.update(piece_data)
    return sha1.digest()

def create_pieces_string(pieces):
    hash_pieces = []
    for piece_file_path in pieces:
            with open(piece_file_path, "rb") as piece_file:
                piece_data = piece_file.read()
                piece_hash = calculate_piece_hash(piece_data)
                hash_pieces.append(f"{piece_hash}")
    return hash_pieces

def split_file_into_pieces(file_path, piece_length):
    pieces = []
    with open(file_path, "rb") as file:
        counter = 1
        while True:
            piece_data = file.read(piece_length)
            if not piece_data:
                break
            #Piece_file name
            piece_file_path = f"{file_path}_piece{counter}"
            with open(piece_file_path, "wb") as piece_file:
                piece_file.write(piece_data)
            pieces.append(piece_file_path)
            counter += 1
    return pieces

def merge_pieces_into_file(pieces, output_file_path):
    with open(output_file_path, "wb") as output_file:
        for piece_file_path in pieces:
            with open(piece_file_path, "rb") as piece_file:
                piece_data = piece_file.read()
                output_file.write(piece_data)

def get_list_local_files(directory='.'):
    try:
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        return True
    except Exception as e:
        return f"Error: Unable to list files - {e}"
    
def check_local_files(file_name):
    if not os.path.exists(file_name):
        return False
    else:
        return True
    
def check_local_piece_files(file_name):
    exist_files = []
    directory = os.getcwd()  # Lấy đường dẫn thư mục hiện tại

    for filename in os.listdir(directory):
        if filename.startswith(file_name) and len(filename)>len(file_name):
            exist_files.append(filename)

    if len(exist_files) > 0:
        return exist_files
    else:
        return False

def get_password(prompt="Password: "):
    print(prompt, end="", flush=True)
    password = ""
    
    # Lưu cài đặt terminal hiện tại
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setraw(fd)  # Chuyển terminal sang chế độ raw
        
        while True:
            ch = sys.stdin.read(1)  # Đọc từng ký tự
            if ch == "\n" or ch == "\r":  # Kết thúc khi nhấn Enter
                print("")
                break
            elif ch == "\x7f":  # Xóa ký tự khi nhấn Backspace
                if len(password) > 0:
                    password = password[:-1]
                    print("\b \b", end="", flush=True)
            else:
                password += ch
                print("*", end="", flush=True)  # Hiển thị `*`

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)  # Phục hồi cài đặt ban đầu

    return password

def handle_upload_piece(sock, peers_port, file_name, file_size, pieces):
    pieces_hash = create_pieces_string(pieces)
    num_order_in_file = [str(i) for i in range(1, len(pieces) + 1)]
    piece_hash=[]
    print("You have uploaded:")
    for i in num_order_in_file:
        index = pieces.index(f"{file_name}_piece{i}")
        piece_hash.append(pieces_hash[index])
        print (f"Piece number {i} : {pieces_hash[index]}")
    upload_piece_file(sock,peers_port,file_name, file_size, piece_hash, num_order_in_file)


def handle_list_peers(sock):
    global peers_id

    # Xây dựng lệnh để gửi
    command = {
        "action": "list",
        "peers_id": peers_id,
    }

    try:
        sock.sendall(json.dumps(command).encode())  # Gửi command đi
        response = sock.recv(4096).decode()  # Nhận phản hồi từ server
        peers_list = json.loads(response)  # Chuyển đổi dữ liệu JSON thành list

        # Duyệt qua các peer trong peers_list và in thông tin
        for peer in peers_list:
            peer_id = peer["peer_id"]
            peers_ip = peer["peers_ip"]
            peers_port = peer["peers_port"]
            peers_hostname = peer["peers_hostname"]
            file_name = peer["file_name"]

            print(f"Peer with ID \"{peer_id}\":")
            print(f" . Peer IP: {peers_ip}")
            print(f" . Peer port: {peers_port}")
            print(f" . Peer hostname: {peers_hostname}")
            print(f" . File name: {file_name if file_name else 'None'}\n")

    except Exception as e:
        print(f"Error in handle_list_peers: {e}")



def upload_piece_file(sock,peers_port,file_name, file_size, piece_hash, num_order_in_file):
    global peers_id
    peers_hostname = socket.gethostname()
    command = {
        "action": "upload",
        "peers_id": peers_id,
        "peers_port": peers_port,
        "peers_hostname":peers_hostname,
        "file_name":file_name,
        "file_size":file_size,
        "piece_hash":piece_hash,
        "num_order_in_file":num_order_in_file,
        "number_of_pieces":len(num_order_in_file),
    }
    # shared_piece_files_dir.append(command)
    sock.sendall(json.dumps(command).encode() + b'\n')
    response = sock.recv(4096).decode()
    print(response)

def handler_update_peer_seeder(sock,peers_port,file_name):
    global peers_id
    peers_hostname = socket.gethostname()
    command = {
        "action": "update",
        "peers_id": peers_id,
        "peers_port": peers_port,
        "peers_hostname":peers_hostname,
        "file_name":file_name,
    }
    sock.sendall(json.dumps(command).encode() + b'\n')
    response = sock.recv(4096).decode()
    print(response)

def get_total_pieces_needed(torrent_file_info):
    pieces_count = defaultdict(int)
    # Đếm số mảnh của từng peer_id
    for info in torrent_file_info:
        peers_id = info['peers_id']
        pieces_count[peers_id] += 1  
    
    # Lấy số lượng mảnh lớn nhất trong các peer_id
    max_pieces = max(pieces_count.values()) if pieces_count else 0
    return max_pieces

def request_file_from_peer(peers_ip, peer_port, file_name, piece_hash, num_order_in_file):
    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            peer_port = int(peer_port)  # Đảm bảo peer_port là một số nguyên
        except ValueError:
            print(f"Invalid port: {peer_port} cannot be converted to an integer.")

        peer_sock.connect((peers_ip, int(peer_port)))
        peer_sock.sendall(json.dumps({'action': 'send_file', 'file_name': file_name, 'piece_hash':piece_hash, 'num_order_in_file':num_order_in_file}).encode() + b'\n')

        # Peer will send the file in chunks of 4096 bytes
        with open(f"{file_name}_piece{num_order_in_file}", 'wb') as f:
            while True:
                data = peer_sock.recv(4096)
                if not data:
                    break
                f.write(data)

        peer_sock.close()
        print(f"Piece of file: {file_name}_piece{num_order_in_file} has been fetched from peer.")
    except Exception as e:
        print(f"An error occurred while connecting to peer at {peers_ip}:{peer_port} - {e}")
    finally:
        peer_sock.close()

def handle_download_file(sock,peers_port,file_name, piece_hash, num_order_in_file):
    peers_hostname = socket.gethostname()
    command = {
        "action": "download",
        "peers_id" : peers_id,
        "peers_port": peers_port,
        "peers_hostname":peers_hostname,
        "file_name":file_name,
        "piece_hash":piece_hash,
        "num_order_in_file":num_order_in_file,
    } 

    # command = {"action": "fetch", "fname": fname}
    sock.sendall(json.dumps(command).encode() + b'\n')
    response = json.loads(sock.recv(4096).decode())

    active_peers = response.get('active_peers', [])  # Lấy danh sách peers
    torrent_file_info = response.get('torrent_file_info', [])  # Lấy thông tin torrent
    
    if isinstance(active_peers, list):
        # Hiển thị danh sách các peer có thể tải
        host_info_str = "\n".join([
            f"Peer: {peer_info['peers_hostname']} IP: {peer_info['peers_ip']}:{peer_info['peers_port']}"
            for peer_info in active_peers
        ])
        print(f"Hosts with the file {file_name}:\n{host_info_str}")
        # Tải từng piece từ các peer cho đến khi đủ
        pieces_downloaded = set()  # Lưu các piece đã tải
        total_pieces_needed = 0  # Tổng số lượng piece cần tải

        # Duyệt qua các peer để tải từng piece
        for peer_info in active_peers:
            # Lấy các phần liên quan đến peer hiện tại từ torrent_file_info
            pieces_for_peer = list(filter(lambda piece: piece['peers_id'] == peer_info['peers_id'], torrent_file_info))
            total_pieces_needed = get_total_pieces_needed(torrent_file_info)

            for piece in pieces_for_peer:
                file_name = piece['file_name']
                piece_hash = piece['piece_hash']
                num_order_in_file = piece['num_order_in_file']
                if num_order_in_file not in pieces_downloaded:
                    print(f"Đang tải phần {num_order_in_file} từ peer {peer_info['peers_hostname']}...")
                    request_file_from_peer(
                        peer_info['peers_ip'], 
                        peer_info['peers_port'], 
                        file_name, 
                        piece_hash, 
                        num_order_in_file
                    )
                    pieces_downloaded.add(num_order_in_file)
                    # Kiểm tra xem đã đủ các piece chưa
                    pieces = check_local_piece_files(file_name)  # Kiểm tra các phần đã tải xuống
                    if len(pieces) == total_pieces_needed:  # Nếu đủ số lượng piece cần thiết
                        merge_pieces_into_file(pieces, file_name)
                        print(f"Đã tải đủ các piece và hoàn thành file: {file_name}")
                        handler_update_peer_seeder(sock,peers_port,file_name)
                        return  # Thoát khỏi hàm khi hoàn thành file

        # Nếu không đủ piece
        if len(pieces_downloaded) < total_pieces_needed:
            print("Đã tải tất cả các peer nhưng vẫn chưa đủ các piece.")
    else:
        print("Không nhận được thông tin về các peer hoạt động.")
    

def send_piece_to_client(conn, piece):
    with open(piece, 'rb') as f:
        while True:
            bytes_read = f.read(4096)
            if not bytes_read:
                break
            conn.sendall(bytes_read)

def handle_file_request(conn, shared_files_dir):
    try:
        data = conn.recv(4096).decode()
        command = json.loads(data)
        if command['action'] == 'send_file':
            file_name = command['file_name']
            num_order_in_file = command['num_order_in_file']
            file_path = os.path.join(shared_files_dir, f"{file_name}_piece{num_order_in_file}")
            send_piece_to_client(conn, file_path)
    finally:
        conn.close()

def handle_tracker_file(sock, file_name):
    command = {
        "action": "tracker",
        "file_name":file_name,
    } 

    # command = {"action": "fetch", "fname": fname}
    sock.sendall(json.dumps(command).encode() + b'\n')
    response = json.loads(sock.recv(4096).decode())
    print(response)

def start_host_service(port, shared_files_dir):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('0.0.0.0', port))
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.listen()

    while not stop_event.is_set():
        try:
            server_sock.settimeout(1) 
            conn, addr = server_sock.accept()
            thread = threading.Thread(target=handle_file_request, args=(conn, shared_files_dir))
            thread.start()
        except socket.timeout:
            continue
        except Exception as e:
            break

    server_sock.close()

def authenticate_user(sock):
    global peers_id
    peers_hostname = socket.gethostname()
    while True:
        # Hiển thị tùy chọn cho người dùng
        action = input("Bạn có tài khoản chưa? (login/register/exit): ").strip().lower()
        
        if action == 'login':
            username = input("Tên đăng nhập: ").strip()
            password = get_password()
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            # Gửi yêu cầu đăng nhập tới server
            command = {
                "action": "login",
                "peers_id" : peers_id,
                "peers_hostname":peers_hostname,
                "username":username,
                "password_hash":password_hash
            }
            sock.sendall(json.dumps(command).encode() + b'\n')
            response = json.loads(sock.recv(4096).decode())
            
            if response.get("status") == "success":
                print("==== Đăng nhập thành công ====")
                return True
            else:
                print("Đăng nhập thất bại. Vui lòng thử lại.")
        
        elif action == 'register':
            username = input("Tên đăng nhập: ").strip()
            password = input("Mật khẩu: ").strip()
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            # Gửi yêu cầu tạo tài khoản tới server
            command = {
                "action": "register",
                "peers_id" : peers_id,
                "peers_hostname":peers_hostname,
                "username":username,
                "password_hash":password_hash
            }
            sock.sendall(json.dumps(command).encode() + b'\n')
            response = json.loads(sock.recv(4096).decode())
            
            if response.get("status") == "success":
                print("Tạo tài khoản thành công! Bạn có thể đăng nhập.")
            else:
                print("Tạo tài khoản thất bại. Tên đăng nhập đã tồn tại hoặc có lỗi khác.")
        elif action == 'exit':
            return False
        else:
            print("Invalid command.")

def connect_to_server(server_host, server_port, peers_port):
    global peers_id
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_host, server_port))
    peers_hostname = socket.gethostname()
    sock.sendall(json.dumps({'action': 'introduce', 'peers_id': peers_id,'peers_hostname': peers_hostname, 'peers_port':peers_port }).encode() + b'\n')
    return sock

def main(server_host, server_port, peers_port):
    host_service_thread = threading.Thread(target=start_host_service, args=(peers_port, './'))
    host_service_thread.start()
    # Connect to the server
    sock = connect_to_server(server_host, server_port, peers_port)

    
    if not authenticate_user(sock):
        print("Không thể xác thực người dùng.")
        sock.close()
        host_service_thread.join()
        return

    try:
        while True:
            user_input = input("Enter command (upload file_name/ download file_name/ tracker file_name/ list/ exit): ")#addr[0],peers_port, peers_hostname,file_name, piece_hash,num_order_in_file
            command_parts = shlex.split(user_input)
            if len(command_parts) == 1 and command_parts[0].lower() == 'list':
                handle_list_peers(sock)

            elif len(command_parts) == 2 and command_parts[0].lower() == 'upload':
                _,file_name = command_parts
                if check_local_files(file_name):
                    piece_size = 524288  # 524288 byte = 512KB
                    file_size = os.path.getsize(file_name)
                    pieces = split_file_into_pieces(file_name,piece_size)
                    handle_upload_piece(sock, peers_port, file_name, file_size, pieces)
                elif (pieces := check_local_piece_files(file_name)):
                    handle_upload_piece(sock, peers_port, pieces, file_name)
                else:
                    print(f"Local file {file_name}/piece does not exist.")

            elif len(command_parts) == 2 and command_parts[0].lower() == 'download':
                try:
                    _, file_name = command_parts
                    pieces = check_local_piece_files(file_name)
                    pieces_hash = [] if not pieces else create_pieces_string(pieces)
                    num_order_in_file= [] if not pieces else [item.split("_")[-1][5:] for item in pieces]
                    handle_download_file(sock,peers_port,file_name, pieces_hash,num_order_in_file)
                except Exception as e:
                    print("Invalid fetch command.")
                    # continue
            
            elif len(command_parts) == 2 and command_parts[0].lower() == 'tracker':
                try:
                    _, file_name = command_parts
                    handle_tracker_file(sock, file_name)
                except Exception as e:
                    print("Invalid fetch command.")
                    # continue

            elif user_input.lower() == 'exit':
                stop_event.set()  # Stop the host service thread
                sock.close()
                break
            else:
                print("Invalid command.")

    finally:
        sock.close()
        host_service_thread.join()


if __name__ == "__main__":
    # Replace with your server's IP address and port number
    SERVER_HOST = '192.168.1.10'
    SERVER_PORT = 65432
    CLIENT_PORT = 65434
    main(SERVER_HOST, SERVER_PORT,CLIENT_PORT)