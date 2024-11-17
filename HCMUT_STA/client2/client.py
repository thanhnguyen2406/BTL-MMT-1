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

def handler_seeding_piece(sock, peers_port, file_name, file_size, pieces):
    pieces_hash = create_pieces_string(pieces)
    num_order_in_file = [str(i) for i in range(1, len(pieces) + 1)]
    piece_hash=[]
    print("You have uploaded:")
    for i in num_order_in_file:
        index = pieces.index(f"{file_name}_piece{i}")
        piece_hash.append(pieces_hash[index])
        print (f"Piece number {i} : {pieces_hash[index]}")
    seeding_piece_file(sock,peers_port,file_name, file_size, piece_hash, num_order_in_file)


def handler_list_peers(sock, peers_port):
    global peers_id
    peers_hostname = socket.gethostname()
    # Xây dựng lệnh để gửi
    command = {
        "action": "list",
        "peers_id": peers_id,
        "peers_port": peers_port,
        "peers_hostname":peers_hostname,
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
        print(f"Error in handler_list_peers: {e}")

def seeding_piece_file(sock,peers_port,file_name, file_size, piece_hash, num_order_in_file):
    global peers_id
    peers_hostname = socket.gethostname()
    command = {
        "action": "seeding",
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

def request_piece_from_peer(peers_ip, peer_port, file_name, num_order_in_file=None):
    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            peer_port = int(peer_port)  # Đảm bảo peer_port là một số nguyên
        except ValueError:
            print(f"Invalid port: {peer_port} cannot be converted to an integer.")

        peer_sock.connect((peers_ip, int(peer_port)))

        if num_order_in_file is not None:
            # Yêu cầu tải một piece cụ thể
            command = {"action": "send_piece", "file_name": file_name, "num_order_in_file": num_order_in_file}
            peer_sock.sendall(json.dumps(command).encode() + b'\n')

            # Tải piece từ peer
            with open(f"{file_name}_piece{num_order_in_file}", 'wb') as f:
                while True:
                    data = peer_sock.recv(4096)
                    if not data:
                        break
                    f.write(data)
            print(f"Tải thành công: {file_name}_piece{num_order_in_file}")

            return f"{file_name}_piece{num_order_in_file}"

        else:
            # Yêu cầu danh sách các piece
            command = {"action": "get_piece_info", "file_name": file_name}
            peer_sock.sendall(json.dumps(command).encode() + b'\n')
            response = peer_sock.recv(4096).decode()
            piece_info = json.loads(response)
            return piece_info.get("pieces", [])

    except Exception as e:
        print(f"An error occurred while connecting to peer at {peers_ip}:{peer_port} - {e}")
        return [] if num_order_in_file is None else None
    finally:
        peer_sock.close()

def get_piece_info_thread(peer_info, file_name, piece_availability, lock):
    try:
        # Gửi yêu cầu đến peer để lấy thông tin các mảnh
        peer_pieces = request_piece_from_peer(peer_info['peers_ip'], peer_info['peers_port'], file_name)
        
        # Cập nhật thông tin mảnh vào piece_availability dưới sự bảo vệ của lock
        with lock:
            for piece in peer_pieces:
                if piece not in piece_availability:
                    piece_availability[piece] = []
                piece_availability[piece].append(peer_info)
    except Exception as e:
        print(f"Error from getting information from peer {peer_info['peers_hostname']}: {e}")

def download_piece_thread(piece, peers_holding_piece, pieces_downloaded, lock, file_name):
    for peer_info in peers_holding_piece:
        try:
            with lock:
                pieces_downloaded.add(piece)

            print(f"Đang tải piece {piece} từ peer {peer_info['peers_hostname']}...")
            success = request_piece_from_peer(
                peer_info['peers_ip'],
                peer_info['peers_port'],
                file_name,
                piece
            )

            if success:
                print(f"Đã tải thành công piece {piece}")
                return
        except Exception as e:
            print(f"Lỗi khi tải piece {piece} từ peer {peer_info['peers_hostname']}: {e}")

def handler_download_file(sock,peers_port,file_name, piece_hash, num_order_in_file):
    global peers_id
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
    number_of_pieces = response.get('number_of_pieces', [])
    
    while isinstance(number_of_pieces, list) and len(number_of_pieces) == 1:
        number_of_pieces = number_of_pieces[0]

    if isinstance(active_peers, list):
        # Vòng lặp 1: Kết nối đến các peer để lấy thông tin các piece
        piece_availability = {}  # Map lưu thông tin piece -> danh sách peer nắm giữ piece
        lock = threading.Lock()  # Lock cho đồng bộ hóa

        threads = []  # Danh sách để chứa các thread
        for peer_info in active_peers:
            # Tạo một thread cho mỗi peer để lấy thông tin các mảnh song song
            thread = threading.Thread(target=get_piece_info_thread, args=(peer_info, file_name, piece_availability, lock))
            threads.append(thread)
            thread.start()

        # Đảm bảo rằng tất cả các thread đã hoàn thành
        for thread in threads:
            thread.join()

        # Sắp xếp các piece theo "rarest piece first"
        sorted_pieces = sorted(piece_availability.items(), key=lambda x: len(x[1]))
        pieces_downloaded = set()

        # Vòng lặp 2: Tải các piece theo thứ tự đã sắp xếp
        download_threads = []  # Danh sách để chứa các thread tải piece
        for piece, peers_holding_piece in sorted_pieces:
            if piece in pieces_downloaded:
                continue
            
            # Tạo và khởi chạy một thread cho mỗi mảnh
            thread = threading.Thread(target=download_piece_thread, args=(piece, peers_holding_piece, pieces_downloaded, lock, file_name))
            download_threads.append(thread)
            thread.start()

        # Chờ tất cả các thread hoàn thành
        for thread in download_threads:
            thread.join()

        # Sau khi tất cả các mảnh đã được tải về, thực hiện gộp các mảnh lại
        if len(pieces_downloaded) == number_of_pieces:
                merge_pieces_into_file(check_local_piece_files(file_name), file_name)
                print(f"Đã tải đủ các piece và hoàn thành file: {file_name}")
                handler_update_peer_seeder(sock, peers_port, file_name)
                return 
        
        # Nếu không đủ piece sau khi thử tất cả các peer
        print("Đã tải từ tất cả các peer nhưng vẫn chưa đủ các piece.")
    else:
        print("Not found any host with file {file_name}")

def send_piece_to_client(conn, piece):
    with open(piece, 'rb') as f:
        while True:
            bytes_read = f.read(4096)
            if not bytes_read:
                break
            conn.sendall(bytes_read)

def handler_request(conn, shared_files_dir):
    try:
        # Nhận dữ liệu yêu cầu
        data = conn.recv(4096).decode()
        command = json.loads(data)

        if command["action"] == "get_piece_info":
            file_name = command["file_name"]
            pieces = []

            # Duyệt qua thư mục chia sẻ để lấy danh sách các piece
            for filename in os.listdir(shared_files_dir):
                if filename.startswith(file_name) and "_piece" in filename:
                    try:
                        num_order_in_file = int(filename.split("_piece")[-1])
                        pieces.append(num_order_in_file)
                    except ValueError:
                        print(f"Lỗi phân tích tên file: {filename}")

            response = {"pieces": pieces}
            conn.sendall(json.dumps(response).encode())

        elif command["action"] == "send_piece":
            file_name = command["file_name"]
            num_order_in_file = command["num_order_in_file"]
            file_path = os.path.join(shared_files_dir, f"{file_name}_piece{num_order_in_file}")

            if os.path.exists(file_path):
                send_piece_to_client(conn, file_path)
            else:
                print(f"Không tìm thấy file: {file_path}")
        
        elif command["action"] == "ping":
            print("\nPing request received, responding with pong...")
            response = {'action': 'pong'}
            conn.sendall(json.dumps(response).encode())

    except Exception as e:
        print(f"Lỗi trong handler_request: {e}")
    finally:
        conn.close()

def handler_tracker_file(sock, file_name, peers_port):
    global peers_id
    peers_hostname = socket.gethostname()
    command = {
        "action": "tracker",
        "peers_id" : peers_id,
        "peers_port": peers_port,
        "peers_hostname":peers_hostname,
        "file_name":file_name,
    } 

    # command = {"action": "fetch", "fname": fname}
    sock.sendall(json.dumps(command).encode() + b'\n')
    response = json.loads(sock.recv(4096).decode())
    print(response)

def authenticate_user(sock):
    global peers_id
    peers_hostname = socket.gethostname()
    while True:
        # Hiển thị tùy chọn cho người dùng
        action = input("Do you have an account? (login/register/exit): ").strip().lower()
        
        if action == 'login':
            username = input("Username: ").strip()
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
                print("==== Log in successfully ====")
                return True
            else:
                print("Fail to log in. Please try again.")
        
        elif action == 'register':
            username = input("Username: ").strip()
            password = input("Password: ").strip()
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
                print("Create account successfully! You can log in now.")
            else:
                print("Fail to create account. Username has been exist.")
        elif action == 'exit':
            return False
        else:
            print("Invalid command.")

def connect_to_server(server_host, server_port, peers_port):
    global peers_id

    global stop_event
    stop_event = threading.Event()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_host, server_port))
    peers_hostname = socket.gethostname()
    sock.sendall(json.dumps({'action': 'introduce', 'peers_id': peers_id,'peers_hostname': peers_hostname, 'peers_port':peers_port }).encode() + b'\n')
    return sock

def start_host_service(port, shared_files_dir):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('0.0.0.0', port))
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.listen()

    while not stop_event.is_set():
        try:
            server_sock.settimeout(1) 
            conn, addr = server_sock.accept()
            thread = threading.Thread(target=handler_request, args=(conn, shared_files_dir))
            thread.start()
        except socket.timeout:
            continue
        except Exception as e:
            break

    server_sock.close()

def main(server_host, server_port, peers_port):
    host_service_thread = threading.Thread(target=start_host_service, args=(peers_port, './'))
    host_service_thread.start()
    # Connect to the server
    sock = connect_to_server(server_host, server_port, peers_port)

    if not authenticate_user(sock):
        print("Authentication failed. Exiting...")
        stop_event.set()  # Báo hiệu dừng luồng
        host_service_thread.join(timeout=5)  # Đợi luồng phụ dừng
        sock.close()
        return

    try:
        while True:
            user_input = input("Enter command (seeding file_name/ download file_name/ tracker file_name/ list/ exit): ")#addr[0],peers_port, peers_hostname,file_name, piece_hash,num_order_in_file
            command_parts = shlex.split(user_input)
            if len(command_parts) == 1 and command_parts[0].lower() == 'list':
                handler_list_peers(sock, peers_port)

            elif len(command_parts) == 2 and command_parts[0].lower() == 'seeding':
                _,file_name = command_parts
                if check_local_files(file_name):
                    piece_size = 524288  # 524288 byte = 512KB
                    file_size = os.path.getsize(file_name)
                    pieces = split_file_into_pieces(file_name,piece_size)
                    handler_seeding_piece(sock, peers_port, file_name, file_size, pieces)
                elif (pieces := check_local_piece_files(file_name)):
                    handler_seeding_piece(sock, peers_port, pieces, file_name)
                else:
                    print(f"Local file {file_name}/piece does not exist.")

            elif len(command_parts) == 2 and command_parts[0].lower() == 'download':
                try:
                    _, file_name = command_parts
                    pieces = check_local_piece_files(file_name)
                    pieces_hash = [] if not pieces else create_pieces_string(pieces)
                    num_order_in_file= [] if not pieces else [item.split("_")[-1][5:] for item in pieces]
                    handler_download_file(sock,peers_port,file_name, pieces_hash,num_order_in_file)
                except Exception as e:
                    print("Invalid fetch command.")
                    # continue
            
            elif len(command_parts) == 2 and command_parts[0].lower() == 'tracker':
                try:
                    _, file_name = command_parts
                    handler_tracker_file(sock, file_name, peers_port)
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
    SERVER_HOST = '192.168.1.7'
    SERVER_PORT = 65432
    CLIENT_PORT = 65434
    main(SERVER_HOST, SERVER_PORT,CLIENT_PORT)