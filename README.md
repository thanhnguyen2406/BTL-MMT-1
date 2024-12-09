# HCMUT_CO3093_ComputerNetworks
# `Assignment1: Develop a network application`

## Overview
Build a Simple Torrent-like Application (STA) with the protocols defined by each group, using the TCP/IP protocol stack and must support multi-direction data transfering (MDDT).


## Requirements 
- Python 3
- MySQL installed on the Server machine 
```
## SET UP ENV
cd /path/to/your/project
sudo apt update
sudo apt install python3-venv
python3 -m venv env
source env/bin/activate
pip install mysql-connector-python
```

## Usage
1. Create database with MySQL by running these commands:
```sql
CREATE TABLE DHT_peers (
    peer_id VARCHAR(50) PRIMARY KEY,
    peers_ip VARCHAR(50),
    peers_port INT,
    peers_hostname VARCHAR(255),
    hash_info JSON
);

CREATE TABLE torrent_file (
    hash_info CHAR(40) PRIMARY KEY,  
    file_name VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,       
    piece_size INT NOT NULL,
    number_of_pieces INT NOT NULL,
    download_count INT DEFAULT 0
);
``` 
2. Start the central server:
   - $ cd server
   - Config server.py file to connect to database
   ```python
   conn = mysql.connector.connect(
        host="localhost",        
        database="sta_server", 
        user="USERNAME",    
        password="PASSSWORD"  
    )
   ```
   - Run the `server.py` script to start the central server. Ensure the server is running before proceeding with client actions.

3. Client Setup:
   - $ cd client1
   - $ cd client2
   - Edit the `SERVER_HOST`, `SERVER_PORT`, `CLIENT_PORT` setting in the `client.py` file to configure the IP for the central server. After that run the `client.py` script to start the client and connect to the central server.

