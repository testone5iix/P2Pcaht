# SecureP2P Chat

A decentralized, privacy-focused P2P chat application using Tor hidden services, end-to-end encryption, and a Textual-based UI.

## Why a Single File?

- **Portability**: Easy to share and run as a single script.
- **Simplicity**: Reduces complexity for small projects.
- **Security**: Minimizes external file dependencies.

## Features

- Tor-based anonymity
- End-to-end encryption (ChaCha20Poly1305, X25519, Ed25519)
- Perfect forward secrecy with key rotation
- TOFU key verification
- Replay protection
- Rate limiting
- Message broadcasting
- Terminal-based UI

## Requirements

- **Python**: Version 3.7+
- **Tor**: Installed and accessible
- **Python Libraries**: `cryptography`, `textual`, `pyperclip` (optional)

### Downloading Python

- **Windows**:
  - Download: https://www.python.org/downloads/windows/
  - Run installer, select "Add Python to PATH," and install.[](https://www.python.org/downloads/)
- **Mac**:
  - Download: https://www.python.org/downloads/macos/
  - Run installer and follow prompts.[](https://www.python.org/downloads/)
- **Linux**:
  - Install via package manager:
    ```bash
    sudo apt install python3 python3-pip  # Ubuntu/Debian
    sudo yum install python3 python3-pip  # RHEL/CentOS
    ```

### Downloading Tor

- **Windows**:
  - Download: https://www.torproject.org/download/
  - Run installer, select destination, and install.[](https://www.geeksforgeeks.org/installation-guide/how-to-download-and-install-tor-browser-on-windows/)
- **Mac**:
  - Download: https://www.torproject.org/download/
  - Drag Tor Browser to Applications folder.[](https://vpnoverview.com/privacy/anonymous-browsing/how-to-install-tor/)
- **Linux**:
  - Install via package manager:
    ```bash
    sudo apt install tor  # Ubuntu/Debian
    sudo yum install tor  # RHEL/CentOS
    ```
  - Or download from: https://www.torproject.org/download/[](https://www.torproject.org/download/)

### Installing Python Dependencies

```bash
pip install cryptography textual pyperclip
```

## Setup

1. Clone from https://github.com/testone5iix/P2Pcaht.git
2. Ensure Tor and Python are installed
3. Run:
   ```bash
   python3 p2pchat.py
   ```

## Usage

- Start: `python3 p2pchat.py`
- Connect: `/connect <onion_address>`
- Send messages: Type and press Enter
- Commands: `/connect`, `/peers`, `/verify`, `/stats`, `/onion`, `/copyonion`, `/quit`, `/help`

## Configuration

Edit constants in `p2pchat.py`:
- `TCP_PORT`: 37021
- `KEY_ROTATION_INTERVAL`: 3600s
- `RATE_LIMIT_WINDOW`: 10s
- `RATE_LIMIT_COUNT`: 20 messages
- `SHOW_SENSITIVE`: False
- `TOR_SOCKS_PORT`: 9050
- `TOR_CONTROL_PORT`: 9051

## Files

- `p2pchat.log`: Logs
- `peer_fingerprints.db`: Peer fingerprints
- `replay_cache.db`: Replay protection
- `identity.key`: Private key
- `tordata/`: Tor configuration

## Security

- Protect `identity.key`
- Backup `peer_fingerprints.db`
- Adjust rate limits as needed

## Troubleshooting

- **Tor Failure**: Verify Tor executable and check `p2pchat.log`
- **Connection Issues**: Confirm onion address/port
- **Dependencies**: Ensure `cryptography`, `textual`, `pyperclip` are installed

## License

MIT License
