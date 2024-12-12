<p align="center">
  <a href="https://edash-project.netlify.app/">
    <img src='https://github.com/user-attachments/assets/79654e6e-2146-4cb0-809b-3e7ce78533c6' width='600px'>
    <h1 align="center">Cryptography Practice - Chat App</h1>
  </a>
</p>

**Author:**
- Rosa Reyes

This project implements an application that enables encryption and decryption of messages using symmetric encryption (AES-GCM) and asymmetric encryption (RSA). It also incorporates the use of digital signatures, certificates, and a Public Key Infrastructure (PKI) for enhanced security and authenticity. 

Additionally, the application includes a web interface for user registration and authentication, as well as the exchange of encrypted messages.

## Folder Structure

The folder structure of this project is as follows:

```
cryptography-project/
│
├── backend/ 
    ├── backend.py           # Backend for authentication and storing passwords and users in a database.
    ├── crypto.py            # Functions for encryption and decryption of messages and keys.
├── frontend/ 
    ├── components.py        # Auxiliary components for forms and messages.
├── certificates/            # Folder to store the PKI
├── main.py                  # Main file to run the application server.
├── requirements.txt         # File of necessary dependencies to run the project.
└── users.db                 # SQLite database to store registered users.
```

## Prerequisites

1. **Python 3.7 or higher**

2. **Virtualenv**: It is recommended to install a virtual environment to avoid dependency conflicts:
   ```bash
   pip install virtualenv
   ```

## Installation and Configuration

### Step 1: Clone the repository
Clone this repository to your local machine:
```bash
git clone https://github.com/rosareyes/crypto-lab1
cd crypto-lab1
```

### Step 2: Create and activate the virtual environment
1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   ```
2. Activate the virtual environment:
   - On Windows:
     ```bash
     venv\Scriptsctivate
     ```
   - On MacOS/Linux:
     ```bash
     source venv/bin/activate
     ```

### Step 3: Install dependencies
Install the required dependencies by running:
```bash
pip install -r requirements.txt
```

## Usage

### 1. Run the server
To start the server and run the application, execute:
```bash
python main.py
```

### 2. Access the application
Open your web browser and go to `http://localhost:5001/` to view the user interface.

### 3. Register and authenticate
- Use the registration forms to create users (User-1 and User-2).
- Each user can log in and send encrypted messages to the other user.
- Messages are encrypted using AES-GCM (symmetric encryption), and the symmetric keys used are encrypted with RSA (asymmetric encryption).

## Main Features

- **Message encryption and decryption**: Using AES-GCM for message encryption and RSA for encrypting symmetric keys.
- **User registration and authentication**: Securely stores users in the SQLite database, using `Scrypt` to derive and store password hashes.
- **Digital signatures and certificates**: Use of digital signatures and certificates generated with OpenSSL.

## Terminal Logs
The terminal provides detailed logs of the cryptography processes, such as encryption, decryption, and key exchanges. Below are sample screenshots:

**1. Terminal Logs: Sender process**
<p align="center">
  <img src='https://github.com/user-attachments/assets/bceccab6-e266-42bb-b7bb-b386513e5680' width='800px'>
</p>

**2. Terminal Logs: Receiver process**
<p align="center">
  <img src='https://github.com/user-attachments/assets/68ca6731-7b89-4755-9913-a90238c6aef2' width='800px'>
</p>


## Notes

- **`certificates/` directory**: This directory contains certificates for CA1, user 1, and user 2.
- **Database**: The `users.db` database securely stores user credentials.

---

## Running Tests

To test the functionality, register two users (User-1 and User-2) and log in with each to send messages. Observe the terminal output to see the encryption and decryption process steps.
