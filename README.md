# AuraVera: Privacy‑Preserving Biometric Authentication with Zero‑Knowledge Proofs

AuraVera is a privacy‑preserving, multi‑factor biometric authentication system that combines biometrics, password‑based authentication, and zero‑knowledge proofs (Groth16). The system ensures that biometric data and secrets are never stored or revealed, while still allowing the server to verify identity correctness and session freshness.
The project implements an end‑to‑end workflow covering enrollment, authentication, and attack resistance (replay attacks, rainbow table attacks, and unauthorized access).



## 📌 Key Features

- Privacy‑preserving biometric authentication (no raw biometric storage)
- Multi‑factor authentication (username + password + biometrics)
- Zero‑knowledge proof system using Groth16
- ZK‑friendly hashing inside the circuit using MiMC
- Memory‑hard password derivation using Argon2
- Salted commitments to prevent rainbow table attacks
- Challenge–response mechanism to prevent replay attacks
- Cloud‑native deployment (local + AWS support)



## ⚙️ How the System Works (High Level)

1. Enrollment
- Biometric features are encoded on the client
- A secret is derived using biometrics, password, and salt
- A zero‑knowledge proof is generated and sent to the server
- The server stores only a commitment, never raw biometrics
2. Authentication
- The server issues a fresh challenge (nonce)
- The client generates a zero‑knowledge proof bound to this challenge
- The server verifies the proof and authenticates the user if valid


## ▶️ How to Run the Project (Local Setup)

### Prerequisites
- Go (for the ZKP service)
- Python with Jupyter Notebook
- VS Code (recommended)

### Step 1: Start the ZKP Computation Service
Open a terminal and run:
```bash
cd zkp-circuit
go mod tidy
go run main.go
```
Wait until you see:
```text
Go Groth16 ZKP Service is starting on port :8080
```
⚠️ Keep this terminal running.

### Step 2: Start the Authentication Server
If port 5001 is already in use, free it:
```bash
Get-Process -Id (Get-NetTCPConnection -LocalPort 5001).OwningProcess | Stop-Process -Force
```
Then:
1. Open server.ipynb
2. Run all cells

⚠️ The last cell will remain running, do NOT stop or close it.

This notebook acts as the authentication server and verifier.

### Step 3: Run the Client Tests
1. Open client.ipynb
2. Run all cells
3. Check the output of the final cell for:
```text
FINAL RESULTS
```
AND
```text
ZKP CIRCUIT SUMMARY
```
This summary reports successful and blocked authentication attempts.



## ☁️ Running on AWS
To run the system against the cloud deployment:
- First make sure you have your EC2 instance running on AWS environment
- Copy the Public IPv4 address to Cell 4 in clientAWS.ipynb
- Run all cells in clientAWS.ipynb

In this mode, both the server and ZKP service are already deployed on AWS.



## 🔧 Important Configuration Notes
- Number of Images Tested

In client.ipynb, Cell 5 contains the variable:
```bash
NUM_SUBJECTS = <value>
```
This variable controls how many fingerprint images (subjects) are used during testing. Increasing it increases the total number of test cases.



- Server IP Configuration
In client.ipynb, Cell 4 contains the server IP address:
```bash
SERVER_IP = "127.0.0.1"
```

Use 127.0.0.1 for local testing
Replace with the public/private AWS IP when running in the cloud.



## Dataset
 
This project uses the *SOCOFing (Synthetic Fingerprint Database)* dataset for biometric evaluation.
 
- Dataset source: https://www.kaggle.com/datasets/ruizgara/socofing
- The dataset is used strictly for *research and experimental evaluation purposes*.
- All rights and credits belong to the original dataset authors.



## 📄 License
This project is provided for academic and research use. Please cite appropriately if used in publications.
