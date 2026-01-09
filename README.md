# 🛡️ Basic Network Sniffer

A simple yet powerful **Python-based Network Sniffer** built as part of the **CodeAlpha Cyber Security Project**.  
This project demonstrates how to capture and analyze network packets using Python, providing insights into network traffic for educational and security purposes.

---

## 📂 Project Structure

CodeAlpha_Basic-Network-Sniffer/
│
├── network_sniffer.py   # Main script for capturing and displaying packets
├── README.md             # Project documentation (this file)
└── LICENSE              # License file

---


## 🚀 Features
- Captures live network packets.
- Displays source and destination IP addresses.
- Shows protocol information (TCP, UDP, ICMP, etc.).
- Lightweight and beginner-friendly implementation.
- Can be extended for deeper packet analysis.

---

## 🛠️ Requirements
- Python 3.x
- Administrator/root privileges (required for raw socket access)

### Install Dependencies
```bash
pip install scapy
```

---

## ▶️ Usage

Run the script with administrator privileges:

```bash
sudo python network_sniffer.py
```

The program will start capturing packets and display details such as:

- Source IP
- Destination IP
- Protocol type

---

## 📖 Example Output:

```bash
Protocol: TCP | Source: 192.168.1.10 | Destination: 142.250.190.78
Protocol: UDP | Source: 192.168.1.15 | Destination: 8.8.8.8
Protocol: ICMP | Source: 192.168.1.20 | Destination: 192.168.1.1
```

---

## ⚠️ Disclaimer
- This project is intended **for educational purposes only**.
- Unauthorized packet sniffing on networks you don’t own or have permission to monitor may be illegal.
- Use responsibly.

---

## 📜 License
This project is licensed under the MIT License – see the file for details.

---

## 🙌 Acknowledgements
- CodeAlpha for project inspiration.
- Python community for libraries and resources.

---

## 👨‍💻 Author

**Ashish Raj**  

Passionate about AI, ML, and creative applications of technology.

📌 GitHub Profile:- https://github.com/ashishraj-hub

📌Linkedin Profile:- https://www.linkedin.com/in/ashish-raj-ashishraj/
