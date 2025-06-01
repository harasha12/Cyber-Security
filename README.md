# Cyber-Security internship
**COMPANY**: CodeAlpha
**NAME**:VANGARA HIMA VENKATA HARSHAVARDHAN
**STUDENT ID**: CA/JU1/8283
**DOMAIN NAME**:CYBER SECURITY
**BATCH DURATION**:01-05-2025 to 01-06-2025
**DESCRIPTION**:This project focuses on building a Basic Network Sniffer using Python, a tool that captures and analyzes real-time network traffic. It simulates the functionality of packet sniffers like Wireshark but at a beginner-friendly level using Python’s scapy library. The objective of the project is to understand how data packets move through a network, how different protocols work, and how packets can be programmatically analyzed for learning and security purposes.
A network sniffer is a software tool used to monitor, capture, and analyze packets of data as they pass over a network. These tools are widely used in networking, cybersecurity, and IT infrastructure management to troubleshoot issues, analyze performance, detect threats, or simply understand how communication takes place at the packet level.
In this project, I used the Python programming language along with the scapy library, which provides extensive support for packet capturing, dissection, and manipulation. The sniffer script is capable of capturing live packets from the network interface and printing essential details for each packet, such as:
Source IP address
Destination IP address
Protocol type (TCP, UDP, ICMP)
Source and Destination Port numbers
Raw Payload Data (if present)
The sniffer works by listening to the selected network interface and handling each packet using a callback function. In this function, the packet is parsed, and depending on its type, corresponding attributes are extracted and displayed. For instance, if a TCP packet is captured, the script extracts and shows the source and destination port numbers, which helps understand services like HTTP (port 80), HTTPS (port 443), and others. If it’s an ICMP packet, it can be part of a ping request or response.
The project requires administrative or root privileges to run successfully, as packet sniffing is a low-level operation that interacts directly with network hardware. On Windows, this may involve running the terminal as Administrator, and on Linux, using sudo to execute the script.
