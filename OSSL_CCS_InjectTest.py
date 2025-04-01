#!/usr/bin/env python3

import sys
import socket
import time
import struct

# Check command-line arguments
if len(sys.argv) < 2:
    print("Tripwire VERT CVE-2014-0224 Detection Tool v0.4\nUsage: %s <host> [port=443]" % sys.argv[0])
    sys.exit(1)

strHost = sys.argv[1]
iPort = int(sys.argv[2]) if len(sys.argv) > 2 else 443

print("***CVE-2014-0224 Detection Tool v0.4***\nBrought to you by Tripwire VERT (@TripwireVERT)")

# SSL/TLS version definitions
dSSL = {
    "SSLv3": b"\x03\x00",
    "TLSv1": b"\x03\x01",
    "TLSv1.1": b"\x03\x02",
    "TLSv1.2": b"\x03\x03",
}

# Simplified cipher suites (common ones to ensure compatibility)
ssl3_cipher = {
    b"\x00\x04": "TLS_RSA_WITH_RC4_128_MD5",
    b"\x00\x05": "TLS_RSA_WITH_RC4_128_SHA",
    b"\x00\x0a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x2f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    b"\x00\x35": "TLS_RSA_WITH_AES_256_CBC_SHA",
}

def make_hello(strSSLVer):
    """Construct a Client Hello message."""
    # Handshake record layer
    version = dSSL[strSSLVer]
    ciphers = b"".join(ssl3_cipher.keys())
    cipher_len = len(ciphers)
    hello_data = (
        b"\x01"              # Client Hello type
        b"\x00\x00" + struct.pack(">B", 39 + cipher_len)  # Length (3 bytes)
        + version            # Version
        + struct.pack(">L", int(time.time()))  # Timestamp
        + b"\x00" * 28       # Random (32 bytes total)
        + b"\x00"            # Session ID length
        + struct.pack(">H", cipher_len)  # Cipher suites length
        + ciphers            # Cipher suites
        + b"\x01"            # Compression methods length
        + b"\x00"            # Null compression
    )
    record = (
        b"\x16"              # Handshake record type
        + version            # Version
        + struct.pack(">H", len(hello_data))  # Record length
        + hello_data
    )
    return record

def get_ssl_records(buf):
    """Parse SSL/TLS records from buffer."""
    records = []
    offset = 0
    while offset + 5 <= len(buf):
        try:
            record_type = buf[offset]
            version = buf[offset + 1:offset + 3]
            record_len = struct.unpack(">H", buf[offset + 3:offset + 5])[0]
            if offset + 5 + record_len > len(buf):
                break  # Incomplete record
            records.append((record_type, buf[offset + 5]))
            offset += 5 + record_len
        except:
            break
    return records

def test_ccs_vulnerability(strHost, iPort, strVer):
    """Test for CVE-2014-0224 vulnerability."""
    strLogPre = f"[{strVer}] {strHost}:{iPort}"
    hello = make_hello(strVer)
    
    # Connect to target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((strHost, iPort))
    except socket.error as e:
        print(f"{strLogPre} Connection failed: {e}")
        return False
    
    # Send Client Hello
    print(f"{strLogPre} Sending Client Hello...")
    s.send(hello)
    
    # Receive handshake response
    fServerHello = False
    fCert = False
    try:
        recv = s.recv(2048)
        records = get_ssl_records(recv)
        for rec_type, rec_subtype in records:
            if rec_type == 22:  # Handshake
                if rec_subtype == 2:
                    fServerHello = True
                    print(f"{strLogPre} Received Server Hello")
                elif rec_subtype == 11:
                    fCert = True
                    print(f"{strLogPre} Received Certificate")
        if not (fServerHello and fCert):
            print(f"{strLogPre} Invalid handshake")
            s.close()
            return False
    except socket.error as e:
        print(f"{strLogPre} Error receiving handshake: {e}")
        s.close()
        return False
    
    # Send early CCS
    ccs = b"\x14" + dSSL[strVer] + b"\x00\x01\x01"  # ChangeCipherSpec
    print(f"{strLogPre} Sending early CCS...")
    s.send(ccs)
    
    # Check response
    fVuln = True
    try:
        s.settimeout(1)
        recv = s.recv(2048)
        if recv and recv[0] == 21:  # Alert
            fVuln = False
            print(f"{strLogPre} Rejected early CCS (Alert received)")
    except socket.timeout:
        print(f"{strLogPre} No immediate response to CCS")
    except socket.error:
        print(f"{strLogPre} Connection closed after CCS")
        fVuln = False
    
    # Final verification
    if fVuln:
        try:
            s.send(b"\x15" + dSSL[strVer] + b"\x00\x02\x01\x00")  # Alert
            s.recv(1024)
        except socket.error:
            fVuln = False
            print(f"{strLogPre} CCS accepted but connection dropped")
    
    s.close()
    return fVuln

# Test all SSL/TLS versions
iVulnCount = 0
for strVer in ["TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"]:
    if test_ccs_vulnerability(strHost, iPort, strVer):
        print(f"[{strVer}] {strHost}:{iPort} may allow early CCS")
        iVulnCount += 1
    else:
        print(f"[{strVer}] {strHost}:{iPort} rejected early CCS or failed")

# Final result
if iVulnCount > 0:
    print("***This System Exhibits Potentially Vulnerable Behavior***\nUpgrade OpenSSL if in use.")
    sys.exit(1)
else:
    print("No need to patch.")
    sys.exit(0)
