import sys
import os
import time
import subprocess
import signal
import http.client
import ssl
import json

def test_server():
    print("Starting C2 server...")

    # Start server in background
    # We need to make sure we're in the right directory or adjust paths
    server_path = os.path.abspath("aegis3-fix-stager-dns-and-server-6288426001206539809/c2_server/server.py")

    server_process = subprocess.Popen(
        ["python3", server_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )

    # Give it a moment to start
    time.sleep(5)

    try:
        print("Testing /health endpoint...")

        # Create unverified SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = http.client.HTTPSConnection("127.0.0.1", 4443, context=context)
        conn.request("GET", "/health")

        response = conn.getresponse()
        data = response.read().decode()

        if response.status == 200:
            print("✅ Health check passed!")
            print(f"Response: {data}")
            sys.exit(0)
        else:
            print(f"❌ Health check failed with status code: {response.status}")
            print(f"Response: {data}")
            sys.exit(1)

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        # Print server output for debugging
        stdout, stderr = server_process.communicate()
        print(f"Server STDOUT: {stdout.decode()}")
        print(f"Server STDERR: {stderr.decode()}")
        sys.exit(1)

    finally:
        print("Stopping server...")
        try:
            os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
            server_process.wait()
        except:
            pass

if __name__ == "__main__":
    test_server()
