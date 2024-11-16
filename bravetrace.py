import argparse
import sqlite3
import os
import json
import pandas as pd
import shutil
import win32crypt  # Required for Windows password decryption
import base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import csv
import winreg
import glob




BRAVE_PATH = os.path.normpath(r"%s\AppData\Local\BraveSoftware\Brave-Browser\User Data" % (os.environ['USERPROFILE']))
BRAVE_LOCAL_STATE_PATH = os.path.normpath(r"%s\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State" % (os.environ['USERPROFILE']))
PREFETCH_PATH = r"D:\DIGITAL FORENSIC PROJECT\bravetrace\Prefetch Files" 




def convert_unix_timestamp_to_date(timestamp):
    """Convert a Unix timestamp to a human-readable date (DD/MM/YYYY)."""
    try:
        # Convert timestamp into a human-readable date format
        return datetime.utcfromtimestamp(timestamp).strftime("%d/%m/%Y")
    except Exception as e:
        print(f"Error converting timestamp: {e}")
        return "N/A"


def convert_timestamp_to_date(timestamp):
    """Convert Windows FILETIME timestamp to DD/MM/YYYY format."""
    try:
        return datetime.fromtimestamp(timestamp / 1000000 - 11644473600).strftime("%d/%m/%Y")
    except Exception as e:
        return "N/A"



# Extract execution history from Prefetch files
def extract_prefetch_data():
    prefetch_data = []
    try:
        prefetch_files = glob.glob(os.path.join(PREFETCH_PATH, "*.pf"))
        for prefetch_file in prefetch_files:
            executable_name = os.path.basename(prefetch_file).split("-")[0]
            
            try:
                with open(prefetch_file, 'rb') as f:
                    content = f.read()

                timestamp_offset = 0x60
                timestamp = int.from_bytes(content[timestamp_offset:timestamp_offset+4], byteorder='little')
                execution_time = datetime.utcfromtimestamp(timestamp).strftime('%d/%m/%Y %H:%M:%S')

                prefetch_data.append({
                    "Executable Name": executable_name,
                    "Execution Time": execution_time
                })
            except Exception as e:
                print(f"Error reading prefetch file {prefetch_file}: {e}")
    except Exception as e:
        print(f"Error extracting prefetch data: {e}")
    return prefetch_data


def get_secret_key(local_state_path):
    """Extract secret key from the local state file."""
    try:
        with open(local_state_path, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(f"Error: {str(e)}")
        print("[ERR] Secret key cannot be found")
        return None

def decrypt_password(ciphertext, secret_key):
    """Decrypt the password using AES."""
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
        decrypted_pass = cipher.decrypt(encrypted_password).decode()
        return decrypted_pass
    except Exception as e:
        print(f"Error: {str(e)}")
        print("[ERR] Unable to decrypt password")
        return ""

def extract_passwords():
    """Extract and decrypt passwords from Brave browser's Login Data."""
    login_data_path = os.path.join(BRAVE_PATH, "Default", "Login Data")
    if not os.path.exists(login_data_path):
        print("Login Data file not found.")
        return []

    secret_key = get_secret_key(BRAVE_LOCAL_STATE_PATH)
    if secret_key is None:
        return []

    try:
        conn = sqlite3.connect(login_data_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        passwords = cursor.fetchall()
        conn.close()

        password_data = []
        for origin_url, username, password_encrypted in passwords:
            if origin_url != "" and username != "" and password_encrypted != "":
                decrypted_passwords = decrypt_password(password_encrypted, secret_key)
                password_data.append({
                    "origin_url": origin_url,
                    "username": username,
                    "password": decrypted_passwords
                })
        return password_data
    except Exception as e:
        print(f"Error extracting passwords: {e}")
        return []

def extract_history():
    """Extract browsing history from Brave."""
    history_path = os.path.join(BRAVE_PATH, "Default", "History")
    temp_history_path = "temp_history.db"
    
    if not os.path.exists(history_path):
        print("History file not found.")
        return []

    # Copy the database file to a temporary location
    shutil.copy2(history_path, temp_history_path)

    # Connect to the copied database
    conn = sqlite3.connect(temp_history_path)
    cursor = conn.cursor()
    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
    history = cursor.fetchall()
    conn.close()

    # Clean up the temporary file
    os.remove(temp_history_path)

    history_data = []
    for url, title, visit_count, last_visit_time in history:
        last_visit_date = convert_timestamp_to_date(last_visit_time)
        history_data.append({
            "url": url,
            "title": title,
            "visit_count": visit_count,
            "last_visit_time": last_visit_date
        })
    return history_data

def extract_bookmarks():
    """Extract bookmarks from Brave."""
    bookmarks_path = os.path.join(BRAVE_PATH, "Default", "Bookmarks")
    if not os.path.exists(bookmarks_path):
        print("Bookmarks file not found.")
        return []

    with open(bookmarks_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    bookmarks_data = []
    def parse_bookmarks(bookmark_node):
        if "children" in bookmark_node:
            for child in bookmark_node["children"]:
                parse_bookmarks(child)
        elif "url" in bookmark_node:
            date_added = convert_timestamp_to_date(int(bookmark_node.get("date_added", "0")))
            bookmarks_data.append({
                "name": bookmark_node.get("name"),
                "url": bookmark_node.get("url"),
                "date_added": date_added
            })

    for root in data["roots"].values():
        parse_bookmarks(root)

    return bookmarks_data

def extract_cache_data():
    """Extract cache data from Brave."""
    cache_path = r"C:\Users\Hp\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cache\Cache_Data"
    if not os.path.exists(cache_path):
        print("Cache directory not found.")
        return []

    cache_files = []
    for filename in os.listdir(cache_path):
        file_path = os.path.join(cache_path, filename)
        if os.path.isfile(file_path):
            cache_files.append({
                "file_name": filename,
                "file_size": os.path.getsize(file_path)
            })
    return cache_files

def extract_accessed_urls():
    """Extract recently accessed URLs from Brave."""
    history_path = os.path.join(BRAVE_PATH, "Default", "History")
    if not os.path.exists(history_path):
        print("History file not found.")
        return []

    conn = sqlite3.connect(history_path)
    cursor = conn.cursor()
    cursor.execute("SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")
    accessed_urls = cursor.fetchall()
    conn.close()

    accessed_urls_data = []
    for url, last_visit_time in accessed_urls:
        last_visit_date = convert_timestamp_to_date(last_visit_time)
        accessed_urls_data.append({
            "url": url,
            "last_visit_time": last_visit_date
        })
    return accessed_urls_data

def extract_fillable_data():
    """Extract fillable form data from Brave."""
    autofill_path = os.path.join(BRAVE_PATH, "Default", "Web Data")
    if not os.path.exists(autofill_path):
        print("Autofill data file not found.")
        return []

    conn = sqlite3.connect(autofill_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name, value, date_created FROM autofill")
    fillable_data = cursor.fetchall()
    conn.close()

    fillable_data_extracted = []
    for name, value, date_created in fillable_data:
        # Use the new helper function to convert the Unix timestamp
        date_created_formatted = convert_unix_timestamp_to_date(date_created)
        fillable_data_extracted.append({
            "name": name,
            "value": value,
            "date_created": date_created_formatted
        })
    return fillable_data_extracted


def write_output(data, output_path="bravetrace_report.xlsx"):
    """Write output data to an Excel file."""
    if output_path:
        with pd.ExcelWriter(output_path) as writer:
            for key, value in data.items():
                df = pd.DataFrame(value)
                df.to_excel(writer, sheet_name=key)
        print(f"Data saved to {output_path}")
    else:
        for key, value in data.items():
            print(f"--- {key} ---")
            for item in value:
                print(item)


def display_menu():
    """Display a menu for the user to choose which data to extract."""
    print("\n--- BraveTrace Forensic Tool ---")
    print("Select the artifacts you want to extract:")
    print("1. Browsing History")
    print("2. Passwords")
    print("3. Bookmarks")
    print("4. Cache Data")
    print("5. Recently Accessed URLs")
    print("6. Fillable Form Data")
    print("7. Execution History (Prefetch Files)")
    print("8. Extract All")
    print("9. Exit")
    
    try:
        choice = int(input("\nEnter the number of your choice: "))
    except ValueError:
        print("Invalid input. Please enter a number between 1 and 9.")
        return None
    
    return choice

def main():
    data = {}
    
    while True:
        choice = display_menu()
        
        if choice == 1:
            data['history'] = extract_history()
        elif choice == 2:
            data['passwords'] = extract_passwords()
        elif choice == 3:
            data['bookmarks'] = extract_bookmarks()
        elif choice == 4:
            data['cache'] = extract_cache_data()
        elif choice == 5:
            data['accessed_urls'] = extract_accessed_urls()
        elif choice == 6:
            data['fillable_data'] = extract_fillable_data()
        elif choice == 7:
            data['prefetch_data'] = extract_prefetch_data()
        elif choice == 8:
            data['history'] = extract_history()
            data['passwords'] = extract_passwords()
            data['bookmarks'] = extract_bookmarks()
            data['cache'] = extract_cache_data()
            data['accessed_urls'] = extract_accessed_urls()
            data['fillable_data'] = extract_fillable_data()
            data['prefetch_data'] = extract_prefetch_data()
        elif choice == 9:
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
            continue

        # Write the collected data to Excel automatically
        write_output(data)

        # Ask if the user wants to extract more data or exit
        continue_choice = input("\nWould you like to extract more data? (y/n): ").strip().lower()
        if continue_choice != 'y':
            print("Exiting the tool. Goodbye!")
            break


if __name__ == "__main__":
    main()
