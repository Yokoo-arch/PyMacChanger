"""
Wrote by Yokoo-arch 2023 (https://github.com/Yokoo-arch)
"""

import subprocess
import argparse
import random
import uuid
import re
import pyperclip

def connect_to_wifi(interface_name:str, ssid:str) -> None:
    """
    Connect to a specific wifi network.
    """
    # Set the Wi-Fi interface to the specified SSID
    connect_process = subprocess.Popen(["networksetup", "-setairportnetwork", interface_name, ssid], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    connect_output, _ = connect_process.communicate()

    if connect_process.returncode != 0:
        print(f"[*] Failed to connect to Wi-Fi network: {ssid}")
        print(connect_output)
    else:
        print(f"[*] Connected to Wi-Fi network: {ssid}")

def is_valid_mac_address(mac_address:str) -> bool:
    """
    Checks if a string is a valid MAC address.
    """
    # Define a regular expression pattern for a valid MAC address
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    
    # Use the re.match() function to check if the input matches the pattern
    if re.match(pattern, mac_address):
        return True
    else:
        return False

def change_mac_address(interface_name: str, new_mac_address: str) -> None:
    """
    Changes the MAC address of an interface.
    """
    # Change the MAC address
    try:
        # Get the current Wi-Fi network's SSID
        current_ssid = subprocess.run(["sudo", "networksetup", "-getairportnetwork", "en0"], capture_output=True, text=True)
        current_ssid = current_ssid.stdout.strip().split(": ")[1] if current_ssid.returncode == 0 else None

        if current_ssid:
            # Disconnect from the current Wi-Fi network
            disconnect_process = subprocess.run(["sudo", "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", options.interface,"-z"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if disconnect_process.returncode != 0:
                print(f"[*] Failed to disconnect from Wi-Fi network: {current_ssid}")

            print(f"[*] Disconnected from Wi-Fi network: {current_ssid}")

            subprocess.run(["sudo", "ifconfig", interface_name, "ether", new_mac_address])

            connect_to_wifi(interface_name, current_ssid)

        else:
            print("[*] You are not currently connected to a Wi-Fi network.")
            subprocess.run(["sudo", "ifconfig", interface_name, "ether", new_mac_address])

        #subprocess.run(["sudo", "networksetup", "-setairportpower", interface_name, "off"])
        #subprocess.run(["sudo", "ifconfig", interface_name, "ether", new_mac_address])
        #subprocess.run(["sudo", "networksetup", "-setairportpower", interface_name, "on"])
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        print("[-] Check your internet connection and try again")

def get_permanent_mac_address() -> str:
    """
    Gets the permanent MAC address.
    """
    # Get the hardware MAC address as a bytes object
    mac_bytes = uuid.getnode().to_bytes(6, byteorder='big')
    
    # Convert the bytes to a readable MAC address stringH
    mac_str = ':'.join(['{:02x}'.format(b) for b in mac_bytes])
    
    return mac_str

def get_arguments() -> None:
    """
    Gets the arguments from the CLI.
    """
    parser = argparse.ArgumentParser()
    # We need the interface name
    parser.add_argument("-i", "--interface",
                dest="interface",
                required=True,
                help="Name of the interface. "
                "Type ifconfig for more details.")
    parser.add_argument("-r", "--random",
                    dest="random_mode",
                    action="store_true",
                    help="Change the current MAC adress to a random one.")
    parser.add_argument("-m", "--manual",
                    dest="manual_mode",
                    action="store_true",
                    help="Change the current MAC adress to a specified one.")
    parser.add_argument("-ma", "--mac-adress",
                    dest="mac_address",
                    help="MAC address used for the manual mode.")
    parser.add_argument("-p", "--permanent-mac-address",
                    dest="permanent_mac_address_mode",
                    action="store_true",
                    help="Goes back to your original MAC addresss.")
    parser.add_argument("-g", "--generate-random-mac",
                        dest="generate_random_mac_mode",
                        action="store_true",
                        help="Generates a random MAC address.")
    
    options = parser.parse_args()

    # Check if at least one mode option is provided
    if not any([options.random_mode, options.manual_mode, options.permanent_mac_address_mode, options.generate_random_mac_mode]):
        parser.error("You must specify at least one mode option (-r, -m, -p)")

    # If using manual mode, ensure MAC address is provided
    if options.manual_mode and not options.mac_address:
        parser.error("When using manual mode (-m), you must provide a MAC address (-ma)")

    return parser, options

def generate_random_mac():
    # Generate the first byte with the LSB set to 0 (U/L bit) and the 2nd LSB set to 1 (G/L bit)
    first_byte = random.randint(0x00, 0xfe) & 0xfe | 0x02
    mac_bytes = [first_byte] + [random.randint(0x00, 0xff) for _ in range(5)]
    mac_address = ':'.join(f'{byte:02x}' for byte in mac_bytes)
    return mac_address

def check_string_in_command_output(command:list, search_string:str) -> bool:
    """
    Checks if the search string exists in the command output.
    """
    try:
        # Run the command and capture its output
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)

        # Check if the search string exists in the output
        if search_string in output:
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        # Handle any errors that may occur during command execution
        print("Error:", e)
        return False

if __name__ == "__main__":
    # Get the arguments from the CLI
    parser, options = get_arguments()

    print("[* Welcome to PyMacChanger by Yokoo-arch (add link to github) *]")
    print("[*] This script will change your MAC address and requires administrative privileges")
    print("[*] Beware that this script will disconnect you from internet during the process. Your internet connection should reconnect itself automatically.")
    print("[*] At some point you will be prompter to enter your sudo password")
    print("[*] Press CTRL-C to EXIT at any time. Press ENTER to CONTINUE")
    
    # Wait for the user to press enter
    input("")

    if options.interface and options.random_mode:
        base_mac_address = get_permanent_mac_address()
        new_mac_address = generate_random_mac()
        change_mac_address(options.interface, new_mac_address)

        if check_string_in_command_output(["ifconfig"], new_mac_address):
            print(f"[+] MAC address changed on interface {options.interface} to {new_mac_address}")
            print(f"[*] Your permanent MAC adress on interface {options.interface} was {base_mac_address}")
        else:
            print(f"[-] Failed to change MAC address on interface {options.interface} to {new_mac_address}")

    elif options.interface and options.manual_mode and options.mac_address:
        base_mac_address = get_permanent_mac_address()

        if is_valid_mac_address(options.mac_address) == False:
            print(f"[-] Invalid MAC address: {options.mac_address}")
            exit()

        change_mac_address(options.interface, options.mac_address)

        if check_string_in_command_output(["ifconfig"], options.mac_address):
            print(f"[+] MAC address changed on interface {options.interface} to {options.mac_address}")
            print(f"[*] Your permanent MAC adress on interface {options.interface} was {base_mac_address}")
        else:
            print(f"[-] Failed to change MAC address on interface {options.interface} to {options.mac_address}")
    
    elif options.interface and options.permanent_mac_address_mode:
        mac_address = get_permanent_mac_address()

        change_mac_address(options.interface, mac_address)

        if check_string_in_command_output(["ifconfig"], mac_address):
            print(f"[+] MAC address changed on interface {options.interface} to {options.mac_address}")
        else:
            print(f"[-] Failed to change MAC address on interface {options.interface} to {options.mac_address}")

    
    elif options.generate_random_mac_mode:
        new_mac_address = generate_random_mac()
        print(f"[+] Random MAC address generated: {new_mac_address} for interface: {options.interface}")
        pyperclip.copy(new_mac_address)
        print(f"[*] MAC adress copied to clipboard")

    else:
        parser.error("[!] Invalid Syntax. "
             "Use --help for more details.")