import os, time, sys, hashlib, getpass, platform
from datetime import datetime
from NWM.NWPD import NWA, NWS, C_S
from NWM.NWNF import main


#password and log storage
B_H = "1b2212b6183a91097fe78b5a0160e9f1d0377eb8d6eb20a7bf5fd652f6061e5b"
OP_H = "a47cf51747f0edaca5eb0a80c9666391150818c9aca3efb61fa90d8e2d5a4f4c"
LOG_FILE = "login_attempts.txt"


def log_attempt(success, role="UNKNOWN"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    device_name = platform.node()
    try:
        username = os.getlogin()
    except Exception:
        username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    status = "SUCCESS" if success else "FAILED"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {device_name} | {username} | {status} | {role}\n")

def clear_console():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def NWH():
    print(NWS)
    print("[Help - Available Commands: ]")
    print("[1.] Help | 0, -h, help, Help | < Displays Commands")
    print("[2.] Network Forensics | 1, -n, net, Net | < Opens Network Forensics Module")
    print("[3.] OSINT | 2, -o, whois, WhoIS | < Opens OSINT Module")
    print("[4.] ToolBox | 3, -ts, tbox, TBox | < Opens Malware ToolBox")
    print("[5.] Hashing | 4, -#, hash, Hash | < Displays Encryption")
    print("[6.] Exit | 5, -e, exit, Exit | < Closes Software")
    print(NWS)

def check_password():
    U_I = getpass.getpass("Enter password to run the script: ")
    I_H = hashlib.sha256(U_I.encode()).hexdigest()
    if I_H == OP_H:
        print("Access Granted... {Operator}")
        time.sleep(2)
        role = "Operator"
        log_attempt(True, role)
        clear_console()
        return role
    elif I_H == B_H:
        print("Access Granted... {BaseUser}")
        time.sleep(2)
        role = "BaseUser"
        log_attempt(True, role)
        clear_console()
        return role
    else:
        log_attempt(False, "UNKNOWN")
        print("Incorrect password... Goodbye")
        time.sleep(1)
        script_path = os.path.realpath(__file__)
        os.remove(script_path)

def OS(role):
    while True:
        print(NWS)
        print(NWA)
        print(NWS)
        if role == "Operator":
            print("[Operator Menu]")
            print("0 | Help")
            print("1 | Network Forensics")
            print("2 | OSINT")
            print("3 | ToolBox")
            print("4 | Hashing")
            print("5 | Exit")
            print("7 | View Login Attempts")
        else:
            print("[BaseUser Menu]")
            print("0 | Help")
            print("1 | Network Forensics")
            print("2 | OSINT")
            print("3 | ToolBox")
            print("4 | Hashing")
            print("5 | Exit")

        NWCMD = input("R0OT:~$ ").strip()

        if NWCMD.lower() in ["0", "-h", "help"]:
            NWH()
            time.sleep(2)
            input("Press Any Key To Return")
            C_S()
        elif NWCMD.lower() in ["1", "-n", "net", "Net"]:
            clear_console()
            try:
                main()
            except ModuleNotFoundError:
                print("[Error] Network Module Not Found")
            input("Press Any Key To Return")
            clear_console()

        elif NWCMD.lower() in ["icarus", "-i", "Icarus"]:
            log_attempt(False, "Icarus Down")
            time.sleep(1)
            script_path = os.path.realpath(__file__)
            os.remove(script_path)
        elif NWCMD == "7" and role == "Operator":
            if os.path.exists(LOG_FILE):
                print("\n=== Login Attempts ===")
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    print(f.read())
                print("=====================\n")
            else:
                print("No login attempts recorded yet.")
            input("Press any key to return...")
            clear_console()
        elif NWCMD in ["5", "-e", "exit", "Exit"]:
            print("Exiting...")
            sys.exit()

if __name__ == "__main__":
    user_role = check_password()
    OS(user_role)
