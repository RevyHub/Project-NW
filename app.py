from NullWarden.core.auth import check_password
from NullWarden.network.recon import run_cli_loop
from NullWarden.ui.banners import NWA, NWS, clear_screen


def print_help() -> None:
    print(NWS)
    print("[Help - Available Commands: ]")
    print("[1.] Help | 0, -h, help, Help | < Displays Commands")
    print("[2.] Network Forensics | 1, -n, net, Net | < Opens Network Forensics Module")
    print("[3.] OSINT | 2, -o, whois, WhoIS | < Opens OSINT Module")
    print("[4.] ToolBox | 3, -ts, tbox, TBox | < Opens Malware ToolBox")
    print("[5.] Hashing | 4, -#, hash, Hash | < Displays Encryption")
    print("[6.] Exit | 5, -e, exit, Exit | < Closes Software")
    print(NWS)


def main() -> None:
    role = check_password()
    if role is None:
        print("Incorrect password... Goodbye")
        return

    clear_screen()
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

        command = input("R0OT:~$ ").strip()
        if command.lower() in ["0", "-h", "help"]:
            print_help()
            input("Press Any Key To Return")
            clear_screen()
            continue
        if command.lower() in ["1", "-n", "net", "Net"]:
            clear_screen()
            run_cli_loop()
            input("Press Any Key To Return")
            clear_screen()
            continue
        if command in ["5", "-e", "exit", "Exit"]:
            print("Exiting...")
            break


if __name__ == "__main__":
    main()


