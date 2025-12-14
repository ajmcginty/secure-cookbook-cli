from cli.login_menu import register, login
from cli.main_menu import main_menu

def main():
    while True:
        print("\n=== Super Secret Recipe Cookbook ===")
        print("""1. Register new user
2. Login
3. Exit""")
        s = input("Select an option: ").strip()

        if s == "1":
            register()
        elif s == "2":
            username, k_user, password = login()
            main_menu(username, k_user, password)
        elif s == "3":
            print("Exiting program. Goodbye!")
            break
        else:
            print("Error: invalid option selected. Please try again.")

if __name__ == "__main__":
    main()