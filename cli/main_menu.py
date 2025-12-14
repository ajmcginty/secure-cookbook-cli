from utils.storage import add_user, add_recipe, view_recipe

def add(username, k_user, password):
    """
    Add's recipe name and information to recipes.json (encrypted and signed)
    """

    recipe_name = input("Enter name of recipe: ").lower()
    print("Enter recipe information (type 'DONE' when finished):")
    master_lines = []

    while True:
        line = input()
        if line.strip().upper() == "DONE":
            break
        master_lines.append(line.lower())

    recipe_information = "\n".join(master_lines)

    recipe_entry = {
        "name": recipe_name,
        "information": recipe_information
    }

    add_recipe(username, recipe_name, recipe_entry, k_user, password)

def view(username, k_user):

    recipe_name = input("Enter the name of the recipe: ").lower()

    view_recipe(username, recipe_name, k_user)
    


def main_menu(username, k_user, password):
    while True:
        print("\n=== Super Secret Recipe Cookbook ===")
        print("""1. Add recipe
2. View recipe
3. Log Out""")

        s = input("Select an option: ").strip()

        if s == "1":
            add(username, k_user, password)
        elif s == "2":
            view(username, k_user)
        elif s == "3":
            print("Returning to login screen. Goodbye!")
            break
        else:
            print("Error: invalid option selected. Please try again.")