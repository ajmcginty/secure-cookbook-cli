from utils.storage import add_user, add_recipe, view_recipe

def add(username):
    """
    Add's recipe name and information to recipes.json
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

    add_recipe(username, recipe_name, recipe_entry)

def view(username):

    recipe_name = input("Enter the name of the recipe: ").lower()

    view_recipe(username, recipe_name)
    


def main_menu(username, k_user):
    while True:
        print("\n=== Super Secret Recipe Cookbook ===")
        print("""1. Add recipe
2. View recipe
3. Exit""")

        s = input("Select an option: ").strip()

        if s == "1":
            add(username)
        elif s == "2":
            view(username)
        elif s == "3":
            print("Returning to login screen. Goodbye!")
            break
        else:
            print("Error: invalid option selected. Please try again.")