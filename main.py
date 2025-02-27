import logging

# Set up logging to file (as before)
logging.basicConfig(level=logging.INFO, filename='app.log',
                    format='%(asctime)s - %(levelname)s - %(message)s')

from user_management import cli_menu

if __name__ == "__main__":
    cli_menu()
