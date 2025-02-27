import random
import sympy
import bcrypt
import uuid
import maskpass
import mysql.connector
import logging
import sys
import time

# Set up logging
logging.basicConfig(level=logging.INFO, filename='app.log',
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Global flag and fallback store for users
db_available = True
fallback_user_store = {}

# Try connecting to the MySQL database; if it fails, use fallback storage.
try:
    mydb = mysql.connector.connect(
        host="",
        user="",
        password="",
        database=""
    )
    mycursor = mydb.cursor()
    logging.info("Database connection established.")
except Exception as e:
    logging.error("Failed to connect to the database: %s", e)
    db_available = False
    fallback_user_store = {}  # In-memory dictionary for user data
    logging.info("Using fallback in-memory user store.")

# =====================
# USER MANAGEMENT FUNCTIONS
# =====================

def register_user():
    """
    Registers a new user with username, password, email, and role.
    """
    try:
        print("\n--- User Registration ---")
        username = input("Enter a new username: ")
        email = input("Enter your email: ")
        password = maskpass.askpass(prompt="Enter a password: ", mask="*")
        confirm_password = maskpass.askpass(prompt="Confirm password: ", mask="*")
        if password != confirm_password:
            print("Passwords do not match. Registration aborted.")
            logging.warning("User registration failed: passwords did not match.")
            return

        # Hash the password using bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)

        # Default role is 'user'
        role = "user"
        user_id = str(uuid.uuid4())
        public_key = "user_public_key_here"  # Placeholder for a real public key

        if db_available:
            insert_user_query = """
            INSERT INTO users (user_id, username, email, password_hash, public_key, role) 
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            mycursor.execute(insert_user_query, (user_id, username, email, hashed_password.decode(), public_key, role))
            mydb.commit()
            print("Registration successful!")
            logging.info("New user registered (DB): %s", username)
        else:
            # Save the user in the in-memory fallback store
            fallback_user_store[username] = {
                'user_id': user_id,
                'username': username,
                'email': email,
                'password_hash': hashed_password.decode(),
                'public_key': public_key,
                'role': role
            }
            print("Registration successful! (Fallback storage)")
            logging.info("New user registered (Fallback): %s", username)
    except Exception as e:
        print("An error occurred during registration.")
        logging.error("Error in register_user: %s", e)

def update_profile(username):
    """
    Allows a logged-in user to update their profile (e.g., change password).
    """
    try:
        print("\n--- Update Profile ---")
        choice = input("Do you want to change your password? (y/n): ").lower()
        if choice == 'y':
            current_password = maskpass.askpass(prompt="Enter current password: ", mask="*")
            if verify_user(username, current_password) != "Login successful!":
                print("Incorrect current password.")
                logging.warning("Password update failed for %s: incorrect current password.", username)
                return
            new_password = maskpass.askpass(prompt="Enter new password: ", mask="*")
            confirm_password = maskpass.askpass(prompt="Confirm new password: ", mask="*")
            if new_password != confirm_password:
                print("Passwords do not match.")
                logging.warning("Password update failed for %s: passwords did not match.", username)
                return
            # Hash new password and update
            salt = bcrypt.gensalt()
            hashed_new_password = bcrypt.hashpw(new_password.encode(), salt)
            if db_available:
                update_query = "UPDATE users SET password_hash = %s WHERE username = %s"
                mycursor.execute(update_query, (hashed_new_password.decode(), username))
                mydb.commit()
                print("Password updated successfully!")
                logging.info("User %s updated their password (DB).", username)
            else:
                if username in fallback_user_store:
                    fallback_user_store[username]['password_hash'] = hashed_new_password.decode()
                    print("Password updated successfully! (Fallback storage)")
                    logging.info("User %s updated their password (Fallback).", username)
                else:
                    print("User not found in fallback storage.")
                    logging.warning("User %s not found in fallback storage during profile update.", username)
        else:
            print("No changes made.")
    except Exception as e:
        print("An error occurred while updating your profile.")
        logging.error("Error in update_profile for %s: %s", username, e)

def recover_password():
    """
    A placeholder function for password recovery.
    In a real implementation, you'd send an email with a recovery link.
    """
    try:
        print("\n--- Password Recovery ---")
        username = input("Enter your username: ")
        email = input("Enter your registered email: ")
        if db_available:
            mycursor.execute("SELECT email FROM users WHERE username = %s", (username,))
            result = mycursor.fetchone()
            if result and result[0] == email:
                print("A password recovery link has been sent to your email (simulated).")
                logging.info("Password recovery initiated for user (DB): %s", username)
            else:
                print("User not found or email does not match.")
                logging.warning("Password recovery failed for user (DB): %s", username)
        else:
            user = fallback_user_store.get(username)
            if user and user['email'] == email:
                print("A password recovery link has been sent to your email (simulated, Fallback).")
                logging.info("Password recovery initiated for user (Fallback): %s", username)
            else:
                print("User not found or email does not match.")
                logging.warning("Password recovery failed for user (Fallback): %s", username)
    except Exception as e:
        print("An error occurred during password recovery.")
        logging.error("Error in recover_password: %s", e)

def verify_user(username, entered_password):
    try:
        if db_available:
            mycursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
            result = mycursor.fetchone()
            if result:
                stored_hash = result[0].encode()
                if bcrypt.checkpw(entered_password.encode(), stored_hash):
                    return "Login successful!"
                else:
                    return "Invalid credentials."
            else:
                return "User not found."
        else:
            user = fallback_user_store.get(username)
            if user:
                stored_hash = user['password_hash'].encode()
                if bcrypt.checkpw(entered_password.encode(), stored_hash):
                    return "Login successful!"
                else:
                    return "Invalid credentials."
            else:
                return "User not found."
    except Exception as e:
        logging.error("Error in verify_user for %s: %s", username, e)
        return "Error during verification."

def login():
    try:
        print("\n--- User Login ---")
        username = input("Enter Username -> ")
        password = maskpass.askpass(prompt="Password -> ", mask="*")
        result = verify_user(username, password)
        if result == "Login successful!":
            print(result)
            logging.info("User logged in: %s", username)
            return username
        else:
            print(result)
            logging.warning("Failed login attempt for user: %s", username)
            return None
    except Exception as e:
        print("An error occurred during login.")
        logging.error("Error in login: %s", e)
        return None

# =====================
# ENCRYPTION/DECRYPTION FUNCTIONS
# =====================

def generate_prime():
    return sympy.randprime(2, 99)

def generate_public_key(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    while True:
        e = random.randint(2, phi_n - 1)
        if sympy.gcd(e, phi_n) == 1:
            return e, n 

def generate_private_key(e, p, q):
    phi_n = (p - 1) * (q - 1)
    d = sympy.mod_inverse(e, phi_n)
    return d

def encrypt_message(message, e, n):
    try:
        encrypted_message = [pow(ord(char), e, n) for char in message]
        logging.info("Message encrypted.")
        return encrypted_message
    except Exception as e:
        logging.error("Encryption error: %s", e)
        print("Encryption failed.")
        return None

def decrypt_message(encrypted_message, d, n):
    try:
        decrypted_message = ''.join(chr(pow(char, d, n)) for char in encrypted_message)
        logging.info("Message decrypted.")
        return decrypted_message
    except Exception as e:
        logging.error("Decryption error: %s", e)
        print("Decryption failed.")
        return None

# =====================
# CLI MENU (Improved User Interface)
# =====================

def cli_menu():
    user = None
    while True:
        print("\n==== RSA Encryption Program ====")
        print("1. Login")
        print("2. Register")
        print("3. Recover Password")
        print("4. Exit")
        choice = input("Select an option (1-4): ")

        if choice == '1':
            user = login()
            if user:
                user_session(user)
        elif choice == '2':
            register_user()
        elif choice == '3':
            recover_password()
        elif choice == '4':
            print("Exiting program.")
            logging.info("Program exited by user.")
            sys.exit()
        else:
            print("Invalid choice. Please try again.")
            logging.warning("Invalid menu choice entered.")

def user_session(username):
    """
    After login, present a menu for encryption/decryption and profile management.
    """
    while True:
        print(f"\n--- Welcome, {username} ---")
        print("1. Encrypt/Decrypt a Message")
        print("2. Update Profile")
        print("3. Logout")
        session_choice = input("Select an option (1-3): ")

        if session_choice == '1':
            # Simulate a progress indicator
            print("Generating keys...", end='')
            sys.stdout.flush()
            time.sleep(1)
            p = generate_prime()
            q = generate_prime()
            e, n = generate_public_key(p, q)
            d = generate_private_key(e, p, q)
            print(" Done.\n")
            
            input_message = input("Provide a message for encryption -> ")
            print("Encrypting message...", end='')
            sys.stdout.flush()
            time.sleep(1)
            encrypted_text = encrypt_message(input_message, e, n)
            print(" Done.")
            print("\nEncrypted Message:", encrypted_text)
            
            print("Decrypting message...", end='')
            sys.stdout.flush()
            time.sleep(1)
            decrypted_text = decrypt_message(encrypted_text, d, n)
            print(" Done.")
            print("\nDecrypted Message:", decrypted_text)
        elif session_choice == '2':
            update_profile(username)
        elif session_choice == '3':
            print("Logging out...")
            logging.info("User %s logged out.", username)
            break
        else:
            print("Invalid option. Please try again.")
            logging.warning("Invalid session option entered by user %s.", username)

if __name__ == "__main__":
    cli_menu()