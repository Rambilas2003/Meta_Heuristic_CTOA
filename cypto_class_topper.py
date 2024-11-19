from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

class Student:
    def __init__(self, name, scores, subjects, max_marks, percentage):
        self.name = name
        self.scores = scores  # List of scores for the student
        self.subjects = subjects  # List of subjects for the student
        self.max_marks = max_marks  # List of maximum marks for each subject
        self.total_score = sum(scores)  # Total score across all subjects
        self.total_max_marks = sum(max_marks)  # Total maximum marks across all subjects
        self.percentage = percentage  # Percentage of marks

# Function to generate a key using a password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES key size (256 bits)
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

# Encryption function
def encrypt(plaintext: str, key: bytes) -> dict:
    nonce = os.urandom(12)  # 96-bit nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
    }

# Decryption function
def decrypt(encrypted_data: dict, key: bytes) -> str:
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# Function to get student data input from user
def get_student_data(key):
    """Get user input for student data and encrypt it."""
    students = []
    num_students = int(input("Enter the number of students: "))
    num_subjects = int(input("Enter the number of subjects: "))
    
    subjects = []
    max_marks = []
    for i in range(1, num_subjects + 1):
        subject = input(f"Enter the name of subject {i}: ").strip()
        subjects.append(subject)
        max_marks_for_subject = int(input(f"Enter the maximum marks for {subject}: "))
        max_marks.append(max_marks_for_subject)
    
    for i in range(1, num_students + 1):
        name = input(f"\nEnter the {i}{'st' if i == 1 else 'nd' if i == 2 else 'rd' if i == 3 else 'th'} student name: ").strip()
        scores = []
        for subject in subjects:
            score = int(input(f"Enter {name}'s marks in {subject}: "))
            scores.append(score)
        
        total_score = sum(scores)
        total_max_marks = sum(max_marks)
        percentage = (total_score / total_max_marks) * 100

        student_data = f"{name},{scores},{percentage}"
        encrypted_student_data = encrypt(student_data, key)
        students.append(encrypted_student_data)
    
    return students, subjects, max_marks

# Function to rank students based on decrypted data
def rank_students(students, key):
    """Rank students based on their total scores after decrypting."""
    decrypted_students = []
    for encrypted_student in students:
        decrypted_data = decrypt(encrypted_student, key)
        name, scores, percentage = decrypted_data.split(',')
        scores = list(map(int, scores.strip('[]').split(',')))
        percentage = float(percentage)
        decrypted_students.append(Student(name, scores, [], [], percentage))
    
    return sorted(decrypted_students, key=lambda student: student.percentage, reverse=True)

# Function to display the student at a specific rank
def display_ranked_student(ranked_students, rank):
    """Display details of a student at a specific rank."""
    if 1 <= rank <= len(ranked_students):
        student = ranked_students[rank - 1]
        print(f"\nRank {rank}: {student.name} - Total Score: {sum(student.scores)}/{len(student.scores) * 100} - Percentage: {student.percentage:.2f}%")
    else:
        print("\nInvalid rank! Please enter a valid rank.")

# Main function to execute the program
if __name__ == "__main__":
    print("=== Class Topper Optimization with Cryptography ===")

    # Step 1: Get password from the user to generate encryption key
    password = input("Enter a password to secure the data: ")
    salt = os.urandom(16)  # Generate a random salt
    key = generate_key(password, salt)

    # Step 2: Get input from the user and encrypt it
    students, subjects, max_marks = get_student_data(key)
    
    # Show the encrypted student data for each student
    print("\n=== Encrypted Student Data ===")
    for encrypted_student in students:
        print(f"Encrypted Data: {encrypted_student}")

    # Step 3: Ask for password to decrypt the data and validate it
    while True:
        decryption_password = input("Enter the password to decrypt the student data: ")
        decryption_key = generate_key(decryption_password, salt)
        
        try:
            # Try to decrypt data with the entered password
            decrypted_data = decrypt(students[0], decryption_key)  # Just try with the first student's data
            print("Password correct. Proceeding with decryption...\n")
            break
        except Exception as e:
            print("Wrong password! Please try again.")

    # Step 4: Rank the students by decrypting their data
    ranked_students = rank_students(students, decryption_key)

    # Step 5: Display the full rankings
    print("\n=== Full Rankings ===")
    for rank, student in enumerate(ranked_students, start=1):
        print(f"Rank {rank}: {student.name} - Total Score: {sum(student.scores)}/{len(student.scores) * 100} - Percentage: {student.percentage:.2f}%")

    # Step 6: Highlight the Topper
    topper = ranked_students[0]  # First student in the sorted list has the highest percentage
    print(f"\nTopper: {topper.name} with {topper.percentage:.2f}%")

    # Step 7: Show Decrypted Student Data for Verification
    print("\n=== Decrypted Student Data ===")
    for student in ranked_students:
        print(f"Decrypted Data: {student.name}, Scores: {student.scores}, Percentage: {student.percentage:.2f}%")

    # Step 8: Allow the user to query specific ranks
    while True:
        rank_query = input("\nEnter a rank to view details (or 'exit' to quit): ").strip()
        if rank_query.lower() == "exit":
            print("Exiting the program. Goodbye!")
            break
        if rank_query.isdigit():
            display_ranked_student(ranked_students, int(rank_query))
        else:
            print("Invalid input. Please enter a numeric rank or 'exit'.")
