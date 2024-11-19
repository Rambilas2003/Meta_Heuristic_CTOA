class Student:
    def __init__(self, name, scores, subjects, max_marks):
        self.name = name
        self.scores = scores  # List of scores for the student
        self.subjects = subjects  # List of subjects for the student
        self.max_marks = max_marks  # List of maximum marks for each subject
        self.total_score = sum(scores)  # Total score across all subjects
        self.total_max_marks = sum(max_marks)  # Total maximum marks across all subjects
        self.percentage = (self.total_score / self.total_max_marks) * 100  # Percentage calculation

def get_student_data():
    """Get user input for student data."""
    students = []
    num_students = int(input("Enter the number of students: "))
    num_subjects = int(input("Enter the number of subjects: "))
    
    # Get subject names and maximum marks
    subjects = []
    max_marks = []
    for i in range(1, num_subjects + 1):
        subject = input(f"Enter the name of subject {i}: ").strip()
        subjects.append(subject)
        max_marks_for_subject = int(input(f"Enter the maximum marks for {subject}: "))
        max_marks.append(max_marks_for_subject)
    
    for i in range(1, num_students + 1):
        name = input(f"\nEnter the {i}{'st' if i == 1 else 'nd' if i == 2 else 'rd' if i == 3 else 'th'} student name: ").strip()
        
        # Get the marks for each subject
        scores = []
        for subject in subjects:
            score = int(input(f"Enter {name}'s marks in {subject}: "))
            scores.append(score)
        
        students.append(Student(name, scores, subjects, max_marks))
    
    return students, subjects, max_marks

def rank_students(students):
    """Rank students based on their total scores."""
    return sorted(students, key=lambda student: student.percentage, reverse=True)

def display_ranked_student(ranked_students, rank):
    """Display details of a student at a specific rank."""
    if 1 <= rank <= len(ranked_students):
        student = ranked_students[rank - 1]
        print(f"\nRank {rank}: {student.name} - Total Score: {student.total_score}/{student.total_max_marks} - Percentage: {student.percentage:.2f}%")
        for i, subject in enumerate(student.subjects):
            print(f"{subject}: {student.scores[i]}/{student.max_marks[i]}")
    else:
        print("\nInvalid rank! Please enter a valid rank.")

if __name__ == "__main__":
    print("=== Class Topper Optimization ===")
    
    # Step 1: Get input from the user
    students, subjects, max_marks = get_student_data()
    
    # Step 2: Rank the students
    ranked_students = rank_students(students)
    
    # Step 3: Display the full rankings
    print("\n=== Full Rankings ===")
    for rank, student in enumerate(ranked_students, start=1):
        print(f"Rank {rank}: {student.name} - Total Score: {student.total_score}/{student.total_max_marks} - Percentage: {student.percentage:.2f}%")

    # Step 4: Highlight the Topper
    topper = ranked_students[0]  # First student in the sorted list has the highest percentage
    print(f"\nTopper: {topper.name} with {topper.percentage:.2f}%")

    # Step 5: Allow the user to query specific ranks
    while True:
        rank_query = input("\nEnter a rank to view details (or 'exit' to quit): ").strip()
        if rank_query.lower() == "exit":
            print("Exiting the program. Goodbye!")
            break
        if rank_query.isdigit():
            display_ranked_student(ranked_students, int(rank_query))
        else:
            print("Invalid input. Please enter a numeric rank or 'exit'.")
