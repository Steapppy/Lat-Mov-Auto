import os
import sys
from agent import ThinkAdaptActAgent
from dotenv import load_dotenv

def run_long_test():
    load_dotenv()
    os.environ["OPENAI_API_KEY"] = os.getenv("MISTRAL_API_KEY")
    os.environ["OPENAI_BASE_URL"] = "https://api.mistral.ai/v1"

    user_id = "master_tester"
    # Using a fresh DB for the long test
    agent = ThinkAdaptActAgent(user_id=user_id, db_path="mem0_long_test.db")

    questions = [
        "Find the sum of all natural numbers below 1000 that are multiples of either 3 or 5.",
        "Given a list of integers [1, 10, -10, 1, -5, 4, 3], find the maximum product you can get by multiplying exactly three of these numbers.",
        "Use symbolic math to find the derivative of f(x) = e^(x^2) * ln(x) and evaluate it at x=2.",
        "I have a string 'abcabcbb'. What is the length of the longest part of this string that doesn't have any repeating characters?",
        "Find all real solutions for the quadratic equation 3x^2 + 7x - 10 = 0 using a formula.",
        "In a list where every number appears twice except for one specific number [4, 1, 2, 1, 2], find that unique number using the most efficient method.",
        "Calculate the definite integral of sin(x)^2 from 0 to pi.",
        "Given the list [1, 1, 1, 2, 2, 3] and k=2, find the 2 numbers that appear most frequently.",
        "What is the 15th prime number? Explain how you found it.",
        "I have a set of time intervals: [[1, 3], [2, 6], [8, 10], [15, 18]]. Combine all intervals that overlap into a single list of intervals.",
        "Compute the eigenvalues of the 2x2 matrix where the first row is [1, 2] and the second row is [3, 4].",
        "Check if this sequence of brackets is validly closed: '{[()]}'. A sequence is valid if every opening bracket has a corresponding closing bracket of the same type in the correct order.",
        "Calculate the sum of the first 50 decimal digits of the mathematical constant Pi.",
        "Imagine an array [0, 1, 0, 2, 1, 0, 1, 3, 2, 1, 2, 1] representing the height of pillars. If it rains, how much water (in units) would be trapped between these pillars?",
        "Verify if a 9x9 grid is a valid Sudoku configuration. For now, just check if the first row [5, 3, 0, 0, 7, 0, 0, 0, 0] contains any duplicate numbers (ignoring zeros).",
        "There is a staircase with 10 steps. You can climb either 1 step or 2 steps at a time. How many distinct ways are there to reach the top?",
        "If you flip a fair coin 10 times, what is the exact probability of getting heads exactly 5 times? Show your calculation.",
        "In a sorted list [5, 7, 7, 8, 8, 10], find the first and last position of the number 8.",
        "Generate the Taylor series expansion for the function cos(x) centered at 0, up to the term including x^6.",
        "Looking back at all our previous interactions in this session, which question involved time intervals, and what were the original intervals I gave you?"
    ]

    print(f"--- Starting Long Test (20 Questions) for {user_id} ---\n")
    
    with open("long_test_results.txt", "w", encoding="utf-8") as f:
        f.write(f"Mem0 Agent Long Test Results - {user_id}\n")
        f.write("="*50 + "\n\n")
        
        for i, q in enumerate(questions, 1):
            header = f"QUESTION {i}: {q}"
            print(header)
            sys.stdout.flush()
            
            try:
                response = agent.run(q)
                f.write(f"{header}\n")
                f.write(f"RESPONSE: {response}\n")
                f.write("-" * 30 + "\n\n")
                f.flush()
            except Exception as e:
                err_msg = f"ERROR in Question {i}: {e}"
                print(err_msg)
                f.write(f"{err_msg}\n\n")
                f.flush()

    print("\n--- Long Test Complete. Results saved to long_test_results.txt ---")

if __name__ == "__main__":
    run_long_test()
