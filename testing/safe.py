import os

# Use environment variables for sensitive data
API_KEY = os.getenv("API_KEY", "default_key")

# Safe function to process input
def process_input(user_input):
    try:
        # Validate and convert input to integer
        return int(user_input)
    except ValueError:
        return 0

# Example usage
if __name__ == "__main__":
    user_input = input("Enter a number: ")
    result = process_input(user_input)
    print(f"Processed result: {result}")