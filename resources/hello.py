def say_hello():
    print("Hello from Jenkins job!")
    with open("output.txt", "w") as f:
        f.write("This was generated by Jenkins!")

if __name__ == "__main__":
    say_hello()
