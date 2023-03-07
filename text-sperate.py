with open("Ercot_config.rc.default", "r") as file:
    # Loop through each line in the file
    for line in file:
        # Strip the newline character from the line
        line = line.replace(' ', '')
        # Split the line into a key-value pair using the equals sign delimiter
        value = line.split("=")
        # If the key matches the target ID
        if value == "_modelTypeId.type000000136":
            # Print the value associated with that key
            print(value)