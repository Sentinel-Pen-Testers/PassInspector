import binascii

def dehexify(password):
    dehexed_password = "ERROR DECODING HEX"
    try:
        # Remove the "$HEX[" prefix and "]" suffix
        hex_string = password[len("$HEX["):-1]
        dehexed_password = binascii.unhexlify(hex_string).decode(
            'latin-1')  # Using latin-1 to account for other languages like German
        # dehexed_password = binascii.unhexlify(hex_string).decode('latin-1', 'replace') # Will stop errors,
        # but only by replacing problematic characters
    except binascii.Error:
        # Handle the case where the hex conversion fails
        print("ERROR: Could not dehexify the following value: ", password)
    return dehexed_password