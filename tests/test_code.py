from evrmore_authentication import EvrmoreAuth

# Initialize authentication with debug mode
auth = EvrmoreAuth(debug=True)

# Create a new address for testing
address, wif_key = auth.create_wallet_address()
print(address)

# Generate a challenge
challenge = auth.generate_challenge(address)
print(challenge)

# Sign the challenge with our private key
signature = auth.sign_message(wif_key, challenge)
print(signature)

# Authenticate
session = auth.authenticate(address, challenge, signature)
print(session.token)

# Validate the token
verified = auth.validate_token(session.token)
print(verified)



