from evrmore_authentication import EvrmoreAuth
from evrmore_rpc import EvrmoreClient

client = EvrmoreClient()
auth = EvrmoreAuth(client)

# Create a new address
address = client.getnewaddress()
print(address)

# Generate a challenge
challenge = auth.generate_challenge(address)
print(challenge)

# Sign the challenge
signature = client.signmessage(address, challenge)
print(signature)

# Authenticate
session = auth.authenticate(address, challenge, signature)
print(session.token)

# Validate the token
verified = auth.validate_token(session.token)
print(verified)



