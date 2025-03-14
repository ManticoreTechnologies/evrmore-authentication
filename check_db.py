import sqlite3

# Connect to the database
conn = sqlite3.connect('./evrmore_authentication/data/evrmore_auth.db')
conn.row_factory = sqlite3.Row

# Check authorization codes
print('Authorization Codes:')
cursor = conn.execute('SELECT * FROM oauth_authorization_codes LIMIT 5')
cols = [column[0] for column in cursor.description]
rows = cursor.fetchall()
for row in rows:
    print(dict((cols[i], row[i]) for i in range(len(cols))))

# Check OAuth clients
print('\nOAuth Clients:')
cursor = conn.execute('SELECT client_id, client_name, redirect_uris FROM oauth_clients LIMIT 5')
cols = [column[0] for column in cursor.description]
rows = cursor.fetchall()
for row in rows:
    print(dict((cols[i], row[i]) for i in range(len(cols))))

conn.close() 