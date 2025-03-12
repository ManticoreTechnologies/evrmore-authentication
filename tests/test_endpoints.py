from requests import get

response = get("http://localhost:8000/api/v2/auth/validate")
print(response.json())