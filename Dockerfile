# Evrmore Authentication API Server Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies first to leverage Docker cache
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the source code
COPY . .

# Install the package
RUN pip3 install -e .

# Create a non-root user and switch to it
RUN useradd -m evrauth
USER evrauth

# Expose the API port
EXPOSE 8000

# Run the API server
CMD ["evrmore-auth-api", "--host", "0.0.0.0", "--port", "8000"] 