# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /app

# Copy the server communication script into the container
COPY server_communication.py .

# Install any needed packages specified in requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Run server_communication.py when the container launches
CMD ["python", "server_communication.py"]
