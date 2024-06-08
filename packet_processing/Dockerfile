# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /app

# Copy the packet processing script into the container
COPY packet_processing.py .

# Install any needed packages specified in requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Run packet_processing.py when the container launches
CMD ["python", "packet_processing.py"]
