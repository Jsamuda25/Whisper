# Use Python base image
FROM python:3.11-slim

# Set the working directory
WORKDIR /Whisper

# Copy only the requirements file first (better caching)
COPY requirements.txt .

# Install dependencies (including Flask)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files
COPY . .

# Expose the Flask app's port
EXPOSE 5000

# Run the app
CMD ["python", "main.py"]
