# Use an official Python base image
FROM python:3.11-slim

# Set the PYTHONPATH to include /app
ENV PYTHONPATH=/app

# Set the working directory in the container
WORKDIR /app

# Copy only requirements first (to leverage Docker caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files
COPY . .

# Expose the Flask port (5000)
EXPOSE 5000

# Command to run the application
CMD ["python", "/app/flask_app/app.py"]
