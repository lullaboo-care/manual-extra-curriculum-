# Use an official Python runtime as a parent image
FROM python:alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port the app runs on
EXPOSE 6000

# Use Gunicorn as production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:6000", "app:app"]