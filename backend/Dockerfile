# PhishSecure Bahrain CTI Platform - Backend Docker Configuration
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements_cti.txt .
RUN pip install --no-cache-dir -r requirements_cti.txt

# Copy application code
COPY . .

# Create database directory
RUN mkdir -p /app/data

# Set environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=app_cti.py
ENV FLASK_ENV=production
ENV DATABASE_PATH=/app/data/cti_database.db

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Run the application
CMD ["python", "app_cti.py"]
