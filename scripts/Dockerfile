FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scripts
COPY *.py .

# Create logs directory
RUN mkdir -p /app/logs

ENTRYPOINT ["python", "tag_noncompliant_resources.py"]
