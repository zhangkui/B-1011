FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for OpenCV and libmagic
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create directories for uploads
RUN mkdir -p static/uploads static/qrcodes

EXPOSE 5000

CMD ["python", "app.py"]
