# Use an official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies required by scapy (libpcap)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port Streamlit runs on
EXPOSE 8501

# Command to run the Streamlit dashboard
CMD ["streamlit", "run", "streamlit_dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
