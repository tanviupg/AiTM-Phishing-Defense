FROM python:3.10-slim

WORKDIR /app

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY . /app

# Install dependencies (fastapi and uvicorn)
RUN pip install --no-cache-dir fastapi uvicorn

# Expose ports:
# 8000: SOC Dashboard & Hardening REST API
# 5001: Mock Identity Provider
# 5002: AiTM Reverse Proxy
EXPOSE 8000 5001 5002

CMD ["python", "module3_hardening/api.py"]
