FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dns_report.py ignore_domains.txt ./
ENTRYPOINT ["python", "dns_report.py"]
