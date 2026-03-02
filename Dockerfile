FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV AGENDA_SECRET_KEY=change-me

RUN flask --app run.py init-db

EXPOSE 8000
CMD ["python", "serve.py"]
