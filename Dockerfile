FROM python:3.10

RUN pip install -r requirements.txt
RUN pip install --upgrade gunicorn

COPY src/ /app
WORKDIR /app

ENV GOOGLE_CLOUD_MYSQL_SERVER placeholder
ENV REMOTE_SQL_PASS placeholder
ENV EMAIL_PASS placeholder
ENV PORT 8080

CMD exec gunicorn --bind :$PORT --workers 6--threads 12 __init__:app