FROM python:3.10

RUN pip install -r requirements.txt
RUN pip install --upgrade gunicorn

COPY src/ /app
WORKDIR /app

ENV PORT 8080

CMD exec gunicorn --bind :$PORT --workers 6--threads 12 app:app