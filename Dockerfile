# Below Docker file code for GCP Cloud Run
# Details: https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service
FROM python:3.10.5-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Copy the dependencies file to the working directory
COPY requirements.txt .
# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN rm -f requirements.txt

# Install green unicorn, aka gunicorn to host the app
RUN pip install --no-cache-dir --upgrade gunicorn

# Copy local code to the container image
ENV APP_HOME /app
COPY src/ /app
WORKDIR $APP_HOME

# Set PORT env for flask app to Listen on port 8080
ENV PORT 8080

# Run the web service on container startup. Here we use the gunicorn
# webserver, with 6 worker process and 12 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling
CMD exec gunicorn --bind :$PORT --workers 6 --threads 12 --timeout 0 app:app