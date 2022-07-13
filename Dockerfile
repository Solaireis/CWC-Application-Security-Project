# Below Docker file code for GCP Cloud Run
# Details: https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service

# Use the official lightweight Python image
FROM python:3.10.5-slim

# Install ffmpeg in container
RUN apt-get update && apt-get install -y ffmpeg

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

# Below Docker file code for AWS Lightsail
# Details: https://aws.amazon.com/getting-started/hands-on/serve-a-flask-app/
# # Set base image (host OS)
# FROM python:3.10.5-alpine

# # By default, listen on port 5000
# EXPOSE 5000/tcp
# ENV PORT 5000

# # Copy the dependencies file to the working directory
# COPY requirements.txt .

# # Install any dependencies
# RUN pip install -r requirements.txt
# RUN rm requirements.txt

# Copy local code to the container image
# COPY src/ /app
# WORKDIR /app

# # Set up FFmpeg: https://hub.docker.com/r/jrottenberg/ffmpeg
# docker pull jrottenberg/ffmpeg:4.1-ubuntu

# # Specify the command to run on container start
# CMD ["python", "./app.py"]
