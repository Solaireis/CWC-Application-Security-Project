# Below Docker file code for GCP Cloud Run
# Details: https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service

# Use the official lightweight Python image
FROM python:3.10.6-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Copy the dependency requirements and the python script
# to download the dependencies to the working directory
COPY requirements.txt .
COPY sample/download_dependencies.py .

# Install the dependencies using the copied python script with integrity checks
RUN python3 download_dependencies.py
# RUN pip install -r requirements.txt
# RUN pip install -U gunicorn

# Remove the python script and the requirements file
# after the dependencies are installed
RUN rm -f requirements.txt
RUN rm -f download_dependencies.py

# Copy local code to the container image
ENV APP_HOME /app
COPY src/ /app
WORKDIR $APP_HOME

# Set PORT env for flask app to Listen on port 8080
ENV PORT 8080

# Run the web service on container startup. Here we use the gunicorn webserver.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling
# <filename>:<flask app variable name> which in this case is app:app
CMD exec gunicorn --bind :$PORT --workers 8 --threads 16 --timeout 0 app:app