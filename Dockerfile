# Below Docker file code for GCP Cloud Run
FROM python:3.10.5

# Copy the dependencies file to the working directory
COPY requirements.txt .
# Install any dependencies
RUN pip install -r requirements.txt

# Install green unicorn, aka gunicorn to host the app
RUN pip install --upgrade gunicorn

# Copy the content of the local src directory to the working directory
COPY src/ /app
WORKDIR /app

# Set PORT env for flask app to Listen on port 8080
ENV PORT 8080

CMD exec gunicorn --bind :$PORT --workers 6--threads 12 app:app

# Below Docker file code for AWS Lightsail
# Details: https://aws.amazon.com/getting-started/hands-on/serve-a-flask-app/
# # Set base image (host OS)
# FROM python:3.10.5

# # By default, listen on port 5000
# EXPOSE 5000/tcp
# ENV PORT 5000

# # Copy the dependencies file to the working directory
# COPY requirements.txt .

# # Install any dependencies
# RUN pip install -r requirements.txt

# # Copy the content of the local src directory to the working directory
# COPY src/ /app
# WORKDIR /app

# # Specify the command to run on container start
# CMD [ "python", "./app.py" ]