from flask import Flask, session

# change accordingly to the user account ID that you would want to get access to
VALUE_CHANGE_INPUT = "657a9e3f44e64e7890f378ed4ea6efc0" 

app = Flask(__name__)
app.config["SECRET_KEY"] = "a secret key" # same as the web server secret key

@app.route('/')
def home():
    session["user"] = VALUE_CHANGE_INPUT
    return "Session value: {}\nPlease check the session cookie value in the application settings".format(session["user"])

if __name__ == "__main__":
    app.run(debug=True)