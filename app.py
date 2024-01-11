from config import app
from flask import render_template
import random
import string
@app.route('/')
def base():
    return render_template('base.html')


if __name__ == "__main__":
    app.run(debug=True)

