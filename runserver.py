#!/usr/bin/python3

from backend import app, models, views

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, port=8080)
