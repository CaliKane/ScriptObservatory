#!/usr/bin/python3

import backend

if __name__ == '__main__':
    backend.app.run(debug=True, use_reloader=False, port=8080)
