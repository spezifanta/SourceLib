from flask import Flask, jsonify
from SourceQuery import SourceQuery

app = Flask(__name__)
app.config.update(
  JSONIFY_PRETTYPRINT_REGULAR=True
)

@app.route('/')
def info():
    server = SourceQuery('steamcalculator.com')
    result = server.info()
    result = {**result, **server.rules()}
    result = {**result, **server.players()}
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=27014)
