from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/')
def home():
    return 'API فعاله!'

@app.route('/run', methods=['GET'])
def run_code():
    code = request.args.get('code', '')
    try:
        result = eval(code)
        return jsonify({'output': str(result)})
    except Exception as e:
        return jsonify({'output': f'Error: {str(e)}'})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
