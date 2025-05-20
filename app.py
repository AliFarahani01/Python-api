from flask import Flask, request, jsonify

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
