from flask import Flask, request, jsonify
import sys
import io
import traceback
import time

app = Flask(__name__)

@app.route('/')
def home():
    return 'API فعاله! آماده اجرای کد پایتون.'

@app.route('/run', methods=['GET', 'POST'])
def run_code():
    code = request.args.get('code') if request.method == 'GET' else request.json.get('code', '')
    
    if not code:
        return jsonify({'success': False, 'output': 'هیچ کدی ارسال نشده.'}), 400

    try:
        old_stdout = sys.stdout
        redirected_output = sys.stdout = io.StringIO()

        start = time.time()
        exec(code, {})
        exec_time = (time.time() - start) * 1000

        output = redirected_output.getvalue()
        sys.stdout = old_stdout

        return jsonify({
            'success': True,
            'output': output.strip(),
            'exec_time_ms': round(exec_time, 2)
        })

    except Exception:
        sys.stdout = old_stdout
        return jsonify({
            'success': False,
            'output': traceback.format_exc()
        }), 500
