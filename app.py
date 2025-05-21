from flask import Flask, request, jsonify
import sys
import io
import traceback
import contextlib

app = Flask(__name__)

@app.route('/')
def home():
    return 'API فعال است! از /run برای اجرای کد استفاده کنید.'

@app.route('/run', methods=['GET', 'POST'])
def run_code():
    code = request.args.get('code') if request.method == 'GET' else request.json.get('code')

    if not code:
        return jsonify({'output': 'هیچ کدی ارسال نشده است.'})

    # گرفتن خروجی و خطاها
    stdout = io.StringIO()
    stderr = io.StringIO()

    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exec(code, {'__builtins__': __builtins__})  # اجرای امن‌تر از eval
    except Exception:
        error_trace = traceback.format_exc()
        return jsonify({'output': stderr.getvalue() + error_trace})

    output = stdout.getvalue()
    error_output = stderr.getvalue()

    final_output = output + error_output
    return jsonify({'output': final_output.strip() or 'بدون خروجی'})

if __name__ == '__main__':
    app.run(debug=True)
