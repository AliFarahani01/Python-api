from flask import Flask, request, jsonify
import sys
import io
import time
import traceback

app = Flask(__name__)

@app.route('/')
def home():
    return "API اجرای کامل پایتون فعاله."

@app.route('/run', methods=['POST'])
def run_code():
    try:
        data = request.get_json(force=True)
        code = data.get("code", "")

        if not code:
            return jsonify({"success": False, "error": "هیچ کدی ارسال نشده است."}), 400

        # گرفتن خروجی
        old_stdout = sys.stdout
        redirected_output = sys.stdout = io.StringIO()

        start_time = time.time()

        try:
            exec(code, globals())  # اجرای کامل بدون محدودیت
            output = redirected_output.getvalue()
            success = True
        except Exception:
            output = traceback.format_exc()
            success = False
        finally:
            sys.stdout = old_stdout

        exec_time = round((time.time() - start_time) * 1000, 2)

        return jsonify({
            "success": success,
            "output": output.strip(),
            "exec_time_ms": exec_time
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == '__main__':
    app.run()
