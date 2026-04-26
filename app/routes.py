from flask import Blueprint, jsonify, render_template

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/analyse', methods=['POST'])
def analyse():
    return jsonify({"status": "ok", "message": "analyse endpoint ready"})

@main.route('/health')
def health():
    return jsonify({"status": "ok", "message": "health endpoint ready"})