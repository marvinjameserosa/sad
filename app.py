# app.py

from flask import Flask, render_template, redirect, url_for, request, session, flash, make_response, jsonify
import os
import hashlib
import secrets
from functools import wraps
# Do not import 'random' as it is not used and can sometimes cause confusion

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Flags for each challenge
FLAGS = {
    'intro': 'Ghost-In-The-Shellcode_v2.1',
    'challenge1': 'SEEN{The_Airlock_Is_Open}',
    'challenge2': 'SEEN{WEAREALMOSTTHERE}',
    'challenge3': 'SEEN{KILL_0xDEADBEEFCAFED00D8BADF00D5EAF00D}'
}

# --- CORRECT RSA PARAMETERS ---
# Use these exact definitions. Do not change them.
P = 61
Q = 53
N = P * Q  # 3233
E = 17     # Public exponent

ENCRYPTED_MESSAGE = [2790, 1515, 1386, 3124, 2186, 1197, 2731, 1386, 1709, 3124, 765] # "SOVEREIGNTY"
ENCRYPTED_FLAG_COMPONENT = 2170
# --- END OF PARAMETERS ---

# (Your helper functions and other routes go here...)

# --- Helper Functions (login_required, challenge_access) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You need to access the gateway first.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def challenge_access(level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('challenge_level', 0) < level:
                flash('You need to complete the previous challenges first.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Core Routes (index, login, logout) ---
@app.route('/')
def index():
    if 'logged_in' in session:
        level = session.get('challenge_level', 1)
        return redirect(url_for(f'challenge{level}' if level <= 3 else 'challenge3'))
    return render_template('intro.html', flag=FLAGS['intro'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            session['username'] = username
            session['logged_in'] = True
            session['challenge_level'] = 1
            flash(f'Welcome, {username}! You have accessed the first challenge.', 'success')
            return redirect(url_for('challenge1'))
        else:
            flash('Invalid login credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'system')
    return redirect(url_for('index'))

# --- Challenge 1 Routes ---
@app.route('/challenge1')
@login_required
@challenge_access(1)
def challenge1():
    if 'bypass' in request.cookies and request.cookies.get('bypass') == 'true':
        if session.get('challenge_level', 0) < 2:
            session['challenge_level'] = 2
        flash('Cookie manipulation successful! You bypassed the first challenge.', 'success')
        return redirect(url_for('challenge2'))
    return render_template('challenge1.html')

@app.route('/bypass_cookie')
def bypass_cookie():
    response = make_response(redirect(url_for('challenge1')))
    response.set_cookie('bypass', 'true')
    return response

# --- Challenge 2 Routes (REFACTORED) ---
@app.route('/challenge2')
@login_required
@challenge_access(2)
def challenge2():
    if 'rsa_n' not in session:
        session['rsa_n'] = N
        session['rsa_e'] = E
        session['encrypted_msg'] = ENCRYPTED_MESSAGE
    return render_template('challenge2.html', 
                          previous_flag=FLAGS['challenge1'],
                          rsa_n=session['rsa_n'],
                          rsa_e=session['rsa_e'],
                          encrypted_msg=session['encrypted_msg'])

@app.route('/check_prime', methods=['POST'])
@login_required
@challenge_access(2)
def check_prime():
    try:
        p = int(request.form.get('prime_p', ''))
        q = int(request.form.get('prime_q', ''))
        if (p == P and q == Q) or (p == Q and q == P):
            session['found_primes'] = True
            return jsonify({'success': True, 'message': 'Correct prime factors! Now calculate the private key d.'})
        else:
            return jsonify({'success': False, 'message': 'Those are not the correct prime factors.'})
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Please enter valid numbers.'})

@app.route('/solve_challenge2', methods=['POST'])
@login_required
@challenge_access(2)
def solve_challenge2():
    # --- Start of Diagnostic Printing ---
    print("\n--- Received request for /solve_challenge2 ---")
    
    found_primes_in_session = session.get('found_primes', False)
    print(f"Value of session['found_primes']: {found_primes_in_session}")

    if not found_primes_in_session:
        print("FAIL: 'found_primes' not found or is False in session.")
        return jsonify({'success': False, 'message': 'You must identify the correct prime factors first.'})
    
    try:
        d_from_form = request.form.get('private_key', '')
        message_from_form = request.form.get('decrypted_message', '').strip().upper()
        
        print(f"Private key from form: '{d_from_form}'")
        print(f"Message from form: '{message_from_form}'")

        d = int(d_from_form)
        phi = (P - 1) * (Q - 1)

        is_key_valid = (d * E) % phi == 1
        print(f"Is the private key mathematically valid? {is_key_valid}")
        if not is_key_valid:
            print("FAIL: Private key is not valid.")
            return jsonify({'success': False, 'message': 'The private key is not valid for this RSA system.'})

        is_message_correct = message_from_form == "SOVEREIGNTY"
        print(f"Is the decrypted message correct? {is_message_correct}")
        if not is_message_correct:
            print("FAIL: Decrypted message is incorrect.")
            return jsonify({'success': False, 'message': f'The decrypted message "{message_from_form}" is incorrect. Try again.'})

        # Final verification
        decrypted_component = pow(ENCRYPTED_FLAG_COMPONENT, d, N)
        print(f"Encrypted component to check: {ENCRYPTED_FLAG_COMPONENT}")
        print(f"Result of pow({ENCRYPTED_FLAG_COMPONENT}, {d}, {N}): {decrypted_component}")
        
        is_final_verification_ok = (decrypted_component == 104)
        print(f"Does the result equal 1337? {is_final_verification_ok}")

        if is_final_verification_ok:
            print("SUCCESS: All checks passed.")
            if session.get('challenge_level', 0) < 3:
                session['challenge_level'] = 3
            return jsonify({
                'success': True,
                'message': 'Congratulations! You have broken the RSA encryption.',
                'redirect': url_for('challenge3')
            })
        else:
            print("FAIL: Final verification failed.")
            return jsonify({'success': False, 'message': 'Private key and message are correct, but final verification failed.'})

    except (ValueError, TypeError) as e:
        print(f"ERROR: An exception occurred: {e}")
        return jsonify({'success': False, 'message': 'Please enter a valid number for the private key.'})
    
# --- Challenge 3 Routes ---
@app.route('/challenge3')
@login_required
@challenge_access(3)
def challenge3():
    return render_template('challenge3.html', flag=FLAGS['challenge2'])

@app.route('/execute_transaction', methods=['POST'])
@login_required
@challenge_access(3)
def execute_transaction():
    kill_key = request.form.get('kill_key', '').strip()
    transaction_data = f"user:{session.get('username', 'anonymous')}:time:{os.urandom(8).hex()}"
    transaction_hash = hashlib.sha256(transaction_data.encode()).hexdigest()
    
    if kill_key == FLAGS['challenge3']:
        flash('Transaction executed! The Source Ledger has been neutralized.', 'success')
        return render_template('victory.html', 
                              transaction_hash=transaction_hash, 
                              flag=FLAGS['challenge3'])
    else:
        flash('Transaction initiated but requires valid kill key.', 'warning')
        return render_template('challenge3.html', 
                              flag=FLAGS['challenge2'],
                              transaction_hash=transaction_hash,
                              invalid_attempt=True)

if __name__ == '__main__':
    app.run(debug=True)