from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import firebase_admin
from firebase_admin import credentials, auth, db
import secrets
import bcrypt  # Import bcrypt for password hashing
from datetime import datetime
# Initialize the Flask app
app = Flask(__name__)

# Generate a secure random secret key (or you can use an environment variable)
app.secret_key = secrets.token_hex(16)  # Generates a 32-character hex string

# Initialize Firebase Admin SDK
cred = credentials.Certificate('pass.json')  # Update with the path to your service account file
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://dopeshield-fa348-default-rtdb.firebaseio.com/'  # Your Firebase Realtime Database URL
})


#################
#  Main page    #
#################


@app.route('/')
def index():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    user_data = None
    user_id = request.cookies.get('user_id')
    print(user_id)  # Debug print

    if user_id:
        # Fetch user data from Firebase
        ref = db.reference(f'users/{user_id}')
        user_data = ref.get()

    return render_template('index.html', user=user_data)


#################
#  Sign up      #
#################

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm-password']
        except KeyError as e:
            return redirect(url_for('signup', message=f"Missing form field: {str(e)}", type="error"))

        if password != confirm_password:
            return redirect(url_for('signup', message="Passwords do not match!", type="error"))

        try:
            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Create user in Firebase Authentication
            user = auth.create_user(
                email=email,
                password=password,
                display_name=name
            )

            # Store additional user info in Realtime Database
            ref = db.reference(f'users/{user.uid}')
            ref.set({
                'name': name,
                'email': email,
                'password': hashed_password.decode('utf-8'),
            })

            return redirect(url_for('signin', message="Account created successfully!", type="success"))
        except Exception as e:
            return redirect(url_for('signup', message=f"Error creating account: {e}", type="error"))

    return render_template('signup.html')


#################
#  Sign In      #
#################

@app.route('/signin', methods=['GET', 'POST'])

def signin():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['pass1']

        try:
            # Get user by email
            user = auth.get_user_by_email(email)

            # Fetch user data from Realtime Database
            ref = db.reference(f'users/{user.uid}')
            user_data = ref.get()

            if not user_data:
                return redirect(url_for('signin', message='User not found!', type='error'))

            # Validate password
            stored_hashed_password = user_data.get('password')
            if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                return redirect(url_for('signin', message='Incorrect password!', type='error'))

            # Set a cookie to track user login
            resp = redirect(url_for('index', message='Login successful!', type='success'))
            resp.set_cookie('user_id', user.uid)  # Save user ID in a cookie
            return resp

        except Exception as e:
            return redirect(url_for('signin', message=f'Error signing in: {e}', type='error'))

    return render_template('signin.html')


#################
#  Profile      #
#################


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Check if the user is logged in via the 'user_id' cookie
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        # If there's no cookie, redirect to the login page
        return redirect(url_for('signin', message="You must be logged in to access the profile.", type="error"))

    try:
        # Fetch user data from Firebase Authentication
        user = auth.get_user(user_id_from_cookie)

        # Fetch user details from Realtime Database
        ref = db.reference(f'users/{user.uid}')
        user_data = ref.get()

        if not user_data:
            return redirect(url_for('signin', message='User data not found!', type='error'))

        if request.method == 'POST':
            # Collect form data
            name = request.form['name']
            email = request.form['email']
            age = request.form['age']
            gender = request.form['gender']
            sport = request.form.get('sport', '')
            organization = request.form.get('organization', '')
            testing_history = request.form.get('testing_history', '')
            awareness_training = request.form.get('awareness_training', '')

            # Update the user's profile in the Realtime Database
            ref.update({
                'name': name,
                'email': email,
                'age': age,
                'gender': gender,
                'sport': sport,
                'organization': organization,
                'testing_history': testing_history,
                'awareness_training': awareness_training
            })

            # Redirect to the profile page with a success message
            return redirect(url_for('profile', message="Profile updated successfully!", type="success"))

        # Render the profile page with the fetched user data and optional messages
        message = request.args.get('message', '')
        message_type = request.args.get('type', '')
        return render_template('profile.html', user=user_data, message=message, type=message_type)

    except Exception as e:
        # Redirect to signin with an error message
        return redirect(url_for('signin', message=f'Error loading profile: {e}', type='error'))

#######################
#    Delete Account   #
#######################


@app.route('/delete_account', methods=['POST'])
def delete_account():
    # Retrieve the user_id from the cookie to identify the user
    user_id = request.cookies.get('user_id')
    if not user_id:
        return redirect(url_for('signin', message="You must be logged in to delete your account.", type="error"))

    try:
        # Delete user from Firebase Authentication
        auth.delete_user(user_id)

        # Remove user data from the Firebase Realtime Database
        db.reference(f'users/{user_id}').delete()

        # Clear the cookie after deletion
        resp = redirect(url_for('signup', message="Account deleted successfully!", type="success"))
        resp.delete_cookie('user_id')  # Clear the user_id cookie
        return resp

    except Exception as e:
        # Handle any errors during account deletion
        return redirect(url_for('profile', message=f"Error deleting account: {e}", type="error"))


#######################
#    Logout           #
#######################

@app.route('/logout')
def logout():
    # Clear the session or cookie
    resp = redirect(url_for('index'))  # Redirect to the index page after logout
    resp.delete_cookie('user_id')  # Remove the user_id cookie to log the user out
    return resp

# @app.route('/save_game_data', methods=['POST'])
# def save_game_data():
#     try:
#         data = request.get_json()
#         user_id = data.get('userId')
#         score = data.get('score')
#         time_taken = data.get('timeTaken')

#         if not user_id:
#             return jsonify({'success': False, 'message': 'User ID not provided'}), 400

#         ref = db.reference(f'users/{user_id}/game_data')

#         game_session = {
#             'score': score,
#             'time_taken': time_taken,
#             'timestamp': int(datetime.utcnow().timestamp())
#         }

#         ref.push(game_session)

#         return jsonify({'success': True, 'message': 'Game data saved successfully.'}), 200

#     except Exception as e:
#         return jsonify({'success': False, 'message': f'Error saving game data: {e}'}), 500
    


#######################
#        Podcast      #
#######################
    
@app.route('/pod')
def pod():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the game.", type="error"))
    return render_template("podcast.html")



#######################
#       Rules         #
#######################

@app.route('/awar')
def rule():
    
    return render_template("rule.html")

#######################
#    Analytics        #
#######################

@app.route('/anal')
def anal():
    
    return render_template("anal.html")


#######################
#      Courses        #
#######################

@app.route('/courses')
def courses():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the courses.", type="error"))
    return render_template("courses.html")

@app.route('/course1')
def course1():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the course.", type="error"))
    return render_template("course-1.html")

@app.route('/course2')
def course2():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the course.", type="error"))
    return render_template("course-2.html")

@app.route('/course3')
def course3():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the course.", type="error"))
    return render_template("course-3.html")

@app.route('/course4')
def course4():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the course.", type="error"))
    return render_template("course-4.html")

@app.route('/course5')
def course5():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the course.", type="error"))
    return render_template("course-5.html")

@app.route('/course6')
def course6():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the course.", type="error"))
    return render_template("course-6.html")

#######################
#   Certificates      #
#######################

@app.route('/certificate')
def certificate():
    return render_template("certificate.html")

@app.route('/certificate2')
def certificate2():
    return render_template("certificate-2.html")

@app.route('/certificate3')
def certificate3():
    return render_template("certificate-3.html")

@app.route('/certificate4')
def certificate4():
    return render_template("certificate-4.html")

@app.route('/certificate5')
def certificate5():
    return render_template("certificate-5.html")

@app.route('/certificate6')
def certificate6():
    return render_template("certificate-6.html")




#######################
#      Games          #
#######################


#############################
#   Game-1 Doping Dilemma   #
#     (quiz-game.html)      #
#############################


@app.route('/record_quiz_score', methods=['POST'])
def record_quiz_score():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

    print(f"User ID: {user_id}")  # Print the user ID

    data = request.get_json()
    quiz_score = data.get('quiz_score')
    duration = data.get('duration')

    if quiz_score is None or duration is None:
        return jsonify({'status': 'error', 'message': 'Invalid data provided'}), 400

    # Update Firebase reference to use user_id
    reference = db.reference(f'users/{user_id}/quiz_statistics')
    current_time = int(datetime.now().timestamp())

    # Save quiz results to the updated path
    reference.push({
        'quiz_score': quiz_score,
        'duration': duration,
        'timestamp': current_time
    })

    return jsonify({'status': 'success', 'message': 'Quiz score recorded successfully'})

#############################
#   Game-1 Doping Dilemma   #
#     (Visulaization)       #
#############################


@app.route('/quiz_visualization', methods=['GET'])
def quiz_visualization():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'message': 'User not logged in'}), 401

    # Fetch quiz statistics from Firebase
    ref = db.reference(f'users/{user_id}/quiz_statistics')
    quiz_data = ref.get()

    if not quiz_data:
        return jsonify({'message': 'No quiz data found'}), 404

    # Prepare data for the graph
    timestamps = []
    scores = []
    durations = []

    for quiz in quiz_data.values():
        quiz_score = quiz.get('quiz_score')
        duration = quiz.get('duration')
        timestamp = quiz.get('timestamp')

        if quiz_score is not None and duration is not None and timestamp is not None:
            date = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            timestamps.append(date)
            scores.append(quiz_score)
            durations.append(duration)

    return render_template('graph-1.html', timestamps=timestamps, scores=scores, durations=durations)



#############################
#   Game-2 Ethics Enigma    #
#     (word-puzzle.html)    #
#############################


@app.route('/submit_game_score', methods=['POST'])
def submit_game_score():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

    print(f"User ID: {user_id}")  # Print the user ID

    data = request.get_json()
    game_score = data.get('game_score')
    time_elapsed = data.get('time_elapsed')

    if game_score is None or time_elapsed is None:
        return jsonify({'status': 'error', 'message': 'Invalid data provided'}), 400

    # Update Firebase reference to use user_id
    reference = db.reference(f'users/{user_id}/game_stats')
    current_time = int(datetime.now().timestamp())

    # Save game results to the updated path
    reference.push({
        'game_score': game_score,
        'time_elapsed': time_elapsed,
        'timestamp': current_time
    })

    return jsonify({'status': 'success', 'message': 'Game score submitted successfully'})


#############################
#   Game-2 Ethics Enigma    #
#     (Visualization)       #
#############################


@app.route('/visualization', methods=['GET'])
def serve_visualization():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({"message": "User not logged in"}), 401  # User is not logged in

    # Fetch game stats from Firebase at the specific path
    ref = db.reference(f'users/{user_id}/game_stats')
    game_stats = ref.get()

    # If no stats are available, return an error
    if not game_stats:
        return jsonify({"message": "No game data found"}), 404

    # Prepare the data for Chart.js
    dates = []
    scores = []
    time_elapsed = []

    # Iterate through game stats to extract the necessary data
    for game in game_stats.values():
        game_score = game.get('game_score')
        time_taken = game.get('time_elapsed')
        timestamp = game.get('timestamp')

        if game_score is not None and time_taken is not None and timestamp is not None:
            date = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')
            dates.append(date)
            scores.append(game_score)
            time_elapsed.append(time_taken)

    return render_template('graph-2.html', dates=dates, scores=scores, time_elapsed=time_elapsed)


#############################
#   Game-3 Life's Bounty    #
#     (life-bounty.html)    #
#############################



@app.route('/record_game_performance', methods=['POST'])
def record_game_performance():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

    data = request.get_json()
    score = data.get('score')
    duration = data.get('duration')

    if score is None or duration is None:
        return jsonify({'status': 'error', 'message': 'Invalid input data'}), 400

    # Reference Firebase based on user ID
    user_data_ref = db.reference(f'users/{user_id}/performance_metrics')
    timestamp = int(datetime.now().timestamp())

    # Save game performance metrics
    user_data_ref.push({
        'score': score,
        'duration': duration,
        'timestamp': timestamp
    })

    return jsonify({'status': 'success', 'message': 'Game performance recorded successfully'})

#############################
#   Game-3 Life's Bounty    #
#     (Visualization)       #
#############################


@app.route('/game_performance_visualization', methods=['GET'])
def game_performance_visualization():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'message': 'User not logged in'}), 401

    # Fetch performance metrics from Firebase
    ref = db.reference(f'users/{user_id}/performance_metrics')
    performance_data = ref.get()

    if not performance_data:
        return jsonify({'message': 'No performance data found'}), 404

    # Prepare data for the graph
    timestamps = []
    scores = []
    durations = []

    for entry in performance_data.values():
        score = entry.get('score')
        duration = entry.get('duration')
        timestamp = entry.get('timestamp')

        if score is not None and duration is not None and timestamp is not None:
            date = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            timestamps.append(date)
            scores.append(score)
            durations.append(duration)

    return render_template('graph-3.html', timestamps=timestamps, scores=scores, durations=durations)


#############################
#    Game-4 Word whirl      #
#   (word-scramble.html)    #
#############################

    
@app.route('/submit_score', methods=['POST'])
def submit_score():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

    data = request.get_json()
    score = data.get('score')
    time_taken = data.get('time_taken')

    if score is None or time_taken is None:
        return jsonify({'status': 'error', 'message': 'Invalid data provided'}), 400

    # Reference the user's game data in Firebase
    ref = db.reference(f'users/{user_id}/game_data')
    timestamp = int(datetime.now().timestamp())

    # Save game results
    ref.push({
        'score': score,
        'time_taken': time_taken,
        'timestamp': timestamp
    })

    return jsonify({'status': 'success', 'message': 'Score submitted successfully'})


#############################
#    Game-4 Word whirl      #
#   (visualization)         #
#############################


@app.route('/visualize_user_scores', methods=['GET'])
def visualize_user_scores():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

    try:
        # Fetch game data from Firebase
        ref = db.reference(f'users/{user_id}/game_data')
        game_data = ref.get()

        if not game_data:
            return jsonify({'status': 'error', 'message': 'No game data found'}), 404

        # Prepare data for visualization
        timestamps = []
        scores = []
        time_taken = []

        for game in game_data.values():
            timestamps.append(datetime.fromtimestamp(game['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
            scores.append(game['score'])
            time_taken.append(game['time_taken'])

        # Render visualization template
        return render_template(
            'graph-4.html',
            timestamps=timestamps,
            scores=scores,
            time_taken=time_taken
        )

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error fetching game data: {e}'}), 500



#############################
#  Game-5 True or tainted?  #
#       (true.html)         #
#############################


@app.route('/submit_tf_game_result', methods=['POST'])
def submit_tf_game_result():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

    data = request.get_json()
    game_score = data.get('game_score')
    time_elapsed = data.get('time_elapsed')

    if game_score is None or time_elapsed is None:
        return jsonify({'status': 'error', 'message': 'Invalid data provided'}), 400

    # Update Firebase reference to use user_id
    reference = db.reference(f'users/{user_id}/tf_game_stats')
    current_time = int(datetime.now().timestamp())

    # Save game results to the updated path
    reference.push({
        'game_score': game_score,
        'time_elapsed': time_elapsed,
        'timestamp': current_time
    })

    return jsonify({'status': 'success', 'message': 'Game result submitted successfully'})


#############################
#  Game-5 True or tainted?  #
#       (visualization)     #
#############################


@app.route('/tf_game_visualization', methods=['GET'])
def tf_game_visualization():
    user_id = request.cookies.get('user_id')  # Retrieve user ID from cookies
    if not user_id:
        return jsonify({'message': 'User not logged in'}), 401

    # Fetch game stats from Firebase
    ref = db.reference(f'users/{user_id}/tf_game_stats')
    game_data = ref.get()

    if not game_data:
        return jsonify({'message': 'No game data found'}), 404

    # Prepare data for the graph
    timestamps = []
    scores = []
    time_elapsed = []

    for game in game_data.values():
        game_score = game.get('game_score')
        time_taken = game.get('time_elapsed')
        timestamp = game.get('timestamp')

        if game_score is not None and time_taken is not None and timestamp is not None:
            date = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            timestamps.append(date)
            scores.append(game_score)
            time_elapsed.append(time_taken)

    return render_template('graph-5.html', timestamps=timestamps, scores=scores, times=time_elapsed)





#############################
#  Game-1 Doping dilemma    #
#############################


@app.route('/game3')
def game3():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the game.", type="error"))

    return render_template('quiz-game.html')


#############################
#  Game-2 Ethics enigma     #
#############################

@app.route('/game2')
def game():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the game.", type="error"))

    return render_template('word-puzzle.html')


#############################
#  Game-3 Life Bounty       #
#############################

@app.route('/life')
def life():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the game.", type="error"))
    
    return render_template("life")



#############################
#  Game-4 word whirl        #
#############################

@app.route('/word-scramble')
def word_scramble():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the game.", type="error"))
    
    return render_template("word-scramble.html")


#############################
#  Game-5 True or tainted?  #
#############################


@app.route('/game4')
def game4():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the game.", type="error"))

    return render_template('true.html')



#############################
#      Leaderbord           #
#############################


@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    # Retrieve all users from the Firebase database
    users_ref = db.reference('users')
    users_data = users_ref.get()

    leaderboard_data = []

    # Iterate through all users and get their names and performance data
    for user_id, user_data in users_data.items():
        user_name = user_data.get('name', 'Unknown')
        performance_ref = db.reference(f'users/{user_id}/performance_metrics')
        performance_data = performance_ref.get()

        total_score = 0
        games_played = 0

        # Calculate total score and games played
        if performance_data:
            for game in performance_data.values():
                total_score += game.get('score', 0)
                games_played += 1

        # Calculate average score
        average_score = total_score / games_played if games_played > 0 else 0

        leaderboard_data.append({
            'user_name': user_name,
            'total_score': total_score,
            'average_score': round(average_score, 2),
            'games_played': games_played
        })

    # Sort the leaderboard by total_score in descending order
    leaderboard_data.sort(key=lambda x: x['total_score'], reverse=True)

    return render_template('leaderboard.html', leaderboard=leaderboard_data)

#############################
#      Life After Doping    #
#############################

@app.route('/rebuild')
def rebuild():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to oppoertunities.", type="error"))
    return render_template("after-doping.html")


#############################
#        Casestudy          #
#############################

@app.route('/case')
def case():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to case study.", type="error"))
    return render_template("case-study.html")

#############################
#  Frequently Asked Qns     #
#############################

@app.route('/faq')
def faq():
    return render_template("faq.html")

#############################
#          News             #
#############################

@app.route('/news')
def news():
    user_id_from_cookie = request.cookies.get('user_id')

    if not user_id_from_cookie:
        return redirect(url_for('signin', message="You must be logged in to access the game.", type="error"))
    return render_template("news.html")


# Run the app
if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
