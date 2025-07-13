from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from neo4j import GraphDatabase
from dotenv import load_dotenv
load_dotenv()
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import uuid
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Keep consistent with your working version

# Neo4j Configuration
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', '12345678')  # Match your working version

class Neo4jConnection:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def close(self):
        self.driver.close()
    
    def query(self, query, parameters=None):
        with self.driver.session() as session:
            result = session.run(query, parameters)
            return [record for record in result]

# Initialize Neo4j connection
db = Neo4jConnection(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

# Graph Coloring Algorithm Implementation
class GraphColoring:
    def __init__(self, graph):
        self.graph = graph
        self.colors = {}
        self.analysis = {
            'execution_time': 0,
            'coloring_order': [],
            'throughput': 0
        }
    
    def validate_coloring(self):
        """Validate if coloring is valid (no adjacent nodes with same color)"""
        for node, neighbors in self.graph.items():
            for neighbor in neighbors:
                if self.colors.get(node) == self.colors.get(neighbor):
                    return False
        return True

    def analyze_performance(self, start_time, end_time, node_count):
        """Analyze algorithm performance"""
        self.analysis['execution_time'] = (end_time - start_time) * 1000  # in ms
        self.analysis['throughput'] = node_count / (end_time - start_time) if (end_time - start_time) > 0 else 0
        return self.analysis

    def greedy_coloring(self):
        """Greedy coloring algorithm with performance analysis"""
        start_time = time.time()
        
        vertices = sorted(self.graph.keys(), 
                        key=lambda v: len(self.graph[v]), 
                        reverse=True)
        
        self.colors = {}
        self.analysis['coloring_order'] = []
        
        for vertex in vertices:
            adjacent_colors = set()
            for neighbor in self.graph.get(vertex, []):
                if neighbor in self.colors:
                    adjacent_colors.add(self.colors[neighbor])
            
            color = 0
            while color in adjacent_colors:
                color += 1
                
            self.colors[vertex] = color
            self.analysis['coloring_order'].append((vertex, color))
        
        end_time = time.time()
        self.analyze_performance(start_time, end_time, len(vertices))
        
        return self.colors

    def welsh_powell_coloring(self):
        """Welsh-Powell graph coloring algorithm with performance analysis"""
        start_time = time.time()
        
        nodes = sorted(self.graph.keys(), 
                     key=lambda x: len(self.graph[x]), 
                     reverse=True)
        
        self.colors = {}
        self.analysis['coloring_order'] = []
        color = 0
        
        while nodes:
            current = nodes[0]
            self.colors[current] = color
            self.analysis['coloring_order'].append((current, color))
            nodes.remove(current)
            
            non_adjacent = [node for node in nodes 
                          if current not in self.graph[node]]
            
            for node in non_adjacent:
                conflict = any(self.colors.get(neigh) == color 
                          for neigh in self.graph[node])
                if not conflict:
                    self.colors[node] = color
                    self.analysis['coloring_order'].append((node, color))
                    nodes.remove(node)
            
            color += 1
        
        end_time = time.time()
        self.analyze_performance(start_time, end_time, len(self.graph))
        
        return self.colors

# Time slots mapping
TIME_SLOTS = {
    0: "Senin 08:00-10:00",
    1: "Senin 10:00-12:00", 
    2: "Senin 13:00-15:00",
    3: "Selasa 08:00-10:00",
    4: "Selasa 10:00-12:00",
    5: "Selasa 13:00-15:00",
    6: "Rabu 08:00-10:00",
    7: "Rabu 10:00-12:00",
    8: "Rabu 13:00-15:00",
    9: "Kamis 08:00-10:00",
    10: "Kamis 10:00-12:00",
    11: "Kamis 13:00-15:00",
    12: "Jumat 08:00-10:00",
    13: "Jumat 10:00-12:00",
    14: "Jumat 13:00-15:00"
}

def init_database():
    """Initialize database with constraints and sample data"""
    db.query("CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.user_id IS UNIQUE")
    db.query("CREATE CONSTRAINT course_id IF NOT EXISTS FOR (c:Course) REQUIRE c.course_id IS UNIQUE")
    
    admin_exists = db.query("MATCH (u:User {role: 'admin'}) RETURN u LIMIT 1")
    if not admin_exists:
        admin_id = str(uuid.uuid4())
        db.query("""
            CREATE (u:User {
                user_id: $user_id,
                username: 'admin',
                email: 'admin@university.ac.id',
                password: $password,
                role: 'admin',
                created_at: datetime()
            })
        """, {
            'user_id': admin_id,
            'password': 'admin123'  # Plaintext password
        })

# Authentication decorators
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        result = db.query("""
            MATCH (u:User {username: $username})
            RETURN u.user_id as user_id, 
                   u.password as password,  
                   u.role as role, 
                   u.username as username
        """, {'username': username})
        
        if result and result[0]['password'] == password:
            session['user_id'] = result[0]['user_id']
            session['username'] = result[0]['username']
            session['role'] = result[0]['role']
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    user_id = session.get('user_id')
    
    if role == 'admin':
        stats = {
            'total_users': db.query("MATCH (u:User) RETURN count(u) as count")[0]['count'],
            'total_courses': db.query("MATCH (c:Course) RETURN count(c) as count")[0]['count'],
            'total_enrollments': db.query("MATCH (:Student)-[:ENROLLED_IN]->(:Course) RETURN count(*) as count")[0]['count']
        }
        return render_template('admin_dashboard.html', stats=stats)
    
    elif role == 'dosen':
        courses = db.query("""
            MATCH (d:Lecturer {user_id: $user_id})-[:TEACHES]->(c:Course)
            RETURN c.course_id as course_id, c.name as name, 
                   c.credits as credits, c.schedule_slot as schedule_slot
        """, {'user_id': user_id})
        
        for course in courses:
            course['schedule_time'] = TIME_SLOTS.get(course['schedule_slot'], 'Not scheduled')
        
        return render_template('lecturer_dashboard.html', courses=courses)
    
    elif role == 'mahasiswa':
        courses = db.query("""
            MATCH (s:Student {user_id: $user_id})-[:ENROLLED_IN]->(c:Course)
            RETURN c.course_id as course_id, c.name as name, 
                   c.credits as credits, c.schedule_slot as schedule_slot
        """, {'user_id': user_id})
        
        for course in courses:
            course['schedule_time'] = TIME_SLOTS.get(course['schedule_slot'], 'Not scheduled')
        
        return render_template('student_dashboard.html', courses=courses)

# User Management Routes
@app.route('/users')
@login_required
@admin_required
def manage_users():
    users = db.query("""
        MATCH (u:User)
        OPTIONAL MATCH (u)-[:IS_STUDENT]->(s:Student)
        OPTIONAL MATCH (u)-[:IS_LECTURER]->(l:Lecturer)
        RETURN u.user_id AS user_id,
               COALESCE(s.nama, l.nama, u.username) AS display_name,
               u.email AS email,
               u.role AS role
        ORDER BY display_name
    """)
    return render_template('manage_users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        existing = db.query("MATCH (u:User {username: $username}) RETURN u", {'username': username})
        if existing:
            flash('Username already exists!', 'error')
            return render_template('add_user.html')
        
        user_id = str(uuid.uuid4())
        db.query("""
            CREATE (u:User {
                user_id: $user_id,
                username: $username,
                email: $email,
                password: $password,
                role: $role,
                created_at: datetime()
            })
        """, {
            'user_id': user_id,
            'username': username,
            'email': email,
            'password': password,  # Plaintext password
            'role': role
        })
        
        if role == 'mahasiswa':
            db.query("""
                MATCH (u:User {user_id: $user_id})
                CREATE (s:Student {user_id: $user_id})
                CREATE (u)-[:IS_STUDENT]->(s)
            """, {'user_id': user_id})
        elif role == 'dosen':
            db.query("""
                MATCH (u:User {user_id: $user_id})
                CREATE (l:Lecturer {user_id: $user_id})
                CREATE (u)-[:IS_LECTURER]->(l)
            """, {'user_id': user_id})
        
        flash('User created successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('add_user.html')

@app.route('/users/delete/<user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = db.query("MATCH (u:User {user_id: $user_id}) RETURN u.role as role", {'user_id': user_id})
    if user and user[0]['role'] == 'admin':
        flash('Cannot delete admin user!', 'error')
        return redirect(url_for('manage_users'))
    
    db.query("MATCH (u:User {user_id: $user_id}) DETACH DELETE u", {'user_id': user_id})
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

# Course Management Routes
@app.route('/courses')
@login_required
def manage_courses():
    if session.get('role') != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    courses_data = db.query("""
        MATCH (c:Course)
        OPTIONAL MATCH (l:Lecturer)-[:TEACHES]->(c)
        OPTIONAL MATCH (u:User)-[:IS_LECTURER]->(l)
        RETURN c.course_id as course_id, 
               c.name as name, 
               c.credits as credits, 
               c.schedule_slot as schedule_slot,
               COALESCE(l.nama, u.username, 'Not assigned') as lecturer_name
        ORDER BY c.name
    """)

    courses = []
    for record in courses_data:
        course = dict(record)
        course['schedule_time'] = TIME_SLOTS.get(course['schedule_slot'], 'Not scheduled')
        courses.append(course)
    
    return render_template('manage_courses.html', courses=courses)

@app.route('/courses/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_course():
    if request.method == 'POST':
        course_id = request.form['course_id']
        name = request.form['name']
        credits = int(request.form['credits'])
        lecturer_id = request.form.get('lecturer_id')
        
        existing = db.query("MATCH (c:Course {course_id: $course_id}) RETURN c", {'course_id': course_id})
        if existing:
            flash('Course ID already exists!', 'error')
            return redirect(url_for('add_course'))
        
        db.query("""
            CREATE (c:Course {
                course_id: $course_id,
                name: $name,
                credits: $credits,
                created_at: datetime()
            })
        """, {
            'course_id': course_id,
            'name': name,
            'credits': credits
        })
        
        if lecturer_id:
            db.query("""
                MATCH (c:Course {course_id: $course_id})
                MATCH (l:Lecturer {user_id: $lecturer_id})
                CREATE (l)-[:TEACHES]->(c)
            """, {
                'course_id': course_id,
                'lecturer_id': lecturer_id
            })
        
        flash('Course created successfully!', 'success')
        return redirect(url_for('manage_courses'))
    
    lecturers = db.query("""
        MATCH (u:User)-[:IS_LECTURER]->(l:Lecturer)
        RETURN l.user_id as user_id, u.username as username
        ORDER BY u.username
    """)
    
    return render_template('add_course.html', lecturers=lecturers)

@app.route('/courses/delete/<course_id>')
@login_required
@admin_required
def delete_course(course_id):
    db.query("MATCH (c:Course {course_id: $course_id}) DETACH DELETE c", {'course_id': course_id})
    flash('Course deleted successfully!', 'success')
    return redirect(url_for('manage_courses'))

# Enrollment Management
@app.route('/enrollments')
@login_required
def manage_enrollments():
    if session.get('role') == 'mahasiswa':
        user_id = session.get('user_id')

        enrollments = db.query("""
            MATCH (s:Student {user_id: $user_id})-[:ENROLLED_IN]->(c:Course)
            RETURN s.nama AS student_name,
                   c.course_id AS course_id, 
                   c.name AS course_name, 
                   c.credits AS credits
        """, {'user_id': user_id})
        
        available_courses = db.query("""
            MATCH (c:Course)
            WHERE NOT EXISTS {
                MATCH (s:Student {user_id: $user_id})-[:ENROLLED_IN]->(c)
            }
            RETURN c.course_id AS course_id, c.name AS name, c.credits AS credits
        """, {'user_id': user_id})
        
        return render_template('student_enrollments.html', 
                             enrollments=enrollments, 
                             available_courses=available_courses)
    
    elif session.get('role') == 'admin':
        enrollments = db.query("""
            MATCH (u:User)-[:IS_STUDENT]->(s:Student)-[:ENROLLED_IN]->(c:Course)
            RETURN s.nama AS student_name, 
                   c.course_id AS course_id, 
                   c.name AS course_name, 
                   s.user_id AS student_id
            ORDER BY s.nama, c.course_id
        """)
        return render_template('manage_enrollments.html', enrollments=enrollments)
    
    else:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/enrollments/add', methods=['POST'])
@login_required
def add_enrollment():
    if session.get('role') == 'mahasiswa':
        user_id = session.get('user_id')
        course_id = request.form['course_id']
        
        existing = db.query("""
            MATCH (s:Student {user_id: $user_id})-[:ENROLLED_IN]->(c:Course {course_id: $course_id})
            RETURN s
        """, {'user_id': user_id, 'course_id': course_id})
        
        if existing:
            flash('Sudah terdaftar dalam mata kuliah ini!', 'error')
        else:
            db.query("""
                MATCH (s:Student {user_id: $user_id})
                MATCH (c:Course {course_id: $course_id})
                CREATE (s)-[:ENROLLED_IN {enrolled_at: datetime()}]->(c)
            """, {'user_id': user_id, 'course_id': course_id})
            flash('Berhasil mendaftar mata kuliah!', 'success')
    
    return redirect(url_for('manage_enrollments'))

@app.route('/enrollments/remove', methods=['POST'])
@login_required
def remove_enrollment():
    if session.get('role') == 'mahasiswa':
        user_id = session.get('user_id')
        course_id = request.form['course_id']
        
        db.query("""
            MATCH (s:Student {user_id: $user_id})-[r:ENROLLED_IN]->(c:Course {course_id: $course_id})
            DELETE r
        """, {'user_id': user_id, 'course_id': course_id})
        flash('Mata kuliah berhasil dibatalkan!', 'success')
    
    return redirect(url_for('manage_enrollments'))

# Schedule Generation
@app.route('/schedule')
@login_required
@admin_required
def view_schedule():
    courses_data = db.query("""
        MATCH (c:Course)
        RETURN c.course_id as course_id, c.name as name, c.schedule_slot as schedule_slot
        ORDER BY c.schedule_slot
    """)
    
    courses = [dict(record) for record in courses_data]
    
    schedule = {}
    for course in courses:
        slot = course['schedule_slot']
        if slot is not None:
            time_slot = TIME_SLOTS.get(slot, f"Slot {slot}")
            if time_slot not in schedule:
                schedule[time_slot] = []
            schedule[time_slot].append({
                'course_id': course['course_id'],
                'name': course['name']
            })
    
    conflicts = db.query("""
        MATCH (c1:Course)<-[:ENROLLED_IN]-(s:Student)-[:ENROLLED_IN]->(c2:Course)
        WHERE c1.schedule_slot = c2.schedule_slot AND c1 <> c2
        RETURN c1.course_id as course1_id, c1.name as course1_name,
               c2.course_id as course2_id, c2.name as course2_name,
               c1.schedule_slot as slot,
               count(s) as student_count
        ORDER BY student_count DESC
    """)
    
    conflict_list = [dict(record) for record in conflicts]
    
    return render_template(
        'schedule.html', 
        schedule=schedule, 
        time_slots=TIME_SLOTS,
        conflicts=conflict_list
    )

@app.route('/schedule/generate', methods=['POST'])
@login_required
@admin_required
def generate_schedule():
    courses = db.query("MATCH (c:Course) RETURN c.course_id as course_id")
    course_ids = [c['course_id'] for c in courses]

    conflict_graph = {course_id: [] for course_id in course_ids}

    for i, course1 in enumerate(course_ids):
        for course2 in course_ids[i+1:]:
            common = db.query("""
                MATCH (s:Student)-[:ENROLLED_IN]->(c1:Course {course_id: $course1})
                MATCH (s)-[:ENROLLED_IN]->(c2:Course {course_id: $course2})
                RETURN count(s) as count
            """, {'course1': course1, 'course2': course2})
            if common and common[0]['count'] > 0:
                conflict_graph[course1].append(course2)
                conflict_graph[course2].append(course1)

    algorithm = request.form.get('algorithm', 'greedy')
    gc = GraphColoring(conflict_graph)
    
    if algorithm == 'welsh_powell':
        coloring = gc.welsh_powell_coloring()
    else:
        coloring = gc.greedy_coloring()

    for course_id, slot in coloring.items():
        db.query("""
            MATCH (c:Course {course_id: $course_id})
            SET c.schedule_slot = $slot
        """, {'course_id': course_id, 'slot': slot})

    verify_conflicts = db.query("""
        MATCH (c1:Course)<-[:ENROLLED_IN]-(s:Student)-[:ENROLLED_IN]->(c2:Course)
        WHERE c1.schedule_slot = c2.schedule_slot AND c1.course_id <> c2.course_id
        RETURN count(s) as conflict_count
    """)[0]['conflict_count']

    if verify_conflicts > 0:
        flash(f'Schedule generated using {algorithm.upper()}, but {verify_conflicts} conflicts remain.', 'warning')
    else:
        flash(f'Schedule generated successfully using {algorithm.upper()} with no conflicts! '
              f'Total slots used: {len(set(coloring.values()))}', 'success')

    return redirect(url_for('view_schedule'))

@app.route('/schedule/clear', methods=['POST'])
@login_required
@admin_required
def clear_schedule():
    db.query("MATCH (c:Course) SET c.schedule_slot = null")
    flash('Schedule cleared successfully!', 'success')
    return redirect(url_for('view_schedule'))

# API Routes
@app.route('/api/schedule/conflicts')
@login_required
def api_schedule_conflicts():
    results = db.query("""
        MATCH (s:Student)-[:ENROLLED_IN]->(c1:Course),
              (s)-[:ENROLLED_IN]->(c2:Course)
        WHERE c1 <> c2 AND id(c1) < id(c2)
        AND c1.schedule_slot = c2.schedule_slot
        RETURN c1.course_id AS course1_id, c1.name AS course1_name,
               c2.course_id AS course2_id, c2.name AS course2_name,
               c1.schedule_slot AS slot, count(s) AS student_count
        ORDER BY student_count DESC
    """)
    return jsonify(results)

@app.route('/api/schedule/conflicts/before')
@login_required
@admin_required
def preview_conflicts():
    conflicts = db.query("""
        MATCH (c1:Course)<-[:ENROLLED_IN]-(s:Student)-[:ENROLLED_IN]->(c2:Course)
        WHERE c1.course_id < c2.course_id
        RETURN c1.course_id AS course1_id, c1.name AS course1_name,
               c2.course_id AS course2_id, c2.name AS course2_name,
               count(s) AS student_count
        ORDER BY student_count DESC
    """)
    return jsonify(conflicts)

# Graph Visualization
@app.route("/graph")
def show_graph():
    with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)) as driver:
        with driver.session() as session:
            result = session.run("MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 50")

            nodes = {}
            edges = []

            for record in result:
                n = record["n"]
                m = record["m"]
                r = record["r"]

                for node in [n, m]:
                    node_id = node.id
                    if node_id not in nodes:
                        nodes[node_id] = {
                            "id": node_id,
                            "label": node.get("name") or node.get("course_id") or str(node.id),
                            "group": list(node.labels)[0] if node.labels else "Unknown"
                        }

                edges.append({
                    "from": n.id,
                    "to": m.id,
                    "label": r.type,
                    "arrows": "to",
                    "color": "#ff0000" if r.type == "CONFLICTS_WITH" else "#888"
                })

            graph_data = {
                "nodes": list(nodes.values()),
                "edges": edges
            }

            return render_template("graph_visualization.html", graph_data=graph_data)

if __name__ == '__main__':
    init_database()
    app.run(debug=True, port=5050)