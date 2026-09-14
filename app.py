from flask import Flask, render_template, request, redirect, session, url_for
from db import get_db_connection
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import os

app = Flask(__name__)

# =========================================================
# FLASK SECRET KEY
# =========================================================

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "account_id" not in session:
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


# =========================================================
# ROLE REQUIRED
# =========================================================

def role_required(*allowed_roles):

    def decorator(view):

        @wraps(view)
        def wrapped_view(*args, **kwargs):

            if "account_id" not in session:
                return redirect(url_for("login"))

            if session.get("role") not in allowed_roles:
                return "Access denied", 403

            return view(*args, **kwargs)

        return wrapped_view

    return decorator


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT account_id, username, password_hash, role,
                   doctor_id, patient_id, status
            FROM users
            WHERE username = %s
            """,
            (username,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            # Pending account
            if user["status"] == "pending":

                return render_template(
                    "login.html",
                    error="Your account is waiting for Admin approval."
                )

            # Rejected account
            if user["status"] == "rejected":

                return render_template(
                    "login.html",
                    error="Your account has been rejected by Admin."
                )

            # Approved account
            session.clear()

            session["account_id"] = user["account_id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["doctor_id"] = user["doctor_id"]
            session["patient_id"] = user["patient_id"]

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


# =========================================================
# PATIENT REGISTRATION
# =========================================================

@app.route("/register/patient", methods=["GET", "POST"])
def register_patient():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        age = request.form.get("age", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        blood_group = request.form.get("blood_group", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not all([
            name,
            age,
            gender,
            phone,
            address,
            blood_group,
            username,
            password
        ]):

            return render_template(
                "register_patient.html",
                error="Please fill in all fields."
            )

        connection = get_db_connection()
        cursor = connection.cursor()

        try:

            # Check username
            cursor.execute(
                """
                SELECT account_id
                FROM users
                WHERE username = %s
                """,
                (username,)
            )

            if cursor.fetchone():

                return render_template(
                    "register_patient.html",
                    error="Username already exists."
                )

            # Add patient
            cursor.execute(
                """
                INSERT INTO patients
                (name, age, gender, phone, address, blood_group)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    name,
                    age,
                    gender,
                    phone,
                    address,
                    blood_group
                )
            )

            patient_id = cursor.lastrowid

            # Find last PAT account
            cursor.execute(
                """
                SELECT account_id
                FROM users
                WHERE account_id LIKE 'PAT%'
                ORDER BY account_id DESC
                LIMIT 1
                """
            )

            last_account = cursor.fetchone()

            if last_account:

                last_number = int(
                    last_account[0][3:]
                )

                account_id = f"PAT{last_number + 1:03d}"

            else:

                account_id = "PAT001"

            # Hash password
            password_hash = generate_password_hash(password)

            # Create pending account
            cursor.execute(
                """
                INSERT INTO users
                (
                    account_id,
                    username,
                    password_hash,
                    role,
                    patient_id,
                    status
                )
                VALUES (%s, %s, %s, 'patient', %s, 'pending')
                """,
                (
                    account_id,
                    username,
                    password_hash,
                    patient_id
                )
            )

            connection.commit()

            return render_template(
                "login.html",
                success=(
                    "Registration submitted successfully. "
                    "Your account is waiting for Admin approval."
                )
            )

        except Exception as e:

            connection.rollback()

            print("Patient registration error:", e)

            return render_template(
                "register_patient.html",
                error="Registration failed. Please try again."
            )

        finally:

            cursor.close()
            connection.close()

    return render_template("register_patient.html")


# =========================================================
# DOCTOR REGISTRATION
# =========================================================

@app.route("/register/doctor", methods=["GET", "POST"])
def register_doctor():

    if request.method == "POST":

        name = request.form.get("name", "").strip()

        specialization = request.form.get(
            "specialization",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        department_id = request.form.get(
            "department_id",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not all([
            name,
            specialization,
            phone,
            email,
            department_id,
            username,
            password
        ]):

            return render_template(
                "register_doctor.html",
                error="Please fill in all fields."
            )

        connection = get_db_connection()
        cursor = connection.cursor()

        try:

            # Check username
            cursor.execute(
                """
                SELECT account_id
                FROM users
                WHERE username = %s
                """,
                (username,)
            )

            if cursor.fetchone():

                return render_template(
                    "register_doctor.html",
                    error="Username already exists."
                )

            # Check department
            cursor.execute(
                """
                SELECT id
                FROM departments
                WHERE id = %s
                """,
                (department_id,)
            )

            if not cursor.fetchone():

                return render_template(
                    "register_doctor.html",
                    error="Invalid department ID."
                )

            # Add doctor
            cursor.execute(
                """
                INSERT INTO doctors
                (
                    name,
                    specialization,
                    phone,
                    email,
                    department_id
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    name,
                    specialization,
                    phone,
                    email,
                    department_id
                )
            )

            doctor_id = cursor.lastrowid

            # Find last DOC account
            cursor.execute(
                """
                SELECT account_id
                FROM users
                WHERE account_id LIKE 'DOC%'
                ORDER BY account_id DESC
                LIMIT 1
                """
            )

            last_account = cursor.fetchone()

            if last_account:

                last_number = int(
                    last_account[0][3:]
                )

                account_id = f"DOC{last_number + 1:03d}"

            else:

                account_id = "DOC001"

            # Hash password
            password_hash = generate_password_hash(password)

            # Create pending doctor account
            cursor.execute(
                """
                INSERT INTO users
                (
                    account_id,
                    username,
                    password_hash,
                    role,
                    doctor_id,
                    status
                )
                VALUES (%s, %s, %s, 'doctor', %s, 'pending')
                """,
                (
                    account_id,
                    username,
                    password_hash,
                    doctor_id
                )
            )

            connection.commit()

            return render_template(
                "login.html",
                success=(
                    "Doctor registration submitted successfully. "
                    "Your account is waiting for Admin approval."
                )
            )

        except Exception as e:

            connection.rollback()

            print("Doctor registration error:", e)

            return render_template(
                "register_doctor.html",
                error="Registration failed. Please try again."
            )

        finally:

            cursor.close()
            connection.close()

    return render_template("register_doctor.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
@login_required
def home():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM patients"
    )

    total_patients = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM doctors"
    )

    total_doctors = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM appointments"
    )

    total_appointments = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM beds WHERE status = 'Available'"
    )

    available_beds = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return render_template(
        "index.html",
        total_patients=total_patients,
        total_doctors=total_doctors,
        total_appointments=total_appointments,
        available_beds=available_beds
    )


# =========================================================
# PATIENTS PAGE
# =========================================================

@app.route("/patients")
@role_required("admin", "doctor", "patient")
def patients():

    connection = get_db_connection()
    cursor = connection.cursor()

    if session.get("role") == "patient":

        cursor.execute(
            """
            SELECT *
            FROM patients
            WHERE id = %s
            """,
            (session.get("patient_id"),)
        )

    else:

        cursor.execute(
            """
            SELECT *
            FROM patients
            ORDER BY id DESC
            """
        )

    patients = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "patients.html",
        patients=patients
    )


# =========================================================
# ADD PATIENT - ADMIN ONLY
# =========================================================

@app.route("/add_patient", methods=["POST"])
@role_required("admin")
def add_patient():

    name = request.form["name"]
    age = request.form["age"]
    gender = request.form["gender"]
    phone = request.form["phone"]
    blood_group = request.form["blood_group"]
    address = request.form["address"]

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO patients
        (
            name,
            age,
            gender,
            phone,
            address,
            blood_group
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            name,
            age,
            gender,
            phone,
            address,
            blood_group
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect("/patients")
    # =========================================================
# DELETE PATIENT - ADMIN ONLY
# =========================================================

@app.route("/delete_patient/<int:patient_id>", methods=["POST"])
@role_required("admin")
def delete_patient(patient_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Delete patient's appointments
        cursor.execute(
            """
            DELETE FROM appointments
            WHERE patient_id = %s
            """,
            (patient_id,)
        )

        # Delete patient's bills
        cursor.execute(
            """
            DELETE FROM bills
            WHERE patient_id = %s
            """,
            (patient_id,)
        )

        # Delete patient's user account
        cursor.execute(
            """
            DELETE FROM users
            WHERE patient_id = %s
            """,
            (patient_id,)
        )

        # Delete patient
        cursor.execute(
            """
            DELETE FROM patients
            WHERE id = %s
            """,
            (patient_id,)
        )

        connection.commit()

    except Exception as e:

        connection.rollback()

        print("Delete patient error:", e)

        return "Failed to delete patient", 500

    finally:

        cursor.close()
        connection.close()

    return redirect(url_for("patients"))


# =========================================================
# DOCTORS PAGE
# =========================================================
@app.route("/doctors")
@role_required("admin", "doctor")
def doctors():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            doc.id,
            doc.name,
            doc.specialization,
            doc.phone,
            doc.email,
            doc.department_id,
            d.name AS department_name
        FROM doctors doc
        LEFT JOIN departments d
            ON doc.department_id = d.id
        ORDER BY doc.id DESC
        """
    )

    doctors = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "doctors.html",
        doctors=doctors
    )


# =========================================================
# ADD DOCTOR - ADMIN ONLY
# =========================================================

@app.route("/add_doctor", methods=["POST"])
@role_required("admin")
def add_doctor():

    name = request.form["name"]
    specialization = request.form["specialization"]
    phone = request.form.get("phone")
    email = request.form.get("email")
    department_id = request.form["department_id"]

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO doctors
        (
            name,
            specialization,
            phone,
            email,
            department_id
        )
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            name,
            specialization,
            phone,
            email,
            department_id
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect("/doctors")


# =========================================================
# APPOINTMENTS PAGE
# =========================================================

@app.route("/appointments")
@role_required("admin", "doctor", "patient")
def appointments():

    connection = get_db_connection()
    cursor = connection.cursor()

    # Departments available for patient booking
    cursor.execute(
        """
        SELECT DISTINCT d.id, d.name
        FROM departments d
        INNER JOIN doctors doc
            ON doc.department_id = d.id
        ORDER BY d.name
        """
    )

    available_departments = cursor.fetchall()

    # Patient sees only their own appointments
    if session.get("role") == "patient":

        cursor.execute(
            """
            SELECT
                a.id,
                d.name AS doctor_name,
                dep.name AS department_name,
                a.appointment_date,
                a.appointment_time,
                a.status
            FROM appointments a
            INNER JOIN doctors d
                ON a.doctor_id = d.id
            LEFT JOIN departments dep
                ON d.department_id = dep.id
            WHERE a.patient_id = %s
            ORDER BY a.appointment_date DESC,
                     a.appointment_time DESC
            """,
            (session.get("patient_id"),)
        )

    # Doctor sees only their appointments
    elif session.get("role") == "doctor":

        cursor.execute(
            """
            SELECT
                a.id,
                p.name AS patient_name,
                d.name AS doctor_name,
                dep.name AS department_name,
                a.appointment_date,
                a.appointment_time,
                a.status
            FROM appointments a
            INNER JOIN patients p
                ON a.patient_id = p.id
            INNER JOIN doctors d
                ON a.doctor_id = d.id
            LEFT JOIN departments dep
                ON d.department_id = dep.id
            WHERE a.doctor_id = %s
            ORDER BY a.appointment_date DESC,
                     a.appointment_time DESC
            """,
            (session.get("doctor_id"),)
        )

    # Admin sees all appointments
    else:

        cursor.execute(
            """
            SELECT
                a.id,
                p.name AS patient_name,
                d.name AS doctor_name,
                dep.name AS department_name,
                a.appointment_date,
                a.appointment_time,
                a.status
            FROM appointments a
            INNER JOIN patients p
                ON a.patient_id = p.id
            INNER JOIN doctors d
                ON a.doctor_id = d.id
            LEFT JOIN departments dep
                ON d.department_id = dep.id
            ORDER BY a.appointment_date DESC,
                     a.appointment_time DESC
            """
        )

    appointments = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "appointments.html",
        appointments=appointments,
        available_departments=available_departments
    )


# =========================================================
# SHOW DOCTORS BY DEPARTMENT
# =========================================================

@app.route("/department_doctors/<int:department_id>")
@role_required("admin", "patient")
def department_doctors(department_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT doc.id, doc.name, doc.specialization
        FROM doctors doc
        WHERE doc.department_id = %s
        ORDER BY doc.name
        """,
        (department_id,)
    )

    doctors = cursor.fetchall()

    cursor.execute(
        """
        SELECT id, name
        FROM departments
        WHERE id = %s
        """,
        (department_id,)
    )

    department = cursor.fetchone()

    cursor.close()
    connection.close()

    return render_template(
        "department_doctors.html",
        doctors=doctors,
        department=department
    )


# =========================================================
# BOOK APPOINTMENT
# =========================================================

@app.route(
    "/book_appointment/<int:doctor_id>",
    methods=["GET", "POST"]
)
@role_required("patient")
def book_appointment(doctor_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    # Get doctor information
    cursor.execute(
        """
        SELECT id, name, specialization
        FROM doctors
        WHERE id = %s
        """,
        (doctor_id,)
    )

    doctor = cursor.fetchone()

    if not doctor:

        cursor.close()
        connection.close()

        return "Doctor not found", 404

    # Book appointment
    if request.method == "POST":

        appointment_date = request.form["appointment_date"]
        appointment_time = request.form["appointment_time"]

        patient_id = session.get("patient_id")

        cursor.execute(
            """
            INSERT INTO appointments
            (
                patient_id,
                doctor_id,
                appointment_date,
                appointment_time,
                status
            )
            VALUES (%s, %s, %s, %s, 'Scheduled')
            """,
            (
                patient_id,
                doctor_id,
                appointment_date,
                appointment_time
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("appointments"))

    cursor.close()
    connection.close()

    return render_template(
        "book_appointment.html",
        doctor=doctor
    )


# =========================================================
# CANCEL APPOINTMENT - PATIENT ONLY
# =========================================================

@app.route(
    "/cancel_appointment/<int:appointment_id>",
    methods=["POST"]
)
@role_required("patient")
def cancel_appointment(appointment_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    # Patient can cancel only their own scheduled appointment
    cursor.execute(
        """
        UPDATE appointments
        SET status = 'Cancelled'
        WHERE id = %s
        AND patient_id = %s
        AND status = 'Scheduled'
        """,
        (
            appointment_id,
            session.get("patient_id")
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("appointments"))


# =========================================================
# DOCTOR - UPDATE APPOINTMENT STATUS
# =========================================================

@app.route(
    "/update_appointment_status/<int:appointment_id>",
    methods=["POST"]
)
@role_required("doctor")
def update_appointment_status(appointment_id):

    new_status = request.form.get("status")

    # Allow only valid statuses
    if new_status not in [
        "Scheduled",
        "Completed",
        "Cancelled"
    ]:

        return "Invalid status", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    # Doctor can update only their own appointments
    cursor.execute(
        """
        UPDATE appointments
        SET status = %s
        WHERE id = %s
        AND doctor_id = %s
        """,
        (
            new_status,
            appointment_id,
            session.get("doctor_id")
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("appointments"))


# =========================================================
# DEPARTMENTS PAGE
# =========================================================

@app.route("/departments")
@login_required
def departments():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM departments
        ORDER BY id DESC
        """
    )

    departments = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "departments.html",
        departments=departments
    )


# =========================================================
# ADD DEPARTMENT - ADMIN ONLY
# =========================================================

@app.route("/add_department", methods=["POST"])
@role_required("admin")
def add_department():

    name = request.form["name"]

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO departments (name)
        VALUES (%s)
        """,
        (name,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect("/departments")


# =========================================================
# PHARMACY PAGE
# =========================================================

@app.route("/pharmacy")
@login_required
def pharmacy():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM medicines
        ORDER BY id DESC
        """
    )

    medicines = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "pharmacy.html",
        medicines=medicines
    )


# =========================================================
# ADD MEDICINE - ADMIN ONLY
# =========================================================

@app.route("/add_medicine", methods=["POST"])
@role_required("admin")
def add_medicine():

    name = request.form["name"]
    category = request.form.get("category")
    quantity = request.form["quantity"]
    price = request.form["price"]
    expiry_date = request.form["expiry_date"]

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO medicines
        (
            name,
            category,
            quantity,
            price,
            expiry_date
        )
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            name,
            category,
            quantity,
            price,
            expiry_date
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect("/pharmacy")


# =========================================================
# BILLING PAGE
# =========================================================

@app.route("/billing")
@role_required("admin", "patient")
def billing():

    connection = get_db_connection()
    cursor = connection.cursor()

    if session.get("role") == "patient":

        cursor.execute(
            """
            SELECT *
            FROM bills
            WHERE patient_id = %s
            ORDER BY id DESC
            """,
            (session.get("patient_id"),)
        )

    else:

        cursor.execute(
            """
            SELECT *
            FROM bills
            ORDER BY id DESC
            """
        )

    bills = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "billing.html",
        bills=bills
    )


# =========================================================
# ADD BILL - ADMIN ONLY
# =========================================================

@app.route("/add_bill", methods=["POST"])
@role_required("admin")
def add_bill():

    patient_id = request.form["patient_id"]
    amount = request.form["amount"]
    payment_status = request.form["payment_status"]
    bill_date = request.form["bill_date"]

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO bills
        (
            patient_id,
            amount,
            payment_status,
            bill_date
        )
        VALUES (%s, %s, %s, %s)
        """,
        (
            patient_id,
            amount,
            payment_status,
            bill_date
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect("/billing")


# =========================================================
# ADMIN - PENDING REGISTRATIONS
# =========================================================

@app.route("/admin/registrations")
@role_required("admin")
def admin_registrations():

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            u.account_id,
            u.username,
            u.role,
            u.status,
            u.created_at,
            p.name AS patient_name,
            d.name AS doctor_name,
            d.specialization
        FROM users u

        LEFT JOIN patients p
            ON u.patient_id = p.id

        LEFT JOIN doctors d
            ON u.doctor_id = d.id

        WHERE u.status = 'pending'

        ORDER BY u.created_at DESC
        """
    )

    registrations = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_registrations.html",
        registrations=registrations
    )


# =========================================================
# ADMIN - APPROVE REGISTRATION
# =========================================================

@app.route(
    "/admin/approve/<account_id>",
    methods=["POST"]
)
@role_required("admin")
def approve_registration(account_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET status = 'approved'
        WHERE account_id = %s
        AND status = 'pending'
        """,
        (account_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_registrations")
    )


# =========================================================
# ADMIN - REJECT REGISTRATION
# =========================================================

@app.route(
    "/admin/reject/<account_id>",
    methods=["POST"]
)
@role_required("admin")
def reject_registration(account_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET status = 'rejected'
        WHERE account_id = %s
        AND status = 'pending'
        """,
        (account_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_registrations")
    )


# =========================================================
# HOSPITAL REPORTS
# =========================================================

@app.route("/reports")
@login_required
def reports():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM patients"
    )

    total_patients = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM doctors"
    )

    total_doctors = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM appointments"
    )

    total_appointments = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM medicines"
    )

    total_medicines = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM bills"
    )

    total_bills = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return render_template(
        "reports.html",
        total_patients=total_patients,
        total_doctors=total_doctors,
        total_appointments=total_appointments,
        total_medicines=total_medicines,
        total_bills=total_bills
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )