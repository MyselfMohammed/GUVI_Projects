import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

import hashlib

import mysql.connector
from mysql.connector import Error

# ---------- Config: use st.secrets for DB credentials ----------

def get_db_connection():
    config = st.secrets["mysql"]
    db_connection = mysql.connector.connect(
        host=config["host"],
        user=config["user"],
        password=config["password"],
        database=config["database"],
    )
    return db_connection

# ---------- Helpers ----------

# The function receives the password as a normal Python string.
# Converts the string into bytes, because SHA-256 works only on bytes.
# This applies the SHA-256 hashing algorithm and produces a 32-byte hash internally.
# Converts the raw binary hash into a 64-character hexadecimal string.
# The function returns this hex string, which is safe to store in a database.

# Example: hash_password_sha256("hello123")
# Output: b0389fa3f3a4bc903e6e9db6466b740249bca7ff280991690dd54df498c2a68f

def hash_password_sha256(plain_password:str)->str:
    return hashlib.sha256(plain_password.encode("utf-8")).hexdigest()

def create_user(username:str, plain_password:str, role:str) -> tuple[bool,str]:
    hashed_password = hash_password_sha256(plain_password)
    try:
        # Calls the function get_db_connection(), Returns a MySQL connection object.
        db_connection = get_db_connection()    
         
        # Cursor allows to execute SQL queries.
        cursor = db_connection.cursor()  # Returns rows as tuples (To access values, We can use indexes like row[0])      
        
        # Inserts a new row into the users table. Uses placeholders %s to prevent SQL injection (A Technique where attacker puts SQL code into input fields).
        cursor.execute(
            "INSERT INTO cqms.registered_users(username, hashed_password, role) VALUES (%s, %s, %s)",
            (username, hashed_password, role),) 
        
        # Commits the INSERT. Without commit(), the new user would not be saved.
        db_connection.commit()                  
        
        # Frees resources. Always good practice after DB operations.
        cursor.close()                          
        
        # Frees resources. Always good practice after DB operations.
        db_connection.close()                   
        
        # First value: True → operation succeeded. Second value: success message
        return True, "New User Registered Successfully !!" 
    
    # IntegrityError when a UNIQUE constraint is violated.
    except mysql.connector.IntegrityError as e: 
        # False → failure, "Username Already Exists" → error reason
        return False, "Username Already Exists" 
    
    # Catch all other MySQL errors (connection fail, wrong column name, etc.)
    except Error as e:
        return False, f"DB-Error : {e}"   
    
def verify_user(username:str, plain_password:str, role:str) -> tuple[bool,str]:
    hashed_password = hash_password_sha256(plain_password)
    try:
        # Calls the function get_db_connection(), Returns a MySQL connection object.
        db_connection = get_db_connection()    
         
        # Cursor allows to execute SQL queries.
        cursor = db_connection.cursor(dictionary=True)  # Returns rows as dictionaries (To access values, We can use column names like row["id"])
              
        # Inserts a new row into the users table. Uses placeholders %s to prevent SQL injection (A Technique where attacker puts SQL code into input fields).
        cursor.execute("SELECT id, username, hashed_password, role FROM cqms.registered_users WHERE username = %s",(username,)) 

        # Fetches Row Item matched with Username
        row = cursor.fetchone()
        
        # Frees resources. Always good practice after DB operations.
        cursor.close()                          
        
        # Frees resources. Always good practice after DB operations.
        db_connection.close()  
        
        if not row:
            return False, "Invalid Username and Password"
        if row["role"]!= role:
            return False, "Role Mismatching"
        if row["hashed_password"] != hashed_password:
            return False, "Invalid Username and Password"
        return True, "Logged In Successfully"
    except Error as e:
        return False, f"DB-Error : {e}"
    

def client_query_insertion(client_email:str, client_mobile:int, query_heading:str, query_description:str,) -> tuple[bool,str]:
    """
    Inserts a new row into client_queries, then backfills query_id as Q001, Q002, ...
    Returns (success_boolean, message).
    """
    try:
        # Calls the function get_db_connection(), Returns a MySQL connection object.
        db_connection = get_db_connection()    
         
        # Cursor allows to execute SQL queries.
        cursor = db_connection.cursor()  # Returns rows as tuples (To access values, We can use indexes like row[0])      
        
        # Inserts a new row into the client_queries table. Uses placeholders %s to prevent SQL injection (A Technique where attacker puts SQL code into input fields).
        cursor.execute(
            "INSERT INTO cqms.client_queries(client_email, client_mobile, query_heading, query_description, status, date_created, date_closed) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (client_email, client_mobile, query_heading, query_description, "Opened", datetime.now(), None)) 
        
        # Get the auto-generated numeric id
        new_id = cursor.lastrowid   # integer AUTO_INCREMENT value

        # Format query_id as Q### (3 digits). Adjust Zero fill / format width as needed.
        new_query_id = f"Q{new_id:02d}"

        # Update the same row to set query_id
        cursor.execute("UPDATE client_queries SET query_id = %s WHERE Id = %s",(new_query_id, new_id))
        
        # Commits the INSERT. Without commit(), the new user would not be saved.
        db_connection.commit()                  
        
        # Frees resources. Always good practice after DB operations.
        cursor.close()                          
        
        # Frees resources. Always good practice after DB operations.
        db_connection.close()                   
        
        # First value: True → operation succeeded. Second value: success message
        return True, f"Query Raised Successfully !!. Your Query Id = {new_query_id}"
   
    # Catch all other MySQL errors (connection fail, wrong column name, etc.)
    except Error as e:
        return False, f"DB-Error : {e}"   

def fetch_queries(status_filter:str, category_filter:str,):
    """
    Fetches Queries from Table - client_queries.
    Returns (success_boolean, message).
    """
    try:
        # Calls the function get_db_connection(), Returns a MySQL connection object.
        db_connection = get_db_connection()    
         
        # Cursor allows to execute SQL queries.
        cursor = db_connection.cursor(dictionary=True)  # Returns rows as dictionaries (To access values, We can use column names like row["id"])   
        
        query_syntax = """
                    SELECT Id, query_id, client_email, client_mobile, query_heading, query_description, status,date_created, date_closed
                    FROM cqms.client_queries WHERE 1=1
                """ 
        query_parameters = []
        
        if status_filter != "All":
            query_syntax += "AND status = %s"
            query_parameters.append(status_filter)
            
        if category_filter != "All":
            query_syntax += "AND  query_heading = %s"
            query_parameters.append(category_filter)
            
        # Fetch All the Queries Matched With Above Criteria
        cursor.execute(query_syntax, query_parameters) 
        query_rows = cursor.fetchall()        
        
        # Frees resources. Always good practice after DB operations.
        cursor.close()                          
        
        # Frees resources. Always good practice after DB operations.
        db_connection.close()                   
        
        # Return Fetched Queries
        return query_rows
   
    # Catch all other MySQL errors (connection fail, wrong column name, etc.)
    except Error as e:
        return [] 
    
def close_selected_query(query_id:int):
    """
    Closes the Selected Query.
    Returns (success_boolean, message).
    """
    try:
        # Calls the function get_db_connection(), Returns a MySQL connection object.
        db_connection = get_db_connection()    
         
        # Cursor allows to execute SQL queries.
        cursor = db_connection.cursor()  # Returns rows as tuples (To access values, We can use indexes like row[0])     
        
        # Closes the Matched Query
        cursor.execute("UPDATE cqms.client_queries SET status = %s, date_closed = %s WHERE Id = %s", ("Closed", datetime.now(),query_id)) 
        
         # Commits the INSERT. Without commit(), the new user would not be saved.
        db_connection.commit()   
        
        # Frees resources. Always good practice after DB operations.
        cursor.close()                          
        
        # Frees resources. Always good practice after DB operations.
        db_connection.close()                   
        
        # Return Fetched Queries
        return True, f"Query ({query_id}) Closed Successfully"
   
    # Catch all other MySQL errors (connection fail, wrong column name, etc.)
    except Error as e:
        return False, f"DB-Error : {e}"

# ---------- Session-state initialization (run only once when app starts) ----------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

# Reset values when the user clicks “Logout” (run manually on user action)   
def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

# ---------- UI - Login Page ----------

#st.set_page_config(page_title = "CQMS (Client/Support)", layout = "centered")
st.markdown("<h1 style='text-align:center;'> <b> CQMS (Client/Support) </b> </h1>", unsafe_allow_html=True)

if st.session_state.logged_in:
    
    if st.session_state.role == "Client":
        # ---------- UI - Client Page ----------
        st.markdown(f"<h3 style='text-align:center;'> <b><u> Query Insertion Page (Client Side) </u></b> </h3>", unsafe_allow_html=True)
        st.markdown(f"<h4 style='text-align:center;'> <b> User : {st.session_state.username} - Role : {st.session_state.role} </b> </h4>", unsafe_allow_html=True) 

        input_email_id = st.text_input("Email ID", key = "input_email_id")
        mobile_number = st.text_input("Mobile Number", key = "input_mobile_number")
        input_mobile_number = int(mobile_number) if mobile_number else None
        input_query_heading = st.text_input("Query Heading", key = "input_query_heading")
        input_query_description = st.text_input("Query Description", key = "input_query_description")
            
        if st.button("Submission"):
            verification_boolean, verification_message = client_query_insertion(input_email_id, input_mobile_number, input_query_heading, input_query_description)
            if verification_boolean :
                st.success(verification_message)
            else:
                st.error(verification_message)
        
        if st.button("Logout"):
            logout()
            st.rerun()
        st.stop()
    else:
        st.markdown("<h3 style='text-align:center;'> <b><u> Query Management Page (Support Side) </u></b> </h3>", unsafe_allow_html=True)
        st.markdown(f"<h4 style='text-align:center;'> <b> User : {st.session_state.username} - Role : {st.session_state.role} </b> </h4>", unsafe_allow_html=True) 
        
        # Filters Creation
        status_filter = st.selectbox("Filter By Status", ["All", "Opened", "Closed"])
        
        # Setting the Status Category as "All" By Default
        query_category_list = ["All"]
        
         # Calls the function get_db_connection(), Returns a MySQL connection object.
        db_connection = get_db_connection()    
         
        # Cursor allows to execute SQL queries.
        cursor = db_connection.cursor()  # Returns rows as tuples (To access values, We can use indexes like row[0])     
        
        # Closes the Matched Query
        cursor.execute("SELECT DISTINCT query_heading FROM cqms.client_queries") 
        
        # Output : query_category_list_unique = [("Hardware", 1), ("Software", 2)]
        query_category_list_unique = cursor.fetchall() 
        
        # Frees resources. Always good practice after DB operations.
        cursor.close()                          
        
        # Frees resources. Always good practice after DB operations.
        db_connection.close()  
        
        query_category_list.extend(query_category[0] for query_category in query_category_list_unique)
        category_filter = st.selectbox("Filter By Category", query_category_list)
        
        # Fetch filtered queries
        
        fetched_queries = fetch_queries(status_filter, category_filter)
        
        if not fetched_queries:
            st.info("No Queries Found For Selected Filters.")
        else:
            df = pd.DataFrame(fetched_queries)
            st.dataframe(df)

            # Select a query to close (Open only) -> fetched_queries is a list of dictionaries (returned from DB).
            open_queries = [query for query in fetched_queries if query["status"] == "Opened"]
                
            if open_queries:
                selected = st.selectbox("Select Query to Close", options=[f"{q['Id']} - {q['query_heading']} ({q['query_id']})" for q in open_queries])
                selected_id = int(selected.split(" - ")[0]) # Extracts Id From Query
                
            if st.button("Close This Query"):
                verification_boolean, verification_message = close_selected_query(selected_id)
                if verification_boolean:
                    st.success(verification_message)
                    st.rerun()
                else:
                    st.error(verification_message)
            else:
                st.info("No Queries To Close")
            
    if st.button("Logout"):
        logout()
        st.rerun()
    st.stop()
    
tab_login, tab_registeration = st.tabs(["Login","Register"])

with tab_login:
    st.header("Login page")
    
    login_username = st.text_input("Username", key = "login_username")
    login_password = st.text_input("Password", type = "password", key = "login_password")
    login_role = st.selectbox("Role",["Client","Support"], key = "login_role")
    
    if st.button("Login"):
        verification_boolean, verification_message = verify_user(login_username.strip(), login_password, login_role)
        if verification_boolean :
            st.session_state.logged_in = True
            st.session_state.username = login_username.strip()
            st.session_state.role = login_role
            st.success(verification_message)
            st.rerun() # A command that forces the entire app script to restart from the top immediately.
        else:
            st.error(verification_message)
            
with tab_registeration:
    st.header("Registeration Page")
    
    reg_username = st.text_input("Username", key = "reg_username")
    reg_password = st.text_input("Password", type = "password", key = "reg_password")
    reg_password_confirmation = st.text_input("Confirm Password", type = "password", key = "reg_password_confirmation")
    reg_role = st.selectbox("Role", ["Client","Support"], key = "reg_role")
    
    if st.button("Register"):
        if not reg_username.strip():
            st.error("Username Required")
        elif not reg_password:
            st.error("Password Required")
        elif not reg_password_confirmation:
            st.error("Password Is Not Matching")
        else:
            verification_boolean, verification_message = create_user(reg_username.strip(), reg_password, reg_role)
            if verification_boolean:
                st.success("Registered Successfully - Please Login Through the Login Page")
            else:
                st.error(verification_message)