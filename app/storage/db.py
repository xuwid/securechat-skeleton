"""MySQL users table + salted hashing (no chat storage)."""
import pymysql
import hashlib
import secrets
import os
from typing import Optional, Tuple
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Database:
    """Database handler for user authentication."""
    
    def __init__(self):
        """Initialize database connection."""
        self.host = os.getenv('DB_HOST', 'localhost')
        self.port = int(os.getenv('DB_PORT', 3306))
        self.user = os.getenv('DB_USER', 'scuser')
        self.password = os.getenv('DB_PASSWORD', 'scpass')
        self.database = os.getenv('DB_NAME', 'securechat')
        self.connection = None
    
    def connect(self):
        """Establish database connection."""
        try:
            self.connection = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                cursorclass=pymysql.cursors.DictCursor
            )
            return self.connection
        except pymysql.Error as e:
            print(f"[!] Database connection failed: {e}")
            raise
    
    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def init_tables(self):
        """Create users table if it doesn't exist."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        
        try:
            if not self.connection:
                self.connect()
            
            with self.connection.cursor() as cursor:
                cursor.execute(create_table_sql)
                self.connection.commit()
                print("[+] Database tables initialized successfully")
        except pymysql.Error as e:
            print(f"[!] Failed to create tables: {e}")
            raise
    
    def register_user(self, email: str, username: str, password: str) -> bool:
        """
        Register a new user with salted password hashing.
        
        Args:
            email: User email
            username: Username
            password: Plain password
            
        Returns:
            True if registration successful
        """
        try:
            # Generate random 16-byte salt
            salt = secrets.token_bytes(16)
            
            # Compute salted password hash: SHA-256(salt || password)
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            
            if not self.connection:
                self.connect()
            
            with self.connection.cursor() as cursor:
                sql = """
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
                """
                cursor.execute(sql, (email, username, salt, pwd_hash))
                self.connection.commit()
                
            print(f"[+] User registered: {username}")
            return True
            
        except pymysql.IntegrityError as e:
            print(f"[!] Registration failed: User already exists - {e}")
            return False
        except pymysql.Error as e:
            print(f"[!] Registration failed: {e}")
            return False
    
    def verify_user(self, email: str, password: str) -> bool:
        """
        Verify user credentials using salted hash.
        
        Args:
            email: User email
            password: Plain password
            
        Returns:
            True if credentials are valid
        """
        try:
            if not self.connection:
                self.connect()
            
            with self.connection.cursor() as cursor:
                sql = "SELECT salt, pwd_hash FROM users WHERE email = %s"
                cursor.execute(sql, (email,))
                result = cursor.fetchone()
                
                if not result:
                    print(f"[!] User not found: {email}")
                    return False
                
                salt = result['salt']
                stored_hash = result['pwd_hash']
                
                # Recompute hash with stored salt
                computed_hash = hashlib.sha256(salt + password.encode()).hexdigest()
                
                # Constant-time comparison to prevent timing attacks
                return secrets.compare_digest(computed_hash, stored_hash)
                
        except pymysql.Error as e:
            print(f"[!] Verification failed: {e}")
            return False
    
    def get_user_salt(self, email: str) -> Optional[bytes]:
        """
        Retrieve salt for a user.
        
        Args:
            email: User email
            
        Returns:
            Salt bytes or None if user not found
        """
        try:
            if not self.connection:
                self.connect()
            
            with self.connection.cursor() as cursor:
                sql = "SELECT salt FROM users WHERE email = %s"
                cursor.execute(sql, (email,))
                result = cursor.fetchone()
                
                if result:
                    return result['salt']
                return None
                
        except pymysql.Error as e:
            print(f"[!] Failed to retrieve salt: {e}")
            return None
    
    def user_exists(self, email: str = None, username: str = None) -> bool:
        """
        Check if user exists by email or username.
        
        Args:
            email: User email (optional)
            username: Username (optional)
            
        Returns:
            True if user exists
        """
        try:
            if not self.connection:
                self.connect()
            
            with self.connection.cursor() as cursor:
                if email:
                    sql = "SELECT COUNT(*) as count FROM users WHERE email = %s"
                    cursor.execute(sql, (email,))
                elif username:
                    sql = "SELECT COUNT(*) as count FROM users WHERE username = %s"
                    cursor.execute(sql, (username,))
                else:
                    return False
                
                result = cursor.fetchone()
                return result['count'] > 0
                
        except pymysql.Error as e:
            print(f"[!] Failed to check user existence: {e}")
            return False


def compute_salted_hash(salt: bytes, password: str) -> str:
    """
    Compute SHA-256(salt || password) and return as hex.
    
    Args:
        salt: Random salt bytes
        password: Plain password
        
    Returns:
        Hex string of hash
    """
    return hashlib.sha256(salt + password.encode()).hexdigest()


# CLI for database initialization
if __name__ == "__main__":
    import sys
    
    if "--init" in sys.argv:
        print("[*] Initializing database...")
        db = Database()
        try:
            db.connect()
            db.init_tables()
            print("[+] Database initialized successfully")
        except Exception as e:
            print(f"[!] Initialization failed: {e}")
            sys.exit(1)
        finally:
            db.close()
    else:
        print("Usage: python -m app.storage.db --init")
