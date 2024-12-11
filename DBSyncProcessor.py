import os
import csv
import json
import mysql.connector
from datetime import datetime
import sys
from pathlib import Path
from dotenv import load_dotenv

def load_configuration():
    """Load configuration from .env file if it exists, otherwise use environment variables"""
    # Try to load .env file if it exists
    env_path = Path('.env')
    if env_path.exists():
        print("Using .env file for configuration")
        load_dotenv()
    else:
        print("No .env file found, using environment variables")

    # Required configuration parameters
    required_vars = ['MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DATABASE']
    config = {}
    missing_vars = []

    for var in required_vars:
        value = os.getenv(var)
        if value is None:
            missing_vars.append(var)
        else:
            config[var.lower()] = value

    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please either:")
        print("1. Create a .env file with the required variables, or")
        print("2. Set the environment variables directly")
        print("\nRequired variables:")
        for var in required_vars:
            print(f"- {var}")
        sys.exit(1)

    return config

def truncate_table(cursor):
    """Truncate the all_domains table"""
    try:
        print("Truncating existing data from all_domains table...")
        cursor.execute("TRUNCATE TABLE all_domains")
        print("Table truncated successfully")
    except mysql.connector.Error as err:
        print(f"Error truncating table: {err}")
        raise

def parse_date(date_str):
    """Convert date string to MySQL date format or return None if invalid"""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return None

def parse_domain_status(status_str):
    """Parse domain status string to JSON"""
    if not status_str or status_str == 'null':
        return '[]'
    try:
        if status_str.startswith('['):
            return status_str
        return json.dumps([status_str])
    except:
        return '[]'

def main():
    # Load configuration from either .env or environment variables
    config = load_configuration()
    
    # Connect to MySQL
    try:
        conn = mysql.connector.connect(
            host=config['mysql_host'],
            user=config['mysql_user'],
            password=config['mysql_password'],
            database=config['mysql_database']
        )
        cursor = conn.cursor()
        print("Successfully connected to MySQL database")
        
        # Truncate existing data
        truncate_table(cursor)
        
    except mysql.connector.Error as err:
        print(f"Error connecting to MySQL: {err}")
        sys.exit(1)

    insert_query = """
    INSERT INTO all_domains (
        psl_entry, top_level_domain, dns_status, whois_status,
        whois_domain_expiry_date, whois_domain_registration_date,
        whois_domain_status, psl_txt_status, expiry_check_status
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    try:
        csv_path = Path('data/all.csv')
        if not csv_path.exists():
            print(f"Error: CSV file not found at {csv_path}")
            sys.exit(1)

        with open(csv_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            
            batch_size = 1000
            batch = []
            total_records = 0
            
            for row in csv_reader:
                record = (
                    row['psl_entry'],
                    row['top_level_domain'],
                    row['dns_status'],
                    row['whois_status'],
                    parse_date(row['whois_domain_expiry_date']),
                    parse_date(row['whois_domain_registration_date']),
                    parse_domain_status(row['whois_domain_status']),
                    row['psl_txt_status'],
                    row['expiry_check_status']
                )
                batch.append(record)
                
                if len(batch) >= batch_size:
                    cursor.executemany(insert_query, batch)
                    conn.commit()
                    total_records += len(batch)
                    print(f"Processed {total_records} records")
                    batch = []
            
            if batch:
                cursor.executemany(insert_query, batch)
                conn.commit()
                total_records += len(batch)
                print(f"Total records processed: {total_records}")

    except Exception as e:
        print(f"Error processing data: {e}")
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()