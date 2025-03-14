import re
import dns.resolver
import smtplib
import requests
import threading
from queue import Queue
import pandas as pd
import streamlit as st
from streamlit_extras.metric_cards import style_metric_cards
import whois
import base64
import json

CACHE_TTL = 600

# Initialize a DNS resolver with caching enabled
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8']
resolver.cache = dns.resolver.Cache()

# Comprehensive regex for email validation
def is_valid_email(email):
    pattern = r'''
        ^                         # Start of string
        (?!.*[._%+-]{2})          # No consecutive special characters
        [a-zA-Z0-9._%+-]{1,64}    # Local part: allowed characters and length limit
        (?<![._%+-])              # No special characters at the end of local part
        @                         # "@" symbol
        [a-zA-Z0-9.-]+            # Domain part: allowed characters
        (?<![.-])                 # No special characters at the end of domain
        \.[a-zA-Z]{2,}$           # Top-level domain with minimum 2 characters
    '''
    return re.match(pattern, email, re.VERBOSE) is not None

# DNS query with caching
def query_dns(record_type, domain):
    try:
        record_name = domain if record_type == 'MX' else f'{domain}.'
        cache_result = resolver.cache.get((record_name, record_type))
        if cache_result is not None and (dns.resolver.mtime() - cache_result.time) < CACHE_TTL:
            return True
        resolver.timeout = 2
        resolver.lifetime = 2
        resolver.resolve(record_name, record_type)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.Timeout:
        return False
    except:
        return False

def has_valid_mx_record(domain):
    def query_mx(results_queue):
        results_queue.put(query_dns('MX', domain))

    def query_a(results_queue):
        results_queue.put(query_dns('A', domain))

    mx_queue = Queue()
    a_queue = Queue()
    mx_thread = threading.Thread(target=query_mx, args=(mx_queue,))
    a_thread = threading.Thread(target=query_a, args=(a_queue,))
    mx_thread.start()
    a_thread.start()
    mx_thread.join()
    a_thread.join()
    mx_result = mx_queue.get()
    a_result = a_queue.get()
    return mx_result or a_result

def verify_email(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NoAnswer:
        return False

    for mx in mx_records:
        try:
            smtp_server = smtplib.SMTP(str(mx.exchange))
            smtp_server.ehlo()
            smtp_server.mail('')
            code, message = smtp_server.rcpt(str(email))
            smtp_server.quit()
            if code == 250:
                return True
        except Exception as e:
            print(f"Error verifying email {email}: {e}")
    return False

def is_disposable(domain):
    blacklists = [
        'https://raw.githubusercontent.com/andreis/disposable-email-domains/master/domains.txt',
        'https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt'
    ]

    for blacklist_url in blacklists:
        try:
            blacklist = set(requests.get(blacklist_url).text.strip().split('\n'))
            if domain in blacklist:
                return True
        except Exception as e:
            print(f'Error loading blacklist {blacklist_url}: {e}')
    return False

def validate_email(email):
    if not is_valid_email(email):
        return False, "Invalid email format"
    
    domain = email.split('@')[1]
    if is_disposable(domain):
        return False, "Disposable email address"
    
    if not has_valid_mx_record(domain):
        return False, "Invalid domain or no MX records found"

    if verify_email(email):
        return True, "Email address is valid and exists"
    else:
        return False, "Email address does not exist"

def process_txt(file):
    emails = file.read().decode('utf-8').splitlines()
    results = []
    valid_emails = []
    for email in emails:
        is_valid, message = validate_email(email)
        results.append([email, message])
        if is_valid:
            valid_emails.append(email)
    result_df = pd.DataFrame(results, columns=['Email', 'Status'])
    st.dataframe(result_df)
    return valid_emails

def process_csv(file):
    df = pd.read_csv(file)
    results = []
    valid_emails = []
    for email in df['Email']:
        is_valid, message = validate_email(email)
        results.append([email, message])
        if is_valid:
            valid_emails.append(email)
    result_df = pd.DataFrame(results, columns=['Email', 'Status'])
    st.dataframe(result_df)
    return valid_emails

def process_pasted_emails(pasted_emails):
    emails = [email.strip() for email in pasted_emails.replace(',', '\n').splitlines() if email.strip()]
    results = []
    valid_emails = []
    for email in emails:
        is_valid, message = validate_email(email)
        results.append([email, message])
        if is_valid:
            valid_emails.append(email)
    result_df = pd.DataFrame(results, columns=['Email', 'Status'])
    st.dataframe(result_df)
    return valid_emails

def download_file(data, file_type):
    if file_type == "csv":
        csv = data.to_csv(index=False).encode('utf-8')
        b64 = base64.b64encode(csv).decode()
        href = f'<a href="data:file/csv;base64,{b64}" download="valid_emails.csv">Download CSV</a>'
    elif file_type == "txt":
        txt = "\n".join(data).encode('utf-8')
        b64 = base64.b64encode(txt).decode()
        href = f'<a href="data:file/txt;base64,{b64}" download="valid_emails.txt">Download TXT</a>'
    elif file_type == "json":
        json_data = json.dumps(data, indent=4).encode('utf-8')
        b64 = base64.b64encode(json_data).decode()
        href = f'<a href="data:file/json;base64,{b64}" download="valid_emails.json">Download JSON</a>'
    return href

# Set page configuration
st.set_page_config(
    page_title="Email Verification Tool",
    page_icon="✅",
    layout="centered",
)

# Custom CSS for HTB-like styling
custom_css = """
<style>
body {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: 'Courier New', Courier, monospace;
}
.custom-textarea {
    background-color: #161b22;
    border: 2px solid #30363d;
    border-radius: 8px;
    padding: 10px;
    font-size: 16px;
    width: 100%;
    color: #c9d1d9;
}
.custom-button {
    background-color: #238636;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 16px;
    cursor: pointer;
}
.custom-button:hover {
    background-color: #2ea043;
}
</style>
"""

# Inject custom CSS
st.markdown(custom_css, unsafe_allow_html=True)

# ASCII Logo
ascii_logo = """
