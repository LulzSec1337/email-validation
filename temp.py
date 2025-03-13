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
    for email in emails:
        is_valid, message = validate_email(email)
        results.append([email, message])
    result_df = pd.DataFrame(results, columns=['Email', 'Status'])
    st.dataframe(result_df)

def process_csv(file):
    df = pd.read_csv(file)
    results = []
    for email in df['Email']:
        is_valid, message = validate_email(email)
        results.append([email, message])
    result_df = pd.DataFrame(results, columns=['Email', 'Status'])
    return result_df

def process_pasted_emails(pasted_emails):
    emails = [email.strip() for email in pasted_emails.replace(',', '\n').splitlines() if email.strip()]
    results = []
    for email in emails:
        is_valid, message = validate_email(email)
        results.append([email, message])
    result_df = pd.DataFrame(results, columns=['Email', 'Status'])
    st.dataframe(result_df)

# Set page configuration
st.set_page_config(
    page_title="Email Verification Tool",
    page_icon="✅",
    layout="centered",
)

# Custom CSS for styling the text area and button with Tailwind CSS
tailwind_css = """
<style>
@import url('https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css');

.custom-textarea {
    @apply bg-gray-100 border-2 border-gray-300 rounded-lg p-4 text-lg w-full shadow-md transition-all duration-300;
}

.custom-textarea:focus {
    @apply border-blue-500 outline-none;
}

.custom-button {
    @apply bg-blue-500 text-white border-none rounded-lg py-2 px-4 text-lg cursor-pointer transition-all duration-300;
}

.custom-button:hover {
    @apply bg-blue-700;
}
</style>
"""

# Inject custom CSS
st.markdown(tailwind_css, unsafe_allow_html=True)

def main():
    st.title("Email Verification Tool", help="This tool verifies the validity of an email address.")
    st.info("The result may not be accurate. However, it has 90% accuracy.")

    t1, t2 = st.tabs(["Single Email", "Bulk Email Processing"])

    with t1:
        email = st.text_input("Enter an email address:", key="single_email", placeholder="e.g., example@domain.com")
        
        if st.button("Verify", key="single_verify"):
            with st.spinner('Verifying...'):
                result = {}

                result['syntaxValidation'] = is_valid_email(email)

                if result['syntaxValidation']:
                    domain_part = email.split('@')[1] if '@' in email else ''

                    if not domain_part:
                        st.error("Invalid email format. Please enter a valid email address.")
                    else:
                        if not has_valid_mx_record(domain_part):
                            st.warning("Not valid: MX record not found.")
                        else:
                            result['MXRecord'] = has_valid_mx_record(domain_part)
                            if result['MXRecord']:
                                result['smtpConnection'] = verify_email(email)
                            else:
                                result['smtpConnection'] = False

                            result['isDisposable'] = is_disposable(domain_part)

                            is_valid = (
                                result['syntaxValidation']
                                and result['MXRecord']
                                and result['smtpConnection']
                                and not result['isDisposable']
                            )

                            st.markdown("**Result:**")

                            col1, col2, col3 = st.columns(3)
                            col1.metric(label="Syntax", value=result['syntaxValidation'])
                            col2.metric(label="MX Record", value=result['MXRecord'])
                            col3.metric(label="Is Disposable", value=result['isDisposable'])
                            style_metric_cards()
                            
                            if not result['smtpConnection']:
                                st.warning("SMTP connection not established.")
                            
                            with st.expander("See Domain Information"):
                                try:
                                    dm_info = whois.whois(domain_part)
                                    st.write("Registrar:", dm_info.registrar)
                                    st.write("Server:", dm_info.whois_server)
                                    st.write("Country:", dm_info.country)
                                except:
                                    st.error("Domain information retrieval failed.")
                            
                            if is_valid:
                                st.success(f"{email} is a Valid email")
                            else:
                                st.error(f"{email} is an Invalid email")
                                if result['isDisposable']:
                                    st.text("It is a disposable email")

    with t2:
        st.header("Bulk Email Processing")
        
        input_file = st.file_uploader("Upload a CSV or TXT file", type=["csv", "txt"])
        
        st.markdown("### Paste Emails Below")
        pasted_emails = st.text_area(
            "Paste emails here (one per line or separated by commas)",
            height=200,
            key="pasted_emails",
            help="You can paste a list of emails separated by commas or newlines."
        )
        
        if st.button("Validate Pasted Emails", key="validate_pasted_emails"):
            if pasted_emails:
                with st.spinner("Validating pasted emails..."):
                    process_pasted_emails(pasted_emails)
            else:
                st.warning("Please paste some emails to validate.")
        
        if input_file:
            st.write("Processing...")
            if input_file.type == 'text/plain':
                process_txt(input_file)
            else:
                df = process_csv(input_file)
                st.success("Processing completed. Displaying results:")
                st.dataframe(df)

if __name__ == "__main__":
    main()
