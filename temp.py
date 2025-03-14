import pandas as pd
import source_code as sc
from suggestion import suggest_email_domain
import whois
from popular_domains import emailDomains
import streamlit as st
from streamlit_extras.metric_cards import style_metric_cards
from streamlit.components.v1 import html

# Set page configuration
st.set_page_config(
    page_title="Email Verification Tool",
    page_icon="✅",
    layout="centered",
)

# Custom HTML and CSS for styling
custom_html = """
<style>
body {
    font-family: 'Arial', sans-serif;
    background-color: #f4f4f9;
    color: #333;
}

.custom-textarea {
    background-color: #fff;
    border: 2px solid #ddd;
    border-radius: 8px;
    padding: 10px;
    font-size: 16px;
    width: 100%;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    transition: border-color 0.3s ease;
}

.custom-textarea:focus {
    border-color: #007bff;
    outline: none;
}

.custom-button {
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 16px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

.custom-button:hover {
    background-color: #0056b3;
}

.tab-content {
    margin-top: 20px;
}

.metric-card {
    background-color: #007bff;
    color: white;
    padding: 10px;
    border-radius: 8px;
    text-align: center;
}

.metric-card h4 {
    margin: 0;
}

.metric-card p {
    margin: 5px 0 0;
}
</style>
"""

# Inject custom HTML and CSS
html(custom_html)

# Function to label an email
def label_email(email):
    if not sc.is_valid_email(email):
        return "Invalid"
    if not sc.has_valid_mx_record(email.split('@')[1]):
        return "Invalid"
    if not sc.verify_email(email):
        return "Unknown"
    if sc.is_disposable(email.split('@')[1]):
        return "Risky"
    return "Valid"

# Function to process pasted emails and return DataFrame
def process_pasted_emails(pasted_emails):
    # Split the pasted emails by newlines and commas
    emails = [email.strip() for email in pasted_emails.replace(',', '\n').splitlines() if email.strip()]

    # Create a list to store the results
    results = []

    for email in emails:
        label = label_email(email)
        results.append([email, label])

    # Create a DataFrame for the results
    result_df = pd.DataFrame(results, columns=['Email', 'Label'])
    result_df.index = range(1, len(result_df) + 1)  # Starting index from 1

    return result_df

# Function to download DataFrame as selected file type
def download_dataframe(df, file_format):
    if file_format == 'CSV':
        return df.to_csv(index=False).encode('utf-8')
    elif file_format == 'TXT':
        return df.to_csv(index=False, sep='\t').encode('utf-8')
    elif file_format == 'JSON':
        return df.to_json(orient='records').encode('utf-8')

# Main function
def main():
    st.title("Email Verification Tool", help="This tool verifies the validity of an email address.")
    st.info("The result may not be accurate. However, it has 90% accuracy.")

    t1, t2 = st.tabs(["Single Email", "Bulk Email Processing"])

    with t1:
        # Single email verification
        email = st.text_input("Enter an email address:", key="single_email", help="Enter the email address you want to verify.")
        
        if st.button("Verify", key="verify_single"):
            with st.spinner('Verifying...'):
                result = {}

                # Syntax validation
                result['syntaxValidation'] = sc.is_valid_email(email)

                if result['syntaxValidation']:
                    domain_part = email.split('@')[1] if '@' in email else ''

                    if not domain_part:
                        st.error("Invalid email format. Please enter a valid email address.")
                    else:
                        # Additional validation for the domain part
                        if not sc.has_valid_mx_record(domain_part):
                            st.warning("Not valid: MX record not found.")
                            suggested_domains = suggest_email_domain(domain_part, emailDomains)
                            if suggested_domains:
                                st.info("Suggested Domains:")
                                for suggested_domain in suggested_domains:
                                    st.write(suggested_domain)
                            else:
                                st.warning("No suggested domains found.")
                        else:
                            # MX record validation
                            result['MXRecord'] = sc.has_valid_mx_record(domain_part)

                            # SMTP validation
                            if result['MXRecord']:
                                result['smtpConnection'] = sc.verify_email(email)
                            else:
                                result['smtpConnection'] = False

                            # Temporary domain check
                            result['is Temporary'] = sc.is_disposable(domain_part)

                            # Determine validity status and message
                            is_valid = (
                                result['syntaxValidation']
                                and result['MXRecord']
                                and result['smtpConnection']
                                and not result['is Temporary']
                            )

                            st.markdown("**Result:**")

                            # Display metric cards with reduced text size
                            col1, col2, col3 = st.columns(3)
                            col1.markdown(f"<div class='metric-card'><h4>Syntax</h4><p>{result['syntaxValidation']}</p></div>", unsafe_allow_html=True)
                            col2.markdown(f"<div class='metric-card'><h4>MxRecord</h4><p>{result['MXRecord']}</p></div>", unsafe_allow_html=True)
                            col3.markdown(f"<div class='metric-card'><h4>Is Temporary</h4><p>{result['is Temporary']}</p></div>", unsafe_allow_html=True)
                            style_metric_cards()
                            
                            # Show SMTP connection status as a warning
                            if not result['smtpConnection']:
                                st.warning("SMTP connection not established.")
                            
                            # Show domain details in an expander
                            with st.expander("See Domain Information"):
                                try:
                                    dm_info = whois.whois(domain_part)
                                    st.write("Registrar:", dm_info.registrar)
                                    st.write("Server:", dm_info.whois_server)
                                    st.write("Country:", dm_info.country)
                                except:
                                    st.error("Domain information retrieval failed.")
                            
                            # Show validity message
                            if is_valid:
                                st.success(f"{email} is a Valid email")
                            else:
                                st.error(f"{email} is an Invalid email")
                                if result['is Temporary']:
                                    st.text("It is a disposable email")

    with t2:
        # Bulk email processing
        st.header("Bulk Email Processing")
        
        # Option to upload a file
        input_file = st.file_uploader("Upload a CSV, XLSX, or TXT file", type=["csv", "xlsx", "txt"])
        
        # Option to paste emails directly
        st.markdown("### Paste Emails Below")
        pasted_emails = st.text_area(
            "Paste emails here (one per line or separated by commas)",
            height=200,
            key="pasted_emails",
            help="You can paste a list of emails separated by commas or newlines.",
        )

        # Select file format for download
        file_format = st.selectbox("Select file format for download", ["CSV", "TXT", "JSON"])

        # Add a custom validation button
        if st.button("Validate Pasted Emails", key="validate_pasted_emails", help="Click to validate the pasted emails."):
            if pasted_emails:
                with st.spinner("Validating pasted emails..."):
                    result_df = process_pasted_emails(pasted_emails)
                    st.dataframe(result_df)

                    # Filter valid emails
                    valid_emails_df = result_df[result_df['Label'] == 'Valid']

                    # Provide download link
                    st.download_button(
                        label="Download Valid Emails",
                        data=download_dataframe(valid_emails_df, file_format),
                        file_name=f"valid_emails.{file_format.lower()}",
                        mime="text/csv" if file_format == 'CSV' else "text/plain" if file_format == 'TXT' else "application/json"
                    )
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
