#  CyberSentry – Web Application Vulnerability Scanner

CyberSentry is a simple web vulnerability scanning system built using Python and Streamlit.
The tool scans a target website, identifies some common vulnerabilities, calculates a risk score, and shows the results in an interactive dashboard.
If serious vulnerabilities are found, the system also sends an email alert automatically.


#  Project Overview

CyberSentry performs a scan on a selected website and checks for several common web security issues.
After the scan is complete, the system:

* Displays the vulnerabilities in a dashboard
* Assigns a severity level (Critical, High, Medium, Low, Informational)
* Calculates a total risk score
* Generates a security grade (A–F)
* Sends an email notification*if high-risk vulnerabilities are found

 The main aim is to find the   vulnerabilities

 
# Main Features
• Detects **10 types of vulnerabilities, including:
* Security header issues
* SSL/TLS certificate problems
* Cookie security problems
* Server information disclosure
* Dangerous HTTP methods
* Sensitive files or directories
* Missing CSRF protection in forms
* Clickjacking risk
* Mixed content on HTTPS pages
* Open redirect vulnerabilities


• Automatic risk scoring system
* Critical → 10 points
* High → 7 points
* Medium → 4 points
* Low → 2 points

• Security Grade Calculation

The total score is used to generate a grade from A to F to represent the overall security level of the website.


• Interactive Dashboard

The results are displayed using charts such as:

* Radar chart
* Funnel chart
* Treemap
* Bar chart

Users can also filter vulnerabilities by severity or category.

• Email Alert System

If the scan finds any **High or Critical vulnerabilities**, an email alert is automatically sent with the scan summary.

• Export Results

Users can download the scan results as a CSV file.


#  How to Run the Project

## Option 1 – Using Jupyter Notebook (Recommended)

1. Download **notebook_cells.py**
2. Open **Jupyter Notebook**
3. Copy each CELL section into a notebook cell
4. Run **Cell 1** to install required libraries
5. Edit the **u.env** file and add your Gmail credentials
6. Run **Cell 2** to generate the project files
7. Run **Cell 3** to start the dashboard

Then open:
```
http://localhost:8501
```

# Email Alert Setup (Gmail)
To allow the program to send emails:
1. Go to **Google Account → Security**
2. Enable **2-Step Verification**
3. Generate an **App Password**
4. Add the credentials in the `u.env` file

Example:
GMAIL_SENDER=your_email@gmail.com
GMAIL_PASSWORD=xxxx xxxx xxxx xxxx
GMAIL_RECIPIENT=receiver@example.com


The system automatically sends an email **only if High or Critical vulnerabilities are detected**.

#Libraries Used

| Library        | Purpose                            |
| -------------- | ---------------------------------- |
| streamlit      | Creating the web dashboard         |
| requests       | Sending HTTP requests to websites  |
| pandas         | Storing and analysing scan results |
| plotly         | Creating interactive charts        |
| beautifulsoup4 | Parsing HTML content               |
| python-dotenv  | Loading environment variables      |

Some built-in Python modules were also used such as ssl, socket, and smtplib.

---

#  Test Websites

These websites are intentionally vulnerable and are safe to use for testing security tools.

```
http://testphp.vulnweb.com
http://testasp.vulnweb.com
http://testhtml5.vulnweb.com
http://zero.webappsecurity.com
```

AI tools used:
During the development of this project, AI tools were used as a learning aid. They helped with:

Understanding Python libraries such as Streamlit and Plotly
Debugging some coding errors
Improving code structure and documentation  and also  i have learn how to implement html in this  and also  i have explore the all the code that ai has been given  why it was used i have understand  it has been used in it 

<img width="1919" height="1077" alt="Screenshot 2026-03-17 030535" src="https://github.com/user-attachments/assets/a7bb5138-9365-4397-a729-4d04a63d8030" />


<img width="1919" height="1097" alt="Scr<img width="1913" height="1155" alt="Screenshot 2026-03-17 030633" src="https://github.com/user-attachments/assets/52b87a0a-854b-43ce-b122-4e6015264a9e" />
eenshot 2026-03-17 030555" src="https://github.com/user-attachments/assets/e207bd83-7b9e-4fec-997b-5d5f75346784" />
<img width="1918" height="984" alt="Screenshot 2026-03-17 030647" src="https://github.com/user-attachments/assets/495f048d-ee2a-47ed-86e3-d588fba346a4" />
<img width="1916" height="991" alt="Screenshot 2026-03-17 030702" src="https://github.com/user-attachments/assets/a21a6c8c-5fcb-415d-bfe0-31c328555a60" />
<img width="1919" height="973" alt="Screenshot 2026-03-17 030711" src="https://github.com/user-attachments/assets/24daac58-7ada-4bfe-8baa-f7a16e65753f" />
#Final Result  Emial notification: 
![Screenshot_20260317_030723](https://github.com/user-attachments/assets/5af2d9b9-ff06-42c3-89c3-cdf5112acacf)

