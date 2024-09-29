from flask import Flask, render_template
import plotly.graph_objs as go
import plotly.io as pio
import requests

# Sample vulnerability data for demonstration
vulnerabilities = [
    {
        'cve_id': "CVE-1999-0095",
        'published': "1988-10-01T04:00:00.000",
        'lastModified': "2019-06-11T20:29:00.263",
        'severity': "HIGH",  # Ensure this matches your actual data
        'description': "The debug command in Sendmail allows remote attackers to execute commands as root."
    }
]

# Create Flask app
app = Flask(__name__)

# Dashboard Route
@app.route('/')
def dashboard():
    # Data processing for dashboard
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln['severity'].capitalize()  # Capitalize to match the keys
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Create bar chart for severity levels
    bar_chart = go.Figure(
        data=[go.Bar(x=list(severity_counts.keys()), y=list(severity_counts.values()))],
        layout=go.Layout(title="Vulnerability Severity Levels", xaxis_title="Severity", yaxis_title="Count")
    )
    
    # Convert Plotly chart to HTML
    bar_chart_html = pio.to_html(bar_chart, full_html=False)

    # Prepare vulnerability details to display
    vulnerability_details = vulnerabilities  # Replace with real data source if necessary

    # Render dashboard template with chart and details
    return render_template('dashboard.html', chart=bar_chart_html, details=vulnerability_details)

if __name__ == "__main__":
    app.run(debug=True)

