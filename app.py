from flask import Flask, make_response, request #Import Flask and request modules from the flask package
import json
import csv
from io import StringIO, BytesIO
from reportlab.lib.pagesizes import letter 
from reportlab.pdfgen import canvas 
from reportlab.lib.utils import simpleSplit
import re 

app = Flask(__name__) #Flask application

#HASH DETECTION
def detect_hash(hash_value): 
    
   #step 1: Clean input
    hash_value = hash_value.strip()
    hash_value = hash_value.lower()
   

    #step 2: check if input is empty
    if not hash_value:
        return [{"algorithm": "No input", "reasoning": "No hash value provided"}]
    

    #step 3: detect bycrpt hashes (prefixes)
    if hash_value.startswith("$2a$") or hash_value.startswith("$2b$") or hash_value.startswith("$2y$"):
        return [{"algorithm": "bycrypt","reasoning": "Starts with bycrypt prefix ($2a$/$2b$/$2y$"}] 
    
    if hash_value.startswith("$argon2"):
        return [{"algorithm": "Argon2", "reasoning": "Starts with Argon2 prefix ($argon2)"}]
    

    #step 4:validate that input is hexadecimal
    try:
        int(hash_value, 16)
    except ValueError:
        return [{"algorithm": "Invalid", "reasoning": "Not a valid hexadecimal hash value"}]
          
          
    #step 5: identify hash type by length
    length = len(hash_value) 
    possible = [] #list to store possible hash types 


    if length == 32: 
        possible.append({"algorithm": "MD5", "reasoning": "32 character hexadecimal hash (128 bits)"})
        
        possible.append({"algorithm": "NTLM", "reasoning": "32 character hexadecimal hash (128 bits) - Windows password hash"})

    elif length == 40:
        possible.append({"algorithm": "SHA-1", "reasoning": "40 character hexadecimal hash (160 bits)"})

    elif length == 64:
        possible.append({"algorithm": "SHA-256", "reasoning": "64 character hexadecimal hash (256 bits)"})

    elif length == 128:
        possible.append({"algorithm": "SHA-512", "reasoning": "128 character hexadecimal hash (512 bits)"})

    else:
        possible.append({"algorithm": "Unknown", "reasoning": f"Length {length} characters does not match any common hash"})

        
    return possible

#EXPORT FUNCTIONS 
def export_to_json(hash_input, results):
    """Export detection results to JSON format"""
    export_data = {
        "input_hash": hash_input,
        "detections_results": results,
        "summary": {
            "total_possibilities": len(results)
        }
    }
    return json.dumps(export_data, indent=2)

def export_to_csv(hash_input, results):
    """Export detection results to CSV format"""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Input Hash", "Detected Algorithm", "Reasoning"])
    for r in results:
        writer.writerow([hash_input, r["algorithm"], r["reasoning"]])
    return output.getvalue()

def export_to_pdf(hash_input, results):
    """Export detection results to PDF format"""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    #title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Hash Type Detection Report")

    #input hash
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 80, "Input Hash:")
    c.setFont("Helvetica", 10)
    hash_display = hash_input[:80] + ("..." if len(hash_input) > 80 else "")
    c.drawString(50, height - 95, hash_display)

    # results
    y_position = height - 130
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_position, "Detection Results:")
    y_position -= 25

    c.setFont("Helvetica", 10)
    for i, r in enumerate(results):
        if y_position < 50:  # Check if we need a new page
            c.showPage()
            y_position = height - 50
            c.setFont("Helvetica", 10)

        c.drawString(50, y_position, f"{i+1}. Algorithm: {r['algorithm']}")
        c.drawString(70, y_position - 15, f"Reasoning: {r['reasoning'][:80]}")
        y_position -= 40

    c.save()
    buffer.seek(0)
    return buffer

    

#HOMEPAGE ROUTE
@app.route('/', methods=['GET', 'POST']) #when the user visits the homepage
def home():

    html_results = "" #store formatted HTML
    current_hash = "" #store current hash for export buttons


    if request.method == 'POST': 

        export_format = request.form.get("export_format") #checks if export request 
        user_hash = request.form.get("hash_input")

        if export_format and user_hash:

            results = detect_hash(user_hash) #handles export

            if export_format == "json":
                json_data = export_to_json(user_hash, results)
                response = make_response(json_data)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Content-Disposition'] = f'attachment; filename=hash_detection_{user_hash[:10]}.json'
                return response
            
            elif export_format == "csv":
                csv_data = export_to_csv(user_hash, results)
                response = make_response(csv_data)
                response.headers['Content-Type'] = 'text/csv'
                response.headers['Content-Disposition'] = f'attachment; filename=hash_detection_{user_hash[:10]}.csv'
                return response
            
            elif export_format == "pdf":
                pdf_buffer = export_to_pdf(user_hash, results)
                response = make_response(pdf_buffer.getvalue())
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = f'attachment; filename=hash_detection_{user_hash[:10]}.pdf'
                return response
            
        else: #normal detection 
                user_hash = request.form.get("hash_input")
                current_hash = user_hash
                results = detect_hash(user_hash)

                for item in results:
                    html_results += f'''
                    <div style="border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; background-color: #f9f9f9;">
                        <strong style="color: #2c3e50;"> Algorithm:</strong> {item["algorithm"]}<br>
                        <strong style="color: #2c3e50;"> Reasoning:</strong> {item["reasoning"]}
                    </div>
                    '''
            
    return f'''
    <!DOCTYPE html>
        <html>
    <head>
        <title>Hash Type Detector</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                max-width: 900px;
                margin: 50px auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            .container {{
                background-color: white;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }}
            h2 {{
                color: #2c3e50;
                border-bottom: 3px solid #667eea;
                padding-bottom: 10px;
                margin-top: 0;
            }}
            h3 {{
                color: #2c3e50;
                margin-top: 20px;
            }}
            input[type="text"] {{
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                border: 2px solid #ddd;
                border-radius: 8px;
                font-family: monospace;
                font-size: 14px;
                box-sizing: border-box;
                transition: border-color 0.3s;
            }}
            input[type="text"]:focus {{
                border-color: #667eea;
                outline: none;
            }}
            button {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
                font-weight: bold;
                transition: transform 0.2s;
            }}
            button:hover {{
                transform: translateY(-2px);
            }}
            .export-buttons {{
                margin-top: 20px;
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }}
            .export-btn {{
                background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
                padding: 8px 16px;
                font-size: 14px;
            }}
            .export-btn:hover {{
                transform: translateY(-2px);
            }}
            .footer {{
                margin-top: 30px;
                padding-top: 15px;
                border-top: 1px solid #eee;
                font-size: 12px;
                color: #7f8c8d;
                text-align: center;
            }}
            .supported {{
                display: inline-block;
                background: #e0e7ff;
                color: #667eea;
                padding: 3px 8px;
                margin: 3px;
                border-radius: 12px;
                font-size: 11px;
            }}
            .no-results {{
                color: #7f8c8d;
                text-align: center;
                padding: 20px;
                background-color: #f8f9fa;
                border-radius: 8px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔍 Hash Type Detector</h2>
            <p>Enter a hash value to identify the most likely hashing algorithm(s).</p>
            
            <form method="post">
                <input type="text" name="hash_input" placeholder="Enter hash value (e.g., 5d41402abc4b2a76b9719d911017c592)" required value="{current_hash}">
                <button type="submit">🔎 Detect Hash Type</button>
            </form>
            
            <h3>📊 Detection Results:</h3>
            {html_results if html_results else '<div class="no-results">Enter a hash above and click "Detect Hash Type" to see results.</div>'}
            
            {html_results and current_hash and '''
            <div class="export-buttons">
                <form method="post" style="display: inline;">
                    <input type="hidden" name="hash_input" value="''' + current_hash + '''">
                    <input type="hidden" name="export_format" value="json">
                    <button type="submit" class="export-btn">📄 Export as JSON</button>
                </form>
                <form method="post" style="display: inline;">
                    <input type="hidden" name="hash_input" value="''' + current_hash + '''">
                    <input type="hidden" name="export_format" value="csv">
                    <button type="submit" class="export-btn">📊 Export as CSV</button>
                </form>
                <form method="post" style="display: inline;">
                    <input type="hidden" name="hash_input" value="''' + current_hash + '''">
                    <input type="hidden" name="export_format" value="pdf">
                    <button type="submit" class="export-btn">📑 Export as PDF</button>
                </form>
            </div>
            ''' or ''}
            
            <div class="footer">
                <strong>Supported Hash Types:</strong>
                <span class="supported">MD5</span>
                <span class="supported">NTLM</span>
                <span class="supported">SHA-1</span>
                <span class="supported">SHA-256</span>
                <span class="supported">SHA-512</span>
                <span class="supported">bcrypt</span>
                <span class="supported">Argon2</span>
                <br><br>
                <small>Detection based on hash length, prefixes, and hexadecimal validation.</small>
            </div>
        </div>
    </body>
    </html>
    '''

# RUN APPLICATION 
if __name__ == '__main__':
    app.run(debug=True)




        

        
  


