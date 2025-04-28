from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # or a separate home page

@app.route('/arp')
def arp_lab():
    return render_template('Arp_lab.html')

@app.route('/ddos')
def ddos_lab():
    return render_template('DDoS_lab.html')

@app.route('/recon')
def recon_lab():
    return render_template('Recon_lab.html')

# Additional routes (e.g., /python_scapy, /Tcp, /Snort_lab, /DEF, etc.) as needed:
@app.route('/Wireshark+scapy')
def python_scapy():
    return render_template('python_scapy.html')

@app.route('/Tcp')
def tcp_lab():
    return render_template('Tcp_lab.html')

@app.route('/IDS')
def IDS_lab():
    return render_template('IDS_lab.html')

@app.route('/Chl')
def Chl_lab():
    return render_template('chl.html')

if __name__ == '__main__':
    app.run(debug=True)
