# 🔍PortPulse 


**AI Powered TCP Connect Port Scanner**

portPulse is a sleek, interactive Streamlit app that performs TCP connect scans on specified IP addresses or domains, intelligently analyzes open ports, and predicts network vulnerability risk using a trained AI model. It also enriches scan results with Censys.io intelligence and provides a dynamic network visualization.

---

## Features

- Fast TCP Connect scanning of user-defined port ranges  
- AI-driven vulnerability risk prediction (Low, Medium, High)  
- Real-time progress and scan status updates  
- Enrichment with Censys host data (requires Censys API credentials)  
- Interactive network node visualization of open ports  
- Download scan results in JSON or CSV format  
- Stylish terminal-inspired UI with dark green hacking theme  

---

## Demo

Try it live at:  
https://portpulse-mzwrnlvjnpxpded6lpymdm.streamlit.app/

---

## Installation

1. Clone this repository:  
   `git clone https://github.com/yourusername/portpulse.git`  
   `cd portpulse`

2. Create and activate a Python virtual environment (optional but recommended):  
   Linux/macOS: `python -m venv venv && source venv/bin/activate`  
   Windows: `python -m venv venv && venv\Scripts\activate`

3. Install dependencies:  
   `pip install -r requirements.txt`

4. Run the app locally:  
   `streamlit run app.py`

---

## Usage

- Enter the target IP address or domain to scan.  
- Specify the ports or port ranges (e.g., `20-80, 443, 8080`).  
- Optionally, provide your Censys API ID and Secret to enable enrichment.  
- Click **Start TCP Connect Scan 🔎** to begin scanning.  
- View scan results, AI risk assessment, and network visualization.  
- Download results as JSON or CSV for further analysis.

---

## Dependencies

- Python 3.7+  
- Streamlit  
- scikit-learn  
- pandas  
- numpy  
- plotly  
- censys  
- Standard Python libraries: socket, json, time

---

## API Credentials

To access Censys enrichment data, create a free account at [Censys.io](https://censys.io/) and generate your API ID and Secret. These credentials are required inputs in the app but optional if you want to skip enrichment.

---

## License

MIT License © portPulse Team

---

## Contact

For feedback or contributions, please open an issue or submit a pull request.

---

*Developed with ❤️ by the Ammy*
