# mapD3FEND
Map MITRE ATT&amp;CK Techniques to D3FEND Techniques data

---

## Getting Started

Follow these steps to set up your local environment and run the tool:

### 1. Clone the Repository
```powershell
git clone https://github.com/alan7s/mapD3FEND.git
cd mapD3FEND
```

### 2. Create a Virtual Environment
It is highly recommended to use a virtual environment to keep dependencies isolated:
```powershell
python -m venv venv
```

### 3. Activate the Environment
On Windows (PowerShell):
```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install Dependencies
Once the environment is active, install the required packages:
```powershell
pip install -r requirements.txt
```

### 5. Run the script
Start the mapping process:
```powershell
python mapD3FEND.py
```

### 6. Check the resources folder
defend_db.jsonl file is available in the resources folder:
```powershell
cd resources
dir
```

---