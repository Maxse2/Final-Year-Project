# \# LogView - A Log Analysis and Correlation Engine for Security Event Detection





LogView is a proof-of-concept security log analysis platform designed to perform ingestion, normalisation and correlation on security event logs from multiple different sources, with a high degree of modularity to allow for additional sources and alert types to be added without altering the entire system.



The system applies correlation rules on normalised data to detect suspicious behaviour, and has an intuitive UI that allow users to find the root of potential security failures on their system without the bloat of modern SIEM applications.



This project was developed as a part of a final-year undergraduate project in Cyber-Security - the goal was to design and implement a lightweight SIEM system capable of analysing logs of differing sources and formats.



### \## Key Features

* Log Ingestion and Storage using **MongoDB**
* Log Normalisation across several formats
* Rule-based correlation engine
* Interactive Streamlit Dashboard with **Alert Visualisation** and **Filtering.**
* Event and Alert Storage



### \## Supported Log Types

* Windows 11 Security Event Logs
* Linux Auth Logs (auth.log)
* Apache Server Logs (access.log)



### \## Correlation Rules

* Brute Force Detection
* Password Spraying Detection
* Suspicious Network Transition Detection



## \## System Architecture



Log File -> Log Ingestion -> Normalisation/Event Storage -> Correlation Engine/Alert Storage -> Dashboard/Visualisation



## \### System Components



| Component | Description |

|-----------|-------------|

| Ingestion | Takes uploaded files, determines what type of log they are, and passes them to the correct normalisation module. |

| Normalisation | Receives ingested files and normalises them to fit a universal schema so that correlation rules can be applied. |

| Correlation Engine | Takes normalised log data, runs against pre-set correlation rules then generates and stores alerts based on detected behaviour. |

| Dashboard | Streamlit UI. Allows upload and deletion of files, and presents processed data for visualisation and filtering. |



## \### Technologies Used

* Python
* Streamlit
* MongoDB
* Pandas
* Regex (for unstructured log parsing)



## \## Installation



### \### Clone Repository

```

git clone https://github.com/Maxse2/Final-Year-Project.git

cd Final-Year-Project

```



### \### Install Dependencies

```

pip install -r requirements.txt

```



Download and install MongoDB Community Server at: https://www.mongodb.com/try/download/community



Start MongoDB:



```powershell

net start mongodb

```



\### Run Application

(with /Final-Year-Project/Webapp open in terminal)

```

python -m streamlit run app.py

```















