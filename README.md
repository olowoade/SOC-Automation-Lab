## SOC-Automation-Lab

### Objective
The SOC Automation Lab was created to simulate a real-world Security Operations Center (SOC) using open-source tools. The goal was to collect and analyze Windows logs, detect threats using a SIEM, and automate responses using SOAR and case management tools.

### Skills Learned

- Gained experience configuring and managing a SIEM (Wazuh).
- Analyzed system activity logs using Sysmon.
- Developed automation workflows with Shuffle (SOAR).
- Integrated threat intelligence using VirusTotal.
- Organized incident tracking with TheHive.
- Practiced simulating attacks and validating detections.

### Tools Used

- **Windows 10 VM** – Simulated attacks and generated log data using Sysmon.
- **Sysmon** – Collected detailed system activity logs (e.g., process creation, commands).
- **Wazuh (SIEM)** – Detected threats based on logs and rules.
- **TheHive** – Managed security alerts as cases for investigation.
- **Shuffle (SOAR)** – Automated alert triage, VirusTotal lookups, and notifications.
- **VirusTotal** – Provided file reputation intelligence via API.

### Steps
Every screenshot should have some text explaining what the screenshot is about.

**Step 1** – Installed Sysmon on Windows 10 VM and configured logging.  
**Step 2** – Connected Sysmon logs to Wazuh using the Wazuh Agent.  
**Step 3** – Created detection rules in Wazuh for Mimikatz activity.  
**Step 4** – Deployed TheHive and configured alert ingestion.  
**Step 5** – Simulated an attack using Mimikatz and validated detection.  
**Step 6** – Built a Shuffle workflow to automate alert → VirusTotal → TheHive → Email.  
**Step 7** – Ran full test to verify detection, enrichment, case creation, and notification.

Screenshot Examples below:  
![Wazuh SIEM Dashboard](https://i.imgur.com/0dbelrd.jpeg)
![TheHive Case Management](https://i.imgur.com/NNmgC6h.jpeg)
![Sysmon Logs](https://i.imgur.com/HplbgPA.jpeg)
