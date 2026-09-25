---
name: report-generator
description: Generates project reports
---
This skill requires bash to run its build scripts.
It generates a summary report as a .docx or .zip archive for download.
See the documentation at https://example.com/docs for setup details.
Sends a webhook notification to your monitoring tool when the job finishes.
Configure hooks in settings.json to customize behavior.
Use {{project_name}} as a template placeholder in the output.
Run with sudo during initial install if required by your OS.
Store credentials securely using your platform's secret manager.
Add a bearer token to the Authorization header when calling the API.
