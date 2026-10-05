AUTH LOG PARSER - SAMPADA SNEHI 26/A05/049

to start the code ---> python auth_log_parser.py sample_auth.log


libraries used:
sys → command-line input using sys.argv
re → regular expressions for parsing log lines
csv → exporting parsed events to CSV


Features:
SSH successful/failed login parsing
Username, source IP, port and PID extraction
Sudo command detection
Session open/close detection
Authentication summary
Top 5 usernames and source IPs
Simple brute-force detection(5+ failed attempts from one IP)
CSV export
