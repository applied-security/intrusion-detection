# Includes parameters to determine sensitivity of the system

SQLI_SENSITIVITY = 3 # A value between 1-lowest & 3-highest

# 1-10 Scale
THREAT_SCORES = {
	'no_referrer': 1, 
	'xss': 9,
	'sql_injection': 10,
	'remote_file_inclusion': 7,
	'scanning_tool': 5,
	'no_user_agent': 6,
	'fake_bot': 4,
	'blacklisted_address': 3,
	'ddos': 8
}
