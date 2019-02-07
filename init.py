from datetime import datetime
import pandas as pd
import pandasql
import numpy as np
import os
import sys
import socket
from urllib.request import Request, urlopen
from tqdm import tqdm
import code
import collections
import config

sql = pandasql.PandaSQL()

FIELD_ORDER = [
                'address',            # ip address
                'ident',              # client machine runs identd => id info
                'authuser',           # token for Basic HTTP authentication
                'timestamp',          # this gets split into 2 fields
                                      #    'day'    %Y-%m-%d
                                      #    'time'   %H:%M:%S
                'request',            # this field gets replaced into 3 fields
                                      #    'method'   e.g. GET
                                      #    'url'      e.g. /article1.html
                                      #    'protocol' e.g. HTTP/1.1
                'response_code',      # e.g. 404
                'response_bytes',     # number of bytes returned
                'referrer',           # e.g. "https://www.doc.ic.ac.uk/"
                'user_agent',
                'tls',                # e.g. TLSv1.2
                'unknown_field_4'     # something to do with encryption e.g. ECDHE-RSA-AES128-GCM-SHA256
              ]

# urls to gather blacklisted ip address - https://github.com/jgamblin/isthisipbad/blob/master/isthisipbad.py
BLACKLIST_IP_SOURCE_URLS = [
                              # 'http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',    # TOR
                              'http://rules.emergingthreats.net/blockrules/compromised-ips.txt',        # EmergingThreats
                              # 'http://reputation.alienvault.com/reputation.data',                       # AlienVault
                              'http://www.blocklist.de/lists/bruteforcelogin.txt',                      # BlocklistDE
                              # 'http://dragonresearchgroup.org/insight/sshpwauth.txt',                   # Dragon Research Group - SSH
                              # 'http://dragonresearchgroup.org/insight/vncprobe.txt',                    # Dragon Research Group - VNC
                              # 'http://www.nothink.org/blacklist/blacklist_malware_http.txt',            # NoThinkMalware
                              # 'http://antispam.imp.ch/spamlist',                                        # antispam.imp.ch
                              # 'http://www.dshield.org/ipsascii.html?limit=10000',                       # dshield
                              'http://malc0de.com/bl/IP_Blacklist.txt'                                 # malc0de
                              # 'http://hosts-file.net/rss.asp'                                           # MalWareBytes
                           ]

# use this map to verify bots
# e.g. if the key is within the user_agent field then check that the value is in the hostname
USER_AGENT_HOSTNAME_MAP = {
                            'yandex': 'yandex',
                            'googlebot': 'googlebot',
                            'semrushbot': 'semrush',
                            'bingbot': 'msn',
                            'changedetection': 'changedetection',
                            'piplbot': 'pipl'
                          }

def parse_line(line):
  # first tokenise by spaces
  obj = {}
  field_count = 0
  block_count = 0   # block is considered anything within quotes or square brackets
  in_escape = False  # next character is escaped, e.g. the text we see is literally \"
  current_token = ""

  # checking for blocks of strings with whitespace is a hack
  for character in line:
    will_escape = False
    if character == "\\" and not in_escape:
      will_escape = True
    elif character == "\"" and not in_escape:
      if block_count > 0:
        block_count -= 1
      else:
        block_count += 1
    elif character == "[" and not in_escape:
      block_count += 1
    elif character == "]" and not in_escape and block_count > 0:
      block_count -= 1
    elif character == " " and block_count == 0:
      obj[FIELD_ORDER[field_count]] = current_token
      current_token = ""
      field_count += 1
    else:
      current_token += character
    in_escape = will_escape

  # now fine grain the tokens
  request_tokens = obj['request'].split(" ")
  if len(request_tokens) == 3:
    obj['method'] = request_tokens[0]
    obj['url'] = request_tokens[1]
    obj['protocol'] = request_tokens[2]
  del obj['request']

  # convert timestamp string into a useful data type
  obj['timestamp'] = datetime.strptime(obj['timestamp'], "%d/%b/%Y:%H:%M:%S %z")

  # convert timestamp back to a sql format
  obj['day'] = obj['timestamp'].strftime("%Y-%m-%d")
  obj['time'] = obj['timestamp'].strftime("%H:%M:%S")

  # NOTE: we are removing unknown or useless fields since it takes up much memory
  del obj['timestamp']
  del obj['ident']
  del obj['authuser']
  del obj['response_bytes']
  del obj['unknown_field_4']
  return obj

def parse_file_into_objects(path):
  file = open(path, "r")
  data = []
  for line in file:
    data.append(parse_line(line))
  return data

def find_all_access_logs(root):
  print('[~] Looking for access logs in ' + root)
  access_logs = []
  for root, dirs, files in os.walk(root):
    for file in files:
      if "ssl-access.log" in file and ".gz" not in file:
         access_logs.append(os.path.join(root, file))
  print("[+] Found " + str(len(access_logs)) + " access logs!")
  return access_logs

def load_access_logs(files):
  number_of_files = len(files)
  print("[~] Loading access logs..")

  dataframe_collection = pd.DataFrame()
  for i in tqdm(range(number_of_files)):
    file = files[i]

    new_dataframe = pd.DataFrame(parse_file_into_objects(file))
    dataframe_collection = pd.concat([dataframe_collection, new_dataframe], ignore_index=True)

  print("[+] " + str(number_of_files) + " access logs loaded!")
  return dataframe_collection

def parse_files_into_database(root):
  files = find_all_access_logs(root)
  return load_access_logs(files)

def fetch_blacklisted_addresses_from(url):
  blacklist = []
  print('[~] Fetching blacklisted addresses from ' + url)
  try:
    request = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    contents = urlopen(request).read().decode('utf-8')
    lines = contents.split('\n')
    for line in lines:
      # ignore comments and empty lines
      if "//" in line or line == "":
        continue
      blacklist.append(line.strip())
  except:
    print('[!] Failed to fetch ' + url)    
  return blacklist

def fetch_blacklisted_addresses():
  # todo: collect black list from all sources defined in BLACKLIST_IP_SOURCE_URLS
  blacklist = []
  for url in BLACKLIST_IP_SOURCE_URLS:
    blacklist = blacklist + fetch_blacklisted_addresses_from(url)

  print('[+] Fetched ' + str(len(blacklist)) + ' blacklisted addresses')
  return pd.DataFrame({'address': list(set(blacklist))}) # first removes duplicates by using set

def filter_requests_with_no_useragent(data):
  return sql('select *, "no user agent" as reason from data where user_agent = "-"')

def filter_requests_with_no_referrer(data):
  return sql('select *, "no referrer" as reason from data where referrer = "-"')

def calculate_total_requests_per_day(data):
  return sql('select count(*) as requests, day from data group by day')

def calculate_average_requests_per_day(data):
  number_of_days = sql('select count(distinct(day)) as number_of_days from data')['number_of_days'][0]
  return sql('select (count(*) / ' + str(number_of_days) + ') as average from data')['average'][0]

def user_agent_to_crawler_name(user_agent):
  for bot in USER_AGENT_HOSTNAME_MAP:
    if bot in user_agent.lower():
      return bot
  return ""

# finds user agents of yandex and reverse dns look up to see if they are legimate yandex bots
# optimise: use a transposition table (fixed size hash table), a single ip address occur many times
# optimise: E.G. convert ip address to hex and then perform (HEX % 20000) to check before you calculate the index of the array to cache it in
def filter_fake_crawler_bots(data):
  violations = []
  for index, row in data.iterrows():
    crawler_name = user_agent_to_crawler_name(row["user_agent"])

    # ignore rows which are not related to a crawler
    if crawler_name == "":
      continue

    # verify crawlers user agent matches host name
    try:
      resolved_domain_name = socket.gethostbyaddr(row["address"])[0]
      # check the hostname is valid
      if USER_AGENT_HOSTNAME_MAP[crawler_name] not in resolved_domain_name:
        violations.append(data.iloc[index])
        continue

      # Run a forward DNS lookup on the host name retrieved to make sure the ip is the same
      resolved_ip_address = socket.gethostbyaddr(resolved_domain_name)[2]
      if row["address"] not in resolved_ip_address:
        violations.append(data.iloc[index])
        continue

    except:
      # If resolving fails or throws exception then we will ignore this
      # violations.append(data.iloc[index])
      continue


  print_matches(len(violations), 'fake bots')
  result = pd.DataFrame(violations)
  result['reason'] = 'fake bots'
  return result

def filter_blacklisted_addresses(data, blacklist):
  return sql('select *, "blacklisted address" as reason from data where address in (select address from blacklist)')

# Takes the data variable, column to compare and an array of regex rules and returns
# any records in data that match at least one of the rules
def match_regex(data, column, rules, flip=False):
    if flip:
        tmp = [~column.str.contains(rule, regex=True) for rule in rules]
    else:
        tmp = [column.str.contains(rule, regex=True) for rule in rules]
    matches = [[m[i] for m in tmp] for i in range(len(tmp[0]))]  # Bool[][]
    result = []
    for i in range(len(matches)):
        for m in matches[i]:
            if m:
                result.append(data.iloc[i])
                break
    return pd.DataFrame(result)

# Simple output for the number of a threat found by the system
def print_matches(num, threat):
    if num > 0:
        m = '[!] Found '
        m += str(num)
        m += ' instance of ' if num == 1 else ' instances of '
        m += threat
        print(m)
    return


# checks for any </...> patterns in the URL
def filter_xss(data):
    c1 = '(%3C|<)'       # checks for <
    c2 = '(%2F|\/)*'     # checks for /
    c3 = '[a-zA-Z0-9]+'  # checks for string in tag
    c4 = '(%3E|>)'       # checks for >
    reg = c1 + c2 + c3 + c4
    matches = match_regex(data, data.url, [reg])
    print_matches(len(matches), 'XSS')
    return matches
# checks for different common patterns used in SQL-Injection attacks in the URL
def filter_sqli(data):
    c1 = '(%27|\')'                    # checks for ' delimiter
    c2 = '(%23|#|--)'                  # checks for comments
    c3 = '(%3D|=)'                     # checks for =
    c4 = '[^\n]*'                      # checks for 0+ new lines
    c5 = '(' + c1 + '|--|%3B|;)'       # checks for ; / -- / '
    c6 = '(\s|%20)*'                   # checks for 0+ whitespaces
    c7 = '(%6F|o|O|%4F)(%72|r|R|%52)'  # checks for or | OR
    c8 = '(select|union|insert|update|delete|replace|truncate)'  # checks for SQL keywords
    c9 = c8.upper()
    rules = []
    rules.append(c1 + c6 + c7)        # detects ' followed by or | OR
    rules.append(c1 + c8 + '|' + c9)  # detects SQL keywords
    if (config.SQLI_SENSITIVITY > 2):
        rules.append(c3 + c4 + c5)    # detects delimiter after = (NOTE: this gives false-positives)
        rules.append(c1 + '|' + c2)   # detects escape character in url
    elif (config.SQLI_SENSITIVITY == 2):
        rules.append(c1 + '|' + c2)   # detects escape character in url
    matches = match_regex(data, data.url, rules)
    print_matches(len(matches), 'SQL injection')
    return matches

# checks for references to a remote file in the URL
def filter_remote_file_inclusion(data):
    reg = '(https?|ftp|php|data):'
    matches = match_regex(data, data.url, [reg])
    print_matches(len(matches), 'remote file inclusion')
    return matches

# checks for unknown referers
# NOTE: Need to think of a smarter way to identify potentially dangerous referers
def filter_csrf(data):
    doc = 'www.doc.ic.ac.uk'
    none = '-'
    google = 'https://www.google.'
    reg = doc + '|' + none + '|' + google
    matches = match_regex(data, data.referrer, [reg], True)
    print_matches(len(matches), 'CSRF')
    return matches

# checks for known scanning tools
def filter_scanning_tools(data, path):
    file = open(path, "r")
    agents = []
    for line in file:
        line = line.rstrip()
        if line != '' and line[0] != '#':
            agents.append(line)
    reg = '|'.join(agents)
    matches = match_regex(data, data.user_agent, [reg])
    print_matches(len(matches), 'scanning tools')
    return matches

def mark_ddos_traffic(data):
  SM_LIMIT = 5
  MD_LIMIT = 300
  LG_LIMIT = 2000
  ddos_rows = []

  last_found = 0
  dump_buffer = collections.deque(100 * [0], 100)

  small = collections.deque(100 * [0], 100)
  med = collections.deque(1000 * [0], 1000)
  large = collections.deque(10000 * [0], 10000)
  for index, row in data.iterrows():
    dump_buffer.appendleft(row)

    time = datetime.strptime(row.time, "%H:%M:%S")
    small.appendleft(time)
    med.appendleft(time)
    large.appendleft(time)

    if index > 10000 and index % 100 == 0:
      smdelta = abs((small[-1] - small[0]).total_seconds())
      meddelta = abs((med[-1] - med[0]).total_seconds())
      lgdelta = abs((large[-1] - large[0]).total_seconds())

      if smdelta < SM_LIMIT or meddelta < MD_LIMIT or lgdelta < LG_LIMIT:
        if index > last_found + 100:
          ddos_rows += list(dump_buffer)
          last_found = index
        print('[!] Found a potential ddos attack.', '100 in', smdelta, '1000 in ', meddelta, '10000 in', lgdelta)

      if index % 1000 == 0:
        sys.stdout.write("Small: %5d  Med: %5d  Large: %10d  %%\r" % (smdelta, meddelta, lgdelta))
        sys.stdout.flush()


  result = pd.DataFrame(ddos_rows)
  result['reason'] = 'DDOS'
  return result


# a good idea would be to only have a few log files when testing / developing for quick feedback
# if memory error, consider using 64 bit version of python or buy more ram :)
blacklist = fetch_blacklisted_addresses()
# all logs can be found at /homes/ih1115/ssl-logs
# a smaller set of these logs can be found at /homes/ih1115/min-ssl-logs
data = parse_files_into_database("/homes/ih1115/ssl-logs")
# data = parse_files_into_database("../ssl-logs")

# Signature
filter_scanning_tools(data, "scanners-user-agents.data").to_csv('scanning_tools.csv', index=False)
filter_xss(data).to_csv('possible_xss.csv', index=False)
filter_sqli(data).to_csv('possible_sqli.csv', index=False)
filter_remote_file_inclusion(data).to_csv('remote_file_inclusion.csv', index=False)
filter_requests_with_no_useragent(data).to_csv('useragent_not_set.csv', index=False)
filter_requests_with_no_referrer(data).to_csv('referrer_not_set.csv', index=False)

# Anaomoly
mark_ddos_traffic(data).to_csv('possible_ddos.csv', index=False)
filter_blacklisted_addresses(data, blacklist).to_csv('blacklisted_addresses.csv', index=False)
filter_fake_crawler_bots(data).to_csv('possible_fake_bots.csv', index=False)

