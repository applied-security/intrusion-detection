from datetime import datetime
import pandas as pd
import pandasql
import numpy as np
import os
import socket
from tqdm import tqdm
sql = pandasql.PandaSQL()

field_order = [
                'address',            # ip address
                'unknown_field_1',    # usually empty
                'unknown_field_2',    # usually empty
                'timestamp',          # this gets split into 2 fields
                                      #    'day'    %Y-%m-%d
                                      #    'time'   %H:%M:%S
                'request',            # this field gets replaced into 3 fields
                                      #    'method'   e.g. GET
                                      #    'url'      e.g. /article1.html
                                      #    'protocol' e.g. HTTP/1.1
                'response_code',      # e.g. 404
                'unknown_field_3',    # some sort of code
                'referrer',           # e.g. "https://www.doc.ic.ac.uk/"
                'user_agent',
                'tls',                # e.g. TLSv1.2
                'unknown_field_4'     # something to do with encryption e.g. ECDHE-RSA-AES128-GCM-SHA256
              ]

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
      obj[field_order[field_count]] = current_token
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
  del obj['unknown_field_1']
  del obj['unknown_field_2']
  del obj['unknown_field_3']
  del obj['unknown_field_4']
  return obj

def parse_file_into_objects(path):
  file = open(path, "r")
  data = []
  for line in file:
    data.append(parse_line(line))
  return data

def find_all_access_logs(root):
  access_logs = []
  for root, dirs, files in os.walk(root):
    for file in files:
      if "ssl-access.log" in file and ".gz" not in file:
         access_logs.append(os.path.join(root, file))

  return access_logs

def parse_files_into_database(root):
  files = find_all_access_logs(root)
  number_of_files = len(files)
  print("[+] Found " + str(number_of_files) + " access logs!")
  print("[~] Loading access logs..")

  dataframe_collection = pd.DataFrame()
  for i in tqdm(range(number_of_files)):
    file = files[i]

    new_dataframe = pd.DataFrame(parse_file_into_objects(file))
    # dataframe_collection = dataframe_collection.append(new_dataframe, ignore_index=True)
    dataframe_collection = pd.concat([dataframe_collection, new_dataframe], ignore_index=True)

  print("[+] " + str(number_of_files) + " access logs loaded!")
  return dataframe_collection

def filter_requests_with_no_useragent(data):
  return sql('select * from data where user_agent = "-"')

def filter_requests_with_no_referrer(data):
  return sql('select * from data where referrer = "-"')

def calculate_total_requests_per_day(data):
  return sql('select count(*) as requests, day from data group by day')

def calculate_average_requests_per_day(data):
  number_of_days = sql('select count(distinct(day)) as number_of_days from data')['number_of_days'][0]
  return sql('select (count(*) / ' + str(number_of_days) + ') as average from data')['average'][0]

def filter_requests_by_yandex_useragent(data):
  return sql('select * from data where user_agent like "%%yandex%%"')

# finds user agents of yandex and reverse dns look up to see if they are legimate yandex bots
def filter_fake_yandex_bots(data):
  yandex_requests = filter_requests_by_yandex_useragent(data)
  for index, row in yandex_requests.iterrows():
    if "yandex" in socket.gethostbyaddr(row["address"])[0]:
      # we are only keeping the bad ones
      yandex_requests.drop(index, inplace=True)

# a good idea would be to only have a few log files when testing / developing for quick feedback
# if memory error, consider using 64 bit version of python or buy more ram :)
data = parse_files_into_database("/homes/ih1115/ssl-logs/")
filter_requests_with_no_useragent(data).to_csv('useragent_not_set.csv', index=False)
filter_requests_with_no_referrer(data).to_csv('referrer_not_set.csv', index=False)
filter_fake_yandex_bots(data).to_csv('fake_yandex_bot.csv', index=False)
