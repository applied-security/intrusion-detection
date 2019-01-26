from datetime import datetime
import pandas as pd
import pandasql
import numpy as np
sql = pandasql.PandaSQL()

fieldOrder = [
                'address',            # ip address
                'unknown_field_1',    # usually empty
                'unknown_field_2',    # usually empty
                'timestamp',          # time of request
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

def parseLine(line):
  # first tokenise by spaces
  obj = {}
  field_count = 0
  in_block = False   # block is considered anything within quotes or square brackets
  in_escape = False  # next character is escaped, e.g. the text we see is literally \"

  current_token = ""
  for character in line:

    will_escape = False
    if character == "\\" and not in_escape:
      will_escape = True
    elif (character == "\"" or character == "[" or character == "]") and not in_escape:
      in_block = not in_block
    elif character == " " and not in_block:
      obj[fieldOrder[field_count]] = current_token
      current_token = ""
      field_count += 1
    else:
      current_token += character
    in_escape = will_escape

  # now fine grain the tokens
  request_tokens = obj['request'].split(" ")
  if len(request_tokens) == 2:
    obj['method'] = request_tokens[0]
    obj['url'] = request_tokens[1]
    obj['protocol'] = request_tokens[2]
  del obj['request']

  # convert timestamp string into a useful data type
  obj['timestamp'] = datetime.strptime(obj['timestamp'], "%d/%b/%Y:%H:%M:%S %z")

  # convert timestamp back to a sql format
  obj['timestamp'] = obj['timestamp'].strftime("%Y-%m-%d %H:%M:%S")  

  return obj

def parseFileIntoDatabase(path):
  file = open(path, "r")
  data = []
  for line in file:
    data.append(parseLine(line))

  dataframe = pd.DataFrame(data)
  return dataframe

def filterRequestsWithNoUserAgent(data):
  return sql('select * from data where user_agent = "-"')

def filterRequestsWithNoReferrer(data):
  return sql('select * from data where referrer = "-"')


data = parseFileIntoDatabase("C:\\Users\\Rogue\\Downloads\\ssl-logs\\ssl-access.log-20181002\\ssl-access.log-20181002")
# now we can directly use SQL to collect data

# print(sql('select * from data where address like "213.%%"')) # %% is a single % which is wild card in sql
print(filterRequestsWithNoUserAgent(data))


# todo: https://security.stackexchange.com/questions/122692/should-i-block-the-yandex-bot
# we can check if user agents of yandex bots are legitmate yandex bots and not someone just using the Yandex User-Agent