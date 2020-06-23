#!/usr/bin/env python3
import urllib.request
import pprint
import json
import copy
import sys
import time

url = 'http://localhost:8181/onos/v1'
username = 'onos'
password = 'rocks'

def find_path(graph, start, end, path=[]):
  path = path + [start]
  if start == end:
    return path
  if start not in graph:
    return None
  shortest = None
  for node in graph[start]:
    if node not in path:
      newpath = find_path(graph, node, end, path)
      if newpath:
        if not shortest or len(newpath) < len(shortest):
          shortest = newpath
  return shortest

def setup_flow(device, rules):
    params = json.dumps(rules).encode('utf8')
    req = urllib.request.Request(url + '/flows/' + device, data=params,
                             headers={'content-type': 'application/json'})
    result = urllib.request.urlopen(req).read()

def get_mac(device, port):
  print("Importing MAC information")
  ports = get_json_response(url + '/devices/' + device + '/ports')['ports']
  for currentPort in ports:
    if currentPort['port'] == port:
      return currentPort['annotations']['portMac']


def generate_flow_rules(path, host1, host2):
  print("Pushing Flow rules")
  rules = {}
  flow_template = {
    'priority': 40001,
    'timeout': 0,
    'isPermanent': True,
    'deviceId': "of:0000000000000001",
    'treatment': {
      'instructions': [
        {
          'type': 'OUTPUT',
          'port': '1'
        }
      ]
    },
    'selector': {
      'criteria': [
        {
          'type': 'ETH_SRC',
          'mac': 'asfd'
        },
        {
          'type': 'IN_PORT',
          'port': '2'
        }
      ]
    }
  }

  in_port = None
  out_port = None
  device_id = None
  for index, item in enumerate(path):
    if index % 3 == 0:
      in_port = item.split('/')[1]
    elif index % 3 == 1:
      device_id = item
    elif index % 3 == 2:
      out_port = item.split('/')[1]

      new_rule_in = copy.deepcopy(flow_template)
      new_rule_in['deviceId'] = device_id
      new_rule_in['treatment']['instructions'][0]['port'] = out_port
      new_rule_in['selector']['criteria'][1]['port'] = in_port
      new_rule_in['selector']['criteria'][0]['mac'] = host1.split('/')[0]
      new_rule_in['selector']['criteria'][0]['type'] = 'ETH_SRC'

      new_rule_out = copy.deepcopy(flow_template)
      new_rule_out['deviceId'] = device_id
      new_rule_out['treatment']['instructions'][0]['port'] = in_port
      new_rule_out['selector']['criteria'][1]['port'] = out_port
      new_rule_out['selector']['criteria'][0]['mac'] = host2.split('/')[0]
      new_rule_out['selector']['criteria'][0]['type'] = 'ETH_SRC'
      rules[device_id] = [new_rule_in, new_rule_out]


  return rules

def get_json_response(url):
    return json.loads(urllib.request.urlopen(url).read().decode('utf-8'))

def delete_single_flow(flow_id, switch_id):
  req = urllib.request.Request(
    url + '/flows/' + switch_id + '/' + flow_id,
    method='DELETE'
  )
  result = urllib.request.urlopen(req).read()

def delete_all_rules(switch_id):
  rules = get_json_response(url + '/flows/' + switch_id)['flows']
  for flow in rules:
    if flow['treatment']['instructions'][0]['port'] != 'CONTROLLER':
      delete_single_flow(flow['id'], switch_id)

def get_devices():
  print("Importing Switch information")
  devices = get_json_response(url + '/devices')['devices']
  return devices

def get_links():
  print("Importing Link information")
  links = get_json_response(url + '/links')['links']
  return links

def register_http_opener_auth():
  print("Checking authentication")
  password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
  password_mgr.add_password(None, url, username, password)
  handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
  opener = urllib.request.build_opener(handler)
  urllib.request.install_opener(opener)
  print("Authentication completed!")

def generate_graph(devices, links):
  print("Graph generation")
  graph = {}
  for item in devices:
    graph[item['id']] = []
    ports = get_json_response(url + '/devices/' + item['id'] + '/ports')['ports']
    for port in ports:
      if port['isEnabled'] == True:
        graph[item['id']].append(item['id'] + '/' + port['port'])
        graph[item['id'] + '/' + port['port']] = []
        graph[item['id'] + '/' + port['port']].append(item['id'])

  for item in links:
    if item['state'] == 'ACTIVE':
      graph[item['src']['device'] + '/' + item['src']['port']].append(item['dst']['device'] + '/' + item['dst']['port'])

  return graph

def setup_all_rules(rules):
  for key, value in flow_rules.items():
    for item in value:
      setup_flow(key, item)

def get_position(hostid):
  return '/'.join(list(get_json_response(url + '/hosts/' + hostid)['locations'][0].values()))

def check_path_equlity(path1, path2):
  print("Path check underway")
  if len(path1) == len(path2):
    for index in range(len(path1)):
      if path1[index] != path2[index]:
        return False
    else:
      return True
  else:
    return False


if __name__ == "__main__":
  pp = pprint.PrettyPrinter(indent=4)
  if len(sys.argv) < 3:
    print('Not enough arguments!')
  else:
    register_http_opener_auth()
    while True:
      devices = get_devices()
      links = get_links()
      graph = generate_graph(devices, links)
      #print(type(graph))
      jsson=json.dumps(graph)
      f=open("graph_D1.json","w")
      f.write(jsson)
      f.close()


      host1 = sys.argv[1]
      host2 = sys.argv[2]
      host1_position = get_position(host1)
      host2_position = get_position(host2)
      print("Deleting old flow rules")
      for device in devices:
        delete_all_rules(device['id'])
      print("Finding the shortest path")
      path = find_path(graph, host1_position, host2_position)
      print("Shortest path:\n%s" % path)
      if path is not None:
        flow_rules = generate_flow_rules(path, host1, host2)
        setup_all_rules(flow_rules)
        print("Setting up new flow rules")
        break
      else:
         print('Failed to find a path!!')


    print('Initial path setup done!')

    while True:
      time.sleep(5)
      devices = get_devices()
      links = get_links()
      current_graph = generate_graph(devices, links)
      print("Finding a new path")
      new_path = find_path(current_graph, host1_position, host2_position)
      if new_path is None:
        print('Failed to find a path!!')
        continue

      if not check_path_equlity(new_path, path):
        print("New path detected:\n%s" % new_path)
        flow_rules = generate_flow_rules(new_path, host1, host2)
        setup_all_rules(flow_rules)
        print("Setting up new flow rules")
      else:
        print('Path did not change!')

