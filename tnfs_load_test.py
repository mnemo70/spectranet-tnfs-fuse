#!/usr/bin/python

import argparse
import logging
import random
import time
import threading
import tnfs_client3

logging.basicConfig()
logging.root.setLevel(logging.INFO)

class TestConn:
  def __init__(self, host, port, protocol):
     self.session = tnfs_client3.Session([host, port], protocol)
     self.pwd = []

  def path(self, file = None):
    segments = self.pwd
    if file:
      segments.append(file)
    return '/' + '/'.join(segments)
  
  def cd(self, dir):
    if dir == '..':
      self.pwd.pop()
    else:
      self.pwd.append(dir)

def run_session(iterations, connection_count, thread_id, host, port, protocol):
  try:
    connections = []
    for i in range(connection_count):
      connections.append(TestConn(host, port, protocol))

    for i in range(iterations):
      conn = random.choice(connections)
      entries = conn.session.ListDirX(conn.path(), '', 0, 0)
      dirs = [e for e in entries if e.isDir()]
      files = [e for e in entries if not e.isDir()]

      actions = ['stat_root']
      weights = [5]

      if len(dirs) > 0:
        actions += ['change_dir']
        weights += [5]
    
      if conn.path() != '/':
        actions += ['parent_dir']
        weights += [5]
    
      if len(files) > 0:
        actions += ['open_file']
        weights += [90]

      action = random.choices(actions, weights, k = 1)[0]
      if i % 100 == 0:
        logging.info("Thread: %d\tIteration: %d\tAction: %s", thread_id, i, action)

      match action:
        case 'stat_root':
          conn.session.Stat('/')

        case 'change_dir':
          conn.cd(random.choice(dirs).name)

        case 'parent_dir':
          conn.cd('..')

        case 'open_file':
          file = random.choice(files)
          path = conn.path(file.name)
          body = conn.session.GetFile(path)
          if len(body) != file.size:
            logging.critical('Invalid size for file %s', path)

    for c in connections:
      c.session.Umount()

  except ConnectionError as e:
    logging.critical(e, exc_info = True)

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('-t', '--threads', type=int, default = 1, help = 'Number of threads')
  parser.add_argument('-i', '--iterations', type=int, default = 1000, help = 'Number of iterations per thread')
  parser.add_argument('-c', '--connections', type=int, default = 32, help = 'Number of sessions/connections per thread')
  parser.add_argument('host')
  parser.add_argument('port', nargs='?', type=int, default=16384)

  group = parser.add_mutually_exclusive_group()
  group.add_argument('--tcp', action='store_true')
  group.add_argument('--udp', action='store_true')

  args = parser.parse_args()

  protocol = None
  if args.tcp:
    protocol = 'tcp'
  elif args.udp:
    protocol = 'udp'

  threads = []
  for i in range(args.threads):
    t = threading.Thread(target = run_session, args = [args.iterations, args.connections, i, args.host, args.port, protocol])
    threads.append(t)

  for t in threads:
    t.start()

  for t in threads:
    t.join()
