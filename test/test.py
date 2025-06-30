import unittest
from os import listdir, path
from shutil import rmtree
from io import BytesIO
import sys, subprocess, time
from klutshnik import klutshnik
from klutshnik.cfg import getcfg
import tracemalloc
from pyoprf import multiplexer
import contextlib

# to get coverage, run
# PYTHONPATH=.. coverage run test.py
# coverage report -m
# to just run the tests do
# python3 -m unittest discover --start-directory .

keyid = b"keyid"
data = b"data1"

class Input:
  def __init__(self, txt = None):
    if txt is None:
      self.buffer = BytesIO(data)
    else:
      self.buffer = BytesIO(txt)
  def isatty(self):
      return False
  def close(self):
    return

test_path = path.dirname(path.abspath(__file__))
klutshnik.config = klutshnik.processcfg(getcfg('klutshnik', test_path ))
klutshnik.config['ltsigkey_path']="client.key"
#for s in klutshnik.config['servers'].keys():
#  klutshnik.config['servers'][s]['ssl_cert']='/'.join([test_path, klutshnik.config['servers'][s]['ssl_cert']])
#  klutshnik.config['servers'][s]['ltsigkey']='/'.join([test_path, klutshnik.config['servers'][s]['ltsigkey']])

def connect(peers=None):
  if peers == None:
    peers = klutshnik.config['servers']
  m = multiplexer.Multiplexer(peers)
  m.connect()
  return m

class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
      cls._oracles = []
      for idx in range(len(klutshnik.config['servers'])):
        log = open(f"{test_path}/servers/{idx}/log", "w")
        cls._oracles.append(
          (subprocess.Popen("../../../server/zig-out/bin/klutshnikd", cwd = f"{test_path}/servers/{idx}/", stdout=log, stderr=log, pass_fds=[log.fileno()]), log))
        log.close()
      time.sleep(0.8)

    @classmethod
    def tearDownClass(cls):
      for p, log in cls._oracles:
        p.kill()
        r = p.wait()
        log.close()
      time.sleep(0.4)

    def tearDown(self):
      for idx in range(len(klutshnik.config['servers'])):
        ddir = f"{test_path}/servers/{idx}/data/"
        if not path.exists(ddir): continue
        for f in listdir(ddir):
          rmtree(ddir+f)

    def test_create(self):
        with connect() as s:
            res = klutshnik.create(s, keyid)
        self.assertIsInstance(res, str)

    def test_create_2x(self):
        with connect() as s:
            res = klutshnik.create(s, keyid)
        self.assertIsInstance(res, str)
        with connect() as s:
            self.assertRaises(ValueError, klutshnik.create, s, keyid)

    def test_decrypt(self):
        with connect() as s:
            pk = klutshnik.create(s, keyid)
        o = BytesIO()
        i = Input()
        sys.stdin = i
        with contextlib.redirect_stdout(o):
          klutshnik.encrypt(pk)
        ct = o.getvalue()

        # reading from fd 0 and writing to fd 1 fucks this contextlib stuff up.

        o = BytesIO()
        i = Input(ct)
        with contextlib.redirect_stdout(o):
          with connect() as s:
            klutshnik.decrypt(s)
        self.assertEqual(data, o.getvalue())

    #def test_invalid_pwd(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get, s, otherpwd, keyid)

    #def test_invalid_keyid(self):
    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get, s, pwd, keyid)

    #def test_update(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))
    #    with connect() as s:
    #        res = klutshnik.get(s, pwd, keyid)
    #    self.assertIsInstance(res, str)
    #    self.assertEqual(res.encode('utf8'),data)

    #    updated = b"updated blob"
    #    with connect() as s:
    #        self.assertTrue(klutshnik.update(s, pwd, keyid, updated))

    #    with connect() as s:
    #        res1 = klutshnik.get(s, pwd, keyid)
    #    self.assertIsInstance(res1, str)
    #    self.assertEqual(res1.encode('utf8'),updated)

    #def test_update_invalid_pwd(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))
    #    with connect() as s:
    #        res = klutshnik.get(s, pwd, keyid)
    #    self.assertIsInstance(res, str)
    #    self.assertEqual(res.encode('utf8'),data)

    #    updated = b"updated blob"
    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.update, s, otherpwd, keyid, updated)

    #def test_delete(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    with connect() as s:
    #        self.assertTrue(klutshnik.delete(s, pwd, keyid))

    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get, s, pwd, keyid)

    #def test_delete_invalid_pwd(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.delete, s, otherpwd, keyid)

    #def test_reset_fails(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    with connect() as s:
    #         self.assertRaises(ValueError, klutshnik.get, s, otherpwd, keyid)

    #    with connect() as s:
    #        res = klutshnik.get(s, pwd, keyid)
    #    self.assertIsInstance(res, str)
    #    self.assertEqual(res.encode('utf8'),data)

    #def test_lock(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    # lock it
    #    for _ in range(3):
    #        with connect() as s:
    #            self.assertRaises(ValueError, klutshnik.get, s, otherpwd, keyid)

    #    # check that it is locked
    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get, s, pwd, keyid)

    #def test_get_rtoken(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    # get recovery token
    #    with connect() as s:
    #        rtoken = klutshnik.get_recovery_tokens(s, pwd, keyid)
    #    self.assertIsInstance(rtoken, str)

    #def test_get_rtoken_invalid_pwd(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    # get recovery token
    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get_recovery_tokens, s, otherpwd, keyid)

    #def test_unlock(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    # get recovery token
    #    with connect() as s:
    #        rtoken = klutshnik.get_recovery_tokens(s, pwd, keyid)
    #    self.assertIsInstance(rtoken, str)

    #    # lock it
    #    for _ in range(3):
    #        with connect() as s:
    #            self.assertRaises(ValueError, klutshnik.get, s, otherpwd, keyid)

    #    # check that it is locked
    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get, s, pwd, keyid)

    #    # unlock it
    #    with connect() as s:
    #      self.assertTrue(klutshnik.unlock(s, rtoken, keyid))

    #    # check success of unlocking
    #    with connect() as s:
    #        res = klutshnik.get(s, pwd, keyid)
    #    self.assertIsInstance(res, str)
    #    self.assertEqual(res.encode('utf8'),data)

    #def test_unlock_invalid_rtoken(self):
    #    with connect() as s:
    #        self.assertTrue(klutshnik.create(s, pwd, keyid, data))

    #    # get recovery token
    #    with connect() as s:
    #        rtoken = klutshnik.get_recovery_tokens(s, pwd, keyid)
    #    self.assertIsInstance(rtoken, str)

    #    # lock it
    #    for _ in range(3):
    #        with connect() as s:
    #            self.assertRaises(ValueError, klutshnik.get, s, otherpwd, keyid)

    #    # check that it is locked
    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get, s, pwd, keyid)

    #    # unlock it
    #    with connect() as s:
    #      self.assertRaises(ValueError, klutshnik.unlock, s, rtoken[::-1], keyid)

    #    # check success of unlocking
    #    with connect() as s:
    #        self.assertRaises(ValueError, klutshnik.get, s, pwd, keyid)

if __name__ == '__main__':
  unittest.main()
