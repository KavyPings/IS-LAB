"""
CONCEPT 11 : ACCESS CONTROL  (role based, time based, ownership)
(Lab 4, and EVERY scenario question that lists "user roles & permissions")

The sample exam question gives you Students / Faculties / HoDs with different
allowed actions. That is textbook RBAC. This file is the drop-in answer.

MODELS COVERED
  RBAC  - permission depends on the user's ROLE
  DAC   - owner of an object decides who may touch it
  MAC / Bell-LaPadula - clearance levels, "no read up, no write down"
  Time-based - access valid only between two timestamps
"""

import hashlib
import os
from datetime import datetime, timedelta


# ===========================================================================
# 1. ROLE BASED ACCESS CONTROL (RBAC)  <- use this one by default
# ===========================================================================

# ROLE -> set of permission names. Edit this dict to match the question.
ROLE_PERMISSIONS = {
    "student": {"encrypt", "sign", "upload", "view_own"},
    "faculty": {"decrypt", "verify", "hash", "view_all"},
    "hod":     {"view_hash", "verify"},
    "admin":   {"encrypt", "decrypt", "sign", "verify", "hash",
                "upload", "view_all", "view_hash", "manage_users"},
}


class User:
    """One account. Password is stored as a salted SHA-256 hash, never plain."""

    def __init__(self, username, password, role):
        self.username = username
        self.role = role
        self.salt = os.urandom(16)
        self.pw_hash = self._hash(password)
        self.created = datetime.now()

    def _hash(self, password):
        return hashlib.sha256(self.salt + password.encode()).hexdigest()

    def check_password(self, password):
        return self._hash(password) == self.pw_hash

    def permissions(self):
        return ROLE_PERMISSIONS.get(self.role, set())

    def can(self, action):
        return action in self.permissions()


class AccessControl:
    """Small in-memory user directory + login + permission checks."""

    def __init__(self):
        self.users = {}
        self.current = None                      # who is logged in

    def add_user(self, username, password, role):
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"unknown role {role}")
        self.users[username] = User(username, password, role)
        return self.users[username]

    def login(self, username, password):
        u = self.users.get(username)
        if u and u.check_password(password):
            self.current = u
            return True
        return False

    def logout(self):
        self.current = None

    def require(self, action):
        """Raise if the logged-in user may not do `action`.
        Call this at the top of every menu handler."""
        if self.current is None:
            raise PermissionError("not logged in")
        if not self.current.can(action):
            raise PermissionError(
                f"role '{self.current.role}' is not allowed to '{action}'")
        return True

    def allowed(self, action):
        """Same check but returns True/False instead of raising."""
        return self.current is not None and self.current.can(action)


# ===========================================================================
# 2. DISCRETIONARY ACCESS CONTROL (DAC) - owner grants rights per object
# ===========================================================================

class AccessMatrix:
    """matrix[(subject, object)] = {'read','write',...}"""

    def __init__(self):
        self.matrix = {}
        self.owners = {}

    def create(self, obj, owner):
        self.owners[obj] = owner
        self.matrix[(owner, obj)] = {"read", "write", "delete"}

    def grant(self, granter, subject, obj, rights):
        if self.owners.get(obj) != granter:
            raise PermissionError("only the owner can grant rights")
        self.matrix.setdefault((subject, obj), set()).update(rights)

    def revoke(self, granter, subject, obj):
        if self.owners.get(obj) != granter:
            raise PermissionError("only the owner can revoke rights")
        self.matrix.pop((subject, obj), None)

    def check(self, subject, obj, right):
        return right in self.matrix.get((subject, obj), set())


# ===========================================================================
# 3. MANDATORY ACCESS CONTROL / BELL-LAPADULA
# ===========================================================================

LEVELS = {"public": 0, "internal": 1, "confidential": 2, "secret": 3, "topsecret": 4}


def can_read(subject_clearance, object_classification):
    """Simple Security Property: NO READ UP."""
    return LEVELS[subject_clearance] >= LEVELS[object_classification]


def can_write(subject_clearance, object_classification):
    """*-Property: NO WRITE DOWN."""
    return LEVELS[subject_clearance] <= LEVELS[object_classification]


# ===========================================================================
# 4. TIME-BASED / LIMITED-DURATION ACCESS  (DRM style questions)
# ===========================================================================

class TimedGrant:
    """Give a user access to one object for N hours, revocable at any time."""

    def __init__(self):
        self.grants = {}                     # (user, obj) -> expiry datetime

    def grant(self, user, obj, hours=24):
        self.grants[(user, obj)] = datetime.now() + timedelta(hours=hours)

    def revoke(self, user, obj):
        self.grants.pop((user, obj), None)

    def check(self, user, obj):
        exp = self.grants.get((user, obj))
        return exp is not None and datetime.now() < exp

    def list_active(self):
        now = datetime.now()
        return {k: v for k, v in self.grants.items() if v > now}


if __name__ == "__main__":
    ac = AccessControl()
    ac.add_user("kavy", "pass123", "student")
    ac.add_user("prof", "pass456", "faculty")
    print("login ok   :", ac.login("kavy", "pass123"))
    print("can encrypt:", ac.allowed("encrypt"), "| can decrypt:", ac.allowed("decrypt"))
    try:
        ac.require("decrypt")
    except PermissionError as e:
        print("blocked    :", e)

    m = AccessMatrix()
    m.create("marks.txt", "prof")
    m.grant("prof", "kavy", "marks.txt", {"read"})
    print("DAC read   :", m.check("kavy", "marks.txt", "read"),
          "| write:", m.check("kavy", "marks.txt", "write"))

    print("BLP read   :", can_read("confidential", "internal"),
          "| read up:", can_read("internal", "secret"))

    t = TimedGrant()
    t.grant("kavy", "movie1", hours=2)
    print("timed      :", t.check("kavy", "movie1"), t.check("kavy", "movie2"))
