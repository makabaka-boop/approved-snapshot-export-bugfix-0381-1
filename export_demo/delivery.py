"""Named-recipient delivery of approved export chunks."""
import json
import time
import uuid
from .errors import ForbiddenError, InvalidStateError, NotFoundError, ValidationError
from .schema import write_tx
from . import audit

SCHEMA = """
CREATE TABLE IF NOT EXISTS recipient_grants (
 id TEXT PRIMARY KEY, application_id INTEGER NOT NULL, owner TEXT NOT NULL,
 recipient TEXT NOT NULL, indexes TEXT NOT NULL, expires INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recipient_receipts (
 grant_id TEXT NOT NULL, request_key TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(grant_id,request_key)
);
"""

class DeliveryService:
    def __init__(self, exports, clock=None):
        self.exports = exports
        self.clock = clock or time.time
        c=exports._conn()
        try:c.executescript(SCHEMA)
        finally:c.close()

    def grant(self, owner, application_id, recipient, indexes, expires):
        app=self.exports.get_application(owner, application_id)
        if app['applicant'] != owner or app['status'] != 'approved':
            raise ForbiddenError('approved export owner required')
        self.exports._load_actor(recipient)
        if not indexes or any(type(x) is not int or x < 0 for x in indexes):
            raise ValidationError('nonnegative chunk indexes required')
        if expires <= self.clock():raise ValidationError('expiry is in the past')
        gid=uuid.uuid4().hex
        c=self.exports._conn()
        try:
            with write_tx(c):
                c.execute('INSERT INTO recipient_grants VALUES (?,?,?,?,?,?,0)',
                    (gid,application_id,owner,recipient,json.dumps(indexes),expires))
                audit.append_entry(c,actor=owner,action='RECIPIENT_GRANTED',entity=gid,
                    details={'application_id':application_id,'recipient':recipient,'indexes':indexes})
        finally:c.close()
        return {'id':gid,'application_id':application_id,'recipient':recipient,'expires':expires}

    def revoke(self, owner, grant_id):
        c=self.exports._conn()
        try:
            with write_tx(c):
                row=c.execute('SELECT * FROM recipient_grants WHERE id=?',(grant_id,)).fetchone()
                if not row:raise NotFoundError('grant not found')
                if row['owner']!=owner:raise ForbiddenError('grant owner required')
                c.execute('UPDATE recipient_grants SET revoked=1 WHERE id=?',(grant_id,))
                audit.append_entry(c,actor=owner,action='RECIPIENT_REVOKED',entity=grant_id,details={})
        finally:c.close()

    def receive(self, recipient, grant_id, application_id, indexes, request_key):
        self.exports._load_actor(recipient)
        c=self.exports._conn()
        try:
            grant=c.execute('SELECT * FROM recipient_grants WHERE id=?',(grant_id,)).fetchone()
            if not grant:raise NotFoundError('grant not found')
            if grant['recipient']!=recipient:raise ForbiddenError('recipient mismatch')
            if grant['revoked'] or self.clock()>=grant['expires']:
                raise InvalidStateError('grant inactive')
            old=c.execute('SELECT payload FROM recipient_receipts WHERE grant_id=? AND request_key=?',
                (grant_id,request_key)).fetchone()
            if old:return json.loads(old[0])
            allowed=json.loads(grant['indexes'])
        finally:c.close()
        received=[]
        for index in indexes:
            if index not in allowed:raise ForbiddenError('chunk outside grant')
            d=self.exports.claim_chunk(grant['owner'],application_id,index)
            received.append({'index':index,'sha256':d.content_sha256,'text':d.content.decode(),
                             'repeated':d.repeated,'recipient':recipient})
        payload={'grant_id':grant_id,'application_id':application_id,'chunks':received}
        c=self.exports._conn()
        try:
            with write_tx(c):
                c.execute('INSERT INTO recipient_receipts VALUES (?,?,?)',
                    (grant_id,request_key,json.dumps(payload)))
                audit.append_entry(c,actor=recipient,action='RECIPIENT_RECEIVED',entity=grant_id,
                    details={'application_id':application_id,'indexes':indexes,'request_key':request_key})
        finally:c.close()
        return payload
