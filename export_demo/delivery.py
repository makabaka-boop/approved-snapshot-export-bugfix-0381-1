"""指定接收人的批量交付。

不变量：

1. **授权三元组绑定**：授权在创建时绑定 ``(申请, 接收人, 分块清单)``。领取请求
   必须与该三元组逐字一致；只凭"同一申请人"无法借授权领取其另一份导出。
2. **请求指纹幂等**：``request_key`` 的语义是"同一请求的重试标识"，在同一接收人
   范围内全局唯一（跨授权/跨导出也不可复用）。服务端为
   ``(grant_id, application_id, indexes)`` 计算请求指纹并随回执存档；
   同键同指纹 → 返回原回执；同键不同指纹（换了导出或分块清单）→ 拒绝。
3. **整批原子**：预检（全部块都属于授权申请且尚未交付）与全部
   ``available -> delivered`` 翻转在同一个 ``BEGIN IMMEDIATE`` 事务内完成，
   任何一块不满足则整批回滚，不会出现"前几块已交付、整批失败"。
4. **撤销/到期只阻止新交付**：已完成的回执是历史交付证据，授权撤销或到期后，
   原接收人持原 ``request_key``（同指纹）仍可取回与回执完全相同的字节；
   但换导出、换清单或换接收人仍被拒绝。
5. **接收人留痕**：交付动作（含块翻转）以**实际接收人**身份写审计，
   ``chunks.claimed_by`` 记接收人；回执固化每个块的 sha256，
   授权范围、实际内容与历史交付证据可互相核对。
"""

import hashlib
import json
import sqlite3
import time
import uuid

from . import audit
from .errors import (
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    ValidationError,
)
from .schema import write_tx

SCHEMA = """
CREATE TABLE IF NOT EXISTS recipient_grants (
 id TEXT PRIMARY KEY, application_id INTEGER NOT NULL, owner TEXT NOT NULL,
 recipient TEXT NOT NULL, indexes TEXT NOT NULL, expires INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recipient_receipts (
 grant_id TEXT NOT NULL, request_key TEXT NOT NULL,
 recipient TEXT NOT NULL, application_id INTEGER NOT NULL,
 fingerprint TEXT NOT NULL, payload TEXT NOT NULL,
 delivered_at TEXT NOT NULL,
 PRIMARY KEY(grant_id,request_key)
);
-- request_key 标识"接收人的一次领取请求"，在同一接收人范围内全局唯一，
-- 防止同键跨授权/跨导出重放被当成不同请求。
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_recipient_key
 ON recipient_receipts(recipient, request_key);
"""

# 轻量迁移：旧库补齐回执表新增列（演示环境的临时库直接重建）。
_MIGRATIONS = (
    "ALTER TABLE recipient_receipts ADD COLUMN recipient TEXT",
    "ALTER TABLE recipient_receipts ADD COLUMN application_id INTEGER",
    "ALTER TABLE recipient_receipts ADD COLUMN fingerprint TEXT",
    "ALTER TABLE recipient_receipts ADD COLUMN delivered_at TEXT",
)


def _request_fingerprint(grant_id, application_id, indexes):
    """绑定授权、导出与分块清单的请求指纹：任一项改变即不匹配。"""
    material = audit.canonical_json(
        {"grant_id": grant_id, "application_id": application_id, "indexes": indexes}
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

class _Deny(Exception):
    """事务内拒绝：回滚后在事务外补一条 denied 审计（与 service 层同构）。"""

    def __init__(self, reason, message, exc_cls):
        self.reason = reason
        self.message = message
        self.exc_cls = exc_cls


class DeliveryService:
    def __init__(self, exports, clock=None):
        self.exports = exports
        self.clock = clock or time.time
        c = exports._conn()
        try:
            c.executescript(SCHEMA)
            for stmt in _MIGRATIONS:
                try:
                    c.execute(stmt)
                except Exception:
                    pass  # 列已存在
        finally:
            c.close()

    # ---------------------------------------------------------------- 授权

    def grant(self, owner, application_id, recipient, indexes, expires):
        app = self.exports.get_application(owner, application_id)
        if app["applicant"] != owner or app["status"] != "approved":
            raise ForbiddenError("approved export owner required")
        self.exports._load_actor(recipient)
        indexes = self._validate_indexes(indexes)
        if expires <= self.clock():
            raise ValidationError("expiry is in the past")
        gid = uuid.uuid4().hex

        def work(c):
            # 授权清单必须落在该导出实际存在的块范围内
            total = c.execute(
                "SELECT COUNT(*) FROM chunks WHERE application_id=?",
                (application_id,),
            ).fetchone()[0]
            if any(i >= total for i in indexes):
                raise ValidationError(
                    f"chunk index out of range (this export has {total} chunks)"
                )
            c.execute(
                "INSERT INTO recipient_grants VALUES (?,?,?,?,?,?,0)",
                (gid, application_id, owner, recipient, json.dumps(indexes), expires),
            )
            audit.append_entry(
                c, actor=owner, action="RECIPIENT_GRANTED", entity=gid,
                details={
                    "application_id": application_id,
                    "recipient": recipient,
                    "indexes": indexes,
                    "expires": expires,
                },
            )

        self.exports._run_write_tx(work)
        return {
            "id": gid,
            "application_id": application_id,
            "recipient": recipient,
            "indexes": indexes,
            "expires": expires,
        }

    def revoke(self, owner, grant_id):
        def work(c):
            row = c.execute(
                "SELECT * FROM recipient_grants WHERE id=?", (grant_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("grant not found")
            if row["owner"] != owner:
                raise ForbiddenError("grant owner required")
            if row["revoked"]:
                raise InvalidStateError("grant already revoked")
            c.execute(
                "UPDATE recipient_grants SET revoked=1 WHERE id=?", (grant_id,)
            )
            audit.append_entry(
                c, actor=owner, action="RECIPIENT_REVOKED", entity=grant_id,
                details={},
            )

        self.exports._run_write_tx(work)
        return {"ok": True}

    # ---------------------------------------------------------------- 领取

    @staticmethod
    def _validate_indexes(indexes):
        if not indexes or not isinstance(indexes, list):
            raise ValidationError("nonempty chunk index list required")
        if any(type(x) is not int or x < 0 for x in indexes):
            raise ValidationError("nonnegative chunk indexes required")
        if len(set(indexes)) != len(indexes):
            raise ValidationError("duplicate chunk indexes in request")
        return list(indexes)

    def _deny(self, actor, grant_id, deny):
        c = self.exports._conn()
        try:
            with write_tx(c):
                audit.append_entry(
                    c, actor=actor, action="RECIPIENT_RECEIVED", entity=grant_id,
                    result="denied",
                    details={"reason": deny.reason, "message": deny.message},
                )
        finally:
            c.close()
        raise deny.exc_cls(deny.message)

    def receive(self, recipient, grant_id, application_id, indexes, request_key):
        self.exports._load_actor(recipient)
        if not isinstance(application_id, int):
            raise ValidationError("application_id must be an integer")
        if not request_key or not isinstance(request_key, str):
            raise ValidationError("request_key required")
        indexes = self._validate_indexes(indexes)
        fingerprint = _request_fingerprint(grant_id, application_id, indexes)

        def work(c):
            grant = c.execute(
                "SELECT * FROM recipient_grants WHERE id=?", (grant_id,)
            ).fetchone()
            if not grant:
                raise _Deny("grant_not_found", "grant not found", NotFoundError)
            if grant["recipient"] != recipient:
                raise _Deny(
                    "recipient_mismatch",
                    "only the named recipient can use this grant",
                    ForbiddenError,
                )
            # —— 先看回执：已完成交付的证据永远可取（撤销/到期只阻止新交付）。
            # request_key 在接收人范围内全局标识一次请求，故按
            # (recipient, request_key) 查找，跨授权同键也会命中。
            old = c.execute(
                "SELECT grant_id, recipient, application_id, fingerprint, payload "
                "FROM recipient_receipts WHERE recipient=? AND request_key=?",
                (recipient, request_key),
            ).fetchone()
            if old:
                if old["grant_id"] != grant_id or old["application_id"] != application_id:
                    raise _Deny(
                        "request_conflict",
                        "request_key already used for a different grant/export",
                        InvalidStateError,
                    )
                # 同一领取编号必须对应同一导出、同一分块清单
                if old["fingerprint"] and old["fingerprint"] != fingerprint:
                    raise _Deny(
                        "request_conflict",
                        "request_key already used for a different chunk list",
                        InvalidStateError,
                    )
                # 重放校验：固化的摘要必须仍是授权申请下这些块的当前字节
                payload = json.loads(old["payload"])
                self._verify_replay(c, grant, payload)
                audit.append_entry(
                    c, actor=recipient, action="RECIPIENT_RECEIVED", entity=grant_id,
                    result="success",
                    details={
                        "application_id": application_id,
                        "indexes": indexes,
                        "request_key": request_key,
                        "replayed": True,
                    },
                )
                return payload

            # —— 新交付：授权必须有效 ——
            if grant["revoked"] or self.clock() >= grant["expires"]:
                raise _Deny("grant_inactive", "grant revoked or expired",
                            InvalidStateError)
            # 授权三元组之一：导出必须与授权创建时绑定的导出一致
            if grant["application_id"] != application_id:
                raise _Deny(
                    "application_mismatch",
                    "grant is bound to a different export application",
                    ForbiddenError,
                )
            app = c.execute(
                "SELECT applicant, status FROM export_applications WHERE id=?",
                (application_id,),
            ).fetchone()
            if app is None:
                raise _Deny("application_not_found", "export application not found",
                            NotFoundError)
            if app["applicant"] != grant["owner"]:
                raise _Deny(
                    "owner_mismatch",
                    "grant owner is no longer the applicant of this export",
                    ForbiddenError,
                )
            if app["status"] != "approved":
                raise _Deny(
                    "application_not_approved",
                    "export is not in approved state; batch not delivered",
                    InvalidStateError,
                )
            allowed = json.loads(grant["indexes"])

            # —— 预检：全部块都在授权清单内、属于本申请、且尚未交付 ——
            chunks = []
            for index in indexes:
                if index not in allowed:
                    raise _Deny(
                        "chunk_outside_grant",
                        f"chunk {index} is outside the grant scope",
                        ForbiddenError,
                    )
                row = c.execute(
                    "SELECT chunk_index, content, content_sha256, status FROM chunks "
                    "WHERE application_id=? AND chunk_index=?",
                    (application_id, index),
                ).fetchone()
                if row is None:
                    raise _Deny(
                        "bad_chunk", f"chunk index does not exist: {index}",
                        NotFoundError,
                    )
                if row["status"] != "available":
                    # 已有交付（申请人自领或另一批次），本批不做部分交付
                    raise _Deny(
                        "chunk_already_delivered",
                        f"chunk {index} already delivered; batch not delivered",
                        InvalidStateError,
                    )
                chunks.append(row)

            # —— 整批翻转：单事务原子完成，任一失败整体回滚 ——
            delivered_at = c.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')"
            ).fetchone()[0]
            received = []
            for row in chunks:
                index = row["chunk_index"]
                cur = c.execute(
                    "UPDATE chunks SET status='delivered', claimed_by=?, "
                    "claimed_at=? WHERE application_id=? AND chunk_index=? "
                    "AND status='available'",
                    (recipient, delivered_at, application_id, index),
                )
                if cur.rowcount != 1:  # 并发抢先（理论上同锁内不会发生）
                    raise _Deny(
                        "contended",
                        f"chunk {index} changed concurrently; retry the batch",
                        InvalidStateError,
                    )
                seq = audit.append_entry(
                    c, actor=recipient, action="CHUNK_CLAIMED",
                    entity=f"export:{application_id}/chunk:{index}",
                    result="success",
                    details={
                        "chunk_index": index,
                        "repeated": False,
                        "sha256": row["content_sha256"],
                        "via_grant": grant_id,
                        "recipient": recipient,
                    },
                )
                c.execute(
                    "UPDATE chunks SET audit_seq=? WHERE application_id=? "
                    "AND chunk_index=?",
                    (seq, application_id, index),
                )
                received.append(
                    {
                        "index": index,
                        "sha256": row["content_sha256"],
                        "text": row["content"].decode(),
                        "recipient": recipient,
                    }
                )

            payload = {
                "grant_id": grant_id,
                "recipient": recipient,
                "application_id": application_id,
                "request_key": request_key,
                "chunks": received,
            }
            c.execute(
                "INSERT INTO recipient_receipts "
                "(grant_id, request_key, recipient, application_id, fingerprint, "
                "payload, delivered_at) VALUES (?,?,?,?,?,?,?)",
                (
                    grant_id, request_key, recipient, application_id, fingerprint,
                    json.dumps(payload), delivered_at,
                ),
            )
            audit.append_entry(
                c, actor=recipient, action="RECIPIENT_RECEIVED", entity=grant_id,
                result="success",
                details={
                    "application_id": application_id,
                    "indexes": indexes,
                    "request_key": request_key,
                    "fingerprint": fingerprint,
                    "replayed": False,
                    "chunk_sha256": [r["sha256"] for r in received],
                },
            )
            return payload

        try:
            return self.exports._run_write_tx(work)
        except _Deny as deny:
            self._deny(recipient, grant_id, deny)
        except sqlite3.IntegrityError:
            # 并发下另一个请求已占用同一 (recipient, request_key)
            self._deny(
                recipient, grant_id,
                _Deny("request_conflict",
                      "request_key already used for another request",
                      InvalidStateError),
            )

    # ---------------------------------------------------------------- 重放核对

    def _verify_replay(self, c, grant, payload):
        """凭原回执重取时，逐条核对：接收人、授权申请、块字节摘要。

        任何一项对不上都拒绝，绝不返回"张冠李戴"的字节。
        """
        if payload.get("recipient") != grant["recipient"]:
            raise _Deny("recipient_mismatch",
                        "receipt belongs to another recipient", ForbiddenError)
        app_id = payload.get("application_id")
        if app_id != grant["application_id"]:
            raise _Deny(
                "application_mismatch",
                "receipt is bound to a different export application",
                ForbiddenError,
            )
        for piece in payload.get("chunks", []):
            row = c.execute(
                "SELECT content_sha256 FROM chunks WHERE application_id=? "
                "AND chunk_index=?",
                (app_id, piece["index"]),
            ).fetchone()
            if row is None or row["content_sha256"] != piece["sha256"]:
                raise _Deny(
                    "receipt_content_mismatch",
                    f"stored receipt for chunk {piece['index']} no longer matches "
                    "the approved export bytes",
                    InvalidStateError,
                )
