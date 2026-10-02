"""指定接收人批量交付的安全回归测试。

对应场景中的五类问题：
- 授权绑定导出甲，领取不能带回同一申请人的导出乙；
- 一批中后续分块被拒时，前面分块不得先记交付（整批原子）；
- 同一 request_key 换导出/换清单必须拒绝，不能冒充原请求成功；
- 撤销/到期只阻止新交付，已交付批次仍可由原接收人凭原回执重取原字节；
- 块状态、claimed_by 与审计必须记录实际接收人，回执摘要可核对。
"""

from __future__ import annotations

import json

from export_demo.delivery import DeliveryService
from export_demo.errors import (
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    ValidationError,
)
from export_demo.tests.base import ServiceCase


class DeliveryCase(ServiceCase):
    def setUp(self):
        super().setUp()
        self.clock = [1_000_000.0]
        self.dv = DeliveryService(self.svc, clock=lambda: self.clock[0])
        # alice 两份均已审批的导出甲/乙，chunk_size=2，6 行客户 → 各 3 块
        self.app_a = self._apply_approve(chunk_size=2)
        self.app_b = self._apply_approve(chunk_size=2)

    def _grant(self, app_id, recipient="carol", indexes=(0, 1), ttl=1000):
        g = self.dv.grant("alice", app_id, recipient, list(indexes),
                          expires=int(self.clock[0]) + ttl)
        return g["id"]

    def _chunk_sha(self, app_id, index):
        info = self.svc.get_application("alice", app_id)
        return next(c["content_sha256"] for c in info["chunks"]
                    if c["chunk_index"] == index)

    # ---------------------------------------------------------- 正常路径

    def test_batch_delivered_atomically_and_replayable(self):
        gid = self._grant(self.app_a, indexes=(0, 1))
        payload = self.dv.receive("carol", gid, self.app_a, [0, 1], "key-1")
        self.assertEqual(payload["application_id"], self.app_a)
        self.assertEqual(payload["recipient"], "carol")
        self.assertEqual([c["index"] for c in payload["chunks"]], [0, 1])
        self.assertEqual(payload["chunks"][0]["sha256"], self._chunk_sha(self.app_a, 0))

        # 全部块翻转 delivered，claimed_by 是实际接收人而不是申请人
        info = self.svc.get_application("alice", self.app_a)
        by_index = {c["chunk_index"]: c for c in info["chunks"]}
        self.assertEqual(by_index[0]["status"], "delivered")
        self.assertEqual(by_index[1]["status"], "delivered")
        self.assertEqual(by_index[2]["status"], "available")
        self.assertEqual(by_index[0]["claimed_by"], "carol")

        # 同键同请求：幂等返回同一回执
        again = self.dv.receive("carol", gid, self.app_a, [0, 1], "key-1")
        self.assertEqual(again, payload)

    # ---------------------------------------------------- 导出越界：借甲领乙

    def test_cannot_claim_other_export_of_same_applicant(self):
        gid = self._grant(self.app_a, indexes=(0,))
        # 授权属于甲，却报乙的 application_id —— 旧代码会把乙的块交付出去
        with self.assertRaises(ForbiddenError):
            self.dv.receive("carol", gid, self.app_b, [0], "key-evil")

        # 乙的块必须仍然 available，没有被夹带交付
        info_b = self.svc.get_application("alice", self.app_b)
        self.assertTrue(all(c["status"] == "available" for c in info_b["chunks"]))

    def test_chunk_index_outside_grant_scope_rejected(self):
        gid = self._grant(self.app_a, indexes=(0,))
        with self.assertRaises(ForbiddenError):
            self.dv.receive("carol", gid, self.app_a, [1], "key-x")
        info = self.svc.get_application("alice", self.app_a)
        self.assertEqual(info["chunks"][1]["status"], "available")

    # ------------------------------------------------------- 整批原子性

    def test_batch_all_or_nothing_when_later_chunk_undeliverable(self):
        gid = self._grant(self.app_a, indexes=(0, 1))
        # 申请人先把块 1 领走：批次预检必须在交付块 0 之前发现块 1 不可交付
        self.svc.claim_chunk("alice", self.app_a, 1)
        with self.assertRaises(InvalidStateError):
            self.dv.receive("carol", gid, self.app_a, [0, 1], "key-batch")

        info = self.svc.get_application("alice", self.app_a)
        by_index = {c["chunk_index"]: c for c in info["chunks"]}
        # 块 0 不得被记成交付；无回执产生
        self.assertEqual(by_index[0]["status"], "available")
        self.assertIsNone(by_index[0]["claimed_by"])

    def test_missing_chunk_row_aborts_whole_batch(self):
        gid = self._grant(self.app_a, indexes=(0, 1))
        # 直接删库模拟块行缺失：预检必须在交付块 0 之前发现并整体拒绝
        c = self.svc._conn()
        try:
            c.execute("DELETE FROM chunks WHERE application_id=? AND chunk_index=1",
                      (self.app_a,))
            c.commit()
        finally:
            c.close()
        with self.assertRaises(NotFoundError):
            self.dv.receive("carol", gid, self.app_a, [0, 1], "key-bad")
        info = self.svc.get_application("alice", self.app_a)
        self.assertEqual(info["chunks"][0]["status"], "available")

    # --------------------------------------------- request_key 冲突检测

    def test_same_key_with_different_chunk_list_rejected(self):
        gid = self._grant(self.app_a, indexes=(0, 1))
        first = self.dv.receive("carol", gid, self.app_a, [0], "key-swap")
        # 同一 request_key 改领块 1：必须拒绝，且不能返回块 1 的内容
        with self.assertRaises(InvalidStateError):
            self.dv.receive("carol", gid, self.app_a, [1], "key-swap")
        # 原请求仍返回原回执
        still = self.dv.receive("carol", gid, self.app_a, [0], "key-swap")
        self.assertEqual(still, first)
        info = self.svc.get_application("alice", self.app_a)
        self.assertEqual(info["chunks"][1]["status"], "available")

    def test_same_key_with_different_application_rejected(self):
        gid = self._grant(self.app_a, indexes=(0,))
        gid_b = self._grant(self.app_b, indexes=(0,))
        self.dv.receive("carol", gid, self.app_a, [0], "shared-key")
        # 同样的 request_key 拿去对另一份授权/导出使用：回执键冲突
        with self.assertRaises(InvalidStateError):
            self.dv.receive("carol", gid_b, self.app_b, [0], "shared-key")
        # 同一份授权却夹带另一份导出的 application_id：授权三元组不匹配
        with self.assertRaises(ForbiddenError):
            self.dv.receive("carol", gid, self.app_b, [0], "another-key")

    # ----------------------------------------------- 撤销/到期后的重取

    def test_revoked_grant_allows_replay_but_blocks_new_delivery(self):
        gid = self._grant(self.app_a, indexes=(0, 1))
        first = self.dv.receive("carol", gid, self.app_a, [0, 1], "key-done")
        self.dv.revoke("alice", gid)

        # 已交付批次：原接收人 + 原请求 → 仍可取回完全相同字节
        replay = self.dv.receive("carol", gid, self.app_a, [0, 1], "key-done")
        self.assertEqual(replay, first)

        # 同键换清单：撤销后依旧不允许冒充
        with self.assertRaises(InvalidStateError):
            self.dv.receive("carol", gid, self.app_a, [0], "key-done")
        # 新请求：被撤销闸阻止
        with self.assertRaises(InvalidStateError):
            self.dv.receive("carol", gid, self.app_a, [2], "key-new")

    def test_expired_grant_allows_replay_but_blocks_new_delivery(self):
        gid = self._grant(self.app_a, indexes=(0,))
        first = self.dv.receive("carol", gid, self.app_a, [0], "key-exp")
        self.clock[0] += 10_000  # 授权到期
        self.assertEqual(
            self.dv.receive("carol", gid, self.app_a, [0], "key-exp"), first
        )
        with self.assertRaises(InvalidStateError):
            self.dv.receive("carol", gid, self.app_a, [0], "key-new")

    # ----------------------------------------------------- 接收人核对

    def test_only_named_recipient_can_receive_and_replay(self):
        gid = self._grant(self.app_a, recipient="carol", indexes=(0,))
        with self.assertRaises(ForbiddenError):
            self.dv.receive("dave", gid, self.app_a, [0], "key-r")
        self.dv.receive("carol", gid, self.app_a, [0], "key-r")
        # 交付后换接收人重放同样被拒
        with self.assertRaises(ForbiddenError):
            self.dv.receive("dave", gid, self.app_a, [0], "key-r")

    def test_audit_records_actual_recipient_and_denials(self):
        gid = self._grant(self.app_a, indexes=(0,))
        self.dv.receive("carol", gid, self.app_a, [0], "key-audit")
        entries = self.svc.list_audit("root", limit=500)
        claimed = [e for e in entries
                   if e["action"] == "CHUNK_CLAIMED"
                   and e["details"].get("via_grant") == gid]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["actor"], "carol")
        self.assertEqual(claimed[0]["details"]["recipient"], "carol")

        with self.assertRaises(ForbiddenError):
            self.dv.receive("dave", gid, self.app_a, [0], "key-deny")
        entries = self.svc.list_audit("root", limit=500)
        denied = [e for e in entries if e["action"] == "RECIPIENT_RECEIVED"
                  and e["result"] == "denied"]
        self.assertTrue(denied)
        self.assertEqual(denied[0]["actor"], "dave")

        # 全部动作落哈希链且链完好
        self.assertTrue(self.svc.verify_audit("root")["ok"])

    # --------------------------------------------------------- 授权校验

    def test_grant_requires_approved_owner(self):
        app_pending = self.svc.apply_export("alice", "待审批", chunk_size=2)
        with self.assertRaises(ForbiddenError):
            self.dv.grant("alice", app_pending, "carol", [0],
                          expires=int(self.clock[0]) + 100)
        # bob 不是该申请的所有人
        with self.assertRaises(ForbiddenError):
            self.dv.grant("bob", self.app_a, "carol", [0],
                          expires=int(self.clock[0]) + 100)

    def test_grant_rejects_bad_indexes_and_past_expiry(self):
        future = int(self.clock[0]) + 100
        with self.assertRaises(ValidationError):
            self.dv.grant("alice", self.app_a, "carol", [], future)
        with self.assertRaises(ValidationError):
            self.dv.grant("alice", self.app_a, "carol", [0, 0], future)
        with self.assertRaises(ValidationError):
            self.dv.grant("alice", self.app_a, "carol", [99], future)
        with self.assertRaises(ValidationError):
            self.dv.grant("alice", self.app_a, "carol", [0],
                          expires=int(self.clock[0]) - 1)

    def test_receive_rejects_duplicate_indexes_in_request(self):
        gid = self._grant(self.app_a, indexes=(0,))
        with self.assertRaises(ValidationError):
            self.dv.receive("carol", gid, self.app_a, [0, 0], "key-dup")

    def test_unknown_grant_is_denied_and_audited(self):
        with self.assertRaises(NotFoundError):
            self.dv.receive("carol", "deadbeef", self.app_a, [0], "key-nope")
        entries = self.svc.list_audit("root", limit=500)
        self.assertTrue(any(
            e["action"] == "RECIPIENT_RECEIVED" and e["result"] == "denied"
            and e["details"]["reason"] == "grant_not_found"
            for e in entries
        ))

    # ------------------------------------------------- 回执内容固化核对

    def test_concurrent_same_batch_all_get_same_receipt(self):
        import threading

        gid = self._grant(self.app_a, indexes=(0, 1))
        barrier = threading.Barrier(8)
        results, errors = [], []

        def worker():
            barrier.wait()
            try:
                results.append(
                    self.dv.receive("carol", gid, self.app_a, [0, 1], "race-key")
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors, errors)
        self.assertEqual(len(results), 8)
        # 所有重试拿到字节完全相同的同一回执；块只翻转一次
        first = results[0]
        for r in results[1:]:
            self.assertEqual(
                [c["sha256"] for c in r["chunks"]],
                [c["sha256"] for c in first["chunks"]],
            )
        info = self.svc.get_application("alice", self.app_a)
        self.assertEqual(
            sum(1 for c in info["chunks"] if c["status"] == "delivered"), 2
        )

    def test_concurrent_overlapping_batches_one_wins_nothing_partial(self):
        import threading

        # 两个接收人各持一份授权：批次 [0,1] 与 [1,2] 在块 1 上重叠
        g1 = self._grant(self.app_a, recipient="carol", indexes=(0, 1))
        g2 = self._grant(self.app_a, recipient="dave", indexes=(1, 2))
        barrier = threading.Barrier(2)
        outcomes = {}

        def receive(who, gid, indexes, key):
            barrier.wait()
            try:
                outcomes[who] = ("ok", self.dv.receive(
                    who, gid, self.app_a, indexes, key))
            except Exception as exc:
                outcomes[who] = ("err", type(exc).__name__)

        t1 = threading.Thread(target=receive,
                              args=("carol", g1, [0, 1], "b1"))
        t2 = threading.Thread(target=receive,
                              args=("dave", g2, [1, 2], "b2"))
        t1.start(); t2.start(); t1.join(); t2.join()

        info = self.svc.get_application("alice", self.app_a)
        statuses = {c["chunk_index"]: c["status"] for c in info["chunks"]}
        winner = next(w for w, v in outcomes.items() if v[0] == "ok")
        loser = "dave" if winner == "carol" else "carol"
        self.assertEqual(outcomes[loser][0], "err")
        won_indexes = [0, 1] if winner == "carol" else [1, 2]
        # 赢家的两块全部 delivered；败者独占的块（0 或 2）必须保持 available，
        # 绝不允许出现"败者先翻了一块、随后整批失败"的部分交付
        for i in (0, 1, 2):
            self.assertEqual(statuses[i],
                             "delivered" if i in won_indexes else "available")

    def test_receipt_persists_sha256_per_chunk(self):
        gid = self._grant(self.app_a, indexes=(0, 1))
        payload = self.dv.receive("carol", gid, self.app_a, [0, 1], "key-sha")
        # 直接读库确认回执表固化了指纹与每个块摘要
        c = self.svc._conn()
        try:
            row = c.execute(
                "SELECT fingerprint, payload FROM recipient_receipts "
                "WHERE grant_id=? AND request_key=?", (gid, "key-sha")
            ).fetchone()
        finally:
            c.close()
        self.assertTrue(row["fingerprint"])
        stored = json.loads(row["payload"])
        self.assertEqual(
            [p["sha256"] for p in stored["chunks"]],
            [p["sha256"] for p in payload["chunks"]],
        )
        self.assertEqual(
            [p["sha256"] for p in stored["chunks"]],
            [self._chunk_sha(self.app_a, 0), self._chunk_sha(self.app_a, 1)],
        )
