"""M1 lifecycle owns only its invocation and never starts after failed admission."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = "kryvola-m1-0123456789ab"


def claim(stack):
    stack.folder.mkdir()
    (stack.folder / "ownership.json").write_text(
        json.dumps({"project": stack.project, "token": stack.token})
    )
    stack.owned = True


class M1RunnerTests(unittest.TestCase):
    def test_arbitrary_projects_are_rejected_without_disk_side_effects(self):
        from tools.m1 import Stack

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for project in (
                "production",
                "kryvola-m0-0123456789ab",
                "kryvola-m1-../../",
                PROJECT + "x",
            ):
                with self.subTest(project=project), self.assertRaises(ValueError):
                    Stack(project, root=root)
            self.assertEqual(list(root.iterdir()), [])

    def test_unowned_close_never_calls_compose(self):
        from tools.m1 import Stack

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stack = Stack(PROJECT, root=root)
            self.assertEqual(stack.folder, root / PROJECT)
            self.assertFalse(stack.owned)
            with patch.object(stack, "compose") as compose:
                stack.close()
            compose.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_missing_or_changed_marker_prevents_cleanup(self):
        from tools.m1 import Stack

        for change in ("missing", "project", "token", "extra"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                stack = Stack(PROJECT, root=Path(tmp))
                claim(stack)
                path = stack.folder / "ownership.json"
                if change == "missing":
                    path.unlink()
                else:
                    marker = {"project": stack.project, "token": stack.token}
                    marker[change] = "changed"
                    path.write_text(json.dumps(marker))
                with patch.object(stack, "compose") as compose:
                    with self.assertRaisesRegex(ValueError, "M1_OWNERSHIP_REJECTED"):
                        stack.close()
                compose.assert_not_called()
                self.assertTrue(stack.folder.exists())

    def test_failed_admission_cannot_claim_or_start_services(self):
        from tools.m1 import Stack

        with tempfile.TemporaryDirectory() as tmp:
            stack = Stack(PROJECT, root=Path(tmp))
            with (
                patch.object(
                    stack, "prepare", side_effect=ValueError("M1_ASSET_CHANGED")
                ) as prepare,
                patch.object(stack, "compose") as compose,
            ):
                with self.assertRaisesRegex(ValueError, "M1_ASSET_CHANGED"):
                    stack.start()
            prepare.assert_called_once_with()
            compose.assert_not_called()
            self.assertFalse(stack.owned)
            self.assertFalse(stack.folder.exists())

    def test_startup_failure_cleans_only_its_claimed_project(self):
        from tools.m1 import Stack

        with tempfile.TemporaryDirectory() as tmp:
            stack = Stack(PROJECT, root=Path(tmp))
            commands = []

            def compose(*args, **kwargs):
                commands.append(args)
                if args[0] == "up":
                    raise RuntimeError("startup failed")

            with (
                patch.object(stack, "prepare", side_effect=lambda: claim(stack)),
                patch.object(stack, "compose", side_effect=compose),
            ):
                with self.assertRaisesRegex(RuntimeError, "startup failed"):
                    stack.start()
            self.assertEqual([args[0] for args in commands], ["up", "down"])
            self.assertIn("--volumes", commands[1])
            self.assertFalse(stack.owned)

    def test_rejects_unpinned_images_compute_credentials_and_external_networks(self):
        from tools import m1

        valid = json.loads(m1.COMPOSE.read_bytes())
        import copy

        changes = (
            lambda c: c["services"]["ray"].update(volumes=["owner:/renamed-private-volume"]),
            lambda c: c["services"]["ray"].update(networks=["compute", "data"]),
            lambda c: c["services"]["ray"].update(cap_drop=[]),
            lambda c: c["services"]["ray"].update(security_opt=[]),
            lambda c: c["services"]["ray"].update(read_only=False),
            lambda c: c["services"]["engine"].update(ulimits={}),
            lambda c: c["services"]["engine"].update(image="cpu-engine:latest"),
            lambda c: c["services"]["ray"].update(environment={"DATABASE_URL": "secret"}),
            lambda c: c["services"]["ray"].update(
                volumes=["${M1_RUN:?m1 runner required}/secrets/s3.json:/run/s3.json:ro"]
            ),
            lambda c: c["services"]["owner"].update(networks=["compute"]),
            lambda c: c["networks"]["owner"].update(internal=False),
            lambda c: c["services"]["owner"].update(
                volumes=["/var/run/docker.sock:/var/run/docker.sock"]
            ),
            lambda c: c["services"]["runtime"].update(
                image="${M1_PYTHON_IMAGE:?m1 runner required}"
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "compose.json"
            for change in changes:
                value = copy.deepcopy(valid)
                change(value)
                path.write_text(json.dumps(value))
                with (
                    patch.object(m1, "COMPOSE", path),
                    self.assertRaisesRegex(ValueError, "M1_COMPOSITION_REJECTED"),
                ):
                    m1.check()

    def test_partly_prepared_failure_releases_images_without_compose(self):
        from tools.m1 import Stack

        with tempfile.TemporaryDirectory() as tmp:
            stack = Stack(PROJECT, root=Path(tmp))
            claim(stack)
            stack.building = True
            with (
                patch.object(stack, "compose") as compose,
                patch.object(stack.resources, "close") as release,
            ):
                stack.close()
            compose.assert_not_called()
            release.assert_called_once_with()
            self.assertFalse(stack.folder.exists())
