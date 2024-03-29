from dataclasses import dataclass, asdict, is_dataclass
from binaryninja import (
    show_message_box,
    get_form_input,
    get_choice_input,
    TextLineField,
    MessageBoxIcon,
    MultilineTextField,
    PluginCommand,
    BinaryView,
    Database,
    Function,
)
from binaryninja.mainthread import execute_on_main_thread_and_wait
from binaryninjaui import UIContext
from datetime import datetime
import json

METATDATA_NAME = "snapshot_manager"
ACTIVE_ID_KEY = "active_snapshot_id"

TITLE = "Snapshot Manager"

ss_info = None


class DataClassEncoder(json.JSONEncoder):
    def default(self, obj):
        if is_dataclass(obj):
            return asdict(obj)
        return super().default(obj)


class DataClassDecoder(json.JSONDecoder):
    def __init__(self) -> None:
        super().__init__(object_hook=self.from_dict)

    @staticmethod
    def from_dict(d):
        if "id" in d and "name" in d and "description" in d:
            d = Snapshot(
                int(d["id"]),
                d["name"],
                d["description"],
                d["date"],
            )
        return d


@dataclass
class Snapshot:
    id: int
    name: str
    description: str
    date: str


class SnapshotManager(object):
    def __init__(self, bv: BinaryView) -> None:
        self.snapshots: dict[int, Snapshot] = {}
        self.binary_view: BinaryView = bv

    def _write_to_bndb(self):
        db: Database = self.binary_view.file.database
        db.write_global(
            METATDATA_NAME, json.dumps(self.snapshots, cls=DataClassEncoder)
        )

    def add_snapshot(self, snapshot: Snapshot):
        self.snapshots[snapshot.id] = snapshot
        # add to bndb
        self._write_to_bndb()

    def edit_snapshot(self, snapshot: Snapshot, name: str, description: str):
        snapshot.name = name
        snapshot.description = description
        self.snapshots[snapshot.id] = snapshot
        # add to bndb
        self._write_to_bndb()

    def remove_snapshot(self, snapshot: Snapshot):
        # do not actually remove the Binary Ninja internal snapshot
        if snapshot.id in self.snapshots:
            self.snapshots.pop(snapshot.id)
            self._write_to_bndb()
            return True
        return False

    def remove_all_snapshots(self):
        self.snapshots = {}
        self._write_to_bndb()

    def get_snapshot_names(self):
        return [snapshot.name for snapshot in self.snapshots.values()]

    def get_snapshot_by_name(self, name: str) -> Snapshot:
        for snapshot in self.snapshots.values():
            if snapshot.name == name:
                return snapshot
        return None

    def find_base_snapshot_id(self, database: Database, snapshot_id: int) -> id:
        if database is None:
            return None
        ss = database.get_snapshot(snapshot_id)
        if ss is None:
            return None
        if self.snapshots.get(ss.id) is not None:
            return ss.id
        for parent in ss.parents:
            if self.snapshots.get(parent.id) is not None:
                return self.snapshots[parent.id].id
        return None


def refresh_tab(ctx, path: str):
    tab = ctx.getCurrentTab()

    def close_tab():
        return ctx.closeTab(tab)

    execute_on_main_thread_and_wait(close_tab)

    def open_tab():
        return ctx.openFilename(path)

    execute_on_main_thread_and_wait(open_tab)


def get_snapshot_manager(bv: BinaryView):
    if bv is None or bv.file.has_database is False:
        return None
    db = bv.file.database
    snapshot_manager = bv.session_data.get(METATDATA_NAME)
    if snapshot_manager is None:
        snapshot_manager = SnapshotManager(bv)
        # load data from bndb upon first creation
        if METATDATA_NAME.encode() in db.global_keys:
            ss_info_json = db.read_global(METATDATA_NAME)
            snapshots = {
                int(k): v
                for k, v in json.loads(ss_info_json, cls=DataClassDecoder).items()
            }
            snapshot_manager.snapshots = snapshots
        bv.session_data[METATDATA_NAME] = snapshot_manager
    return snapshot_manager


def take_snapshot(bv: BinaryView, func: Function):
    if bv.file.has_database is False:
        show_message_box(
            TITLE,
            "Database not found. Please save a database first.",
            icon=MessageBoxIcon.ErrorIcon,
        )
        return
    snapshot_manager: SnapshotManager = get_snapshot_manager(bv)
    db = bv.file.database
    name_text = b""
    while name_text == b"":
        name_text = TextLineField("Snapshot Name")
        description_text = MultilineTextField("Description")
        success = get_form_input(
            ["Snapshot Information", name_text, description_text], TITLE
        )
        # handle cancel
        if not success:
            return
        # handle duplicate names
        if name_text.result in snapshot_manager.get_snapshot_names():
            show_message_box(
                TITLE, "Snapshot name already exists!", icon=MessageBoxIcon.ErrorIcon
            )
            name_text = b""
            continue
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    success = bv.save_auto_snapshot()
    if not success:
        show_message_box(
            TITLE, "Failed to take snapshot!", icon=MessageBoxIcon.ErrorIcon
        )
        return
    new_snapshot = Snapshot(
        db.current_snapshot.id,
        name_text.result,
        description_text.result,
        current_datetime,
    )
    snapshot_manager.add_snapshot(new_snapshot)


def restore_snapshot(bv: BinaryView, snapshot_id: int):
    db = bv.file.database
    chosen_snapshot = db.get_snapshot(snapshot_id)
    if chosen_snapshot is None:
        show_message_box(
            TITLE, "Unable to load snapshot.", icon=MessageBoxIcon.ErrorIcon
        )
        return
    db.current_snapshot = chosen_snapshot
    # reload the UI
    ctx = UIContext.activeContext()
    refresh_tab(ctx, bv.file.filename)


def restore_snapshot_callback(bv: BinaryView, func: Function):
    if bv.file.has_database is False:
        show_message_box(
            TITLE,
            "Database not found. Please save a database first.",
            icon=MessageBoxIcon.ErrorIcon,
        )
        return
    snapshot_manager = get_snapshot_manager(bv)
    if len(snapshot_manager.snapshots) == 0:
        show_message_box(TITLE, "No snapshots found!", icon=MessageBoxIcon.ErrorIcon)
        return
    snapshot_names = snapshot_manager.get_snapshot_names()
    snapshot_idx = get_choice_input(
        "Choose DB snapshot to checkout", TITLE, snapshot_names
    )
    # handle cancel
    if snapshot_idx is None:
        return
    snapshot_name = snapshot_names[snapshot_idx]
    snapshot_id = snapshot_manager.get_snapshot_by_name(snapshot_name).id
    restore_snapshot(bv, snapshot_id)


PluginCommand.register_for_function(
    "Snapshot Manager\\Take snapshot",
    "Save current state as DB snapshot",
    take_snapshot,
)

PluginCommand.register_for_function(
    "Snapshot Manager\\Restore snapshot",
    "Checkout to saved snapshot",
    restore_snapshot_callback,
)
