from binaryninja.interaction import (
    show_message_box,
    get_text_line_input,
)
from binaryninjaui import (
    getMonospaceFont,
    UIActionHandler,
    getThemeColor,
    ThemeColor,
    UIContext,
)
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon
from binaryninja import BinaryView
from PySide6.QtGui import (
    QBrush,
)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QVBoxLayout,
    QWidget,
    QTableWidget,
    QTableWidgetItem,
    QMenu,
)
from .snapshot_manager import get_snapshot_manager, restore_snapshot, TITLE

# adapted from https://github.com/borzacchiello/seninja/blob/master/ui/registers_view.py


def _makewidget(parent, val, center=False):
    out = QTableWidgetItem(str(val))
    out.setFlags(Qt.ItemIsEnabled)
    out.setFont(getMonospaceFont(parent))
    if center:
        out.setTextAlignment(Qt.AlignCenter)
    return out


def _get_active_binary_view() -> BinaryView:
    ctx = UIContext.activeContext()
    if ctx is None:
        return None
    action_handler = ctx.contentActionHandler()
    if action_handler is None:
        return None
    action_ctx = action_handler.actionContext()
    if action_ctx is None:
        return None
    return action_ctx.binaryView


class SnapshotWidget(QWidget):
    active_color = QBrush(getThemeColor(ThemeColor.OrangeStandardHighlightColor))

    def __init__(self, parent):
        QWidget.__init__(self, parent)
        self.tabname = ""
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.binary_view = _get_active_binary_view()
        self.data = get_snapshot_manager(self.binary_view)

        self.layout = QVBoxLayout()

        # Set up snapshot table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Name", "Description", "Date"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(
            self.on_customContextMenuRequested
        )
        self.table.doubleClicked.connect(self.on_doubleClick)

        self.layout.addWidget(self.table)
        self.setLayout(self.layout)

    def _refresh(self):
        self.table.clearContents()
        # check for activation of tab before bv is created, also check if db backed
        if (
            self.data is None
            or len(self.data.snapshots) == 0
            or self.binary_view.file.has_database is False
        ):
            self.table.setRowCount(0)
            return
        snapshots = self.data.snapshots.values()
        self.table.setRowCount(len(snapshots))
        for i, snapshot in enumerate(snapshots):
            self.table.setItem(i, 0, _makewidget(self, snapshot.name))
            self.table.setItem(i, 1, _makewidget(self, snapshot.description))
            self.table.setItem(i, 2, _makewidget(self, snapshot.date))
            if snapshot.id == self.data.find_base_snapshot_id(
                self.binary_view.file.database,
                self.binary_view.file.database.current_snapshot.id,
            ):
                self.table.item(i, 0).setForeground(self.active_color)
                self.table.item(i, 1).setForeground(self.active_color)
                self.table.item(i, 2).setForeground(self.active_color)

    def stateInit(self):
        self._refresh()

    # right click menu
    def on_customContextMenuRequested(self, pos):
        item = self.table.itemAt(pos)
        if item is None:
            menu = QMenu()
            refresh = menu.addAction("Refresh")
            action = menu.exec_(self.table.viewport().mapToGlobal(pos))
            if action == refresh:
                self._refresh()
            return
        row_idx = item.row()
        # get column 0 value, which is the snapshot name
        snapshot_name = self.table.item(row_idx, 0).text()
        snapshot = self.data.get_snapshot_by_name(snapshot_name)
        menu = QMenu()
        edit_name = menu.addAction("Edit name")
        edit_desc = menu.addAction("Edit description")
        restore_ss = menu.addAction("Restore to this snapshot")
        delete_snapshot = menu.addAction("Delete snapshot")
        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action is None:
            return
        if action == edit_name:
            new_name = get_text_line_input("Enter new name", "Edit Name")
            if new_name is None:
                return
            self.data.edit_snapshot(snapshot, new_name.decode(), snapshot.description)
            self._refresh()
        elif action == edit_desc:
            new_desc = get_text_line_input("Enter new description", "Edit Description")
            if new_desc is None:
                return
            self.data.edit_snapshot(snapshot, snapshot.name, new_desc.decode())
            self._refresh()
        elif action == delete_snapshot:
            if (
                show_message_box(
                    TITLE,
                    "Are you sure you want to delete this snapshot?",
                    MessageBoxButtonSet.YesNoButtonSet,
                    MessageBoxIcon.WarningIcon,
                )
                == 1
            ):
                self.data.remove_snapshot(snapshot)
                self._refresh()
        elif action == restore_ss:
            restore_snapshot(self.binary_view, snapshot.id)
            # refresh bv as restoring snapshot changes the bv
            self.binary_view = _get_active_binary_view()
            self.data.binary_view = self.binary_view
            # refresh snapshot manager as it was tied to the old bv
            self.data = get_snapshot_manager(self.binary_view)

    # double click event
    def on_doubleClick(self, item: QTableWidgetItem):
        row_idx = item.row()
        col_idx = item.column()
        snapshot_name = self.table.item(row_idx, 0).text()
        snapshot = self.data.get_snapshot_by_name(snapshot_name)
        if col_idx == 0:
            new_name = get_text_line_input("Enter new name", "Edit Name")
            if new_name is None:
                return
            elif new_name == b"":
                show_message_box(
                    TITLE, "Name cannot be empty!", icon=MessageBoxIcon.ErrorIcon
                )
                return
            self.data.edit_snapshot(snapshot, new_name.decode(), snapshot.description)
        elif col_idx == 1:
            new_desc = get_text_line_input("Enter new description", "Edit Description")
            if new_desc is None:
                return
            self.data.edit_snapshot(snapshot, snapshot.name, new_desc.decode())
        self._refresh()

    def notifytab(self, newName):
        self.tabname = newName
        new_bv = _get_active_binary_view()
        if new_bv is not None:
            self.binary_view = new_bv
            # account for when bv created, but snapshot manager not created yet
            if self.data is not None:
                self.data.binary_view = new_bv
        self._refresh()

    def notifyOffsetChanged(self, offset):
        pass

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        return True
