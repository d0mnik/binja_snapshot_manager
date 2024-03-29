from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    getThemeColor,
    ThemeColor,
)
from PySide6 import QtCore
from PySide6.QtGui import QPainter, QBrush, QImage
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QVBoxLayout

from .snapshot_manager_view import SnapshotWidget

from pathlib import Path


class SnapshotManagerWidget(SidebarWidget):
    initSignal = QtCore.Signal(object, object)

    dirty_color = QBrush(getThemeColor(ThemeColor.OrangeStandardHighlightColor))
    expression_color = QBrush(getThemeColor(ThemeColor.RedStandardHighlightColor))
    symbolic_color = QBrush(getThemeColor(ThemeColor.BlueStandardHighlightColor))
    no_color = QBrush(getThemeColor(ThemeColor.WhiteStandardHighlightColor))

    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)
        self.initSignal.connect(self.stateInit)
        self.main_widget = SnapshotWidget(self)

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.main_widget)
        self.layout.setSpacing(0)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(self.layout)

    def stateInit(self):
        self.main_widget.stateInit()

    def notifyViewChanged(self, view_frame):
        newName = view_frame.getTabName() if view_frame is not None else ""
        self.main_widget.notifytab(newName)


class SnapshotManagerWidgetType(SidebarWidgetType):
    name = "Snapshot Manager"

    def __init__(self):
        path_this_file = Path(__file__)
        path_icon = path_this_file.parent / "icons" / "snapshot.svg"

        renderer = QSvgRenderer(path_icon.as_posix())
        icon = QImage(56, 56, QImage.Format_ARGB32)
        icon.fill(0x463F3F)

        p = QPainter(icon)
        renderer.render(p)
        p.end()
        SidebarWidgetType.__init__(self, icon, SnapshotManagerWidgetType.name)

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created for a given context. Different
        # widgets are created for each unique BinaryView. They are created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        return SnapshotManagerWidget(SnapshotManagerWidgetType.name, frame, data)

    def defaultLocation(self):
        # Default location in the sidebar where this widget will appear
        return SidebarWidgetLocation.LeftContent

    def contextSensitivity(self):
        # Context sensitivity controls which contexts have separate instances of the sidebar widget.
        # Using `contextSensitivity` instead of the deprecated `viewSensitive` callback allows sidebar
        # widget implementations to reduce resource usage.

        # This example widget uses a single instance and detects view changes.
        return SidebarContextSensitivity.SelfManagedSidebarContext
